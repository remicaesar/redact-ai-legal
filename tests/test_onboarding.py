"""Setup-only checks; all inputs and installed documents are synthetic."""

import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from contextlib import closing

import fitz

from docker.bootstrap import install_credentials
from legal_analyzer.extraction import extract_text
from legal_analyzer.privacy import analyze_privacy, valid_turkish_national_id, valid_turkish_tax_number

ROOT = Path(__file__).resolve().parents[1]


class CredentialsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'install.json'
        self.db = Path(self.tmp.name) / 'documents.db'

    def test_fresh_random_credentials_are_private_and_survive_reruns(self):
        first = install_credentials(self.path, self.db)
        original = self.path.read_bytes()
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(first['secret_key']), 64)
        self.assertGreaterEqual(len(first['password']), 32)
        self.assertEqual(install_credentials(self.path, self.db), first)
        self.assertEqual(self.path.read_bytes(), original)
        second = install_credentials(self.path.parent / 'second.json', self.db)
        self.assertNotEqual(first['secret_key'], second['secret_key'])
        self.assertNotEqual(first['password'], second['password'])

    def test_missing_credentials_never_replace_an_existing_install(self):
        self.db.write_bytes(b'synthetic existing database sentinel')
        with self.assertRaisesRegex(RuntimeError, 'Database exists'):
            install_credentials(self.path, self.db)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.db.read_bytes(), b'synthetic existing database sentinel')

    def test_invalid_credentials_fail_closed_without_rewriting(self):
        for value in ({}, {'username': 'admin', 'password': '', 'secret_key': 'x'}):
            with self.subTest(value=value):
                self.path.write_text(json.dumps(value))
                before = self.path.read_bytes()
                with self.assertRaises(RuntimeError):
                    install_credentials(self.path, self.db)
                self.assertEqual(self.path.read_bytes(), before)

    def test_creation_is_exclusive(self):
        # Model a concurrent setup creating the file between exists() and open().
        self.path.write_text('another setup owns this file')
        with patch.object(Path, 'exists', return_value=False):
            with self.assertRaises(FileExistsError):
                install_credentials(self.path, self.db)
        self.assertEqual(self.path.read_text(), 'another setup owns this file')


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for directory in ('db', 'legal_analyzer', 'blueprints', 'docker', 'samples'):
            shutil.copytree(ROOT / directory, self.root / directory,
                            ignore=shutil.ignore_patterns('*.db*', '__pycache__'))
        for name in ('app.py', 'classify.py'):
            shutil.copyfile(ROOT / name, self.root / name)
        self.db = self.root / 'db' / 'legal_documents.db'
        self.credentials = self.root / 'install.json'

    def run_bootstrap(self):
        return subprocess.run([sys.executable, '-c',
            "from docker.bootstrap import *; bootstrap(install_credentials(ROOT / 'install.json', ROOT / 'db/legal_documents.db'))"],
            cwd=self.root, capture_output=True, text=True, check=False)

    def rows(self, table):
        with closing(sqlite3.connect(self.db)) as conn:
            return conn.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()

    def test_clean_bootstrap_and_rerun_preserve_documents_reviews_and_credentials(self):
        first = self.run_bootstrap()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(len(self.rows('documents')), 3)
        self.assertEqual(len(self.rows('users')), 1)
        self.assertEqual(len(self.rows('document_matters')), 3)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE privacy_findings SET review_status = 'approved' WHERE id = 1")
            conn.execute("INSERT INTO audit_log (action, metadata) VALUES ('synthetic.review', '{}')")
            conn.execute("INSERT INTO documents (filename, filepath, file_extension, file_size) VALUES ('synthetic-orphan.docx', 'synthetic-orphan.docx', '.docx', 1)")
            conn.commit()
        conn.close()
        tables = ('documents', 'privacy_findings', 'pseudonym_mappings', 'users',
                  'matters', 'document_matters', 'audit_log', 'schema_migrations')
        before = {table: self.rows(table) for table in tables}
        credentials = self.credentials.read_bytes()
        rerun = self.run_bootstrap()
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertEqual({table: self.rows(table) for table in tables}, before)
        self.assertEqual(self.credentials.read_bytes(), credentials)

    def test_missing_sample_refuses_to_start(self):
        (self.root / 'samples/documents/scanned_receipt.pdf').unlink()
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('practice documents are missing', result.stderr)

    def test_classification_errors_refuse_to_start(self):
        # Inject a failed classifier report without touching the application.
        result = subprocess.run([sys.executable, '-c',
            "from unittest.mock import patch; from docker.bootstrap import *; "
            "p=patch('classify.scan_and_classify', return_value={'errors':['synthetic failure'], 'summary':{}}); "
            "p.start(); bootstrap(install_credentials(ROOT/'install.json', ROOT/'db/legal_documents.db'))"],
            cwd=self.root, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Sample classification failed', result.stderr)

    def test_mismatched_admin_credentials_are_not_silently_reset(self):
        self.assertEqual(self.run_bootstrap().returncode, 0)
        users = self.rows('users')
        value = json.loads(self.credentials.read_text())
        value['password'] = 'synthetic-wrong-password'
        self.credentials.write_text(json.dumps(value))
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('do not match the active admin', result.stderr)
        self.assertEqual(self.rows('users'), users)


class LauncherTests(unittest.TestCase):
    def run_launcher(self, args=(), failure=''):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            log = root / 'calls'
            docker = root / 'docker'
            docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALL_LOG"\n'
                              'if [ "$*" = "$FAIL_COMMAND" ]; then exit 1; fi\n')
            docker.chmod(0o755)
            result = subprocess.run(['sh', str(ROOT / 'start.sh'), *args],
                env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                     'CALL_LOG': str(log), 'FAIL_COMMAND': failure},
                capture_output=True, text=True)
            return result, log.read_text().splitlines() if log.exists() else []

    def test_rerun_is_nondestructive_reset_requires_exact_flag(self):
        result, calls = self.run_launcher()
        self.assertEqual(result.returncode, 0)
        self.assertFalse(any('down' in call for call in calls))
        self.assertIn('compose up --build --wait --wait-timeout 120', calls)
        result, calls = self.run_launcher(['--reset'])
        self.assertEqual(result.returncode, 0)
        self.assertLess(calls.index('compose down --volumes'), calls.index('compose up --build --wait --wait-timeout 120'))
        for args in (['--resett'], ['--reset', 'extra']):
            result, calls = self.run_launcher(args)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(calls, [])

    def test_unavailable_engine_and_failed_start_never_claim_ready(self):
        for failure in ('info', 'compose up --build --wait --wait-timeout 120'):
            result, calls = self.run_launcher(failure=failure)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('Redact AI is ready', result.stdout)
            self.assertFalse(any('exec' in call for call in calls))


class ShippedSamplesTests(unittest.TestCase):
    def test_docx_samples_are_synthetic_and_demonstrate_validated_identifiers(self):
        for name in ('turkish_petition.docx', 'english_agreement.docx'):
            with self.subTest(name=name):
                text, warning = extract_text(ROOT / 'samples/documents' / name)
                self.assertFalse(warning)
                self.assertIn('SYNTHETIC SAMPLE', text)
                profile = analyze_privacy(name, text, warning)
                self.assertTrue(any(f['category'] == 'email_address' for f in profile['risk_map']))
                tckn = re.search(r'TCKN: (\d{11})', text).group(1)
                vkn = re.search(r'VKN: (\d{10})', text).group(1)
                self.assertTrue(valid_turkish_national_id(tckn))
                self.assertTrue(valid_turkish_tax_number(vkn))
                samples = {f['sample'] for f in profile['risk_map']}
                self.assertIn(tckn, samples)
                self.assertTrue(any(vkn in sample for sample in samples))
                self.assertTrue('rastgele' in text or 'randomly generated' in text)
                self.assertFalse(profile['release_controls']['redaction_completed'])
                self.assertFalse(profile['release_controls']['human_review_approved'])

    def test_scan_has_an_image_and_no_hidden_text_layer(self):
        with fitz.open(ROOT / 'samples/documents/scanned_receipt.pdf') as pdf:
            self.assertEqual(len(pdf), 1)
            self.assertEqual(pdf[0].get_text().strip(), '')
            self.assertTrue(pdf[0].get_images())
        text, warning = extract_text(ROOT / 'samples/documents/scanned_receipt.pdf')
        self.assertTrue(warning)
        self.assertNotEqual(analyze_privacy('scanned_receipt.pdf', text, warning)['extraction_status']['status'], 'Complete')


if __name__ == '__main__':
    unittest.main()
