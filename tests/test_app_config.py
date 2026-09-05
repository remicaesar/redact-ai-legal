"""Startup and hardening configuration guards.

These cover the things that are set once at import time and are therefore easy
to regress silently: the session secret (which used to have a published default
that made an admin session forgeable), the session cookie flags, the upload
size cap, and the single shared HTML-escaping helper the templates must use
instead of five local copies that did not escape quotes.
"""

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
import app as app_module

PROJECT_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_WITH_ESCAPE_HTML = ["index.html", "matters.html", "matter.html", "studio.html", "audit.html"]


class SecretKeyTests(unittest.TestCase):
    def test_missing_secret_key_refuses_to_start(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit) as raised:
                app_module.resolve_secret_key()

        message = str(raised.exception)
        self.assertIn("LEGAL_ANALYZER_SECRET_KEY", message)
        self.assertIn("secrets.token_hex(32)", message)

    def test_blank_secret_key_refuses_to_start(self):
        with mock.patch.dict(os.environ, {"LEGAL_ANALYZER_SECRET_KEY": "   "}, clear=True):
            with self.assertRaises(SystemExit):
                app_module.resolve_secret_key()

    def test_configured_secret_key_is_used(self):
        with mock.patch.dict(os.environ, {"LEGAL_ANALYZER_SECRET_KEY": "abc123"}, clear=True):
            self.assertEqual(app_module.resolve_secret_key(), "abc123")

    def test_importing_app_without_a_secret_key_exits_nonzero(self):
        # The guard has to fire at import, not at first request: a process that
        # got as far as serving traffic has already signed cookies. dotenv is
        # stubbed out so a developer's local .env cannot satisfy the check.
        code = (
            "import sys, types\n"
            "sys.modules['dotenv'] = types.SimpleNamespace(load_dotenv=lambda *a, **k: None)\n"
            "import app\n"
        )
        env = {key: value for key, value in os.environ.items() if key != "LEGAL_ANALYZER_SECRET_KEY"}
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=PROJECT_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("LEGAL_ANALYZER_SECRET_KEY", result.stderr)
        self.assertIn("secrets.token_hex(32)", result.stderr)


class HardeningConfigTests(unittest.TestCase):
    def test_session_cookies_are_httponly_and_samesite_strict(self):
        self.assertTrue(app_module.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(app_module.app.config["SESSION_COOKIE_SAMESITE"], "Strict")

    def test_request_bodies_are_capped_at_the_extractor_ceiling(self):
        # Werkzeug rejects past MAX_CONTENT_LENGTH and blueprints/documents.py
        # audits against MAX_UPLOAD_BYTES; both must be the number the ZIP
        # extractor is willing to read back, or an upload can claim more disk
        # than extraction will ever process.
        from legal_analyzer.extraction import ZIP_MAX_TOTAL_BYTES

        self.assertEqual(app_module.app.config["MAX_CONTENT_LENGTH"], app_module.MAX_UPLOAD_BYTES)
        self.assertEqual(app_module.MAX_UPLOAD_BYTES, ZIP_MAX_TOTAL_BYTES)

    def test_logout_rejects_get(self):
        rules = [rule for rule in app_module.app.url_map.iter_rules() if str(rule) == "/logout"]
        self.assertEqual(len(rules), 1)
        self.assertNotIn("GET", rules[0].methods)
        self.assertIn("POST", rules[0].methods)


class SharedEscapeHelperTests(unittest.TestCase):
    escape_js = PROJECT_DIR / "static" / "escape.js"

    def test_templates_include_the_shared_helper_and_define_no_local_copy(self):
        for name in TEMPLATES_WITH_ESCAPE_HTML:
            with self.subTest(template=name):
                source = (PROJECT_DIR / "templates" / name).read_text(encoding="utf-8")
                self.assertIn("filename='escape.js'", source)
                self.assertNotIn("function escapeHtml", source)
                self.assertNotIn("function escapeAttr", source)

    def test_escape_js_escapes_quotes_as_well_as_angle_brackets(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed; escape.js behaviour not exercised")
        # The helper is interpolated into double-quoted attributes fed by stored
        # filenames and reviewer replacement text, so quotes matter as much as
        # angle brackets. The old text-node implementation escaped neither.
        script = (
            f"{self.escape_js.read_text(encoding='utf-8')}\n"
            "const value = `x\" onerror='alert(1)' <b>&`;\n"
            "console.log(escapeHtml(value));\n"
            "console.log(escapeAttr(value));\n"
        )
        result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

        escaped, attr_escaped = result.stdout.strip().splitlines()
        self.assertEqual(escaped, "x&quot; onerror=&#39;alert(1)&#39; &lt;b&gt;&amp;")
        self.assertEqual(attr_escaped, escaped)
        self.assertNotIn('"', escaped)
        self.assertNotIn("'", escaped)


if __name__ == "__main__":
    unittest.main()
