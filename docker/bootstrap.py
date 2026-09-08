"""Container-only setup. Application review/detection behavior stays in the app."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STATE = Path('/state/install.json')
SAMPLES = ('turkish_petition.docx', 'english_agreement.docx', 'scanned_receipt.pdf')


def install_credentials(path: Path, db_path: Path) -> dict[str, str]:
    if path.exists():
        credentials = json.loads(path.read_text())
        if (set(credentials) != {'username', 'password', 'secret_key'}
                or any(not isinstance(v, str) or not v.strip() for v in credentials.values())):
            raise RuntimeError('Invalid install.json; restore the credentials volume from backup.')
        return credentials
    if db_path.exists():
        raise RuntimeError('Database exists without install.json. Restore both from backup; refusing to replace credentials.')
    credentials = {
        'username': 'admin',
        'password': secrets.token_urlsafe(24),
        'secret_key': secrets.token_hex(32),
    }
    # Exclusive creation and restrictive permissions: never overwrite an install.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as handle:
        json.dump(credentials, handle)
        handle.flush()
        os.fsync(handle.fileno())
    return credentials


def bootstrap(credentials: dict[str, str]) -> None:
    if any(not (ROOT / 'samples' / 'documents' / name).is_file() for name in SAMPLES):
        raise RuntimeError('Bundled practice documents are missing; rebuild the image from a complete checkout.')
    os.environ['LEGAL_ANALYZER_ADMIN_USERNAME'] = credentials['username']
    os.environ['LEGAL_ANALYZER_ADMIN_PASSWORD'] = credentials['password']
    os.environ['LEGAL_ANALYZER_SECRET_KEY'] = credentials['secret_key']
    os.environ['LEGAL_ANALYZER_STOCK_DIR'] = str(ROOT / 'samples' / 'documents')
    # Same order as the manual quick start, with no destructive init flag.
    from db.init_db import init_database
    from db.migrate import apply_migrations
    init_database()
    apply_migrations(ROOT / 'db' / 'legal_documents.db')

    from classify import scan_and_classify
    report = scan_and_classify(ROOT / 'samples' / 'documents', [])
    if report['errors']:
        raise RuntimeError('Sample classification failed; workstation was not started.')
    print(json.dumps(report['summary']))

    from app import assign_document_to_matter, get_db
    from werkzeug.security import check_password_hash
    conn = get_db()  # Uses the existing first-admin bootstrap; never resets a user.
    try:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (credentials['username'],)).fetchone()
        if (not user or not user['active'] or user['role'] != 'admin'
                or not check_password_hash(user['password_hash'], credentials['password'])):
            raise RuntimeError('Stored credentials do not match the active admin. Restore a matching backup; no account was reset.')
        # Give the classifier's samples a matter without changing existing assignments.
        unassigned = conn.execute('''
            SELECT d.id FROM documents d
            LEFT JOIN document_matters dm ON dm.document_id = d.id
            WHERE dm.document_id IS NULL AND d.filepath IN (?, ?, ?)
        ''', SAMPLES).fetchall()
        if unassigned:
            matter = conn.execute("SELECT id FROM matters WHERE name = 'Synthetic practice'").fetchone()
            matter_id = matter['id'] if matter else conn.execute('''
                INSERT INTO matters (name, status, description)
                VALUES ('Synthetic practice', 'active', 'Fictional onboarding samples. No real parties or matters.')
            ''').lastrowid
            for document in unassigned:
                assign_document_to_matter(conn, document['id'], matter_id)
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', action='store_true', help='Print the existing local login (never the session key).')
    args = parser.parse_args()
    if args.credentials:
        credentials = json.loads(STATE.read_text())
        print(f"Username: {credentials['username']}\nPassword: {credentials['password']}")
        return
    os.umask(0o077)
    credentials = install_credentials(STATE, ROOT / 'db' / 'legal_documents.db')
    bootstrap(credentials)
    # The container listens internally; Compose publishes only on host loopback.
    os.execvp('gunicorn', ['gunicorn', '--workers', '1', '--threads', '4',
                         '--timeout', '180', '--bind', '0.0.0.0:5000', 'wsgi:application'])


if __name__ == '__main__':
    main()
