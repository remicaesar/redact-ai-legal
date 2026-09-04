import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from db.migrate import apply_migrations, migration_status


class MigrationTests(unittest.TestCase):
    def test_fresh_schema_records_migration(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "fresh.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(Path("db/schema.sql").read_text(encoding="utf-8"))
            conn.close()

            applied = apply_migrations(db_path)
            status = migration_status(db_path)

        self.assertIn("001_foundation_tables", applied)
        self.assertIn("002_matter_artifacts", applied)
        self.assertIn("003_pdf_redaction_regions", applied)
        self.assertIn("004_ocr_tokens", applied)
        self.assertTrue(all(item["applied"] for item in status))

    def test_migration_is_idempotent(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "fresh.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(Path("db/schema.sql").read_text(encoding="utf-8"))
            conn.close()

            first = apply_migrations(db_path)
            second = apply_migrations(db_path)

        self.assertEqual(
            first,
            [
                "001_foundation_tables",
                "002_matter_artifacts",
                "003_pdf_redaction_regions",
                "004_ocr_tokens",
                "005_login_throttle",
            ],
        )
        self.assertEqual(second, [])

    def test_existing_database_upgrades_without_data_loss(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "old.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                """
                CREATE TABLE documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    filepath TEXT NOT NULL UNIQUE
                )
                """
            )
            conn.execute("INSERT INTO documents (filename, filepath) VALUES ('old.docx', '/tmp/old.docx')")
            conn.commit()
            conn.close()

            apply_migrations(db_path)
            conn = sqlite3.connect(db_path)
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            count = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            conn.close()

        self.assertEqual(count, 1)
        self.assertIn("users", tables)
        self.assertIn("audit_log", tables)
        self.assertIn("matters", tables)
        self.assertIn("document_artifacts", tables)
        self.assertIn("finding_evidence", tables)
        self.assertIn("pdf_redaction_regions", tables)
        self.assertIn("ocr_tokens", tables)
        self.assertIn("schema_migrations", tables)


if __name__ == "__main__":
    unittest.main()
