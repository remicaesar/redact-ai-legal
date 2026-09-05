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
        self.assertIn("005_finding_review_split_reject", applied)
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
                "005_finding_review_split_reject",
                "005_login_throttle",
            ],
        )
        self.assertEqual(second, [])

    def test_rejected_findings_are_converted_to_dismissed(self):
        """005 resolves the pre-split status, and only for privacy findings.

        'rejected' meant both "false positive" and "real, left unredacted", and
        the system could not tell them apart. Every existing row becomes
        'dismissed' because that is the reading which preserves the old
        observable behaviour: the finding stays resolved and does not block
        release. A rejected PDF redaction box is a different workflow and must
        be untouched.
        """
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "with_rejected.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(Path("db/schema.sql").read_text(encoding="utf-8"))
            conn.execute(
                "INSERT INTO documents (id, filename, filepath) VALUES (1, 'dilekce.docx', '/tmp/dilekce.docx')"
            )
            for status in ("pending", "approved", "rejected", "added_by_reviewer"):
                conn.execute(
                    """
                    INSERT INTO privacy_findings (
                        document_id, category, sample, risk, recommended_action, review_status
                    ) VALUES (1, 'turkish_national_id', '10000000146', 'CRITICAL', 'Redact', ?)
                    """,
                    (status,),
                )
            conn.execute(
                """
                INSERT INTO pdf_redaction_regions (
                    document_id, page_number, x0, y0, x1, y1, category, review_status
                ) VALUES (1, 1, 0, 0, 10, 10, 'turkish_national_id', 'rejected')
                """
            )
            conn.commit()
            conn.close()

            applied = apply_migrations(db_path)

            conn = sqlite3.connect(db_path)
            finding_statuses = sorted(row[0] for row in conn.execute("SELECT review_status FROM privacy_findings"))
            region_statuses = [row[0] for row in conn.execute("SELECT review_status FROM pdf_redaction_regions")]
            conn.close()

        self.assertIn("005_finding_review_split_reject", applied)
        self.assertEqual(finding_statuses, ["added_by_reviewer", "approved", "dismissed", "pending"])
        self.assertNotIn("rejected", finding_statuses)
        self.assertEqual(region_statuses, ["rejected"])

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
