"""db/init_db.py must not destroy an existing database by default.

It used to delete db/legal_documents.db unless KEEP_DB=1 was set, while being
documented as an ordinary setup step, so re-running the documented command wiped
every reviewed document, finding and audit-log row with no prompt.
"""

import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from db import init_db


class InitDatabaseResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "legal_documents.db"

    def build_database_with_a_document(self) -> None:
        with mock.patch.object(init_db, "DB_PATH", self.db_path):
            init_db.init_database()
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            INSERT INTO documents (filename, filepath, file_extension, file_size)
            VALUES ('reviewed.docx', '/tmp/reviewed.docx', '.docx', 10)
            """
        )
        conn.commit()
        conn.close()

    def document_count(self) -> int:
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        finally:
            conn.close()

    def test_default_run_keeps_an_existing_database(self):
        self.build_database_with_a_document()
        self.assertEqual(self.document_count(), 1)

        with mock.patch.object(init_db, "DB_PATH", self.db_path):
            init_db.init_database()

        self.assertEqual(self.document_count(), 1)

    def test_explicit_reset_deletes_the_database(self):
        self.build_database_with_a_document()

        with mock.patch.object(init_db, "DB_PATH", self.db_path):
            init_db.init_database(reset=True)

        self.assertEqual(self.document_count(), 0)

    def test_reset_reports_the_rows_it_is_about_to_destroy(self):
        self.build_database_with_a_document()

        with mock.patch.object(init_db, "DB_PATH", self.db_path):
            with mock.patch("builtins.print") as printed:
                init_db.init_database(reset=True)

        output = "\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertIn("about to DELETE", output)
        self.assertIn("row(s) in documents", output)

    def test_row_counts_skip_empty_tables_and_fts_shadow_tables(self):
        self.build_database_with_a_document()

        counts = init_db.row_counts(self.db_path)

        self.assertEqual(counts.get("documents"), 1)
        self.assertNotIn("audit_log", counts)  # empty tables are not listed
        self.assertEqual([name for name in counts if "_fts" in name], [])


if __name__ == "__main__":
    unittest.main()
