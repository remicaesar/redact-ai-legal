import unittest
from zipfile import ZipFile
from io import BytesIO

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
from app import build_docx


class ExportTests(unittest.TestCase):
    def test_build_docx_contains_document_xml(self):
        data = build_docx("Redacted line")

        with ZipFile(BytesIO(data)) as archive:
            self.assertIn("word/document.xml", archive.namelist())
            document_xml = archive.read("word/document.xml").decode("utf-8")

        self.assertIn("Redacted line", document_xml)


if __name__ == "__main__":
    unittest.main()
