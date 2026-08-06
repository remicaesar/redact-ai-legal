import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile

from legal_analyzer.classifier import supported_file
from legal_analyzer.extraction import extract_text


class UDFSupportTests(unittest.TestCase):
    def test_udf_extension_is_supported(self):
        self.assertTrue(supported_file("dilekce.udf"))

    def test_extracts_plain_xml_udf_text(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "dilekce.udf"
            path.write_text(
                """<?xml version="1.0" encoding="UTF-8"?>
<document><content>Av. Ayse Demir Soruşturma No: 2026/456</content></document>
""",
                encoding="utf-8",
            )

            text, warning = extract_text(path)

        self.assertIsNone(warning)
        self.assertIn("Ayse Demir", text)
        self.assertIn("Soruşturma No: 2026/456", text)

    def test_extracts_zipped_udf_text(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "uyap.udf"
            with ZipFile(path, "w", ZIP_DEFLATED) as archive:
                archive.writestr("meta.bin", b"\x00\x01")
                archive.writestr("content.xml", "<root><p>İstanbul Anadolu Mahkemesi</p><p>Vergi No: 1234567890</p></root>")

            text, warning = extract_text(path)

        self.assertIsNone(warning)
        self.assertIn("İstanbul Anadolu Mahkemesi", text)
        self.assertIn("Vergi No: 1234567890", text)

    def test_empty_udf_is_extraction_gated(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.udf"
            path.write_bytes(b"")

            text, warning = extract_text(path)

        self.assertEqual(text, "")
        self.assertIn("UDF text extraction returned no text", warning)


if __name__ == "__main__":
    unittest.main()
