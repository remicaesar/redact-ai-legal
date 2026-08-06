import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree

from legal_analyzer.docx_quality import analyze_docx_export_quality
from legal_analyzer.docx_redactor import RedactionTarget, redact_docx


def make_docx(path: Path) -> None:
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
  <Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
  <Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/>
  <Override PartName="/word/endnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml"/>
  <Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>
</Types>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""
    document = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Av. Ah</w:t></w:r><w:r><w:t>met Yilmaz</w:t></w:r><w:r><w:t> filed petition</w:t></w:r></w:p>
    <w:tbl><w:tr><w:tc><w:p><w:r><w:t>IBAN TR12 3456</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
    <w:p><w:r><w:t>Public closing line</w:t></w:r></w:p>
  </w:body>
</w:document>
"""
    header = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p><w:r><w:t>Client SecretCo</w:t></w:r></w:p>
</w:hdr>
"""
    footer = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p><w:r><w:t>Footer VKN 1234567890</w:t></w:r></w:p>
</w:ftr>
"""
    footnotes = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:footnote w:id="1"><w:p><w:r><w:t>Footnote MERSIS 0123456789012345</w:t></w:r></w:p></w:footnote>
</w:footnotes>
"""
    endnotes = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:endnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:endnote w:id="1"><w:p><w:r><w:t>Endnote Dosya 2026/123</w:t></w:r></w:p></w:endnote>
</w:endnotes>
"""
    comments = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:comment w:id="0"><w:p><w:r><w:t>Call 0532 111 22 33</w:t></w:r></w:p></w:comment>
</w:comments>
"""
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("custom/keep.xml", "<keep>unchanged</keep>")
        archive.writestr("word/document.xml", document)
        archive.writestr("word/header1.xml", header)
        archive.writestr("word/footer1.xml", footer)
        archive.writestr("word/footnotes.xml", footnotes)
        archive.writestr("word/endnotes.xml", endnotes)
        archive.writestr("word/comments.xml", comments)


class DocxRedactorTests(unittest.TestCase):
    def test_redacts_split_runs_tables_headers_and_comments(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)

            data = redact_docx(
                source,
                [
                    RedactionTarget("Ahmet Yilmaz", "[PERSON_1]"),
                    RedactionTarget("TR12 3456", "[IBAN_1]"),
                    RedactionTarget("SecretCo", "[CLIENT_COMPANY_1]"),
                    RedactionTarget("1234567890", "[VKN_1]"),
                    RedactionTarget("0123456789012345", "[MERSIS_1]"),
                    RedactionTarget("2026/123", "[CASE_NUMBER_1]"),
                    RedactionTarget("0532 111 22 33", "[PHONE_1]"),
                ],
            )

        with ZipFile(BytesIO(data)) as archive:
            names = archive.namelist()
            self.assertIn("custom/keep.xml", names)
            self.assertEqual(archive.read("custom/keep.xml").decode("utf-8"), "<keep>unchanged</keep>")
            combined = "\n".join(
                archive.read(name).decode("utf-8")
                for name in [
                    "word/document.xml",
                    "word/header1.xml",
                    "word/footer1.xml",
                    "word/footnotes.xml",
                    "word/endnotes.xml",
                    "word/comments.xml",
                ]
            )

        self.assertNotIn("Ahmet Yilmaz", combined)
        self.assertNotIn("TR12 3456", combined)
        self.assertNotIn("SecretCo", combined)
        self.assertNotIn("1234567890", combined)
        self.assertNotIn("0123456789012345", combined)
        self.assertNotIn("2026/123", combined)
        self.assertNotIn("0532 111 22 33", combined)
        self.assertIn("[PERSON_1]", combined)
        self.assertIn("[IBAN_1]", combined)
        self.assertIn("[CLIENT_COMPANY_1]", combined)
        self.assertIn("[VKN_1]", combined)
        self.assertIn("[MERSIS_1]", combined)
        self.assertIn("[CASE_NUMBER_1]", combined)
        self.assertIn("[PHONE_1]", combined)

    def test_preserves_unaffected_runs_when_redacting_split_text(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)
            data = redact_docx(source, [RedactionTarget("Ahmet Yilmaz", "[PERSON_1]")])

        with ZipFile(BytesIO(data)) as archive:
            root = ElementTree.fromstring(archive.read("word/document.xml"))
            text_nodes = [node.text or "" for node in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")]

        self.assertIn("Av. [PERSON_1]", text_nodes)
        self.assertIn(" filed petition", text_nodes)
        self.assertIn("IBAN TR12 3456", text_nodes)
        self.assertIn("Public closing line", text_nodes)
        self.assertEqual(text_nodes.count("Public closing line"), 1)
        self.assertNotEqual(text_nodes[0], "".join(text_nodes))

    def test_mask_style_uses_short_uniform_marker(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)
            data = redact_docx(
                source,
                [RedactionTarget("Ahmet Yilmaz", "[PERSON_1]"), RedactionTarget("SecretCo", "[CLIENT_COMPANY_1]")],
                style="mask",
            )

        with ZipFile(BytesIO(data)) as archive:
            combined = "\n".join(archive.read(name).decode("utf-8") for name in ["word/document.xml", "word/header1.xml"])

        self.assertNotIn("Ahmet Yilmaz", combined)
        self.assertNotIn("SecretCo", combined)
        self.assertNotIn("[PERSON_1]", combined)
        self.assertNotIn("[CLIENT_COMPANY_1]", combined)
        self.assertEqual(combined.count("[REDACTED]"), 2)

    def test_does_not_include_mapping_table(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)
            data = redact_docx(source, [RedactionTarget("Ahmet Yilmaz", "[PERSON_1]")])

        with ZipFile(BytesIO(data)) as archive:
            all_text = "\n".join(archive.read(name).decode("utf-8", errors="ignore") for name in archive.namelist())

        self.assertNotIn("mapping", all_text.lower())

    def test_docx_quality_passes_for_layout_preserving_redaction(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)
            targets = [RedactionTarget("Ahmet Yilmaz", "[PERSON_1]")]
            data = redact_docx(source, targets)
            report = analyze_docx_export_quality(source, data, targets)

        self.assertEqual(report["overall_status"], "pass")
        self.assertEqual(report["leakage_count"], 0)
        self.assertEqual(report["missing_package_parts"], [])
        document_report = next(item for item in report["part_reports"] if item["part_name"] == "word/document.xml")
        self.assertEqual(document_report["text_nodes_before"], document_report["text_nodes_after"])
        self.assertEqual(document_report["paragraph_delta"], 0)
        self.assertEqual(document_report["table_delta"], 0)

    def test_docx_quality_fails_when_approved_source_text_leaks(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)
            with ZipFile(source, "r") as archive:
                data = BytesIO()
                with ZipFile(data, "w", ZIP_DEFLATED) as copied:
                    for info in archive.infolist():
                        copied.writestr(info, archive.read(info.filename))
            report = analyze_docx_export_quality(source, data.getvalue(), [RedactionTarget("Ahmet Yilmaz", "[PERSON_1]")])

        self.assertEqual(report["overall_status"], "fail")
        self.assertEqual(report["leakage_count"], 1)


if __name__ == "__main__":
    unittest.main()
