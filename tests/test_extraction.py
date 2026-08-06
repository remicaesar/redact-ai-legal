import shutil
import subprocess
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from legal_analyzer.extraction import extract_text

DOCX_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""


def make_docx(path: Path, text: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", DOCX_CONTENT_TYPES)
        archive.writestr(
            "word/document.xml",
            f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>",
        )


def make_pptx(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "ppt/slides/slide1.xml",
            '<?xml version="1.0"?><p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            "<p:cSld><a:t>Gizli sunum TCKN 10000000146</a:t><a:t>ikinci satir</a:t></p:cSld></p:sld>",
        )
        archive.writestr(
            "ppt/notesSlides/notesSlide1.xml",
            '<?xml version="1.0"?><p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            "<a:t>konusmaci notu Ayse Demir</a:t></p:notes>",
        )


def make_xlsx(path: Path) -> None:
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "xl/sharedStrings.xml",
            f'<?xml version="1.0"?><sst {ns}><si><t>Personel Elif Sahin</t></si></sst>',
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            f'<?xml version="1.0"?><worksheet {ns}><sheetData>'
            '<row><c t="s"><v>0</v></c><c><v>70013389034</v></c>'
            '<c t="inlineStr"><is><t>Maas 42000 TL</t></is></c></row>'
            "</sheetData></worksheet>",
        )


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_truncated_extraction_warns_instead_of_silently_dropping_text(self):
        long_txt = self.tmp_path / "long.txt"
        long_txt.write_text("word " * 200, encoding="utf-8")

        text, warning = extract_text(long_txt, max_chars=100)

        self.assertEqual(len(text), 100)
        self.assertIsNotNone(warning)
        self.assertIn("truncated", warning)
        self.assertIn("NOT scanned", warning)

        full_text, full_warning = extract_text(long_txt)
        self.assertIsNone(full_warning)
        self.assertEqual(len(full_text), 1000)

    def test_pptx_extraction_reads_slides_and_notes(self):
        pptx = self.tmp_path / "deck.pptx"
        make_pptx(pptx)

        text, warning = extract_text(pptx)

        self.assertIsNone(warning)
        self.assertIn("10000000146", text)
        self.assertIn("Ayse Demir", text)

    def test_xlsx_extraction_reads_shared_inline_and_numeric_cells(self):
        xlsx = self.tmp_path / "payroll.xlsx"
        make_xlsx(xlsx)

        text, warning = extract_text(xlsx)

        self.assertIsNone(warning)
        self.assertIn("Elif Sahin", text)
        self.assertIn("70013389034", text)  # numeric cell value, not shared string
        self.assertIn("Maas 42000 TL", text)

    def test_zip_extraction_reads_members_and_skips_nested_zips(self):
        inner_docx = self.tmp_path / "sozlesme.docx"
        make_docx(inner_docx, "Muvekkil Ayse Demir TCKN 10000000146")
        inner_txt = self.tmp_path / "not.txt"
        inner_txt.write_text("Ek bilgi: IBAN TR33 0006 1005 1978 6457 8413 26", encoding="utf-8")
        nested = self.tmp_path / "nested.zip"
        with zipfile.ZipFile(nested, "w") as z:
            z.writestr("x.txt", "hidden")

        bundle = self.tmp_path / "bundle.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.write(inner_docx, "docs/sozlesme.docx")
            archive.write(inner_txt, "docs/not.txt")
            archive.write(nested, "docs/nested.zip")
            archive.writestr("image.bin", b"\x00\x01")

        text, warning = extract_text(bundle)

        self.assertIn("Ayse Demir", text)
        self.assertIn("TR33 0006 1005 1978 6457 8413 26", text)
        self.assertIn("docs/sozlesme.docx", text)  # member header for provenance
        self.assertIsNotNone(warning)
        self.assertIn("nested ZIPs are not extracted", warning)

    def test_zip_without_extractable_members_warns(self):
        bundle = self.tmp_path / "opaque.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("photo.raw", b"\x00" * 10)

        text, warning = extract_text(bundle)

        self.assertEqual(text, "")
        self.assertIn("no extractable document types", warning)

    def test_image_files_point_to_ocr(self):
        image = self.tmp_path / "scan.png"
        image.write_bytes(b"\x89PNG\r\n")

        text, warning = extract_text(image)

        self.assertEqual(text, "")
        self.assertIn("queue OCR", warning)

    @unittest.skipUnless(shutil.which("textutil"), "textutil not available")
    def test_legacy_doc_extraction_via_textutil(self):
        source_txt = self.tmp_path / "brief.txt"
        source_txt.write_text("Davaci Elif Sahin tazminat talep etmektedir.", encoding="utf-8")
        subprocess.run(
            ["textutil", "-convert", "doc", str(source_txt), "-output", str(self.tmp_path / "brief.doc")],
            check=True,
            capture_output=True,
        )

        text, warning = extract_text(self.tmp_path / "brief.doc")

        self.assertIsNone(warning)
        self.assertIn("Elif Sahin", text)


if __name__ == "__main__":
    unittest.main()
