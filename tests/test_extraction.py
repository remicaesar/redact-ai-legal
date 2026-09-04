import json
import shutil
import subprocess
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.sax.saxutils import escape

from legal_analyzer.extraction import extract_text
from legal_analyzer.privacy import analyze_privacy

PROJECT_DIR = Path(__file__).resolve().parent.parent

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


def make_docx_paragraphs(path: Path, lines: list[str]) -> None:
    """Build a real multi-paragraph DOCX -- one `<w:p>` per line, as Word itself would.

    Used to prove line-boundary-sensitive detection rules (and the signature-block
    column-gap heuristic in turkish_names.py) actually see line structure once it
    comes through a real DOCX, not a hand-normalized string.
    """
    body = "".join(
        f'<w:p><w:r><w:t xml:space="preserve">{escape(line)}</w:t></w:r></w:p>' for line in lines
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", DOCX_CONTENT_TYPES)
        archive.writestr(
            "word/document.xml",
            f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body>{body}</w:body></w:document>",
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

    def test_docx_line_boundary_stops_address_rule_from_swallowing_the_next_line(self):
        # Real multi-paragraph DOCX, not a hand-normalized string: each line below
        # is its own <w:p>, exactly as Word would emit it.
        docx = self.tmp_path / "devir.docx"
        make_docx_paragraphs(
            docx,
            [
                "Adres: Bağdat Caddesi No: 41 Daire 7, Kadıköy/İstanbul",
                "Telefon: 0532 118 44 90",
                "E-posta: kerem.alpaslan@ornekhukuk.com.tr",
            ],
        )

        text, warning = extract_text(docx)

        self.assertIsNone(warning)
        self.assertIn("\n", text)  # paragraph breaks must survive extraction
        findings = analyze_privacy(docx.name, text, warning)["risk_map"]
        address_findings = [f for f in findings if f["category"] == "address"]
        self.assertEqual(len(address_findings), 1)
        sample = address_findings[0]["sample"]
        self.assertIn("Bağdat Caddesi", sample)
        self.assertNotIn("Telefon", sample)
        self.assertNotIn("0532", sample)
        self.assertNotIn("E-posta", sample)

    def test_docx_wide_gap_keeps_side_by_side_signature_names_separate(self):
        # Two names padded into side-by-side signature columns with a run of
        # spaces, as extract_docx_text reconstructs it from a real DOCX paragraph.
        docx = self.tmp_path / "signature.docx"
        make_docx_paragraphs(
            docx,
            [
                "Devreden                       Devralan",
                "Kerem Alpaslan                 Zeynep Karaduman",
            ],
        )

        text, warning = extract_text(docx)
        findings = analyze_privacy(docx.name, text, warning)["risk_map"]
        names = {f["sample"] for f in findings if f["category"] == "natural_person_name"}

        self.assertIn("Kerem Alpaslan", names)
        self.assertIn("Zeynep Karaduman", names)
        # The two people must not have been merged into one four-token span
        # ("Kerem Alpaslan Zeynep" or similar) by the column-gap heuristic.
        self.assertNotIn("Kerem Alpaslan Zeynep", names)
        self.assertNotIn("Alpaslan Zeynep Karaduman", names)


class FormatParityTests(unittest.TestCase):
    """The core invariant this fix restores: same content, same findings, any format.

    Before the fix, every binary extractor collapsed all whitespace (including
    newlines) to single spaces before detection ran, so a finding's sample
    regularly spanned a former line break and matched nothing in the real
    document -- 22/78 (28%) unmatched findings on a realistic DOCX sample, and
    silently un-redactable, since redaction is exact-substring match against
    the original file. This walks the full 17-document gold-label corpus end
    to end through both a `.txt` and a generated `.docx` of the same content
    and asserts that gap is gone.
    """

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_txt_and_docx_produce_matching_unswallowed_findings_for_every_gold_document(self):
        from app import build_docx  # local import: app.py is a large Flask module

        labels_path = PROJECT_DIR / "gold" / "gold_labels.example.json"
        spec = json.loads(labels_path.read_text(encoding="utf-8"))
        self.assertEqual(len(spec["documents"]), 17)  # the gold-content corpus this fix targets

        unmatched_txt = 0
        unmatched_docx = 0
        finding_set_diffs = []

        for item in spec["documents"]:
            txt_path = (labels_path.parent / item["path"]).resolve()
            source_text = txt_path.read_text(encoding="utf-8")
            docx_path = self.tmp_path / f"{txt_path.stem}.docx"
            docx_path.write_bytes(build_docx(source_text))
            docx_text, docx_warning = extract_text(docx_path)

            findings_txt = analyze_privacy(txt_path.name, source_text, None)["risk_map"]
            findings_docx = analyze_privacy(docx_path.name, docx_text, docx_warning)["risk_map"]

            unmatched_txt += sum(1 for f in findings_txt if f["sample"] not in source_text)
            unmatched_docx += sum(1 for f in findings_docx if f["sample"] not in docx_text)

            pairs_txt = {(f["category"], f["sample"]) for f in findings_txt}
            pairs_docx = {(f["category"], f["sample"]) for f in findings_docx}
            if pairs_txt != pairs_docx:
                finding_set_diffs.append((item["id"], pairs_txt - pairs_docx, pairs_docx - pairs_txt))

        self.assertEqual(unmatched_txt, 0, "a .txt finding's sample must occur verbatim in the .txt source")
        self.assertEqual(
            unmatched_docx,
            0,
            "a .docx finding's sample must occur verbatim in the extracted .docx text -- "
            "this is the 28%%-unmatched regression this test exists to catch",
        )
        self.assertEqual(
            finding_set_diffs,
            [],
            f"{len(finding_set_diffs)} document(s) found a different (category, sample) finding set "
            ".txt vs .docx -- format parity is the acceptance criterion for this fix",
        )


if __name__ == "__main__":
    unittest.main()
