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
            '<row><c t="s"><v>0</v></c><c><v>55555555550</v></c>'
            '<c t="inlineStr"><is><t>Maas 42000 TL</t></is></c></row>'
            "</sheetData></worksheet>",
        )


# The structural/presentational parts Word emits alongside the body. They carry
# no document text, so extraction must stay silent about them -- if it warned
# here, every real DOCX would be Partial and the warning would mean nothing.
DOCX_STRUCTURAL_PARTS = {
    "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
    "word/_rels/document.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
    "word/styles.xml": '<?xml version="1.0"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
    "word/settings.xml": '<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
    "word/webSettings.xml": '<?xml version="1.0"?><w:webSettings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
    "word/fontTable.xml": '<?xml version="1.0"?><w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
    "word/numbering.xml": '<?xml version="1.0"?><w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
    "word/theme/theme1.xml": '<?xml version="1.0"?><a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"/>',
    "word/media/image1.png": "\x89PNG\r\n",
    "docProps/core.xml": '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"/>',
    "docProps/app.xml": '<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"/>',
}


def wordml_part(tag: str, lines: list[str]) -> str:
    """One `<w:p>` per line inside the given WordprocessingML root (`document`/`hdr`/`ftr`)."""
    body = "".join(
        f'<w:p><w:r><w:t xml:space="preserve">{escape(line)}</w:t></w:r></w:p>' for line in lines
    )
    return (
        f'<?xml version="1.0"?><w:{tag} xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"{body}</w:{tag}>"
    )


def make_docx_package(path: Path, parts: dict[str, str]) -> None:
    """Build a DOCX from explicit part names plus the structural parts Word always emits."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", DOCX_CONTENT_TYPES)
        for name, content in DOCX_STRUCTURAL_PARTS.items():
            archive.writestr(name, content)
        for name, content in parts.items():
            archive.writestr(name, content)


# A letterhead DOCX in the shape Turkish legal practice actually produces: the
# firm banner and client name live in the header part, the file number and TCKN
# in the footer, and the body says nothing identifying on its own.
LETTERHEAD_PARTS = {
    "word/document.xml": wordml_part("document", ["1. Taraflar bu sözleşmeyi imzalamıştır."]),
    "word/header1.xml": wordml_part("hdr", ["Demir Hukuk Bürosu — GİZLİ", "Müvekkil: Ayşe Demir"]),
    "word/footer1.xml": wordml_part("ftr", ["Dosya No: 2024/1471 — TCKN: 10000000146"]),
}


A_NS = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
P_NS = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'
SHEET_NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'


def drawingml_paragraphs(lines: list[str]) -> str:
    """One `<a:p>` per line -- the DrawingML text body every PPTX part uses."""
    return "".join(f"<a:p><a:r><a:t>{escape(line)}</a:t></a:r></a:p>" for line in lines)


def xlsx_worksheet(cells: str, header: str = "", footer: str = "") -> str:
    """A worksheet part with an optional print header/footer, as Excel stores them."""
    header_footer = (
        f"<headerFooter><oddHeader>{escape(header)}</oddHeader>"
        f"<oddFooter>{escape(footer)}</oddFooter></headerFooter>"
        if header or footer
        else ""
    )
    return (
        f'<?xml version="1.0"?><worksheet {SHEET_NS}><sheetData>{cells}</sheetData>'
        f"{header_footer}</worksheet>"
    )


# The structural/presentational parts PowerPoint emits. Extraction must stay
# silent about these or every real deck would be Partial and the warning would
# mean nothing. `ppt/diagrams/drawing1.xml` is here because it is the rendered
# cache of `ppt/diagrams/data1.xml`, which IS read.
PPTX_STRUCTURAL_PARTS = {
    "[Content_Types].xml": "<Types/>",
    "_rels/.rels": "<Relationships/>",
    "ppt/_rels/presentation.xml.rels": "<Relationships/>",
    "ppt/presentation.xml": f"<p:presentation {P_NS}/>",
    "ppt/presProps.xml": f"<p:presentationPr {P_NS}/>",
    "ppt/viewProps.xml": f"<p:viewPr {P_NS}/>",
    "ppt/tableStyles.xml": f"<a:tblStyleLst {A_NS}/>",
    "ppt/theme/theme1.xml": f"<a:theme {A_NS}/>",
    "ppt/media/image1.png": "PNG",
    "ppt/diagrams/layout1.xml": f"<a:layoutDef {A_NS}/>",
    "ppt/diagrams/colors1.xml": f"<a:colorsDef {A_NS}/>",
    "ppt/diagrams/quickStyle1.xml": f"<a:styleDef {A_NS}/>",
    "ppt/diagrams/drawing1.xml": f"<a:drawing {A_NS}/>",
    "docProps/app.xml": "<Properties/>",
}

# Same, for Excel. `xl/drawings/vmlDrawing1.vml` is the legacy note-popup shape
# whose text lives in xl/comments1.xml, which IS read.
XLSX_STRUCTURAL_PARTS = {
    "[Content_Types].xml": "<Types/>",
    "_rels/.rels": "<Relationships/>",
    "xl/_rels/workbook.xml.rels": "<Relationships/>",
    "xl/styles.xml": f"<styleSheet {SHEET_NS}/>",
    "xl/calcChain.xml": f"<calcChain {SHEET_NS}/>",
    "xl/theme/theme1.xml": f"<a:theme {A_NS}/>",
    "xl/media/image1.png": "PNG",
    "xl/printerSettings/printerSettings1.bin": "bin",
    "xl/drawings/vmlDrawing1.vml": "<xml/>",
    "docProps/app.xml": "<Properties/>",
}


def make_ooxml_package(path: Path, structural: dict[str, str], parts: dict[str, str]) -> None:
    """Build a container from explicit part names plus the structural parts the app emits."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in structural.items():
            archive.writestr(name, content)
        for name, content in parts.items():
            archive.writestr(name, content)


# A deck in the shape a firm actually produces: the letterhead is typed onto the
# slide master so it repeats on every slide, and the identifying detail sits in
# a SmartArt diagram, whose text lives in ppt/diagrams/data1.xml. The slide
# itself says nothing identifying.
LETTERHEAD_DECK_PARTS = {
    "ppt/slideMasters/slideMaster1.xml": f'<?xml version="1.0"?><p:sldMaster {A_NS} {P_NS}>'
    + drawingml_paragraphs(["Demir Hukuk Bürosu — GİZLİ"])
    + "</p:sldMaster>",
    "ppt/slides/slide1.xml": f'<?xml version="1.0"?><p:sld {A_NS} {P_NS}>'
    + drawingml_paragraphs(["1. Devir sözleşmesi özeti"])
    + "</p:sld>",
    "ppt/diagrams/data1.xml": '<?xml version="1.0"?><dgm:dataModel '
    + A_NS
    + ' xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram">'
    + drawingml_paragraphs(["Müvekkil: Ayşe Demir", "TCKN: 10000000146"])
    + "</dgm:dataModel>",
}

# Gate fixture: the identifiers exist ONLY in the sheet's print header and
# footer, and the one cell holds a bare number. A fixture that also carried a
# name in a comment or a sheet tab could not express the violation -- the gate
# would stay shut on that other finding even with <headerFooter> unread.
PRINT_HEADER_ONLY_WORKBOOK_PARTS = {
    "xl/worksheets/sheet1.xml": xlsx_worksheet(
        "<row><c><v>42000</v></c></row>",
        header="&LMüvekkil: Ayşe Demir",
        footer="&RTCKN: 10000000146",
    ),
}

# A payroll workbook whose only identifiers are in the sheet's PRINT header and
# footer -- which live inside the sheet part, so the part was read while
# <headerFooter> was skipped -- and in a cell comment. The cells themselves
# carry only a label and a number.
LETTERHEAD_WORKBOOK_PARTS = {
    "xl/workbook.xml": f'<?xml version="1.0"?><workbook {SHEET_NS}>'
    '<sheets><sheet name="Bordro 2024" sheetId="1"/></sheets></workbook>',
    "xl/sharedStrings.xml": f'<?xml version="1.0"?><sst {SHEET_NS}><si><t>Personel</t></si></sst>',
    "xl/worksheets/sheet1.xml": xlsx_worksheet(
        '<row><c t="s"><v>0</v></c><c><v>42000</v></c></row>',
        header='&L&"Arial,Bold"&12Demir Hukuk Bürosu — GİZLİ&RMüvekkil: Ayşe Demir',
        footer="&LDosya No: 2024/1471&RTCKN: 10000000146 &P/&N",
    ),
    "xl/comments1.xml": f'<?xml version="1.0"?><comments {SHEET_NS}>'
    "<authors><author>Elif Şahin</author></authors>"
    '<commentList><comment ref="A1"><text><r><t>Not: maas bilgisi</t></r></text></comment></commentList></comments>',
}


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
        self.assertIn("55555555550", text)  # numeric cell value, not shared string
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


    def test_docx_header_and_footer_text_is_scanned_for_identifiers(self):
        # word/header1.xml and word/footer1.xml were skipped outright, so a
        # letterhead client name and a TCKN produced ZERO findings while
        # extraction still reported Complete.
        docx = self.tmp_path / "letterhead.docx"
        make_docx_package(docx, LETTERHEAD_PARTS)

        text, warning = extract_text(docx)

        self.assertIsNone(warning)
        findings = analyze_privacy(docx.name, text, warning)["risk_map"]
        names = {f["sample"] for f in findings if f["category"] == "natural_person_name"}
        ids = {f["sample"] for f in findings if f["category"] == "turkish_national_id"}
        self.assertIn("Ayşe Demir", names)      # from the header
        self.assertIn("10000000146", ids)       # from the footer

    def test_docx_header_footer_identifiers_keep_the_external_llm_gate_shut(self):
        # The end-to-end proof: even with redaction marked complete and human
        # review approved -- the natural response to an empty findings list --
        # a document whose only identifiers sit in the header and footer must
        # not be certified for external LLM use.
        docx = self.tmp_path / "letterhead.docx"
        make_docx_package(docx, LETTERHEAD_PARTS)

        text, warning = extract_text(docx)
        profile = analyze_privacy(
            docx.name,
            text,
            warning,
            redaction_completed=True,
            human_review_approved=True,
        )

        # Complete matters as much as the gate: the block must come from the
        # findings now being visible, not from an extraction warning. A warning
        # would shut the gate too, and would hide a reintroduced leak.
        self.assertEqual(profile["extraction_status"]["status"], "Complete")
        self.assertFalse(profile["external_llm_gate"]["allowed"])
        self.assertNotEqual(profile["residual_risk"]["level"], "Low")

    def test_docx_parts_are_extracted_in_page_reading_order(self):
        docx = self.tmp_path / "letterhead.docx"
        make_docx_package(docx, LETTERHEAD_PARTS)

        text, _ = extract_text(docx)

        self.assertLess(text.index("Demir Hukuk Bürosu"), text.index("1. Taraflar"))
        self.assertLess(text.index("1. Taraflar"), text.index("Dosya No"))
        # Header text must not run into the first body line: several detection
        # rules bound their trailing context with [^\n], so a joined seam lets a
        # finding's sample swallow text from the next part.
        self.assertIn("Ayşe Demir\n\n1. Taraflar", text)
        self.assertIn("imzalamıştır.\n\nDosya No", text)

    def test_docx_part_boundary_holds_when_a_part_has_no_paragraph(self):
        # Every part a real Word file emits opens with a <w:p>, which already
        # separates it from the previous part. This is the case where it does
        # not: a part whose text hangs outside any paragraph, which the parser
        # tolerates via the trailing flush. The explicit part separator is the
        # only thing keeping the header off the body's first line here.
        docx = self.tmp_path / "loose.docx"
        make_docx_package(
            docx,
            {
                "word/header1.xml": wordml_part("hdr", ["Müvekkil: Ayşe Demir"]),
                "word/document.xml": '<?xml version="1.0"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                '<w:body><w:r><w:t>1. Taraflar bu sözleşmeyi imzalamıştır.</w:t></w:r></w:body></w:document>',
            },
        )

        text, _ = extract_text(docx)

        self.assertIn("Ayşe Demir\n\n1. Taraflar", text)

    def test_unhandled_docx_part_warns_and_blocks_complete_status(self):
        # A part that is neither read nor known-benign must degrade loudly.
        # Chart text is the stand-in here for the whole class -- textboxes in
        # custom parts, embedded workbooks, glossary quick parts.
        docx = self.tmp_path / "chart.docx"
        make_docx_package(
            docx,
            {
                "word/document.xml": wordml_part("document", ["Ekli grafiğe bakınız."]),
                "word/charts/chart1.xml": "<c:chart><c:v>Ayşe Demir</c:v></c:chart>",
            },
        )

        text, warning = extract_text(docx)

        self.assertIsNotNone(warning)
        self.assertIn("word/charts/chart1.xml", warning)
        self.assertIn("NOT extracted", warning)
        status = analyze_privacy(docx.name, text, warning)["extraction_status"]
        self.assertNotEqual(status["status"], "Complete")
        self.assertTrue(status["blocks_external_llm"])

    def test_ordinary_docx_with_structural_parts_extracts_without_warning(self):
        # Anti-vacuity guard for the test above: styles, settings, fonts,
        # numbering, theme, media, relationships and docProps must stay silent,
        # or "warn on everything" would pass every other test in this group.
        docx = self.tmp_path / "plain.docx"
        make_docx_package(
            docx,
            {"word/document.xml": wordml_part("document", ["Sözleşme metni burada."])},
        )

        text, warning = extract_text(docx)

        self.assertIsNone(warning)
        self.assertEqual(text, "Sözleşme metni burada.")
        self.assertEqual(analyze_privacy(docx.name, text, warning)["extraction_status"]["status"], "Complete")


    def test_pptx_slide_master_and_smartart_text_is_scanned_for_identifiers(self):
        # ppt/slideMasters/* and ppt/diagrams/data*.xml were skipped outright,
        # so a deck whose letterhead is on the master and whose client name and
        # TCKN are in a SmartArt diagram produced ZERO findings while extraction
        # still reported Complete. SmartArt is fully visible slide content.
        deck = self.tmp_path / "sunum.pptx"
        make_ooxml_package(deck, PPTX_STRUCTURAL_PARTS, LETTERHEAD_DECK_PARTS)

        text, warning = extract_text(deck)

        self.assertIsNone(warning)
        findings = analyze_privacy(deck.name, text, warning)["risk_map"]
        names = {f["sample"] for f in findings if f["category"] == "natural_person_name"}
        ids = {f["sample"] for f in findings if f["category"] == "turkish_national_id"}
        self.assertIn("Ayşe Demir", names)      # from the SmartArt diagram
        self.assertIn("10000000146", ids)       # from the SmartArt diagram
        self.assertIn("Demir Hukuk Bürosu", text)  # from the slide master

    def test_pptx_master_and_smartart_identifiers_keep_the_external_llm_gate_shut(self):
        # The end-to-end proof for PPTX: even with redaction marked complete and
        # human review approved, a deck whose only identifiers are on the master
        # and in SmartArt must not be certified for external LLM use.
        deck = self.tmp_path / "sunum.pptx"
        make_ooxml_package(deck, PPTX_STRUCTURAL_PARTS, LETTERHEAD_DECK_PARTS)

        text, warning = extract_text(deck)
        profile = analyze_privacy(
            deck.name,
            text,
            warning,
            redaction_completed=True,
            human_review_approved=True,
        )

        # Complete matters as much as the gate: the block must come from the
        # findings now being visible, not from an extraction warning. A warning
        # would shut the gate too, and would hide a reintroduced leak.
        self.assertEqual(profile["extraction_status"]["status"], "Complete")
        self.assertFalse(profile["external_llm_gate"]["allowed"])
        self.assertNotEqual(profile["residual_risk"]["level"], "Low")

    def test_pptx_parts_are_extracted_in_reading_order(self):
        deck = self.tmp_path / "sunum.pptx"
        make_ooxml_package(deck, PPTX_STRUCTURAL_PARTS, LETTERHEAD_DECK_PARTS)

        text, _ = extract_text(deck)

        # Recurring page furniture (the master) before the slides, then the
        # SmartArt bodies hanging off them.
        self.assertLess(text.index("Demir Hukuk Bürosu"), text.index("Devir sözleşmesi"))
        self.assertLess(text.index("Devir sözleşmesi"), text.index("Müvekkil"))
        self.assertIn("GİZLİ\n\n1. Devir", text)  # parts must not run together

    def test_pptx_classic_comment_text_starts_its_own_line(self):
        # A classic PowerPoint comment part is `<p:cm><p:text>` with no `<a:p>`
        # anywhere, so nothing in the parse self-separates it from the slide
        # before it -- the explicit part separator is the only thing keeping the
        # comment off the slide's last line. `<p:text>` is a whole field rather
        # than a run, so each comment also gets its own line.
        deck = self.tmp_path / "yorum.pptx"
        make_ooxml_package(
            deck,
            PPTX_STRUCTURAL_PARTS,
            {
                "ppt/slides/slide1.xml": f'<?xml version="1.0"?><p:sld {A_NS} {P_NS}>'
                + drawingml_paragraphs(["1. Devir sözleşmesi özeti"])
                + "</p:sld>",
                "ppt/comments/comment1.xml": f'<?xml version="1.0"?><p:cmLst {P_NS}>'
                "<p:cm><p:text>Müvekkil: Ayşe Demir</p:text></p:cm>"
                "<p:cm><p:text>TCKN: 10000000146</p:text></p:cm></p:cmLst>",
            },
        )

        text, warning = extract_text(deck)

        self.assertIsNone(warning)
        self.assertIn("özeti\n\nMüvekkil: Ayşe Demir", text)
        self.assertIn("Ayşe Demir\nTCKN: 10000000146", text)

    def test_unhandled_pptx_part_warns_and_blocks_complete_status(self):
        deck = self.tmp_path / "grafik.pptx"
        make_ooxml_package(
            deck,
            PPTX_STRUCTURAL_PARTS,
            {
                "ppt/slides/slide1.xml": f'<?xml version="1.0"?><p:sld {A_NS} {P_NS}>'
                + drawingml_paragraphs(["Ekli grafiğe bakınız."])
                + "</p:sld>",
                "ppt/charts/chart1.xml": "<c:chart><c:v>Ayşe Demir</c:v></c:chart>",
            },
        )

        text, warning = extract_text(deck)

        self.assertIsNotNone(warning)
        self.assertIn("ppt/charts/chart1.xml", warning)
        self.assertIn("NOT extracted", warning)
        status = analyze_privacy(deck.name, text, warning)["extraction_status"]
        self.assertNotEqual(status["status"], "Complete")
        self.assertTrue(status["blocks_external_llm"])

    def test_ordinary_pptx_with_structural_parts_extracts_without_warning(self):
        # Anti-vacuity guard: presentation/presProps/viewProps/tableStyles,
        # theme, media, the three presentational SmartArt parts and docProps
        # must stay silent, or "warn on everything" would pass the test above.
        deck = self.tmp_path / "duz.pptx"
        make_ooxml_package(
            deck,
            PPTX_STRUCTURAL_PARTS,
            {
                "ppt/slides/slide1.xml": f'<?xml version="1.0"?><p:sld {A_NS} {P_NS}>'
                + drawingml_paragraphs(["Sunum metni burada."])
                + "</p:sld>",
            },
        )

        text, warning = extract_text(deck)

        self.assertIsNone(warning)
        self.assertEqual(text, "Sunum metni burada.")
        self.assertEqual(analyze_privacy(deck.name, text, warning)["extraction_status"]["status"], "Complete")

    def test_xlsx_print_header_footer_and_comments_are_scanned_for_identifiers(self):
        # The print header/footer lives INSIDE xl/worksheets/sheet1.xml, so the
        # part was read while <headerFooter> was skipped: a sheet whose only
        # identifiers were its letterhead and a cell comment extracted as the
        # single cell value 42000, with no warning.
        workbook = self.tmp_path / "bordro.xlsx"
        make_ooxml_package(workbook, XLSX_STRUCTURAL_PARTS, LETTERHEAD_WORKBOOK_PARTS)

        text, warning = extract_text(workbook)

        self.assertIsNone(warning)
        findings = analyze_privacy(workbook.name, text, warning)["risk_map"]
        names = {f["sample"] for f in findings if f["category"] == "natural_person_name"}
        ids = {f["sample"] for f in findings if f["category"] == "turkish_national_id"}
        cases = {f["sample"] for f in findings if f["category"] == "case_or_investigation_number"}
        self.assertIn("Ayşe Demir", names)          # print header
        self.assertIn("10000000146", ids)           # print footer
        self.assertIn("Dosya No: 2024/1471", cases)  # print footer
        self.assertIn("Elif Şahin", names)          # xl/comments1.xml author
        self.assertIn("Bordro 2024", text)          # xl/workbook.xml sheet name

    def test_xlsx_print_header_identifiers_keep_the_external_llm_gate_shut(self):
        # The end-to-end proof for XLSX: the only identifiers in this workbook
        # are in the sheet's print header and footer, so if <headerFooter> goes
        # unread the finding count drops to zero and the gate swings open.
        workbook = self.tmp_path / "bordro.xlsx"
        make_ooxml_package(workbook, XLSX_STRUCTURAL_PARTS, PRINT_HEADER_ONLY_WORKBOOK_PARTS)

        text, warning = extract_text(workbook)
        profile = analyze_privacy(
            workbook.name,
            text,
            warning,
            redaction_completed=True,
            human_review_approved=True,
        )

        # Complete matters as much as the gate: the block must come from the
        # findings now being visible, not from an extraction warning. A warning
        # would shut the gate too, and would hide a reintroduced leak.
        self.assertEqual(profile["extraction_status"]["status"], "Complete")
        self.assertFalse(profile["external_llm_gate"]["allowed"])
        self.assertNotEqual(profile["residual_risk"]["level"], "Low")

    def test_xlsx_header_footer_format_codes_are_stripped_and_sections_split(self):
        # Excel stores a print header as one string of format codes plus text.
        # &L/&C/&R are side-by-side print regions, so they become tabs: a tab is
        # the column boundary turkish_names._best_name_run uses to stop two
        # adjacent names merging into one bogus four-token span.
        workbook = self.tmp_path / "imza.xlsx"
        make_ooxml_package(
            workbook,
            XLSX_STRUCTURAL_PARTS,
            {
                "xl/worksheets/sheet1.xml": xlsx_worksheet(
                    "",
                    header='&L&"Times,Bold"&14&KFF0000Kerem Alpaslan&RZeynep Karaduman',
                    footer="&CSayfa &P/&N",
                ),
            },
        )

        text, warning = extract_text(workbook)

        self.assertIsNone(warning)
        self.assertNotIn("&", text)  # every format code consumed
        self.assertNotIn("Arial", text)
        self.assertIn("Kerem Alpaslan\tZeynep Karaduman", text)
        names = {
            f["sample"]
            for f in analyze_privacy(workbook.name, text, warning)["risk_map"]
            if f["category"] == "natural_person_name"
        }
        self.assertIn("Kerem Alpaslan", names)
        self.assertIn("Zeynep Karaduman", names)
        self.assertNotIn("Kerem Alpaslan Zeynep", names)

    def test_unhandled_xlsx_part_warns_and_blocks_complete_status(self):
        # A pivot cache holds a verbatim copy of the source rows, so an
        # unhandled one is exactly the class this must degrade loudly on.
        workbook = self.tmp_path / "pivot.xlsx"
        make_ooxml_package(
            workbook,
            XLSX_STRUCTURAL_PARTS,
            {
                "xl/worksheets/sheet1.xml": xlsx_worksheet("<row><c><v>42000</v></c></row>"),
                "xl/pivotCache/pivotCacheDefinition1.xml": "<pivotCacheDefinition><s v='Ayşe Demir'/></pivotCacheDefinition>",
            },
        )

        text, warning = extract_text(workbook)

        self.assertIsNotNone(warning)
        self.assertIn("xl/pivotCache/pivotCacheDefinition1.xml", warning)
        self.assertIn("NOT extracted", warning)
        status = analyze_privacy(workbook.name, text, warning)["extraction_status"]
        self.assertNotEqual(status["status"], "Complete")
        self.assertTrue(status["blocks_external_llm"])

    def test_ordinary_xlsx_with_structural_parts_extracts_without_warning(self):
        # Anti-vacuity guard: styles, calcChain, theme, media, printerSettings,
        # the legacy vmlDrawing note anchors, relationships and docProps must
        # stay silent, or "warn on everything" would pass the test above.
        workbook = self.tmp_path / "duz.xlsx"
        make_ooxml_package(
            workbook,
            XLSX_STRUCTURAL_PARTS,
            {"xl/worksheets/sheet1.xml": xlsx_worksheet("<row><c><v>42000</v></c></row>")},
        )

        text, warning = extract_text(workbook)

        self.assertIsNone(warning)
        self.assertEqual(text, "42000")
        self.assertEqual(analyze_privacy(workbook.name, text, warning)["extraction_status"]["status"], "Complete")

    def test_zip_reports_members_it_cannot_extract(self):
        # A bundle of one contract plus scanned pages used to extract the
        # contract and report Complete without ever mentioning the pages.
        bundle = self.tmp_path / "dosya.zip"
        contract = self.tmp_path / "sozlesme.txt"
        contract.write_text("Sozlesme metni", encoding="utf-8")
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.write(contract, "sozlesme.txt")
            archive.writestr("tarama1.jpg", b"\xff\xd8ff")
            archive.writestr("notlar.rtf", b"{\\rtf1 Ayse Demir}")

        text, warning = extract_text(bundle)

        self.assertIn("Sozlesme metni", text)
        self.assertIsNotNone(warning)
        self.assertIn("tarama1.jpg", warning)
        self.assertIn("notlar.rtf", warning)
        self.assertIn("NOT extracted", warning)
        status = analyze_privacy(bundle.name, text, warning)["extraction_status"]
        self.assertNotEqual(status["status"], "Complete")
        self.assertTrue(status["blocks_external_llm"])



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
        import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
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
