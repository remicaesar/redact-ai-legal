import re
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree

from legal_analyzer.docx_quality import analyze_docx_export_quality
from legal_analyzer.docx_redactor import (
    TEXT_TAG,
    TURKISH_FOLD_GROUPS,
    RedactionTarget,
    case_insensitive_pattern,
    collect_replacements,
    find_case_insensitive,
    redact_docx,
)


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


def make_minimal_docx(path: Path, paragraphs: list[str]) -> None:
    """A one-part DOCX with exactly one text node per paragraph.

    The case-matching tests assert on whole text-node contents, so they need a
    fixture with no runs split mid-word and no other prose to match against.
    """
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""
    body = "".join(f"<w:p><w:r><w:t>{paragraph}</w:t></w:r></w:p>" for paragraph in paragraphs)
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body></w:document>"
    )
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)


def make_split_run_docx(path: Path, runs: list[str]) -> None:
    """A one-paragraph DOCX whose text is split across several runs.

    make_minimal_docx puts each paragraph in one text node, which cannot exercise
    a replacement span that starts in one Word text node and ends in the next.
    """
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""
    body = "<w:p>" + "".join(f"<w:r><w:t>{run}</w:t></w:r>" for run in runs) + "</w:p>"
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body></w:document>"
    )
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)


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

    def test_replacement_clipped_onto_a_paragraph_boundary_still_writes_its_placeholder(self):
        """A region clipped so it begins ON a paragraph break must still be marked.

        `build_part_spans` carries paragraph breaks as synthetic spans that own
        no `w:t` node, so nothing is ever written to them -- a paragraph break is
        not a character the document contains. A reviewer-added target may hold a
        newline (the add-finding endpoint strips the ends, not the middle), so it
        can match across a break; and when an earlier target already covers the
        first half, the clip puts the survivor's start exactly on that synthetic
        span. Writing the placeholder in the first span that OWNS a node, rather
        than in the span the start falls in, is what keeps it from vanishing
        while its characters are still removed -- text gone with no marker left
        to say anything was redacted, which no export QA check reads as a
        failure.
        """
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, ["Alfa Beta", "Gama Delta"])
            data = redact_docx(
                source,
                [
                    RedactionTarget("Alfa Beta", "[FIRST_1]"),
                    RedactionTarget("Beta\nGama", "[SECOND_1]"),
                ],
            )
        with ZipFile(BytesIO(data)) as archive:
            document = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("[FIRST_1]", document)
        self.assertIn("[SECOND_1]", document)
        self.assertNotIn("Gama", document)
        self.assertIn("Delta", document)

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

    def test_docx_quality_flags_target_never_present_in_source(self):
        # Regression for the merged-span leak fixed in 66184b4: an approved
        # target whose text was never contiguous in the source (e.g. two
        # adjacent table-cell names collapsed into "Selçuk Aydın Elif") matches
        # nothing in either source or output. leaked_sample_count alone can't
        # tell that apart from a target that really was redacted -- both report
        # 0. unapplied_target_count is the check that catches it.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)
            targets = [
                RedactionTarget("Ahmet Yilmaz", "[PERSON_1]"),
                RedactionTarget("Selçuk Aydın Elif", "[PERSON_2]"),
            ]
            data = redact_docx(source, targets)
            report = analyze_docx_export_quality(source, data, targets)

        self.assertEqual(report["leakage_count"], 0)
        self.assertEqual(report["unapplied_target_count"], 1)
        self.assertEqual(report["overall_status"], "warn")
        self.assertTrue(
            any("not found in the source document" in warning for warning in [c["detail"] for c in report["checks"]])
        )

    def test_docx_quality_sees_a_finding_that_was_never_a_target(self):
        # The C-1 leak: a finding reverted to 'pending' after redaction was
        # marked complete is dropped from the target list, so a QA pass that
        # only knows about targets reports leakage_count 0 / "pass" on a file
        # that still contains the identifier in cleartext. Leakage is measured
        # against the document's unrejected findings instead.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)
            data = redact_docx(source, [])

            blind = analyze_docx_export_quality(source, data, [])
            report = analyze_docx_export_quality(source, data, [], sensitive_samples=["Ahmet Yilmaz"])

        self.assertEqual(blind["overall_status"], "pass")
        self.assertEqual(blind["leakage_count"], 0)
        self.assertEqual(report["overall_status"], "fail")
        self.assertEqual(report["leakage_count"], 1)
        self.assertEqual(report["sensitive_sample_count"], 1)

    def test_docx_quality_reports_zero_unapplied_when_target_was_present_and_removed(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_docx(source)
            targets = [RedactionTarget("Ahmet Yilmaz", "[PERSON_1]")]
            data = redact_docx(source, targets)
            report = analyze_docx_export_quality(source, data, targets)

        self.assertEqual(report["unapplied_target_count"], 0)
        self.assertEqual(report["overall_status"], "pass")


class DocxCaseInsensitiveRedactionTests(unittest.TestCase):
    """Approved targets must be removed regardless of case, Turkish included.

    An exact substring search removed only the occurrence whose case matched the
    approved finding and shipped the other one, which is a redaction bypass.
    Turkish makes it more than a `.lower()` call: see the matcher comment in
    docx_redactor.py for why lowercasing corrupts match offsets, and why the
    i/I/ı/İ equivalence is spelled out rather than inherited from re.IGNORECASE.
    """

    def redacted_text_nodes(self, paragraphs: list[str], targets: list[RedactionTarget]) -> list[str]:
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, paragraphs)
            data = redact_docx(source, targets)

        with ZipFile(BytesIO(data)) as archive:
            root = ElementTree.fromstring(archive.read("word/document.xml"))
            return [node.text or "" for node in root.iter(TEXT_TAG)]

    def test_redacts_mixed_case_occurrence_of_approved_target(self):
        # The reproduction: one approved target in caps, the same entity written
        # in title case in the next paragraph. Exact matching removed the first
        # and exported the second in cleartext.
        nodes = self.redacted_text_nodes(
            ["Taraf ARDIC TEKNOLOJI ANONIM SIRKETI ile", "yuklenici Ardic Teknoloji Anonim Sirketi arasinda"],
            [RedactionTarget("ARDIC TEKNOLOJI ANONIM SIRKETI", "[COMPANY_1]")],
        )

        combined = "\n".join(nodes)
        self.assertNotIn("ARDIC TEKNOLOJI ANONIM SIRKETI", combined)
        self.assertNotIn("Ardic Teknoloji Anonim Sirketi", combined)
        self.assertEqual(combined.count("[COMPANY_1]"), 2)
        self.assertEqual(nodes, ["Taraf [COMPANY_1] ile", "yuklenici [COMPANY_1] arasinda"])

    def test_matches_turkish_dotted_i_against_lowercase_i(self):
        # Unicode simple case folding maps 'İ' (U+0130) to itself, so a matcher
        # built on simple folding leaves the lowercase spellings in place.
        nodes = self.redacted_text_nodes(
            ["İSTANBUL merkezli", "İstanbul merkezli", "istanbul merkezli"],
            [RedactionTarget("İSTANBUL", "[CITY_1]")],
        )

        self.assertEqual(nodes, ["[CITY_1] merkezli", "[CITY_1] merkezli", "[CITY_1] merkezli"])

    def test_matches_turkish_dotless_i_against_uppercase_i(self):
        # 'I' is the uppercase of Turkish 'ı', a pair no ASCII-shaped case rule
        # relates, so "Işıl Yıldırım" survives an approved "IŞIL YILDIRIM".
        nodes = self.redacted_text_nodes(
            ["Bilirkisi IŞIL YILDIRIM", "Bilirkisi Işıl Yıldırım"],
            [RedactionTarget("IŞIL YILDIRIM", "[PERSON_1]")],
        )

        self.assertEqual(nodes, ["Bilirkisi [PERSON_1]", "Bilirkisi [PERSON_1]"])

    def test_offsets_stay_correct_when_dotted_i_precedes_the_match(self):
        # The offset-corruption trap, and the reason this is not `text.lower()`.
        # 'İ'.lower() is TWO characters ('i' + U+0307), so an implementation that
        # searches a lowercased copy and slices the ORIGINAL with the resulting
        # index is shifted right by one per preceding 'İ'. There are three here,
        # so a naive implementation blanks "E LIMITED şi" instead of
        # "ACME LIMITED": it leaves "ACM" of the company name in the export and
        # eats two characters of the following word. The exact-equality assertion
        # below is what distinguishes the two.
        paragraph = "İSTANBUL İLİ, Besiktas - ACME LIMITED sirketi kayitlidir."
        nodes = self.redacted_text_nodes([paragraph], [RedactionTarget("ACME LIMITED", "[COMPANY_1]")])

        self.assertEqual(nodes, ["İSTANBUL İLİ, Besiktas - [COMPANY_1] sirketi kayitlidir."])

    def test_leaked_sample_count_counts_a_mixed_case_survivor_as_a_leak(self):
        # If the redactor becomes case-insensitive but this check stays exact,
        # QA reports 0 leaks for exactly the survivors it exists to catch.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, ["yuklenici Ardic Teknoloji Anonim Sirketi arasinda"])
            with ZipFile(source, "r") as archive:
                buffer = BytesIO()
                with ZipFile(buffer, "w", ZIP_DEFLATED) as copied:
                    for info in archive.infolist():
                        copied.writestr(info, archive.read(info.filename))
            report = analyze_docx_export_quality(
                source,
                buffer.getvalue(),
                [],
                sensitive_samples=["ARDIC TEKNOLOJI ANONIM SIRKETI"],
            )

        self.assertEqual(report["leakage_count"], 1)
        self.assertEqual(report["overall_status"], "fail")

    def test_unapplied_target_count_ignores_a_case_difference(self):
        # The mirror failure: a target the redactor did match, in a different
        # case, must not be reported as "never appeared in the source".
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, ["yuklenici Ardic Teknoloji Anonim Sirketi arasinda"])
            targets = [RedactionTarget("ARDIC TEKNOLOJI ANONIM SIRKETI", "[COMPANY_1]")]
            data = redact_docx(source, targets)
            report = analyze_docx_export_quality(source, data, targets)

        self.assertEqual(report["unapplied_target_count"], 0)
        self.assertEqual(report["leakage_count"], 0)
        self.assertEqual(report["overall_status"], "pass")

    def test_unapplied_target_count_still_flags_a_genuinely_absent_target(self):
        # Guards the other direction: the case-insensitive matcher must not be so
        # permissive that this check can no longer fire.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, ["yuklenici Ardic Teknoloji Anonim Sirketi arasinda"])
            targets = [RedactionTarget("Selçuk Aydın Elif", "[PERSON_2]")]
            data = redact_docx(source, targets)
            report = analyze_docx_export_quality(source, data, targets)

        self.assertEqual(report["unapplied_target_count"], 1)
        self.assertEqual(report["overall_status"], "warn")


class DocxDiacriticFoldingRedactionTests(unittest.TestCase):
    """The same bypass one step over: ç/c, ğ/g, ö/o, ş/s, ü/u.

    Turkish is typed without diacritics constantly, so one filing carries
    "ŞİRKETİ" in the heading and "SIRKETI" in the body. Matching only the exact
    glyphs redacts one and exports the other. The fold groups in
    docx_redactor.py deliberately over-match; see the comment there.
    """

    def redacted_text_nodes(self, paragraphs: list[str], targets: list[RedactionTarget]) -> list[str]:
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, paragraphs)
            data = redact_docx(source, targets)

        with ZipFile(BytesIO(data)) as archive:
            root = ElementTree.fromstring(archive.read("word/document.xml"))
            return [node.text or "" for node in root.iter(TEXT_TAG)]

    def test_diacritic_bearing_target_redacts_diacritic_free_text(self):
        nodes = self.redacted_text_nodes(
            ["Taraf ARDIÇ TEKNOLOJİ ANONİM ŞİRKETİ ile", "yuklenici Ardic Teknoloji Anonim Sirketi arasinda"],
            [RedactionTarget("ARDIÇ TEKNOLOJİ ANONİM ŞİRKETİ", "[COMPANY_1]")],
        )

        self.assertEqual(nodes, ["Taraf [COMPANY_1] ile", "yuklenici [COMPANY_1] arasinda"])

    def test_diacritic_free_target_redacts_diacritic_bearing_text(self):
        # The mirror direction. A reviewer approving the finding as it was
        # detected in the body must still clear the heading.
        nodes = self.redacted_text_nodes(
            ["Taraf ARDIÇ TEKNOLOJİ ANONİM ŞİRKETİ ile", "yuklenici Ardic Teknoloji Anonim Sirketi arasinda"],
            [RedactionTarget("Ardic Teknoloji Anonim Sirketi", "[COMPANY_1]")],
        )

        self.assertEqual(nodes, ["Taraf [COMPANY_1] ile", "yuklenici [COMPANY_1] arasinda"])

    def test_fold_and_case_compose_in_one_target(self):
        # 'Ş' has to reach 's' through BOTH a fold and a case change at once, and
        # 'İ' through a fold-group member that no ASCII case rule relates to 'i'.
        nodes = self.redacted_text_nodes(
            ["ŞİRKETİ kaydi", "Şirketi kaydi", "sirketi kaydi", "şirketi kaydi"],
            [RedactionTarget("ŞİRKETİ", "[COMPANY_1]")],
        )

        self.assertEqual(nodes, ["[COMPANY_1] kaydi"] * 4)

    def test_every_fold_group_matches_its_plain_letter(self):
        # One assertion per group, so a group dropped from the table is named by
        # the failure rather than hidden behind a single company-name fixture.
        for target, text in [
            ("ÇANKAYA", "cankaya"),
            ("GÖĞÜS", "gogus"),
            ("İSTANBUL", "istanbul"),
            ("ÖZTÜRK", "ozturk"),
            ("ŞAHİN", "sahin"),
            ("ÜNAL", "unal"),
            ("KÂZIM", "kazim"),
            ("HÂKİMİ", "hakimi"),
            ("MAHKÛM", "mahkum"),
        ]:
            with self.subTest(target=target):
                nodes = self.redacted_text_nodes([f"{text} kaydi"], [RedactionTarget(target, "[X]")])
                self.assertEqual(nodes, ["[X] kaydi"])

    def test_circumflex_vowels_fold_in_both_directions(self):
        # â/î/û are ordinary in Turkish names and legal vocabulary ("Kâzım",
        # "hâkim", "mahkûm") and are dropped in running text as freely as the
        # other diacritics, so the bypass is the same one: an approved "Kâzim"
        # left "Kazim" in the export, and an approved "Kazim" left "Kâzim".
        nodes = self.redacted_text_nodes(
            ["Hakim Kazim Unal", "Hâkim Kâzim Ünal"],
            [RedactionTarget("Kâzim", "[PERSON_1]")],
        )
        self.assertEqual(nodes, ["Hakim [PERSON_1] Unal", "Hâkim [PERSON_1] Ünal"])

        nodes = self.redacted_text_nodes(
            ["Hakim Kazim Unal", "Hâkim Kâzim Ünal"],
            [RedactionTarget("KAZIM", "[PERSON_1]")],
        )
        self.assertEqual(nodes, ["Hakim [PERSON_1] Unal", "Hâkim [PERSON_1] Ünal"])

    def test_fold_groups_are_pairwise_disjoint(self):
        # TURKISH_FOLD_BY_CHAR is built last-group-wins, so two groups sharing a
        # character silently shadow one another instead of merging. The concrete
        # trap: adding frozenset("uUûÛ") alongside frozenset("uUüÜ") looks like
        # the obvious way to fold û, and quietly stops 'u' from reaching 'Ü'.
        # A circumflex vowel belongs in the group of its base letter.
        seen: dict[str, frozenset] = {}
        for group in TURKISH_FOLD_GROUPS:
            for char in group:
                if char in seen:
                    self.fail(
                        f"{char!r} appears in two fold groups ({sorted(seen[char])} and {sorted(group)}); "
                        "merge them into one group instead, or the later one shadows the earlier."
                    )
                seen[char] = group

    def test_every_fold_group_member_matches_every_other_member(self):
        # Derived from the table rather than from a hand-written fixture list, so
        # a character added to a group cannot arrive without coverage, in either
        # direction. Each pair is checked as target-vs-text and text-vs-target.
        for group in TURKISH_FOLD_GROUPS:
            for target_char in sorted(group):
                for text_char in sorted(group):
                    with self.subTest(group="".join(sorted(group)), target=target_char, text=text_char):
                        nodes = self.redacted_text_nodes(
                            [f"kod {text_char}9 kaydi"], [RedactionTarget(f"{target_char}9", "[X]")]
                        )
                        self.assertEqual(nodes, ["kod [X] kaydi"])

    def test_offsets_stay_correct_when_folded_characters_precede_the_match(self):
        # The Trap-1 property has to survive the wider matcher: 'İ' is still two
        # characters lowercased, so a fold implemented via str.lower() would still
        # shift every span after it. Three 'İ' before the target, exact assertion.
        paragraph = "İSTANBUL İLİ, Beşiktaş - ACME LIMITED şirketi kayıtlıdır."
        nodes = self.redacted_text_nodes([paragraph], [RedactionTarget("ACME LIMITED", "[COMPANY_1]")])

        self.assertEqual(nodes, ["İSTANBUL İLİ, Beşiktaş - [COMPANY_1] şirketi kayıtlıdır."])

    def test_leaked_sample_count_counts_a_diacritic_variant_survivor_as_a_leak(self):
        # QA must see the survivor the redactor now removes, or the blind spot
        # outlives the fix -- same argument as the case variant.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, ["yuklenici Ardic Teknoloji Anonim Sirketi arasinda"])
            with ZipFile(source, "r") as archive:
                buffer = BytesIO()
                with ZipFile(buffer, "w", ZIP_DEFLATED) as copied:
                    for info in archive.infolist():
                        copied.writestr(info, archive.read(info.filename))
            report = analyze_docx_export_quality(
                source,
                buffer.getvalue(),
                [],
                sensitive_samples=["ARDIÇ TEKNOLOJİ ANONİM ŞİRKETİ"],
            )

        self.assertEqual(report["leakage_count"], 1)
        self.assertEqual(report["overall_status"], "fail")

    def test_unapplied_target_count_still_flags_a_target_differing_outside_the_fold_table(self):
        # Anti-vacuity for the wider matcher. This target differs from the source
        # text in exactly ONE position -- 'K' where the source has 'c' -- and c/k
        # is not a fold group. If the table ever grows past the six Turkish pairs,
        # this stops firing and the check silently becomes decorative.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, ["yuklenici Ardic Teknoloji Anonim Sirketi arasinda"])
            targets = [RedactionTarget("ARDIK TEKNOLOJI ANONIM SIRKETI", "[COMPANY_1]")]
            data = redact_docx(source, targets)
            report = analyze_docx_export_quality(source, data, targets)

        self.assertEqual(report["unapplied_target_count"], 1)
        self.assertEqual(report["overall_status"], "warn")


class DocxOverlappingTargetTests(unittest.TestCase):
    """Two approved targets that overlap: no part of either may survive.

    Diacritic folding made overlaps ordinary. In
    "Yuklenici ACIK KADIR YILMAZ imzaladi." the approved "AÇIK KADIR" matches
    only because ç folds onto c, it starts earlier than "KADIR YILMAZ", and the
    old selector DROPPED the loser whole instead of clipping it -- so the surname
    shipped in cleartext. Both export QA checks scored that export clean, because
    each only ever looks for the WHOLE sample string and a surviving fragment is
    not one.
    """

    def redacted_text_nodes(self, paragraphs: list[str], targets: list[RedactionTarget]) -> list[str]:
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, paragraphs)
            data = redact_docx(source, targets)

        with ZipFile(BytesIO(data)) as archive:
            root = ElementTree.fromstring(archive.read("word/document.xml"))
            return [node.text or "" for node in root.iter(TEXT_TAG)]

    def test_overlapping_targets_leave_no_fragment_of_either(self):
        # The reproduction, verbatim. "AÇIK KADIR" wins the sort; the residual
        # " YILMAZ" of the loser has to be replaced too.
        nodes = self.redacted_text_nodes(
            ["Yuklenici ACIK KADIR YILMAZ imzaladi."],
            [RedactionTarget("AÇIK KADIR", "[MISC_1]"), RedactionTarget("KADIR YILMAZ", "[PERSON_1]")],
        )

        combined = "\n".join(nodes)
        self.assertNotIn("KADIR", combined)
        self.assertNotIn("YILMAZ", combined)
        self.assertNotIn("ACIK", combined)
        self.assertEqual(nodes, ["Yuklenici [MISC_1][PERSON_1] imzaladi."])

    def test_clipped_span_crossing_a_run_boundary_is_written_back_correctly(self):
        # The residual span is applied by slicing the ORIGINAL Word text nodes, so
        # it has to survive a run split landing inside the overlap: here the first
        # run ends mid-surname, between the two spans' boundary at "KAD|IR".
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_split_run_docx(source, ["Yuklenici ACIK KAD", "IR YILMAZ imzaladi."])
            data = redact_docx(
                source,
                [RedactionTarget("AÇIK KADIR", "[MISC_1]"), RedactionTarget("KADIR YILMAZ", "[PERSON_1]")],
            )

        with ZipFile(BytesIO(data)) as archive:
            root = ElementTree.fromstring(archive.read("word/document.xml"))
            nodes = [node.text or "" for node in root.iter(TEXT_TAG)]

        combined = "".join(nodes)
        self.assertNotIn("YILMAZ", combined)
        self.assertNotIn("KAD", combined)
        self.assertEqual(combined, "Yuklenici [MISC_1][PERSON_1] imzaladi.")

    def test_target_wholly_inside_another_emits_nothing_extra(self):
        # The other direction: a target entirely covered by an already-selected
        # span must contribute NO span at all. Emitting a clipped residual for it
        # unconditionally would produce an inverted (start > end) span and a
        # duplicated placeholder.
        nodes = self.redacted_text_nodes(
            ["Sozlesme ACIK KADIR YILMAZ tarafindan imzalandi."],
            [RedactionTarget("ACIK KADIR YILMAZ", "[PERSON_1]"), RedactionTarget("KADIR", "[MISC_1]")],
        )

        self.assertEqual(nodes, ["Sozlesme [PERSON_1] tarafindan imzalandi."])
        self.assertNotIn("[MISC_1]", nodes[0])

    def test_every_matched_character_is_covered_by_some_emitted_span(self):
        # The invariant, over a three-way overlap where each match extends past
        # the previous one. Asserting on the output text alone would not catch the
        # middle target being dropped here -- its uncovered tail is one space --
        # so this asserts coverage of the union of ALL match positions directly.
        text = "Yuklenici ACIK KADIR YILMAZ HANIM imzaladi."
        targets = [
            RedactionTarget("AÇIK KADIR", "[A]"),
            RedactionTarget("KADIR YILMAZ", "[B]"),
            RedactionTarget("YILMAZ HANIM", "[C]"),
        ]

        selected = collect_replacements(text, targets)

        matched: set[int] = set()
        for target in targets:
            for start, end in find_case_insensitive(text, target.text):
                matched.update(range(start, end))
        covered: set[int] = set()
        for start, end, _ in selected:
            covered.update(range(start, end))
        self.assertEqual(matched - covered, set())

        # And the spans must stay sorted and disjoint: write_replacements_back
        # slices the original text nodes with them.
        self.assertEqual(selected, sorted(selected))
        for (_, first_end, _), (second_start, _, _) in zip(selected, selected[1:]):
            self.assertLessEqual(first_end, second_start)
        for start, end, _ in selected:
            self.assertLess(start, end)


class TargetPatternCacheTests(unittest.TestCase):
    """Compiled approved targets must not be left in re's module-level cache.

    ``case_insensitive_pattern`` was documented as "deliberately uncached". It is
    not: ``re.compile`` stores the compiled object in ``re._cache`` keyed by the
    pattern STRING, which spells the target out as character classes. That is a
    readable copy of an approved identifier surviving in the interpreter, in the
    redaction module of a tool whose thesis is that nothing sensitive leaves the
    device.
    """

    TARGET = "ARDIÇ TEKNOLOJİ ANONİM ŞİRKETİ"

    def tearDown(self):
        re.purge()

    def cached_pattern_strings(self) -> set[str]:
        caches = [re._cache] + ([re._cache2] if hasattr(re, "_cache2") else [])
        return {key[1] for cache in caches for key in cache if isinstance(key[1], str)}

    def test_compiling_a_target_does_cache_it(self):
        # Anti-vacuity, and the measurement the docstring now states: without a
        # purge the character-class rendering of the target IS a live cache key,
        # so the assertions below can fail.
        re.purge()
        pattern = case_insensitive_pattern(self.TARGET).pattern

        self.assertIn(pattern, self.cached_pattern_strings())
        self.assertIn("[CcÇç]", pattern)  # the key is a readable rendering of the target

    def test_redact_docx_leaves_no_target_pattern_in_the_cache(self):
        pattern = case_insensitive_pattern(self.TARGET).pattern
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, ["Taraf ARDIC TEKNOLOJI ANONIM SIRKETI ile"])
            re.purge()
            redact_docx(source, [RedactionTarget(self.TARGET, "[COMPANY_1]")])

        self.assertNotIn(pattern, self.cached_pattern_strings())

    def test_docx_export_qa_leaves_no_sample_pattern_in_the_cache(self):
        pattern = case_insensitive_pattern(self.TARGET).pattern
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.docx"
            make_minimal_docx(source, ["Taraf ARDIC TEKNOLOJI ANONIM SIRKETI ile"])
            data = redact_docx(source, [])
            re.purge()
            analyze_docx_export_quality(source, data, [], sensitive_samples=[self.TARGET])

        self.assertNotIn(pattern, self.cached_pattern_strings())


if __name__ == "__main__":
    unittest.main()
