"""PDF export QA: what the leakage checks can and cannot see."""

import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import fitz

from legal_analyzer.docx_redactor import case_insensitive_pattern
from legal_analyzer.pdf_redactor import (
    PdfRegion,
    analyze_pdf_redaction_quality,
    extract_pdf_text_from_bytes,
    normalized_region,
    redact_pdf,
)


def make_pdf(path: Path, lines: list[str]) -> None:
    """A one-page PDF with each line as its own text run.

    Only ASCII goes into the page: the base-14 Helvetica used here cannot encode
    'İ' or 'Ş', and the point of these tests is a sample whose diacritics differ
    from the document's spelling, not a font check.
    """
    doc = fitz.open()
    page = doc.new_page()
    y = 72
    for line in lines:
        page.insert_text((72, y), line, fontsize=12)
        y += 24
    doc.save(path)
    doc.close()


def region_over(path: Path, needle: str, sample: str, finding_id: int = 1, region_id: int = 1) -> PdfRegion:
    """An approved region boxing the first occurrence of ``needle``."""
    with fitz.open(path) as doc:
        page = doc[0]
        rects = page.search_for(needle)
        assert rects, f"fixture does not contain {needle!r}"
        return normalized_region(
            1,
            rects[0],
            page.rect,
            category="natural_person_name",
            source="detected_text",
            finding_id=finding_id,
            sample=sample,
            region_id=region_id,
        )


def leak_checks(report: dict) -> dict[str, str]:
    return {
        check["name"]: check["status"]
        for check in report["checks"]
        if "not extractable" in check["name"]
    }


class PdfExportQaLeakageTests(unittest.TestCase):
    """The QA that stamps finding_evidence.verification_status must see survivors.

    ``leakage_count`` drives the write that sets a finding's evidence row to
    ``redacted_verified``, so anything this check misses is actively marked
    verified. It used to miss two whole classes: a survivor spelled with a
    different case or Turkish diacritic (the comparison was a plain ``in``), and
    any occurrence of an approved identifier that no region happens to box (the
    loop only ever tested each region's own sample).
    """

    def test_case_and_diacritic_variant_survivor_is_counted(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.pdf"
            make_pdf(source, ["Taraf Ardic Teknoloji Anonim Sirketi ile"])
            # A box drawn over the wrong words: the identifier is untouched, and
            # the approved sample carries the diacritics the document omits.
            region = region_over(
                source, "Taraf", "ARDIÇ TEKNOLOJİ ANONİM ŞİRKETİ", finding_id=7, region_id=11
            )
            data = redact_pdf(source, [region])

            report = analyze_pdf_redaction_quality(
                source, data, [region], sensitive_samples=["ARDIÇ TEKNOLOJİ ANONİM ŞİRKETİ"]
            )

        self.assertEqual(report["leakage_count"], 1)
        self.assertEqual(report["region_leakage_count"], 1)
        self.assertEqual([leak["region_id"] for leak in report["leaked_regions"]], [11])
        self.assertEqual(
            leak_checks(report),
            {
                "Redacted region text not extractable (includes OCR text layers)": "fail",
                "Approved sensitive text not extractable anywhere in the output": "fail",
            },
        )
        self.assertEqual(report["overall_status"], "fail")

    def test_approved_sample_with_no_region_of_its_own_is_counted(self):
        # The DOCX C-1 hole, on the PDF side: a finding that never became a
        # region cannot be seen by a per-region check, so its text shipped with
        # leakage_count 0 and every evidence row stamped redacted_verified.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.pdf"
            make_pdf(source, ["Davaci Ayse Demir", "Taniklar Mehmet Kaya"])
            region = region_over(source, "Ayse Demir", "Ayse Demir")
            data = redact_pdf(source, [region])

            report = analyze_pdf_redaction_quality(
                source, data, [region], sensitive_samples=["Ayse Demir", "Mehmet Kaya"]
            )

        self.assertEqual(report["leaked_regions"], [])  # the boxed one really is gone
        self.assertEqual(report["region_leakage_count"], 0)
        self.assertEqual(report["leakage_count"], 1)
        self.assertEqual(report["sensitive_sample_count"], 2)
        self.assertEqual(
            leak_checks(report)["Approved sensitive text not extractable anywhere in the output"], "fail"
        )
        self.assertEqual(report["overall_status"], "fail")

    def test_second_unboxed_occurrence_of_a_boxed_sample_is_counted(self):
        # Same entity twice, one box. The second occurrence is spelled in caps,
        # which is how it escaped both the box and a plain substring check.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.pdf"
            make_pdf(source, ["Davaci Ayse Demir", "Vekil AYSE DEMIR"])
            region = region_over(source, "Ayse Demir", "Ayse Demir")
            data = redact_pdf(source, [region])
            text_after = extract_pdf_text_from_bytes(data)

            report = analyze_pdf_redaction_quality(source, data, [region], sensitive_samples=["Ayse Demir"])

        self.assertIn("AYSE DEMIR", text_after)  # the fixture really does still carry it
        self.assertEqual(report["leakage_count"], 1)
        self.assertEqual(report["region_leakage_count"], 1)
        self.assertEqual(report["overall_status"], "fail")

    def test_clean_export_still_reports_zero_leakage(self):
        # Anti-vacuity: the widened check must still be able to say "clean", or
        # the two tests above would pass against a check that always fires.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.pdf"
            make_pdf(source, ["Davaci Ayse Demir"])
            region = region_over(source, "Ayse Demir", "Ayse Demir")
            data = redact_pdf(source, [region])

            report = analyze_pdf_redaction_quality(source, data, [region], sensitive_samples=["Ayse Demir"])

        self.assertEqual(report["leakage_count"], 0)
        self.assertEqual(report["region_leakage_count"], 0)
        self.assertEqual(report["leaked_regions"], [])
        self.assertEqual(report["sensitive_sample_count"], 1)
        self.assertEqual(
            leak_checks(report),
            {
                "Redacted region text not extractable (includes OCR text layers)": "pass",
                "Approved sensitive text not extractable anywhere in the output": "pass",
            },
        )

    def test_retained_findings_keep_the_report_off_pass(self):
        # A retained finding is an identifier the reviewer chose to leave in, so
        # it is excluded from the leakage set and leakage_count is 0 by
        # construction. Without a distinct count and check, the report on a PDF
        # still carrying a national ID would be an unqualified clean bill.
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.pdf"
            make_pdf(source, ["Davaci Ayse Demir"])
            region = region_over(source, "Ayse Demir", "Ayse Demir")
            data = redact_pdf(source, [region])

            report = analyze_pdf_redaction_quality(
                source, data, [region], sensitive_samples=["Ayse Demir"], retained_count=1
            )

        self.assertEqual(report["leakage_count"], 0)
        self.assertEqual(report["retained_count"], 1)
        self.assertNotEqual(report["overall_status"], "pass")
        retained_checks = [c for c in report["checks"] if c["name"] == "Identifiers deliberately retained"]
        self.assertEqual([c["status"] for c in retained_checks], ["warn"])
        self.assertIn("1 finding(s) were retained unredacted", retained_checks[0]["detail"])

    def test_pdf_qa_leaves_no_sample_pattern_in_the_re_cache(self):
        # Matching compiles each approved sample into re's module-level cache,
        # where the key is a readable rendering of it. See
        # TargetPatternCacheTests in tests/test_docx_redactor.py.
        sample = "ARDIÇ TEKNOLOJİ ANONİM ŞİRKETİ"
        pattern = case_insensitive_pattern(sample).pattern
        try:
            with TemporaryDirectory() as tmp:
                source = Path(tmp) / "source.pdf"
                make_pdf(source, ["Taraf Ardic Teknoloji Anonim Sirketi ile"])
                region = region_over(source, "Taraf", sample)
                data = redact_pdf(source, [region])
                re.purge()
                analyze_pdf_redaction_quality(source, data, [region], sensitive_samples=[sample])

            caches = [re._cache] + ([re._cache2] if hasattr(re, "_cache2") else [])
            cached = {key[1] for cache in caches for key in cache if isinstance(key[1], str)}
            self.assertNotIn(pattern, cached)
        finally:
            re.purge()


if __name__ == "__main__":
    unittest.main()
