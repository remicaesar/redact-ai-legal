import re
import unittest
from pathlib import Path

from legal_analyzer.docx_redactor import TURKISH_I_FORMS
from legal_analyzer.privacy import (
    CONTEXT_SWEEP_CATEGORIES,
    DETECTION_RULES,
    _COMPANY_SUFFIXES,
    _CONTEXT_SWEEP_ABBREVIATIONS,
    _CONTEXT_SWEEP_CHAR,
    _i_forms,
    DIRECT_IDENTIFIER_CATEGORIES,
    EXTERNAL_LLM_ALLOWED,
    EXTERNAL_LLM_BLOCKED,
    analyze_privacy,
    build_redacted_preview,
    has_direct_identifiers,
    refresh_release_state,
)


class PrivacyAnalysisTests(unittest.TestCase):
    def test_uses_cautious_anonymization_language(self):
        text = "Av. Ahmet Yilmaz, Soruşturma No: 2026/123 ve İstanbul adresi için şikayet sundu."
        result = analyze_privacy("sikayet.docx", text)

        self.assertTrue(result["residual_risk"]["not_fully_anonymous"])
        self.assertIn("risk-reduced", result["positioning"])
        self.assertNotIn("fully anonymous", result["recommended_strategy"].lower())

    def test_detects_critical_legal_context(self):
        text = "Şüpheli hakkında suç ve arama talebi vardır. T.C Kimlik: 12345678901."
        result = analyze_privacy("ceza_sikayet.docx", text)
        risks = {finding["risk"] for finding in result["risk_map"]}

        self.assertIn("CRITICAL", risks)
        self.assertEqual(
            result["llm_ingestion"]["external_hosted_llm_api"],
            EXTERNAL_LLM_BLOCKED,
        )

    def test_extraction_warning_blocks_external_llm(self):
        result = analyze_privacy("scan.pdf", "", "PDF text extraction returned no text; OCR may be required.")

        self.assertEqual(result["extraction_status"]["status"], "Failed")
        self.assertEqual(result["residual_risk"]["level"], "Unknown")
        self.assertEqual(result["external_llm_readiness"], "Blocked until OCR/manual review")
        self.assertTrue(result["human_review_required"])

    def test_low_risk_still_requires_release_controls(self):
        result = analyze_privacy("template.txt", "Generic public template clause.")

        self.assertEqual(result["residual_risk"]["level"], "Low")
        self.assertFalse(result["external_llm_gate"]["allowed"])
        self.assertIn("Redaction pass must be completed.", result["external_llm_gate"]["failed_conditions"])
        self.assertEqual(result["llm_ingestion"]["external_hosted_llm_api"], EXTERNAL_LLM_BLOCKED)
        self.assertTrue(result["human_review_required"])

    def test_external_llm_allowed_only_after_controls(self):
        result = analyze_privacy(
            "template.txt",
            "Generic public template clause.",
            redaction_completed=True,
            human_review_approved=True,
        )

        self.assertEqual(result["residual_risk"]["level"], "Low")
        self.assertTrue(result["external_llm_gate"]["allowed"])
        self.assertEqual(result["llm_ingestion"]["external_hosted_llm_api"], EXTERNAL_LLM_ALLOWED)
        self.assertFalse(result["human_review_required"])

    def test_release_state_refresh_allows_clean_approved_document(self):
        profile = analyze_privacy("template.txt", "Generic public template clause.")
        refreshed = refresh_release_state(profile, redaction_completed=True, human_review_approved=True)

        self.assertTrue(refreshed["external_llm_gate"]["allowed"])
        self.assertEqual(refreshed["external_llm_readiness"], EXTERNAL_LLM_ALLOWED)

    def test_unaccepted_ocr_blocks_release_controls(self):
        profile = analyze_privacy("template.txt", "Generic public template clause.")
        refreshed = refresh_release_state(
            profile,
            redaction_completed=True,
            human_review_approved=True,
            ocr_status="completed",
        )

        self.assertFalse(refreshed["external_llm_gate"]["allowed"])
        self.assertEqual(refreshed["external_llm_readiness"], "Blocked until OCR/manual review")
        self.assertIn("OCR output must be accepted or not required.", refreshed["external_llm_gate"]["failed_conditions"])


if __name__ == "__main__":
    unittest.main()


class FindingExplanationTests(unittest.TestCase):
    def test_every_detected_category_has_an_explanation(self):
        from legal_analyzer.privacy import (
            CATEGORY_EXPLANATIONS,
            DETECTION_RULES,
            explain_category,
            finding_explanations,
        )

        detected = {rule.category for rule in DETECTION_RULES} | {"natural_person_name", "manual_sensitive_text"}
        for category in detected:
            self.assertIn(category, CATEGORY_EXPLANATIONS, category)
            info = explain_category(category)
            self.assertTrue(info["label"] and info["basis"] and info["concern"])

        bundle = finding_explanations()
        self.assertEqual(set(bundle), {"categories", "risks", "direct_identifiers"})
        self.assertEqual(set(bundle["risks"]), {"CRITICAL", "HIGH", "MEDIUM", "LOW"})
        self.assertIn("turkish_national_id", bundle["direct_identifiers"])

    def test_checksum_categories_mention_validation(self):
        from legal_analyzer.privacy import explain_category

        self.assertIn("check-digit", explain_category("turkish_national_id")["basis"])
        self.assertIn("check-digit", explain_category("tax_number")["basis"])

    def test_unknown_category_falls_back_gracefully(self):
        from legal_analyzer.privacy import explain_category

        info = explain_category("something_new")
        self.assertEqual(info["label"], "Something New")
        self.assertTrue(info["basis"])


class ReleaseStateRefreshTests(unittest.TestCase):
    """refresh_release_state() must re-derive residual risk from what remains.

    The happy-path refresh test above uses a document with zero findings, which
    is why the frozen residual-risk bug survived: a clean template is Low at
    detection time, so reusing the stored level is indistinguishable from
    recomputing it. These tests start from a document that really does carry a
    CRITICAL finding and a High detection-time level.
    """

    TEXT = (
        "Istanbul 5. Asliye Ceza Mahkemesi dosyasinda Av. Ayse Demir 01.01.2026 "
        "tarihli dilekce sundu. T.C. Kimlik No: 10000000146"
    )

    def profile(self) -> dict:
        return analyze_privacy("dilekce.docx", self.TEXT)

    def critical_findings(self, profile: dict) -> list[dict]:
        return [f for f in profile["risk_map"] if f["risk"] == "CRITICAL"]

    def test_fixture_is_critical_at_detection_time(self):
        profile = self.profile()

        self.assertTrue(self.critical_findings(profile))
        self.assertEqual(profile["residual_risk"]["level"], "High")

    def test_refresh_allows_a_document_whose_findings_are_all_redacted(self):
        profile = self.profile()
        refreshed = refresh_release_state(
            profile,
            redaction_completed=True,
            human_review_approved=True,
            unresolved_critical_count=0,
            direct_identifiers_remaining=False,
            remaining_findings=[],
        )

        self.assertEqual(refreshed["external_llm_gate"]["failed_conditions"], [])
        self.assertTrue(refreshed["external_llm_gate"]["allowed"])
        self.assertEqual(refreshed["post_review_residual_risk"]["level"], "Low")
        self.assertEqual(refreshed["external_llm_readiness"], EXTERNAL_LLM_ALLOWED)
        # The detection-time measurement is a record, not a working value.
        self.assertEqual(refreshed["residual_risk"]["level"], "High")

    def test_refresh_keeps_the_gate_closed_for_a_rejected_critical_finding(self):
        profile = self.profile()
        refreshed = refresh_release_state(
            profile,
            redaction_completed=True,
            human_review_approved=True,
            unresolved_critical_count=0,
            direct_identifiers_remaining=False,
            remaining_findings=self.critical_findings(profile),
        )

        self.assertFalse(refreshed["external_llm_gate"]["allowed"])
        self.assertEqual(
            refreshed["external_llm_gate"]["failed_conditions"],
            ["Residual risk must be Low."],
        )
        self.assertEqual(refreshed["post_review_residual_risk"]["level"], "High")

    def test_refresh_without_review_state_keeps_the_stored_level(self):
        """A caller that cannot supply review state must not get the open answer."""
        profile = self.profile()
        refreshed = refresh_release_state(
            profile,
            redaction_completed=True,
            human_review_approved=True,
            unresolved_critical_count=0,
            direct_identifiers_remaining=False,
        )

        self.assertFalse(refreshed["external_llm_gate"]["allowed"])
        self.assertIn("Residual risk must be Low.", refreshed["external_llm_gate"]["failed_conditions"])
        self.assertEqual(refreshed["post_review_residual_risk"]["level"], "High")

    def test_refresh_keeps_extraction_gating_ahead_of_the_recompute(self):
        """Nothing remaining is not Low when the text was never fully extracted."""
        profile = analyze_privacy("scan.pdf", "", "PDF text extraction returned no text; OCR may be required.")
        refreshed = refresh_release_state(
            profile,
            redaction_completed=True,
            human_review_approved=True,
            unresolved_critical_count=0,
            direct_identifiers_remaining=False,
            remaining_findings=[],
        )

        self.assertEqual(refreshed["post_review_residual_risk"]["level"], "Unknown")
        self.assertFalse(refreshed["external_llm_gate"]["allowed"])


class ContextFindingIdentifierCutTests(unittest.TestCase):
    """The three context rules must not store another party's identifiers.

    health_data, criminal_allegation and privileged_or_confidential match a
    trigger keyword plus a trailing sweep of up to 120-160 characters. That
    sweep used to carry a name and a national id into the finding's own sample,
    storing them a second time under a category that has nothing to do with
    them. analyze_privacy() now cuts the context span around every direct
    identifier inside it.
    """

    MEDICAL_TEXT = (
        "Davacı hasta Leyla Kaya (TCKN: 66666666660), Özel Marmara Hastanesi'nde 22.09.2025\n"
        "tarihinde geçirdiği cerrahi operasyon sonrası kalıcı sinir hasarı teşhisi konulduğunu,\n"
        "tedavi sürecinde ağır ihmal bulunduğunu iddia etmektedir."
    )
    PRIVILEGED_TEXT = (
        "Müvekkil Cemile Doğan (TCKN: 11111111110), Kadıköy 2. Noterliği onaylı örneği ile,\n"
        "vekaletname kapsamında yetkilendirilmiştir."
    )
    CRIMINAL_TEXT = (
        "Şüpheli Kemal Arslan hakkında nitelikli dolandırıcılık iddiası ile soruşturma "
        "yürütülmektedir."
    )

    def findings(self, filename, text):
        return analyze_privacy(filename, text)["risk_map"]

    def of_category(self, findings, category):
        return [finding for finding in findings if finding["category"] == category]

    def spans(self, findings, category):
        return {(finding["start"], finding["end"]) for finding in self.of_category(findings, category)}

    def test_health_data_sample_keeps_no_patient_identifier(self):
        findings = self.findings("medical_case.txt", self.MEDICAL_TEXT)

        for finding in self.of_category(findings, "health_data"):
            self.assertNotIn("66666666660", finding["sample"])
            self.assertNotIn("Leyla", finding["sample"])
            self.assertNotIn("Kaya", finding["sample"])

        # The identifiers keep their own findings, at their own spans.
        self.assertEqual(
            self.spans(findings, "natural_person_name"),
            {(self.MEDICAL_TEXT.index("Leyla Kaya"), self.MEDICAL_TEXT.index("Leyla Kaya") + len("Leyla Kaya"))},
        )
        self.assertEqual(
            self.spans(findings, "turkish_national_id"),
            {(self.MEDICAL_TEXT.index("66666666660"), self.MEDICAL_TEXT.index("66666666660") + 11)},
        )

    def test_privileged_sample_keeps_no_client_identifier(self):
        findings = self.findings("power_of_attorney.txt", self.PRIVILEGED_TEXT)

        for finding in self.of_category(findings, "privileged_or_confidential"):
            self.assertNotIn("11111111110", finding["sample"])
            self.assertNotIn("Cemile", finding["sample"])
            self.assertNotIn("Doğan", finding["sample"])

        self.assertEqual(
            self.spans(findings, "natural_person_name"),
            {
                (
                    self.PRIVILEGED_TEXT.index("Cemile Doğan"),
                    self.PRIVILEGED_TEXT.index("Cemile Doğan") + len("Cemile Doğan"),
                )
            },
        )
        self.assertEqual(
            self.spans(findings, "turkish_national_id"),
            {(self.PRIVILEGED_TEXT.index("11111111110"), self.PRIVILEGED_TEXT.index("11111111110") + 11)},
        )

        # What is left of the span after the client's name and TCKN are cut out
        # is "), Kadıköy 2". It is reported: a segment that carries a word is
        # kept even when that word turns out to be a bare place name, because
        # the same shape carries a one-word diagnosis. The "(TCKN:" fragment
        # between the two cuts is not -- it is the identifier's own label.
        self.assertEqual(
            [finding["sample"] for finding in self.of_category(findings, "privileged_or_confidential")],
            ["Müvekkil", "), Kadıköy 2"],
        )

    def test_allegation_after_the_identifier_keeps_a_critical_finding(self):
        """The clause after the cut is kept, not dropped.

        Dropping it would leave "hakkında nitelikli dolandırıcılık iddiası ile
        soruşturma yürütülmektedir" with no CRITICAL finding covering it, so a
        reviewer would have nothing to approve and the allegation would survive
        export. Asserted on spans rather than sample substrings: the span is
        what a reviewer approves and what the exporter redacts.
        """
        findings = self.findings("criminal_investigation.txt", self.CRIMINAL_TEXT)
        allegation_start = self.CRIMINAL_TEXT.index("hakkında")
        allegation_end = self.CRIMINAL_TEXT.index("yürütülmektedir") + len("yürütülmektedir")

        covering = [
            finding
            for finding in self.of_category(findings, "criminal_allegation")
            if finding["start"] <= allegation_start and finding["end"] >= allegation_end
        ]
        self.assertEqual(len(covering), 1, self.of_category(findings, "criminal_allegation"))
        self.assertEqual(covering[0]["risk"], "CRITICAL")
        # ... and it starts after the person's name, not before it.
        self.assertGreaterEqual(
            covering[0]["start"],
            self.CRIMINAL_TEXT.index("Kemal Arslan") + len("Kemal Arslan"),
        )

    def test_every_fixture_finding_sample_is_its_own_span(self):
        """The redaction-target contract, for every rule and every fixture.

        A finding's sample is the redaction target (redaction_targets_for_document
        in app.py), the key the PDF exporter maps to coordinate boxes, and the
        string export QA searches the produced file for. It must therefore stay
        literal, contiguous document text at the span the finding reports.
        `_finding()` derives it as the match text stripped and capped at 180
        characters, which is the relation asserted here.
        """
        fixtures = sorted((Path(__file__).parent / "fixtures").glob("*.txt"))
        self.assertGreater(len(fixtures), 10)
        checked = 0
        for fixture in fixtures:
            text = fixture.read_text(encoding="utf-8")
            for finding in self.findings(fixture.name, text):
                checked += 1
                self.assertEqual(
                    finding["sample"],
                    text[finding["start"]:finding["end"]].strip()[:180],
                    f"{fixture.name}: {finding['category']} at {finding['start']}:{finding['end']}",
                )
        self.assertGreater(checked, 100)

    def test_redacted_preview_hides_the_swept_identifiers(self):
        result = analyze_privacy("medical_case.txt", self.MEDICAL_TEXT)

        preview = result["redacted_preview"]
        self.assertNotIn("66666666660", preview)
        self.assertNotIn("Leyla", preview)
        self.assertNotIn("Kaya", preview)

    def test_one_word_diagnosis_after_the_cut_keeps_a_critical_finding(self):
        """A single sensitive word after the identifier is content, not scaffolding.

        Two earlier versions of the discard rule lost this. The first asked every
        non-leading segment for two words. The second also dropped a lone
        Capitalised word as a proper noun, which took "Alzheimer" with it. Both
        left the diagnosis in the document with no finding covering it, so no
        reviewer could approve it for redaction.
        """
        for text, category, word in (
            ("hasta Leyla Kaya (TCKN: 66666666660), kanser.", "health_data", "kanser"),
            ("Müvekkil Cemile Doğan (TCKN: 11111111110), HIV.", "privileged_or_confidential", "HIV"),
            ("hasta Leyla Kaya (TCKN: 66666666660), Alzheimer.", "health_data", "Alzheimer"),
        ):
            with self.subTest(word=word):
                result = analyze_privacy("probe.txt", text)
                start = text.index(word)
                end = start + len(word)

                covering = [
                    finding
                    for finding in self.of_category(result["risk_map"], category)
                    if finding["start"] <= start and finding["end"] >= end
                ]
                self.assertEqual(len(covering), 1, result["risk_map"])
                self.assertEqual(covering[0]["risk"], "CRITICAL")
                self.assertNotIn(word, result["redacted_preview"])

    def test_only_the_identifier_label_fragment_is_discarded(self):
        """"(TCKN:" is dropped; everything that carries a word is reported.

        The label fragment between the name cut and the national-id cut says
        nothing on its own and the identifier's own finding already covers it.
        Every other segment is kept, including the one-word place-name tail
        "), Kadıköy 2" -- see test_one_word_diagnosis_... for why that shape
        cannot be suppressed on form alone.

        The second medical segment reads "...Hastanesi'nde 22.09.2025" and used
        to read "...Hastanesi'nde 22". The old value was the sweep stopping
        halfway through a date, which is the defect _CONTEXT_SWEEP_CHAR's
        between-digits exception fixes, not a property this test protects: what
        it asserts is WHICH segments survive the cut, and that list is
        unchanged at four entries with "(TCKN:" still absent. No identifier
        moved into the sample either -- a date is not a direct identifier, and
        test_health_data_sample_keeps_no_patient_identifier still holds on the
        same fixture.
        """
        medical = [
            finding["sample"] for finding in self.of_category(self.findings("medical_case.txt", self.MEDICAL_TEXT), "health_data")
        ]
        self.assertEqual(
            medical,
            [
                "hasta",
                "), Özel Marmara Hastanesi'nde 22.09.2025",
                "cerrahi operasyon sonrası kalıcı sinir hasarı teşhisi konulduğunu,",
                "tedavi sürecinde ağır ihmal bulunduğunu iddia etmektedir",
            ],
        )

        privileged = [
            finding["sample"]
            for finding in self.of_category(self.findings("power_of_attorney.txt", self.PRIVILEGED_TEXT), "privileged_or_confidential")
        ]
        self.assertEqual(privileged, ["Müvekkil", "), Kadıköy 2"])
        self.assertNotIn("(TCKN:", privileged)


class RedactedPreviewClippingTests(unittest.TestCase):
    """A partially overlapping finding is clipped into the preview, not dropped.

    The preview is persisted in documents.privacy_profile, rendered in the
    Studio and served by the export route as "PRIVACY-REVIEWED REDACTED
    EXPORT", so a finding the selector drops leaves its uncovered remainder in
    that output as raw document text. Same rule and same reason as
    collect_replacements in legal_analyzer/docx_redactor.py.
    """

    def finding(self, category, risk, placeholder, start, end, action="Replace with consistent pseudonym"):
        return {
            "category": category,
            "sample": "",
            "risk": risk,
            "recommended_action": action,
            "placeholder": placeholder,
            "start": start,
            "end": end,
            "fingerprint": placeholder,
        }

    def test_tax_number_overlapping_an_over_matched_name_is_not_printed(self):
        """The name rule runs into the label; the tax number starts inside it.

        "Leyla Kaya Vergi" and "Vergi Kimlik No: 0983930103" share four
        characters and neither contains the other. Dropping the tax number
        printed its ten digits in full.
        """
        text = "nedeniyle soruşturma Leyla Kaya Vergi Kimlik No: 0983930103, ve - av."
        result = analyze_privacy("crossing.txt", text)
        preview = result["redacted_preview"]

        self.assertNotIn("0983930103", preview)
        self.assertNotIn("Kimlik No", preview)
        self.assertIn("[TAX_NUMBER_1]", preview)

        # Every character of the tax number's span is replaced, not just the
        # part the name did not already cover: no tail of that span, down to
        # four characters, survives anywhere in the preview. Shorter than four
        # would match the digit inside "[CRIMINAL_ALLEGATION_3_REDACTED]" and
        # test the placeholder vocabulary instead of the document text.
        tax = [f for f in result["risk_map"] if f["category"] == "tax_number"]
        self.assertEqual(len(tax), 1)
        start, end = tax[0]["start"], tax[0]["end"]
        checked = 0
        for offset in range(start, end - 3):
            checked += 1
            self.assertNotIn(text[offset:end], preview)
        self.assertGreater(checked, 20)

    def test_address_starting_inside_a_name_is_not_printed(self):
        """A name over-matching into a street name, with the address crossing it."""
        text = "Mustafa Demir Fatih Caddesi uzerinde gizli kapsaminda TCKN 80272136706 sorgulandi."
        result = analyze_privacy("crossing.txt", text)
        preview = result["redacted_preview"]

        for raw in ("Mustafa", "Demir", "Fatih", "Caddesi", "80272136706"):
            self.assertNotIn(raw, preview)
        self.assertIn("[PERSON_1]", preview)
        self.assertIn("[ADDRESS_1]", preview)

    def test_finding_wholly_inside_a_chosen_one_adds_no_placeholder(self):
        """Every character of it is already replaced, so it contributes nothing."""
        text = "0123456789 numaralı kişi hakkında işlem yapılmıştır ve dosya kapandı."
        findings = [
            self.finding("health_data", "CRITICAL", "[SENSITIVE_HEALTH_DATA_1]", 0, 40,
                         action="Flag for human legal review"),
            self.finding("turkish_national_id", "CRITICAL", "[NATIONAL_ID_1]", 10, 20),
        ]
        preview = build_redacted_preview(text, findings)

        self.assertEqual(preview.count("["), 1)
        self.assertIn("[SENSITIVE_HEALTH_DATA_1_REDACTED]", preview)
        self.assertNotIn("[NATIONAL_ID_1]", preview)

    def test_crossing_findings_each_get_one_placeholder_and_no_raw_remainder(self):
        """The clip emits the residual once, with no text doubled or dropped."""
        text = "AAAAABBBBBCCCCCDDDDD tail"
        findings = [
            self.finding("natural_person_name", "HIGH", "[PERSON_1]", 0, 10),
            self.finding("iban", "CRITICAL", "[IBAN_1]", 5, 20),
        ]
        preview = build_redacted_preview(text, findings)

        self.assertEqual(preview, "[PERSON_1][IBAN_1] tail")
        self.assertEqual(preview.count("[PERSON_1]"), 1)
        self.assertEqual(preview.count("[IBAN_1]"), 1)
        self.assertNotIn("CCCCC", preview)
        self.assertNotIn("BBBBB", preview)

    def test_address_tied_with_a_narrower_critical_is_not_printed(self):
        """A capitalised trigger word can also start a street name.

        health_data and address then begin at the same offset, the CRITICAL
        wins on risk, and its sweep stops at the first period -- so anything
        that treats a tied start as "one finding wins, the other contributes
        nothing" prints the rest of the address. address is a direct identifier
        and this text is served as the redacted export.
        """
        for text, critical_placeholder in (
            (
                "Sağlık Caddesi No: 5 Daire: 12. Kat Kadıköy İstanbul adresinde oturuyor",
                "[SENSITIVE_HEALTH_DATA_1_REDACTED]",
            ),
            (
                "teşhis, ticari sır\nCaddesi No: 5 Daire: 12. Kat Kadıköy "
                "(Müvekkil TR12 0006 4000 0011 2345 6789 01 ve (",
                "[PRIVILEGED_CONTENT_1_REDACTED]",
            ),
        ):
            with self.subTest(text=text[:30]):
                result = analyze_privacy("tied.txt", text)
                preview = result["redacted_preview"]

                address = [f for f in result["risk_map"] if f["category"] == "address"]
                self.assertEqual(len(address), 1, result["risk_map"])

                # Not one character of the address span survives, checked as
                # every tail of four characters or more.
                start, end = address[0]["start"], address[0]["end"]
                checked = 0
                for offset in range(start, end - 3):
                    checked += 1
                    self.assertNotIn(text[offset:end], preview)
                self.assertGreater(checked, 20)

                for raw in ("Kadıköy", "Caddesi", "Daire"):
                    self.assertNotIn(raw, preview)
                self.assertIn("[ADDRESS_1]", preview)
                self.assertIn(critical_placeholder, preview)

    def test_tied_start_critical_inside_a_wider_low_risk_span_is_replaced(self):
        """The other direction: the nested CRITICAL still wins the tie.

        This is the property RedactedPreviewSpanOrderingTests protects. The
        wider low-risk finding also gets a placeholder now, for the residual the
        CRITICAL does not cover, but it must not displace the CRITICAL.
        """
        text = "22222222220 numaralı kişi hakkında işlem yapılmıştır ve dosya kapandı."
        findings = [
            self.finding("party_role", "MEDIUM", "[PARTY_ROLE_1]", 0, 40,
                         action="Review party-role context for re-identification risk"),
            self.finding("turkish_national_id", "CRITICAL", "[NATIONAL_ID_1]", 0, 11,
                         action="Remove completely or replace with neutral placeholder"),
        ]
        preview = build_redacted_preview(text, findings)

        self.assertTrue(preview.startswith("[NATIONAL_ID_1]"), preview)
        self.assertNotIn("22222222220", preview)
        for offset in range(0, 11 - 3):
            self.assertNotIn(text[offset:11], preview)
        self.assertIn("[PARTY_ROLE_1]", preview)
        self.assertEqual(preview.count("[NATIONAL_ID_1]"), 1)
class LabelledIdentifierSpanTests(unittest.TestCase):
    """A labelled identifier's span must be exactly the text of its sample.

    The sample is the redaction target (redaction_targets_for_document in
    app.py), the key the PDF exporter maps to coordinate boxes and the string
    export QA searches the produced file for, while build_redacted_preview
    replaces the SPAN. turkish_national_id is the only rule whose sample is a
    capture group rather than the whole match, and its span used to be the whole
    match: sample "10000000146" over a span covering "T.C. Kimlik No:
    10000000146". The exporter removed the digits and the preview removed the
    labelled phrase, so the two disagreed about what had been taken out.

    test_every_fixture_finding_sample_is_its_own_span cannot catch this,
    although it asserts the same relation: no fixture and no gold document
    writes a labelled TCKN (measured: 0 labelled against 8 bare), so the shape
    that breaks the relation exists only in the cases below.
    """

    LABELLED_INPUTS = (
        ("T.C. Kimlik No: 10000000146", "turkish_national_id", "10000000146"),
        ("TC Kimlik No 10000000146", "turkish_national_id", "10000000146"),
        ("T.C.  10000000146", "turkish_national_id", "10000000146"),
        ("10000000146", "turkish_national_id", "10000000146"),
        # tax_number takes its sample from the whole match, label included, so
        # its span legitimately covers the label. Same relation, other side of
        # it: sample and span agree, and they agreed before this change too.
        ("Vergi Kimlik No: 0983930103", "tax_number", "Vergi Kimlik No: 0983930103"),
        ("VKN: 0983930103", "tax_number", "VKN: 0983930103"),
    )

    def only_finding(self, text: str) -> dict:
        """The one finding these inputs produce, asserted to be the only one.

        The preview assertion below is exact, which is only meaningful while
        nothing else in the text is replaced.
        """
        findings = analyze_privacy("kimlik.txt", text)["risk_map"]
        self.assertEqual(len(findings), 1, findings)
        return findings[0]

    def test_sample_is_exactly_the_text_at_its_own_span(self):
        for text, category, sample in self.LABELLED_INPUTS:
            with self.subTest(text=text):
                finding = self.only_finding(text)

                self.assertEqual(finding["category"], category)
                self.assertEqual(finding["sample"], sample)
                self.assertEqual(finding["sample"], text[finding["start"]:finding["end"]])

    def test_preview_replaces_exactly_the_redaction_target(self):
        """What the preview blanks is what the exporter removes, character for character."""
        for text, _category, sample in self.LABELLED_INPUTS:
            with self.subTest(text=text):
                result = analyze_privacy("kimlik.txt", text)
                finding = result["risk_map"][0]

                self.assertEqual(
                    result["redacted_preview"],
                    text.replace(sample, finding["placeholder"]),
                )

    def test_national_id_inside_a_swept_clause_is_still_the_digits_only(self):
        """The same relation where a context sweep runs across the identifier.

        health_data, criminal_allegation and privileged_or_confidential sweep a
        whole clause, and the identifier sits inside it. The identifier's own
        finding must still report the digits and nothing else, whatever the
        clause around it does.
        """
        for text in (
            "hasta Leyla Kaya T.C. Kimlik No: 10000000146 kanser",
            "şüpheli Kemal Arslan T.C. Kimlik No: 10000000146 dolandırıcılık",
            "müvekkil Cemile Doğan T.C. Kimlik No: 10000000146 stratejisi",
        ):
            with self.subTest(text=text):
                findings = analyze_privacy("dilekce.txt", text)["risk_map"]

                identifiers = [f for f in findings if f["category"] == "turkish_national_id"]
                self.assertEqual(len(identifiers), 1, findings)
                self.assertEqual(identifiers[0]["sample"], "10000000146")
                self.assertEqual(
                    identifiers[0]["sample"],
                    text[identifiers[0]["start"]:identifiers[0]["end"]],
                )

    def test_the_label_stays_visible_so_a_reader_sees_what_was_removed(self):
        text = "Davalı T.C. Kimlik No: 10000000146 beyanda bulundu"
        result = analyze_privacy("kimlik.txt", text)

        preview = result["redacted_preview"]
        self.assertIn("T.C. Kimlik No:", preview)
        self.assertIn("[NATIONAL_ID_1]", preview)
        self.assertNotIn("10000000146", preview)


class ContextSweepCaseFoldingIsExplicitTests(unittest.TestCase):
    """The sweep spells the i-family out instead of inheriting re.IGNORECASE.

    These assertions are STRUCTURAL on purpose, and it is worth saying why
    rather than leaving the next reader to wonder. No behavioural test can
    distinguish the two forms: the context rules already run under
    re.IGNORECASE, so a bare "Şti" in the lookbehind matches ŞTİ, ŞTI, şti and
    ştı today anyway. Collapsing _i_forms() to return its argument leaves the
    whole suite green -- verified -- which makes it an equivalent mutant
    behaviourally, in the same family as the min/max choice in
    _enclosing_span_end and the clip offset in build_redacted_preview.

    What the expansion buys is the removal of a dependency, which is a
    structural property and has to be asserted structurally. docx_redactor.py
    states the house rule: Python relating 'I' to 'ı' is "an undocumented
    implementation detail: nothing in the re documentation promises" it, so
    TURKISH_I_FORMS is enumerated by hand. If that folding ever narrows, or if
    someone scopes IGNORECASE off these rules, an inherited "Şti" stops being
    crossed and the clause after "ŞTİ." silently loses its CRITICAL finding.
    An explicit character class cannot regress that way, and this test fails if
    anyone puts the inheritance back.
    """

    def test_every_i_family_letter_is_expanded_to_the_whole_family(self):
        expanded = _i_forms("Şti")
        for form in TURKISH_I_FORMS:
            self.assertIn(form, expanded, f"{form!r} missing from {expanded!r}")

    def test_the_compiled_sweep_carries_the_expansion_not_an_inline_flag(self):
        self.assertIn(_i_forms("Şti"), _CONTEXT_SWEEP_CHAR)
        # (?i: is what the expansion replaces; (?-i: on the single-capital
        # class is a different thing and must stay.
        self.assertNotIn("(?i:", _CONTEXT_SWEEP_CHAR)
        self.assertIn("(?-i:", _CONTEXT_SWEEP_CHAR)

    def test_expansion_covers_both_cases_of_every_other_letter(self):
        for abbreviation in _CONTEXT_SWEEP_ABBREVIATIONS:
            expanded = _i_forms(abbreviation)
            with self.subTest(abbreviation=abbreviation):
                for char in abbreviation:
                    self.assertIn(char.upper(), expanded)
                    self.assertIn(char.lower(), expanded)


class ContextSweepNonSentencePeriodTests(unittest.TestCase):
    """The context sweep crosses a period that does not end a sentence.

    health_data, criminal_allegation and privileged_or_confidential match a
    trigger word plus a trailing sweep, and that sweep stops at a period. A
    period that ends an abbreviation or sits inside a date is not a sentence
    boundary, so stopping there ended the span mid-clause and left the
    sensitive part -- the diagnosis, the allegation, the confidential dealing
    -- with no CRITICAL finding at all. A span with no finding cannot be
    approved by a reviewer and is therefore unredactable on export by
    construction, which is the failure these tests exist to prevent.

    Three properties, one test each:
      * the clause after such a period is covered, asserted on SPANS because
        the span is what a reviewer approves and what the exporter redacts;
      * a period that really does end a sentence still stops the sweep;
      * widening the span still stores and prints no direct identifier.
    """

    # One private-use codepoint per source offset, so the preview can be
    # rebuilt over a string in which every position is distinguishable.
    _PROBE_BASE = 0xE000

    def findings(self, text):
        return analyze_privacy("sweep_probe.txt", text)["risk_map"]

    def of_category(self, findings, category):
        return [finding for finding in findings if finding["category"] == category]

    def covering(self, findings, category, clause_start, clause_end):
        return [
            finding
            for finding in self.of_category(findings, category)
            if finding["start"] <= clause_start and finding["end"] >= clause_end
        ]

    def surviving_offsets(self, text, findings):
        """Source offsets that reach the preview as raw document text.

        Position-based on purpose. Searching the preview for a sample string
        both over- and under-counts: a placeholder can contain the substring
        being looked for, and an identifier can be printed in a form the
        sample does not spell.
        """
        probe = "".join(chr(self._PROBE_BASE + index) for index in range(len(text)))
        rendered = build_redacted_preview(probe, findings, max_chars=10**9)
        return {
            ord(char) - self._PROBE_BASE
            for char in rendered
            if self._PROBE_BASE <= ord(char) < self._PROBE_BASE + len(text)
        }

    # Each clause is deliberately free of its own rule's trigger words, so the
    # only way a finding of that category can cover it is by sweeping across
    # the period. A clause containing a trigger would be covered by a finding
    # anchored on the trigger itself and would assert nothing.
    REACHES = (
        ("date between digits", "health_data",
         "hasta 22.09.2025 tarihinde kanser tanısı aldı", "kanser tanısı aldı"),
        # "Müvekkil:" with a colon, not a bare "Müvekkil". company_name's body
        # class cannot cross a colon, so the company span is exactly
        # "Yıldız Ltd. Şti." and the trigger word stays outside it. Without the
        # colon the company match starts at "Müvekkil", the whole leading
        # segment is cut away by _cut_identifiers_from_context_findings, and
        # the "starts before the period" assertion below has nothing left to
        # find -- which is a property of where the identifier begins, not of
        # whether the sweep crossed the period.
        #
        # The bare form only ever passed because company_name missed a
        # title-case suffix: at b334956 the same sentence written
        # "Müvekkil Yıldız LTD. ŞTİ." already produced company_name 0..25 and
        # failed this assertion. The row was resting on that defect.
        ("Ltd. Şti.", "privileged_or_confidential",
         "Müvekkil: Yıldız Ltd. Şti. ile görüşme tutanağı düzenlendi",
         "görüşme tutanağı düzenlendi"),
        ("vb.", "health_data",
         "hasta vb. yakınmalarla kanser tanısı aldı", "kanser tanısı aldı"),
        ("Dr. title", "health_data",
         "hasta Dr. Ayşe Yurt gözetiminde kanser tanısı aldı", "kanser tanısı aldı"),
        ("Av. title", "criminal_allegation",
         "cezai konuda Av. Mehmet Demir dolandırıcılık iddiası öne sürüldü",
         "dolandırıcılık iddiası öne sürüldü"),
        # Keep the trigger adjacent: the address-boundary regression used to
        # need padding here to hide the address prefix swallowing "hasta".
        ("Sok. address word", "health_data",
         "hasta Gül Sok. 5 numarada kanser tanısı aldı",
         "kanser tanısı aldı"),
        # The remaining entries of _CONTEXT_SWEEP_ABBREVIATIONS, one literal
        # sentence each. They are spelled out rather than generated from the
        # constant on purpose: a fixture built from the same tuple the sweep is
        # built from moves with it, so replacing an entry replaces it on both
        # sides and the case can never fail. See
        # test_every_listed_abbreviation_is_crossed for what that generated
        # form can and cannot show.
        ("vs.", "health_data",
         "hasta olan kişi belge vs. eklerle kanser tanısı aldı",
         "kanser tanısı aldı"),
        ("Prof. title", "health_data",
         "hasta olan kişi Prof. Ayşe Yurt gözetiminde kanser tanısı aldı",
         "kanser tanısı aldı"),
        ("Doç. title", "health_data",
         "hasta olan kişi Doç. Ayşe Yurt gözetiminde kanser tanısı aldı",
         "kanser tanısı aldı"),
        ("Cad. address word", "health_data",
         "hasta Bağdat Cad. 41 numarada kanser tanısı aldı",
         "kanser tanısı aldı"),
        ("Mah. address word", "health_data",
         "hasta Fener Mah. 3 numarada kanser tanısı aldı",
         "kanser tanısı aldı"),
        ("Apt. address word", "health_data",
         "hasta Yıldız Apt. 4 numarada kanser tanısı aldı",
         "kanser tanısı aldı"),
        ("bkz.", "health_data",
         "hasta olan kişi bkz. ekli raporda kanser tanısı aldı",
         "kanser tanısı aldı"),
        # The cedilla-free twin of the "Ltd. Şti." row above. Turkish is
        # routinely typed without diacritics, and _i_forms() deliberately does
        # NOT relate 'Ş' to 'S' -- the company suffixes spell that fold out by
        # hand as _S_FORMS for exactly this reason. Without a "Sti" entry the
        # sweep stops at the period this row's clause sits behind, and the
        # allegation after it carries no finding at all: nothing a reviewer can
        # approve, so nothing the exporter will redact.
        ("Ltd. Sti. without the cedilla", "privileged_or_confidential",
         "Müvekkil: Yıldız Ltd. Sti. ile görüşme tutanağı düzenlendi",
         "görüşme tutanağı düzenlendi"),
    )

    def test_the_clause_after_a_non_sentence_period_gets_a_critical_finding(self):
        for label, category, text, clause in self.REACHES:
            with self.subTest(shape=label):
                findings = self.findings(text)
                start = text.index(clause)
                covering = self.covering(findings, category, start, start + len(clause))

                self.assertTrue(covering, self.of_category(findings, category))
                for finding in covering:
                    self.assertEqual(finding["risk"], "CRITICAL")
                # ... and this category's coverage spans ACROSS the period,
                # rather than being a fresh match that happens to start after
                # it: something of this category also begins before the
                # period. Asserted on the category's whole finding set, not on
                # the covering finding alone, because an identifier between the
                # trigger and the clause makes
                # _cut_identifiers_from_context_findings split the one match
                # into a leading segment before the period and the covering
                # segment after it.
                self.assertLess(
                    min(f["start"] for f in self.of_category(findings, category)),
                    text.index("."),
                )

    # The same shape with a period that really does end a sentence. Anchored on
    # "tutanağı"/"onaylı" -- ordinary words, not identifiers. A name in the next
    # sentence would be cut out of the context span by
    # _cut_identifiers_from_context_findings whatever the sweep did, so an
    # assertion anchored on one passes even when the sweep runs straight past
    # the boundary, and proves nothing.
    STOPS = (
        ("date shape", "health_data",
         "hasta 22.09.2025 tarihinde iyileşti. Duruşma tutanağı düzenlendi", "tutanağı"),
        ("ordinal institution", "privileged_or_confidential",
         "Müvekkil Kadıköy 2. Noterliği onaylı örneği ile", "onaylı"),
        ("Ltd. Şti. shape", "privileged_or_confidential",
         "Müvekkil Yıldız Ltd. Şti. ile görüşüldü. Duruşma tutanağı düzenlendi", "tutanağı"),
        ("vb. shape", "health_data",
         "hasta vb. yakınmalarla iyileşti. Duruşma tutanağı düzenlendi", "tutanağı"),
        ("Dr. title shape", "health_data",
         "hasta Dr. Ayşe Yurt gözetiminde iyileşti. Duruşma tutanağı düzenlendi", "tutanağı"),
        ("Sok. address word shape", "health_data",
         "hasta olan kişi Gül Sok. 5 numarada iyileşti. Duruşma tutanağı düzenlendi",
         "tutanağı"),
    )

    def test_a_real_sentence_boundary_in_the_same_shape_still_stops_the_sweep(self):
        for label, category, text, anchor in self.STOPS:
            with self.subTest(shape=label):
                findings = self.findings(text)
                start = text.index(anchor)
                # The rule fires at all -- otherwise this asserts nothing.
                self.assertTrue(self.of_category(findings, category), findings)
                self.assertEqual(
                    self.covering(findings, category, start, start + len(anchor)),
                    [],
                    self.of_category(findings, category),
                )

    def test_english_sti_sentence_end_is_crossed_as_an_accepted_cost(self):
        """Pins what the "Sti" entry COSTS, not what it buys.

        "STI." ends English sentences -- sexually transmitted infection -- and
        it does so in the documents health_data runs on, whose triggers include
        the English "medical" and "patient". So unlike every other entry in
        _CONTEXT_SWEEP_ABBREVIATIONS, this one crosses at a boundary that is
        ordinary prose rather than a typographic coincidence.

        That trade is recorded in the comment on the tuple and accepted there:
        the buy is a Turkish company form written the way Turkish is actually
        typed, the cost runs the safe way (a CRITICAL health span reaching too
        far is over-redaction, not a leak), and the precondition is narrow.

        This test exists so the cost is OBSERVED. It fails if "Sti" is dropped,
        which is correct: dropping it changes the trade, and that should be a
        deliberate edit with this docstring read, not a silent one. It is not
        asserting desired behaviour -- if a future change makes the sweep stop
        here without losing the Turkish crossing, delete this test and say so.
        """
        text = "The medical record notes a prior STI. Kadikoy 2. Noterligi onayli ornegi"
        findings = self.findings(text)
        authority = text.index("Kadikoy")

        covering = self.covering(findings, "health_data", authority, authority + len("Kadikoy"))
        self.assertTrue(
            covering,
            "the accepted cost no longer reproduces; re-read the tuple comment "
            f"before changing it: {self.of_category(findings, 'health_data')}",
        )
        # The half that would make this a leak rather than a cost: whatever the
        # span reaches over, it must still not STORE a direct identifier.
        for finding in covering:
            self.assertNotIn("Noterligi", finding["sample"])

    def test_every_listed_abbreviation_is_crossed(self):
        """One subTest per entry in _CONTEXT_SWEEP_ABBREVIATIONS.

        This checks the MECHANISM, not the membership: it builds each probe
        from the same tuple the sweep is built from, so an entry swapped for
        another string is swapped on both sides and the case still passes. What
        it does catch is an entry the construction cannot turn into a working
        lookbehind -- a regex metacharacter, a casing Python's re does not fold
        the way Turkish needs -- and, via the length check at the end, an entry
        quietly dropped. Which abbreviations are actually in the list is pinned
        by the literal sentences in REACHES, one per entry.

        "hasta olan kişi", not "hasta", for the reason given on the Sok. row:
        the address rule's leading-capital prefix runs under IGNORECASE and
        eats two preceding lowercase words. Nothing after the abbreviation is
        capitalised, so no name rule fires and the span is not cut.
        """
        clause = "kanser tanısı aldı"
        for abbreviation in _CONTEXT_SWEEP_ABBREVIATIONS:
            with self.subTest(abbreviation=abbreviation):
                text = f"hasta olan kişi gül {abbreviation}. beş numarada {clause}"
                findings = self.findings(text)
                start = text.index(clause)
                covering = self.covering(
                    findings, "health_data", start, start + len(clause)
                )

                self.assertTrue(covering, self.of_category(findings, "health_data"))
                for finding in covering:
                    self.assertEqual(finding["risk"], "CRITICAL")
                self.assertLess(
                    min(f["start"] for f in self.of_category(findings, "health_data")),
                    text.index("."),
                )

        # Last, not first, so that breaking an entry reports as that entry's
        # subTest rather than being masked by a length check that fires before
        # the loop runs. This one catches the other failure mode: an entry
        # deleted outright is simply not iterated, so no subTest can miss it.
        self.assertGreaterEqual(len(_CONTEXT_SWEEP_ABBREVIATIONS), 14)

    LEAK_PROBES = (
        ("date between digits",
         "hasta Leyla Kaya (TCKN: 66666666660) 22.09.2025 tarihinde kanser tanısı aldı"),
        ("Ltd. Şti.",
         "Müvekkil Cemile Doğan (TCKN: 11111111110) Yıldız Ltd. Şti. ile "
         "görüşme tutanağı düzenlendi"),
        ("vb.",
         "hasta Ayşe Yurt vb. yakınmalarla kanser tanısı aldı, e-posta ayse@ornek.com"),
        ("Av. title",
         "cezai konuda Av. Mehmet Demir 0532 111 22 33 numarasından "
         "dolandırıcılık iddiası öne sürüldü"),
        # The last two carry a PARTIAL overlap between two identifiers: the
        # name rule over-matches into the label ("Leyla Kaya Vergi") and
        # tax_number starts inside it, so neither contains the other. Without
        # them the raw-output half of this test asserts nothing -- every other
        # probe here has only nested or disjoint spans, and the preview
        # selector's clip-vs-drop choice cannot show up.
        ("date between digits over a crossing identifier pair",
         "hasta Leyla Kaya Vergi Kimlik No: 0983930103 22.09.2025 tarihinde "
         "kanser tanısı aldı"),
        ("Ltd. Şti. over a crossing identifier pair",
         "Müvekkil Cemile Doğan Vergi Kimlik No: 0983930103 Yıldız Ltd. Şti. "
         "ile görüşme tutanağı düzenlendi"),
    )

    def test_the_wider_spans_store_and_print_no_direct_identifier(self):
        for label, text in self.LEAK_PROBES:
            with self.subTest(shape=label):
                findings = self.findings(text)
                identifiers = [
                    f for f in findings if f["category"] in DIRECT_IDENTIFIER_CATEGORIES
                ]
                context = [
                    f for f in findings if f["category"] in CONTEXT_SWEEP_CATEGORIES
                ]
                self.assertTrue(identifiers, findings)
                self.assertTrue(context, findings)

                alive = self.surviving_offsets(text, findings)
                for finding in identifiers:
                    leaked = sorted(
                        offset
                        for offset in range(finding["start"], finding["end"])
                        if offset in alive
                    )
                    self.assertEqual(
                        leaked, [], f"{finding['category']} raw at {leaked}: {text!r}"
                    )

                for clause in context:
                    for finding in identifiers:
                        self.assertGreaterEqual(
                            max(clause["start"], finding["start"]),
                            min(clause["end"], finding["end"]),
                            f"{clause['category']} span holds {finding['category']}",
                        )


class CompanyNameSuffixCaseTests(unittest.TestCase):
    """company_name must match a legal-form suffix in any case, not only shouted.

    company_name was the one rule that overrode the DetectionRule default and
    dropped re.IGNORECASE, and every suffix in its alternation was spelled in
    capitals. Only the shouted forms matched. "Yıldız Anonim Şirketi" -- the
    ordinary Turkish title-case spelling -- produced no company_name finding at
    all.

    That is a missed DIRECT IDENTIFIER, not a missed label. company_name is in
    DIRECT_IDENTIFIER_CATEGORIES, so has_direct_identifiers() stayed False and
    the external-LLM gate lost one of its six arms on a document that names a
    party. test_a_titlecase_company_alone_keeps_the_external_llm_gate_shut is
    the case that asserts the gate consequence rather than the label.

    The gold corpus cannot see any of this: six of its seven company_name
    labels are all-caps and the seventh ("Verdi Faktoring A.Ş.") matched only
    because its SUFFIX was uppercase. Recall and precision are unchanged by the
    fix, which is corpus blindness, not absence of effect.
    """

    def companies(self, text):
        return [
            finding
            for finding in analyze_privacy("sozlesme.txt", text)["risk_map"]
            if finding["category"] == "company_name"
        ]

    # A carrier sentence with no identifier of its own: no title, no party-role
    # word, no number. Whatever fires here fired because of the company name.
    # "Alacaklı X Ltd. Şti." would prove less -- party_role and the person-name
    # rules answer to that anchor and would cover the span for their own
    # reasons.
    CARRIER = "Sozlesme {} tarafindan imzalandi."

    # Every spelling the rule used to miss. Each is a real filing spelling, not
    # a permutation for its own sake: title case is how Turkish prose writes a
    # company, and the diacritic-free twins are how it gets typed on a keyboard
    # that has no ş.
    MISSED_BEFORE_THE_FIX = (
        "Yıldız Ltd. Şti.",
        "Yıldız Ltd.",
        "Yıldız Holding Ltd. Şti.",
        "Yıldız Anonim Şirketi",
        "Yildiz Inc.",
        "Acme llc",
        # Diacritic-free "Sti" for "Şti", in title case. Two separate gaps meet
        # here and it is worth keeping them apart, because only one of them
        # cost a gate arm:
        #
        #   * TITLE CASE "Ltd. Sti." was missed outright at b334956 --
        #     has_direct_identifiers() False, gate arm lost. That is the case
        #     gap this class is about.
        #   * ALL-CAPS "LTD. STI." was NOT missed. It matched the bare LTD
        #     alternative and was TRUNCATED to 'Sozlesme YILDIZ LTD.', leaving
        #     " STI." outside the span. The company name itself was inside the
        #     span, so has_direct_identifiers() was True and no arm was lost.
        #     The fix widens that span; it does not restore a lost arm there.
        #
        # The truncation is the diacritic gap: the old alternation spelled the
        # s of ŞTİ only with its cedilla, and re.IGNORECASE would not have
        # fixed it either, since the flag relates case and never 'Ş' to 'S'.
        "Yildiz Ltd. Sti.",
        "Yildiz Limited Sirketi",
        # Lower-case dotted A.Ş.
        "Verdi Faktoring a.ş.",
        # Bare English suffixes in title case. These must survive the uppercase
        # initial that PROSE_PROBES forces onto the word-shaped suffixes.
        "Acme Holdings Limited",
        "Yıldız Limited",
    )

    # Spellings that already worked. Kept so the fix cannot be a swap of one
    # blind spot for another.
    MATCHED_BEFORE_THE_FIX = (
        "Yıldız LTD. ŞTİ.",
        "Yıldız ANONİM ŞİRKETİ",
        "Yıldız A.Ş.",
        "Yildiz INC.",
        "Acme LLC",
        "Acme PLC",
        "YILDIZ LIMITED SIRKETI",
        "YILDIZ ANONIM SIRKETI",
        "YILDIZ AŞ",
    )

    # Ordinary prose that must NOT produce a company name. Every one of these
    # is clean at b334956, and every one was flagged when the word-shaped
    # suffixes were folded all the way down to their lowercase spellings:
    # 0/11 before, 11/11 after, measured. company_name is a DIRECT identifier,
    # so each match asserts an identifier is present where there is none and
    # hands the exporter "Damages are limited" as a redaction target.
    #
    # English matters here as much as Turkish: this engine runs on English
    # documents by design, and "limited" is ordinary English legal vocabulary.
    PROSE_PROBES = (
        "The Company has limited liability under this agreement",
        "Access to the premises is limited to business hours",
        "Damages are limited by the terms herein",
        "Liability is limited to the fees paid",
        "The parties agree that recovery is limited",
        "This warranty is limited in scope",
        "Payment terms are limited to thirty days",
        "Coverage is limited under section four",
        "Sorumluluk limited tutulmustur",
        "Yetki limited sirket sozlesmesinde belirlenmistir",
        "Değerlendirme inc. edilmiştir",
        # These two exist because review measured that without them the
        # uppercase-initial constraint on LTD and PLC is UNGUARDED: folding
        # either initial survives the entire suite, while measurably producing
        # false positives. "plc" is ordinary vocabulary in the technical
        # annexes attached to commercial filings -- a programmable logic
        # controller -- and lowercase "ltd" appears as a bare token in Turkish
        # registry prose. Neither is a dictionary word, which is why the
        # criterion is phrased on lowercase TOKENS rather than on words.
        "Belge ltd olarak kaydedildi",
        "Bu bir ltd konusudur",
        "The device uses a plc module",
        "Programmable logic plc controllers were installed",
    )

    # The same criterion catches these: a generic reference to the company FORM
    # is not a named company. Fully folded, the two-word Turkish suffixes made
    # "the parties founded a joint-stock company" a direct-identifier finding.
    GENERIC_COMPANY_FORM_PROBES = (
        "Taraflar bir anonim şirketi kurmuştur",
        "Sozlesme bir limited sirketi kurulmasini ongormektedir",
    )

    def test_lower_and_title_case_suffixes_are_detected(self):
        for company in self.MISSED_BEFORE_THE_FIX:
            with self.subTest(company=company):
                text = self.CARRIER.format(company)
                found = self.companies(text)
                self.assertTrue(found, f"no company_name finding in {text!r}")
                # Assert the span reaches the END of the suffix, not merely
                # that something matched. "Yildiz Ltd. Sti." used to match as
                # far as "Ltd." and stop, leaving " Sti." outside the finding
                # and therefore outside anything a reviewer can approve.
                self.assertTrue(
                    any(company in finding["sample"] for finding in found),
                    [finding["sample"] for finding in found],
                )

    def test_uppercase_suffixes_are_still_detected(self):
        for company in self.MATCHED_BEFORE_THE_FIX:
            with self.subTest(company=company):
                text = self.CARRIER.format(company)
                found = self.companies(text)
                self.assertTrue(found, f"no company_name finding in {text!r}")
                self.assertTrue(
                    any(company in finding["sample"] for finding in found),
                    [finding["sample"] for finding in found],
                )

    def test_a_match_cannot_begin_on_a_lowercase_letter(self):
        """The leading [A-ZÇĞİÖŞÜ] class stays case-sensitive.

        This is the trap in the obvious fix. Adding re.IGNORECASE to the rule
        folds the leading class too, and a match may then start mid-word on a
        lowercase letter -- so an all-lowercase sentence yields a "company"
        that is really a fragment of running text. The suffixes carry their own
        case classes precisely so the flag never has to be added.
        """
        for text in (
            "davali yildiz ltd. sti. adresinde bulunmaktadir",
            "taraflar arasinda anonim sirketi kurulmasi kararlastirildi",
            "sozlesme yildiz limited sirketi tarafindan imzalandi",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.companies(text), [])

    def test_a_titlecase_company_alone_keeps_the_external_llm_gate_shut(self):
        """The gate consequence, asserted on the gate and not on the label.

        Everything else in this document is neutral, so company_name is the
        only direct identifier present. Before the fix this text produced no
        direct identifier at all and this arm of the gate went quiet.
        """
        text = "Sozlesme Yıldız Anonim Şirketi tarafindan imzalandi."
        profile = analyze_privacy("sozlesme.txt", text)
        findings = profile["risk_map"]

        identifiers = [
            finding
            for finding in findings
            if finding["category"] in DIRECT_IDENTIFIER_CATEGORIES
        ]
        self.assertEqual(
            {finding["category"] for finding in identifiers}, {"company_name"}, findings
        )
        self.assertTrue(has_direct_identifiers(findings))

        # ... and the gate stays shut even with redaction and review signed
        # off, on the direct-identifier condition specifically.
        refreshed = refresh_release_state(
            profile, redaction_completed=True, human_review_approved=True
        )
        self.assertFalse(refreshed["external_llm_gate"]["allowed"])
        self.assertEqual(
            refreshed["external_llm_readiness"],
            "Blocked until redaction is completed and reviewed",
        )
        # The condition, not just the verdict. Residual risk also lands on Medium
        # for this document, so asserting only "not allowed" would still pass
        # with the direct-identifier arm dead -- which is the arm this is about.
        self.assertIn(
            "No direct identifiers may remain in detected findings.",
            refreshed["external_llm_gate"]["failed_conditions"],
        )

    def test_ordinary_prose_is_not_a_company_name(self):
        """The word-shaped suffixes keep an uppercase initial, and must.

        "limited" is ordinary English legal vocabulary and this engine reads
        English documents. Folded to its lowercase spelling the bare LIMITED
        alternative matched eight plain English clauses and three Turkish ones,
        none of which names a company. company_name is a direct identifier, so
        those are HIGH findings claiming an identifier that is not there.

        Asserted on the whole prose set rather than one clause, because a
        single probe would leave the other suffixes free to regress.
        """
        for text in self.PROSE_PROBES + self.GENERIC_COMPANY_FORM_PROBES:
            with self.subTest(text=text):
                self.assertEqual(
                    [finding["sample"] for finding in self.companies(text)], []
                )

    def test_the_measured_false_positive_shapes_stay_unmatched(self):
        """Two more alternatives are deliberately narrower than the rest.

        Same criterion as test_ordinary_prose_is_not_a_company_name, applied to
        the two forms whose lowercase spelling collides with a Turkish word or
        a Turkish court convention. Both were measured, not guessed. Folding
        bare "AŞ" to [Aa][Şş] makes it match the ordinary word "aş", and adding
        a diacritic-free "A.S." twin makes it match the initials Turkish courts
        anonymise parties to. Widening either buys nothing the dotted "A.Ş."
        form does not already cover and costs false positives on plain prose.
        """
        for text in (
            "Belediye aş evi işletmektedir.",
            "Kurum aş dağıtımı yapmaktadır.",
            "Davacı sıcak aş talebinde bulundu.",
            "Müşteki A.S. beyanında bulunmuştur.",
            "Sanık M.Y. ve tanık A.S. dinlenmiştir.",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    [finding["sample"] for finding in self.companies(text)], []
                )

    # The next two cases are STRUCTURAL, in the spirit of
    # ContextSweepCaseFoldingIsExplicitTests -- but with one important
    # difference from that class, and an earlier revision of this comment got
    # it backwards, so it is worth stating plainly.
    #
    # The obvious alternative -- flags=re.UNICODE|re.IGNORECASE with (?-i:)
    # scoped onto the leading class and plain uppercase suffixes -- is NOT an
    # equivalent mutant here. Built and run by two people independently: it
    # reds three test methods and 17 subtests. (An earlier note in this file
    # said four cases and 26 subtests; that count did not reproduce, and a
    # figure a maintainer cannot reproduce is worse than no figure.)
    # IGNORECASE folds things that sit in no scope, namely the bare "AŞ"
    # literal and the uppercase INITIAL of every word-shaped suffix, so it
    # reintroduces both measured false-positive families at once: "Belediye aş
    # evi işletmektedir." and "Damages are limited by the terms herein" both
    # become company names. test_ordinary_prose_is_not_a_company_name and
    # test_the_measured_false_positive_shapes_stay_unmatched are the
    # behavioural guards against it.
    #
    # So do NOT read these two structural cases as "the only thing standing
    # between us and the IGNORECASE form". They cover what behaviour cannot:
    # the flags check names the cause directly instead of leaving the next
    # reader to infer it from an "aş" failure, and the drift check catches a
    # rule that stops reading _COMPANY_SUFFIXES at all.
    #
    # What the per-character expansion buys is the removal of a dependency.
    # docx_redactor.py states the house rule: that folding is "an undocumented
    # implementation detail: nothing in the re documentation promises" it. If
    # it ever narrows, "Ltd. Şti." stops matching, company_name goes quiet, and
    # the gate loses a direct identifier -- the exact bug this class exists for.

    def test_the_rule_runs_without_ignorecase(self):
        rule = self.company_rule()
        self.assertFalse(rule.flags & re.IGNORECASE)
        self.assertNotIn("(?i:", rule.pattern)

    def test_every_suffix_reaches_the_compiled_pattern(self):
        """The constant and the rule cannot drift apart.

        Behaviourally invisible: a rule that inlined the same alternation as a
        literal would match identically, and _COMPANY_SUFFIXES would then be a
        constant nothing reads, edited in good faith with no effect on
        detection. Only a structural case sees that.
        """
        pattern = self.company_rule().pattern
        for suffix in _COMPANY_SUFFIXES:
            with self.subTest(suffix=suffix):
                self.assertIn(suffix, pattern)

    def test_only_a_suffix_initial_may_sit_outside_a_case_class(self):
        """Every letter AFTER the first spells both of its cases itself.

        The wording of this case changed with the uppercase-initial fix, and
        the change is deliberate rather than an accommodation. A suffix's
        INITIAL is allowed to be a bare uppercase letter, and for the
        word-shaped suffixes it must be: that is what keeps "limited" from
        matching ordinary English prose, measured in
        test_ordinary_prose_is_not_a_company_name.

        Every letter after the initial must still sit in a class. One left
        outside matches a single case, which is the defect this class exists
        for, and no behavioural case here would necessarily probe that
        particular alternative.

        Escapes are stripped first, or the 's' of "\\s*" reads as a bare letter.
        """
        for suffix in _COMPANY_SUFFIXES:
            with self.subTest(suffix=suffix):
                if suffix == "AŞ":
                    # The one suffix that is bare all through, and it is
                    # ASSERTED rather than skipped so it cannot quietly grow.
                    # test_the_measured_false_positive_shapes_stay_unmatched
                    # holds the measurement: folded, this matches the ordinary
                    # Turkish word "aş".
                    self.assertEqual(
                        re.findall(r"[A-Za-zÇĞİÖŞÜçğıöşü]", suffix), ["A", "Ş"]
                    )
                    continue

                without_escapes = re.sub(r"\\.", "", suffix)
                outside_a_class = re.findall(
                    r"[A-Za-zÇĞİÖŞÜçğıöşü]", re.sub(r"\[[^\]]*\]", "", without_escapes)
                )
                self.assertLessEqual(
                    len(outside_a_class),
                    1,
                    f"{suffix!r} spells {outside_a_class} in one case only",
                )
                if outside_a_class:
                    # The one bare letter must be the INITIAL, and uppercase.
                    # A bare letter anywhere else, or a lowercase one, would
                    # narrow the alternative to a spelling nobody uses.
                    self.assertEqual(outside_a_class[0], suffix[0], suffix)
                    self.assertEqual(
                        outside_a_class[0], outside_a_class[0].upper(), suffix
                    )

    def company_rule(self):
        rules = [rule for rule in DETECTION_RULES if rule.category == "company_name"]
        self.assertEqual(len(rules), 1, rules)
        return rules[0]

    # One private-use codepoint per source offset, so the preview can be
    # rebuilt over a string in which every position is distinguishable. Same
    # method and same reasoning as ContextSweepNonSentencePeriodTests: a
    # substring search over the preview both over- and under-counts.
    _PROBE_BASE = 0xE000

    def surviving_offsets(self, text, findings):
        probe = "".join(chr(self._PROBE_BASE + index) for index in range(len(text)))
        rendered = build_redacted_preview(probe, findings, max_chars=10**9)
        return {
            ord(char) - self._PROBE_BASE
            for char in rendered
            if self._PROBE_BASE <= ord(char) < self._PROBE_BASE + len(text)
        }

    def test_a_newly_detected_company_leaks_no_identifier_into_the_preview(self):
        """Detecting more must not make anything render raw or land in another
        category's stored sample.

        A new finding changes which spans overlap, and the preview's
        clip-vs-drop selector resolves overlaps. Each probe puts the company
        next to an identifier of another category and inside a context sweep,
        which is where that resolution can go wrong.
        """
        for label, text in self.LEAK_PROBES:
            with self.subTest(shape=label):
                findings = analyze_privacy("sozlesme.txt", text)["risk_map"]
                identifiers = [
                    f for f in findings if f["category"] in DIRECT_IDENTIFIER_CATEGORIES
                ]
                self.assertTrue(
                    any(f["category"] == "company_name" for f in identifiers), findings
                )

                alive = self.surviving_offsets(text, findings)
                for finding in identifiers:
                    leaked = sorted(
                        offset
                        for offset in range(finding["start"], finding["end"])
                        if offset in alive
                    )
                    self.assertEqual(
                        leaked, [], f"{finding['category']} raw at {leaked}: {text!r}"
                    )

    LEAK_PROBES = (
        ("title-case company inside a confidentiality sweep",
         "Müvekkil: Yıldız Ltd. Şti. ile görüşme tutanağı düzenlendi"),
        ("title-case company beside a tax number",
         "Sozlesme Yıldız Anonim Şirketi Vergi Kimlik No: 0983930103 ile imzalandi"),
        ("lower-case suffix beside an email address",
         "Sozlesme Acme llc ve iletisim adresi hukuk@acme.com olarak bildirildi"),
        ("diacritic-free company inside a criminal-allegation sweep",
         "Cezai konuda Yildiz Ltd. Sti. hakkinda dolandiricilik iddiasi one suruldu"),
    )

    # The last probe above is excluded here, and the exclusion is stated rather
    # than quietly dropped. In it the context sweep stops at the period of the
    # diacritic-free "Sti.", because _CONTEXT_SWEEP_ABBREVIATIONS spells that
    # abbreviation only with its cedilla, so criminal_allegation ends one
    # character short of the company span. The two spans then overlap
    # PARTIALLY, and _cut_identifiers_from_context_findings only removes an
    # identifier that a context span contains.
    #
    # That is pre-existing and not something the company_name fix caused. At
    # b334956 the same sentence produced criminal_allegation 0..28 with the
    # sample 'Cezai konuda Yildiz Ltd. Sti' and NO company_name finding at all
    # -- the identifier sat in that sample with nothing to redact it. After the
    # fix the sample is byte-identical and the identifier additionally has its
    # own finding, so the direction of travel is strictly better. The remaining
    # overlap belongs to the context sweep, not here; it is reported as a
    # finding instead of being fixed under a company_name assignment.
    # Each of these puts a newly-detected company INSIDE a context sweep, so
    # the cut has to split the context finding in two around it. A probe where
    # the two spans are disjoint for unrelated reasons would assert nothing.
    CUT_PROBES = (
        ("title-case Ltd. Şti. inside a confidentiality sweep",
         "Müvekkil: Yıldız Ltd. Şti. ile görüşme tutanağı düzenlendi"),
        ("lower-case llc inside a criminal-allegation sweep",
         "Cezai konuda: Acme llc hakkinda dolandiricilik iddiasi one suruldu"),
        ("diacritic-free Limited Sirketi inside a health-data sweep",
         "hasta olan kişi Yildiz Limited Sirketi nezdinde kanser tanısı aldı"),
    )

    def test_a_newly_detected_company_is_cut_out_of_context_spans(self):
        """No identifier sits inside another category's stored span.

        That is how a context finding's sample ends up holding text belonging
        to a different category, which is a storage leak even when the preview
        renders nothing raw.
        """
        for label, text in self.CUT_PROBES:
            with self.subTest(shape=label):
                findings = analyze_privacy("sozlesme.txt", text)["risk_map"]
                identifiers = [
                    f for f in findings if f["category"] in DIRECT_IDENTIFIER_CATEGORIES
                ]
                context = [
                    f for f in findings if f["category"] in CONTEXT_SWEEP_CATEGORIES
                ]
                self.assertTrue(
                    any(f["category"] == "company_name" for f in identifiers), findings
                )
                self.assertTrue(context, findings)

                for context_finding in context:
                    for finding in identifiers:
                        self.assertGreaterEqual(
                            max(context_finding["start"], finding["start"]),
                            min(context_finding["end"], finding["end"]),
                            f"{context_finding['category']} span holds {finding['category']}",
                        )
