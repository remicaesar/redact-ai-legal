import unittest
from pathlib import Path

from legal_analyzer.privacy import (
    EXTERNAL_LLM_ALLOWED,
    EXTERNAL_LLM_BLOCKED,
    analyze_privacy,
    build_redacted_preview,
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
        """
        medical = [
            finding["sample"] for finding in self.of_category(self.findings("medical_case.txt", self.MEDICAL_TEXT), "health_data")
        ]
        self.assertEqual(
            medical,
            [
                "hasta",
                "), Özel Marmara Hastanesi'nde 22",
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
