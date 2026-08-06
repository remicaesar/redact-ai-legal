import unittest

from legal_analyzer.privacy import EXTERNAL_LLM_ALLOWED, EXTERNAL_LLM_BLOCKED, analyze_privacy, refresh_release_state


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
