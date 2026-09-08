"""Unit tests for the single computed pipeline status (legal_analyzer.status)."""

import json
import unittest

from legal_analyzer.status import (
    STAGE_AWAITING_APPROVAL,
    STAGE_BLOCKED,
    STAGE_NEEDS_OCR,
    STAGE_NEEDS_REVIEW,
    STAGE_OCR_REVIEW,
    STAGE_READY,
    STAGE_READY_TO_FINALIZE,
    compute_pipeline_status,
)


def doc_row(**overrides) -> dict:
    base = {
        "extraction_status": "Complete",
        "ocr_status": "not_required",
        "redaction_completed": 0,
        "human_review_approved": 0,
        "external_llm_readiness": "Blocked until redaction is completed and reviewed",
        "privacy_profile": json.dumps({"external_llm_gate": {"allowed": False, "failed_conditions": ["Redaction pass must be completed."]}}),
    }
    base.update(overrides)
    return base


class PipelineStatusTests(unittest.TestCase):
    def test_failed_extraction_needs_ocr(self):
        status = compute_pipeline_status(doc_row(extraction_status="Failed", ocr_status="queued"))
        self.assertEqual(status["pipeline_stage"], STAGE_NEEDS_OCR)
        self.assertIn("OCR", status["pipeline_message"])

    def test_partial_extraction_needs_ocr(self):
        status = compute_pipeline_status(doc_row(extraction_status="Partial", ocr_status="not_required"))
        self.assertEqual(status["pipeline_stage"], STAGE_NEEDS_OCR)

    def test_completed_ocr_awaits_reviewer_decision(self):
        status = compute_pipeline_status(doc_row(extraction_status="Failed", ocr_status="completed"))
        self.assertEqual(status["pipeline_stage"], STAGE_OCR_REVIEW)
        self.assertIn("accept or reject", status["pipeline_message"])

    def test_rejected_ocr_returns_to_needs_ocr(self):
        status = compute_pipeline_status(doc_row(extraction_status="Failed", ocr_status="rejected"))
        self.assertEqual(status["pipeline_stage"], STAGE_NEEDS_OCR)
        self.assertIn("rejected", status["pipeline_message"])

    def test_accepted_ocr_moves_past_extraction(self):
        status = compute_pipeline_status(
            doc_row(extraction_status="Complete", ocr_status="accepted"),
            pending_findings=2,
        )
        self.assertEqual(status["pipeline_stage"], STAGE_NEEDS_REVIEW)

    def test_pending_findings_need_review_with_count(self):
        status = compute_pipeline_status(doc_row(), pending_findings=3)
        self.assertEqual(status["pipeline_stage"], STAGE_NEEDS_REVIEW)
        self.assertIn("3 findings", status["pipeline_message"])

    def test_pending_pdf_regions_included_in_message(self):
        status = compute_pipeline_status(doc_row(), pending_findings=1, pending_pdf_regions=2)
        self.assertEqual(status["pipeline_stage"], STAGE_NEEDS_REVIEW)
        self.assertIn("1 finding", status["pipeline_message"])
        self.assertIn("2 PDF redaction boxes", status["pipeline_message"])

    def test_all_reviewed_ready_to_finalize(self):
        status = compute_pipeline_status(doc_row())
        self.assertEqual(status["pipeline_stage"], STAGE_READY_TO_FINALIZE)

    def test_redaction_complete_awaits_approval(self):
        status = compute_pipeline_status(doc_row(redaction_completed=1))
        self.assertEqual(status["pipeline_stage"], STAGE_AWAITING_APPROVAL)

    def test_approved_and_gate_allowed_is_ready(self):
        profile = json.dumps({"external_llm_gate": {"allowed": True, "failed_conditions": []}})
        status = compute_pipeline_status(
            doc_row(redaction_completed=1, human_review_approved=1, privacy_profile=profile)
        )
        self.assertEqual(status["pipeline_stage"], STAGE_READY)

    def test_approved_but_gate_blocked_names_specific_condition(self):
        profile = json.dumps(
            {
                "external_llm_gate": {
                    "allowed": False,
                    "failed_conditions": ["Residual risk must be Low.", "Critical findings must be zero."],
                }
            }
        )
        status = compute_pipeline_status(
            doc_row(redaction_completed=1, human_review_approved=1, privacy_profile=profile)
        )
        self.assertEqual(status["pipeline_stage"], STAGE_BLOCKED)
        self.assertIn("Residual risk must be Low", status["pipeline_message"])
        self.assertIn("1 more condition", status["pipeline_message"])

    def test_blocked_without_profile_falls_back_to_readiness_text(self):
        status = compute_pipeline_status(
            {
                "extraction_status": "Complete",
                "ocr_status": "not_required",
                "redaction_completed": 1,
                "human_review_approved": 1,
                "external_llm_readiness": "Blocked until redaction is completed and reviewed",
            }
        )
        self.assertEqual(status["pipeline_stage"], STAGE_BLOCKED)
        self.assertIn("Blocked until redaction", status["pipeline_message"])

    def test_retired_auto_mode_column_does_not_count_as_approval(self):
        """A leftover auto_mode_enabled = 1 must not read as a human approval.

        The column is retired but still present on migrated databases (see
        db/migrations/006_retire_auto_mode_bypass.sql), and compute_pipeline_status
        takes whatever the documents row carries. It used to accept that flag in
        place of human_review_approved; a row still carrying it must now sit at
        "awaiting approval" like any other unapproved document, and the cached
        "allowed" gate in the profile must not talk it past that stage either.
        """
        profile = json.dumps({"external_llm_gate": {"allowed": True, "failed_conditions": []}})
        status = compute_pipeline_status(
            doc_row(redaction_completed=1, auto_mode_enabled=1, privacy_profile=profile)
        )
        self.assertEqual(status["pipeline_stage"], STAGE_AWAITING_APPROVAL)
        self.assertNotEqual(status["pipeline_stage"], STAGE_READY)

    def test_approved_document_is_ready(self):
        """The other direction, so the test above cannot pass by always blocking."""
        profile = json.dumps({"external_llm_gate": {"allowed": True, "failed_conditions": []}})
        status = compute_pipeline_status(
            doc_row(redaction_completed=1, human_review_approved=1, privacy_profile=profile)
        )
        self.assertEqual(status["pipeline_stage"], STAGE_READY)


if __name__ == "__main__":
    unittest.main()
