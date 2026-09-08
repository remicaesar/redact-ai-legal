"""The external-LLM release gate must be reachable, and only by a reviewed document.

``refresh_release_state`` used to reuse the residual-risk level computed at
detection time instead of recomputing it, so the gate's "Residual risk must be
Low." condition could never be satisfied once a CRITICAL finding had been
detected: measured across the 17 documents in ``tests/fixtures/``, a perfect
review pass opened the gate for 0 of them. The tests here pin both directions.

* A fully reviewed document reaches ``external_llm_gate.allowed``.
* Text that is still in the document keeps the gate shut — whether it is
  unresolved (pending/NULL/unrecognized status) or ``retained``, which is
  terminal for review purposes but means the reviewer decided the value STAYS.
* A ``dismissed`` finding — the reviewer's judgement that it is a false
  positive — does NOT keep the gate shut, even at CRITICAL risk. That direction
  matters as much as the blocking one: 10 of the 58 false positives on the gold
  set are CRITICAL-risk, and if dismissing them blocked, the gate would be
  unreachable for those documents by any reviewer action.

The fixture deliberately carries a real CRITICAL finding produced by
``analyze_privacy``. A zero-finding document (the old happy-path fixture in
tests/test_privacy.py) cannot fail these tests and cannot detect the bug.
"""

import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
import app as app_module
from legal_analyzer.privacy import EXTERNAL_LLM_ALLOWED, analyze_privacy
from legal_analyzer.taxonomy import CATEGORIES, SUBCATEGORIES
from tests.test_app_workflow import make_docx
from werkzeug.security import generate_password_hash

# One realistic Turkish petition line: a court, an attorney name, a date, an
# address fragment and a checksum-valid TCKN. It contains the word "tarih",
# which is one of the contextual signals residual_risk_assessment() scores --
# the fixture is only interesting because that word survives redaction.
DOCUMENT_TEXT = (
    "Istanbul 5. Asliye Ceza Mahkemesi dosyasinda Av. Ayse Demir 01.01.2026 "
    "tarihli dilekce sundu. T.C. Kimlik No: 10000000146"
)


class ReviewedDocumentHarness:
    """A one-document review workspace: temp DB, seeded taxonomy, logged-in reviewer.

    A plain mixin rather than a TestCase so importing it elsewhere does not make
    unittest collect this file's tests a second time. tests/test_auto_mode_removed.py
    builds on it.
    """

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.db_path = self.tmp_path / "test.db"
        self.original_db_path = app_module.DB_PATH
        app_module.DB_PATH = self.db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        self.original_export_dir = app_module.EXPORT_DIR
        app_module.EXPORT_DIR = self.tmp_path / "exports"
        self.addCleanup(self.restore_db_path)
        self.addCleanup(self.tmp.cleanup)

        schema = Path("db/schema.sql").read_text(encoding="utf-8")
        conn = sqlite3.connect(self.db_path)
        conn.executescript(schema)
        for name, name_tr, icon in CATEGORIES:
            conn.execute("INSERT OR IGNORE INTO categories (name, name_tr, icon) VALUES (?, ?, ?)", (name, name_tr, icon))
            category_id = conn.execute("SELECT id FROM categories WHERE name = ?", (name,)).fetchone()[0]
            for sub_name, sub_name_tr in SUBCATEGORIES[name]:
                conn.execute(
                    "INSERT OR IGNORE INTO subcategories (category_id, name, name_tr) VALUES (?, ?, ?)",
                    (category_id, sub_name, sub_name_tr),
                )
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'reviewer')",
            ("reviewer", generate_password_hash("secret")),
        )

        docx_path = self.tmp_path / "dilekce.docx"
        make_docx(docx_path, DOCUMENT_TEXT)
        profile = analyze_privacy("dilekce.docx", DOCUMENT_TEXT)
        self.detection_risk_level = profile["residual_risk"]["level"]
        conn.execute(
            """
            INSERT INTO documents (
                id, filename, filepath, file_extension, file_size, title, extraction_status,
                privacy_profile, residual_risk, risk_summary, recommended_strategy,
                external_llm_readiness, human_review_required, redaction_status,
                review_status, ocr_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "dilekce.docx",
                str(docx_path),
                ".docx",
                docx_path.stat().st_size,
                "dilekce",
                "Complete",
                json.dumps(profile),
                profile["residual_risk"]["level"],
                profile["residual_risk"]["summary"],
                profile["recommended_strategy"],
                profile["external_llm_readiness"],
                1,
                profile["redaction_status"],
                "pending_review",
                "not_required",
            ),
        )
        for finding in profile["risk_map"]:
            conn.execute(
                """
                INSERT INTO privacy_findings (
                    document_id, category, sample, risk, recommended_action, placeholder,
                    replacement_text, review_status, source, fingerprint
                ) VALUES (1, ?, ?, ?, ?, ?, ?, 'pending', 'detector', ?)
                """,
                (
                    finding["category"],
                    finding["sample"],
                    finding["risk"],
                    finding["recommended_action"],
                    finding["placeholder"],
                    finding["placeholder"],
                    finding["fingerprint"],
                ),
            )
        conn.commit()
        conn.close()
        self.client = app_module.app.test_client()
        self.client.post("/login", json={"username": "reviewer", "password": "secret"})

    def restore_db_path(self):
        app_module.DB_PATH = self.original_db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        app_module.EXPORT_DIR = self.original_export_dir

    # -- helpers ---------------------------------------------------------

    def detail(self) -> dict:
        response = self.client.get("/api/document/1")
        self.assertEqual(response.status_code, 200)
        return response.json

    def gate(self) -> dict:
        return self.detail()["privacy_profile"]["external_llm_gate"]

    def findings(self) -> list[dict]:
        return self.detail()["findings"]

    def finding_id(self, category: str) -> int:
        matches = [f["id"] for f in self.findings() if f["category"] == category]
        self.assertTrue(matches, f"fixture has no {category} finding")
        return matches[0]

    def review_finding(self, finding_id: int, action: str):
        response = self.client.post(f"/api/finding/{finding_id}/review", json={"action": action})
        self.assertEqual(response.status_code, 200, response.json)

    def approve_all_findings(self):
        response = self.client.post(
            "/api/document/1/findings/review-batch",
            json={"action": "approve", "only_pending": True},
        )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertGreater(response.json["updated"], 0)

    def document_action(self, action: str):
        response = self.client.post("/api/document/1/review", json={"action": action})
        self.assertEqual(response.status_code, 200, response.json)
        return response.json

    def complete_review(self, action: str = "approve"):
        """Drive the fixture through a full, clean review pass."""
        self.approve_all_findings()
        self.document_action("mark_redacted")
        return self.document_action(action)


class GateReachabilityTests(ReviewedDocumentHarness, unittest.TestCase):
    # -- tests -----------------------------------------------------------

    def test_fixture_carries_a_critical_finding(self):
        """Guard against the tests below going vacuous.

        Every assertion in this file is only meaningful because this document
        starts out with a CRITICAL finding and a non-Low detection-time residual
        risk; a clean template would satisfy the gate without any recompute.
        """
        risks = {f["risk"] for f in self.findings()}
        self.assertIn("CRITICAL", risks)
        self.assertNotEqual(self.detection_risk_level, "Low")

    def test_fully_reviewed_document_reaches_allowed(self):
        detail = self.complete_review()

        gate = detail["privacy_profile"]["external_llm_gate"]
        self.assertEqual(gate["failed_conditions"], [])
        self.assertTrue(gate["allowed"])
        self.assertEqual(detail["external_llm_readiness"], EXTERNAL_LLM_ALLOWED)
        self.assertEqual(detail["review_status"], "approved_for_external_llm")
        self.assertEqual(detail["privacy_profile"]["post_review_residual_risk"]["level"], "Low")
        # The detection-time measurement must survive untouched: the accuracy
        # audit and the risk badges are calibrated on it.
        self.assertEqual(
            detail["privacy_profile"]["residual_risk"]["level"],
            self.detection_risk_level,
        )

    def test_unresolved_context_finding_blocks_via_residual_risk(self):
        """A finding reverted to pending closes the gate again.

        court_or_authority is HIGH but is not a direct identifier and not
        CRITICAL, so neither of the gate's count-based conditions can fire: the
        only thing that can block here is the recomputed residual risk.
        """
        self.complete_review()
        self.review_finding(self.finding_id("court_or_authority"), "pending")

        gate = self.gate()
        self.assertFalse(gate["allowed"])
        self.assertEqual(gate["failed_conditions"], ["Residual risk must be Low."])
        self.assertEqual(gate["critical_count"], 0)
        self.assertFalse(gate["direct_identifiers_detected"])

    def test_unresolved_critical_finding_blocks(self):
        self.complete_review()
        self.review_finding(self.finding_id("turkish_national_id"), "pending")

        gate = self.gate()
        self.assertFalse(gate["allowed"])
        self.assertIn("Residual risk must be Low.", gate["failed_conditions"])
        self.assertIn("Critical findings must be zero.", gate["failed_conditions"])

    def test_retained_critical_finding_still_blocks(self):
        """'retained' is terminal, but the identifier is still in the document.

        The reviewer decided this TCKN stays unredacted, so
        unresolved_critical_count cannot see it — retaining is a decision, not
        an omission. Two independent paths must: the residual-risk recompute,
        which treats retained findings as remaining, and
        direct_identifiers_remaining, which counts pending ∪ retained because a
        retained TCKN literally remains.

        This test replaces the pre-split test_rejected_critical_finding_still_blocks.
        The old single 'rejected' status could not distinguish this case from a
        false positive, which is the whole reason for the split.
        """
        self.review_finding(self.finding_id("turkish_national_id"), "retain")
        detail = self.complete_review()

        gate = detail["privacy_profile"]["external_llm_gate"]
        self.assertEqual(gate["critical_count"], 0)
        self.assertTrue(gate["direct_identifiers_detected"])
        self.assertFalse(gate["allowed"])
        self.assertEqual(
            sorted(gate["failed_conditions"]),
            ["No direct identifiers may remain in detected findings.", "Residual risk must be Low."],
        )
        self.assertEqual(detail["privacy_profile"]["post_review_residual_risk"]["level"], "High")
        self.assertEqual(detail["review_status"], "reviewed_blocked")

    def test_retained_direct_identifier_counts_as_remaining(self):
        """direct_identifiers_remaining is pending ∪ retained, not pending alone.

        The gate condition reads "No direct identifiers may remain in detected
        findings", and a retained direct identifier literally remains. This is
        deliberately redundant with the residual-risk path, so the assertion
        here is on that specific condition rather than on gate['allowed'] —
        otherwise residual risk alone would keep the test green with this
        measurement broken.

        natural_person_name is used rather than the TCKN because it is HIGH, not
        CRITICAL: nothing else in the gate can produce this failed condition.
        """
        self.review_finding(self.finding_id("natural_person_name"), "retain")
        detail = self.complete_review()

        gate = detail["privacy_profile"]["external_llm_gate"]
        self.assertTrue(gate["direct_identifiers_detected"])
        self.assertIn("No direct identifiers may remain in detected findings.", gate["failed_conditions"])
        self.assertEqual(gate["critical_count"], 0)

    def test_dismissed_direct_identifier_does_not_count_as_remaining(self):
        """The other direction: a dismissed direct identifier must clear.

        Person names are the largest false-positive source in this detector, so
        if dismissing one still tripped direct_identifiers_remaining the gate
        would be unreachable for most real documents.
        """
        self.review_finding(self.finding_id("natural_person_name"), "dismiss")
        detail = self.complete_review()

        gate = detail["privacy_profile"]["external_llm_gate"]
        self.assertFalse(gate["direct_identifiers_detected"])
        self.assertNotIn("No direct identifiers may remain in detected findings.", gate["failed_conditions"])

    def test_dismissed_critical_finding_does_not_block(self):
        """A CRITICAL false positive must not be able to close the gate.

        This is the workflow the split exists to protect. Precision on the gold
        set is 0.701 and 10 of the 58 false positives are CRITICAL-risk
        (criminal_allegation, health_data, privileged_or_confidential), so if
        dismissing a CRITICAL finding kept residual risk above Low, every
        document with one would be permanently unreleasable with no action a
        reviewer could take.

        The TCKN here is genuinely checksum-valid, so this is the strong form of
        the case: even a dismissed direct identifier at CRITICAL risk clears the
        gate, because 'dismissed' is the reviewer asserting the text is not
        sensitive at all.
        """
        self.review_finding(self.finding_id("turkish_national_id"), "dismiss")
        detail = self.complete_review()

        gate = detail["privacy_profile"]["external_llm_gate"]
        self.assertEqual(gate["failed_conditions"], [])
        self.assertTrue(gate["allowed"])
        self.assertFalse(gate["direct_identifiers_detected"])
        self.assertEqual(detail["privacy_profile"]["post_review_residual_risk"]["level"], "Low")
        self.assertEqual(detail["review_status"], "approved_for_external_llm")

    def test_reject_is_an_alias_for_dismiss_and_never_for_retain(self):
        """The API alias must map to the permissive decision, deliberately.

        Existing clients send {"action": "reject"}. Before the split that
        overwhelmingly meant "false positive", so 'reject' maps to 'dismissed'.
        Mapping it to 'retained' would silently turn every existing caller's
        request into a release blocker; mapping it to 'dismissed' is the choice
        that must be pinned, because it is permissive and therefore the one that
        could hide a real identifier if the alias were ever pointed at the wrong
        status.
        """
        finding_id = self.finding_id("turkish_national_id")
        response = self.client.post(f"/api/finding/{finding_id}/review", json={"action": "reject"})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["review_status"], "dismissed")
        self.assertNotEqual(response.json["review_status"], "retained")

        stored = [f["review_status"] for f in self.findings() if f["id"] == finding_id]
        self.assertEqual(stored, ["dismissed"])

    def test_gate_and_redacted_export_agree_on_approval(self):
        """The gate and the reviewed-DOCX endpoint must answer the same question.

        These two read the approval independently, and when they disagree the
        studio tells a lawyer the document is releasable while the download
        refuses it. They used to disagree because the gate accepted an
        `auto_mode_enabled` flag in place of an approval and the export did not;
        the arm is gone, so the only thing that moves either of them is a human
        approving the document.
        """
        self.approve_all_findings()
        self.document_action("mark_redacted")

        # Every condition but the approval is now met.
        blocked_gate = self.gate()
        self.assertEqual(
            blocked_gate["failed_conditions"],
            ["Human review approval is required."],
            "fixture must reach the approval condition and no other",
        )
        blocked = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(blocked.status_code, 409)
        self.assertIn("Human review approval is required", blocked.json["error"])

        detail = self.document_action("approve")
        self.assertTrue(detail["privacy_profile"]["external_llm_gate"]["allowed"])
        self.assertTrue(detail["human_review_approved"])

        exported = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(
            exported.status_code,
            200,
            "the release gate allows this document but the export endpoint refused it",
        )
        self.assertEqual(
            exported.content_type,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )

    def test_approval_does_not_bypass_the_unresolved_findings_export_guard(self):
        """An approval clears the approval condition only, never the leak guard.

        redaction_completed is a latch, so a finding reverted to pending after
        redaction was marked complete is dropped from the redaction targets and
        would be exported in cleartext. That 409 has to survive a genuine
        approval, which is the strongest state a document can be in.
        """
        self.approve_all_findings()
        self.document_action("mark_redacted")
        self.document_action("approve")
        self.review_finding(self.finding_id("natural_person_name"), "pending")

        response = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(response.status_code, 409)
        self.assertIn("Every privacy finding must be decided", response.json["error"])


if __name__ == "__main__":
    unittest.main()
