"""Human approval has no substitute.

`external_llm_gate_policy()` used to accept a stored `auto_mode_enabled` flag in
place of `human_review_approved`, and `get_exportable_docx()` did the same. The
flag had no UI switch, no indicator while it was on and no audit surface; the
only way to set it was to POST ``{"action": "enable_auto_mode"}`` to
``/api/document/<id>/review``. The whole premise of this product is that a person
signs off before anything leaves it, so the arm was removed rather than made
visible.

These tests pin the guarantee, not the diff. Each one constructs a document that
satisfies every other release condition and shows it is still refused, so
reintroducing the substitution anywhere -- the gate, either export path, the
pipeline status, or a new one -- turns one of them red.
"""

import inspect
import json
import re
import sqlite3
import unittest
from pathlib import Path

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
import app as app_module
from legal_analyzer import privacy
from legal_analyzer.status import STAGE_AWAITING_APPROVAL, STAGE_READY
from tests.test_gate_reachability import ReviewedDocumentHarness

# Everything that could read the retired column. Tests are excluded on purpose:
# tests/test_pipeline_status.py names it to prove a leftover value is ignored.
SOURCE_ROOTS = ("app.py", "classify.py", "benchmark.py", "accuracy_audit.py")
SOURCE_DIRS = ("legal_analyzer", "blueprints", "db", "templates", "static", "docker")


class GateRequiresHumanApprovalTests(ReviewedDocumentHarness, unittest.TestCase):
    """End-to-end, against a document that meets every other condition."""

    def satisfy_everything_but_approval(self):
        """Drive the fixture to the one-condition-left state and prove it is there."""
        self.approve_all_findings()
        self.document_action("mark_redacted")
        gate = self.gate()
        self.assertEqual(
            gate["failed_conditions"],
            ["Human review approval is required."],
            "the fixture must fail the approval condition and nothing else, or these "
            "tests would pass for the wrong reason",
        )
        self.assertFalse(gate["allowed"])
        return gate

    def test_release_gate_cannot_be_satisfied_without_a_human_approval(self):
        self.satisfy_everything_but_approval()
        detail = self.detail()

        self.assertFalse(detail["human_review_approved"])
        self.assertFalse(detail["privacy_profile"]["external_llm_gate"]["allowed"])
        self.assertNotEqual(detail["external_llm_readiness"], privacy.EXTERNAL_LLM_ALLOWED)
        self.assertEqual(detail["pipeline_stage"], STAGE_AWAITING_APPROVAL)

        # ...and a human approval is all it takes, so the block above is the
        # approval condition and not some other unmet one.
        approved = self.document_action("approve")
        self.assertTrue(approved["privacy_profile"]["external_llm_gate"]["allowed"])
        self.assertEqual(approved["pipeline_stage"], STAGE_READY)

    def test_reviewed_docx_export_cannot_be_satisfied_without_a_human_approval(self):
        self.satisfy_everything_but_approval()

        refused = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(refused.status_code, 409, refused.json)
        self.assertIn("Human review approval is required", refused.json["error"])

        self.document_action("approve")
        allowed = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(allowed.status_code, 200, "a genuinely approved document must still export")

    def test_enable_auto_mode_action_is_rejected_and_changes_nothing(self):
        """400, not a silent 200.

        A caller that still sends the old action has to be told nothing
        happened. Answering 200 and returning the document detail would let a
        script -- or a person reading the response -- conclude the document had
        been put into a mode it is not in.
        """
        before = self.satisfy_everything_but_approval()

        for action in ("enable_auto_mode", "disable_auto_mode"):
            with self.subTest(action=action):
                response = self.client.post("/api/document/1/review", json={"action": action})
                self.assertEqual(response.status_code, 400, response.json)
                self.assertEqual(response.json, {"error": "Unsupported review action"})

        after = self.gate()
        self.assertEqual(after["failed_conditions"], before["failed_conditions"])
        self.assertFalse(after["allowed"])
        detail = self.detail()
        self.assertFalse(detail["human_review_approved"])
        self.assertEqual(detail["review_status"], "redaction_complete")

        refused = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(refused.status_code, 409, "the rejected action must not have unlocked the export")

    def test_a_database_where_the_bypass_was_already_used_is_refused(self):
        """The upgrade case, which is the only way a set flag can exist at all.

        `documents.auto_mode_enabled` is retired in place rather than dropped, so
        a database that reached the old endpoint still carries a 1 there AND a
        cached privacy_profile whose gate says "allowed" with no failed
        conditions. Nothing recomputes that JSON until the next review action. So
        this simulates exactly that row -- flag set, approval absent, cache
        stale -- and shows the document is still refused everywhere a decision is
        actually made.
        """
        self.satisfy_everything_but_approval()
        conn = sqlite3.connect(self.db_path)
        profile = json.loads(conn.execute("SELECT privacy_profile FROM documents WHERE id = 1").fetchone()[0])
        profile["external_llm_gate"]["allowed"] = True
        profile["external_llm_gate"]["failed_conditions"] = []
        profile["external_llm_readiness"] = privacy.EXTERNAL_LLM_ALLOWED
        conn.execute(
            """
            UPDATE documents
            SET auto_mode_enabled = 1,
                human_review_approved = 0,
                privacy_profile = ?,
                external_llm_readiness = ?,
                review_status = 'approved_for_external_llm'
            WHERE id = 1
            """,
            (json.dumps(profile), privacy.EXTERNAL_LLM_ALLOWED),
        )
        conn.commit()
        conn.close()

        # The reviewed-DOCX export reads the approval column directly.
        refused = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(refused.status_code, 409, refused.json)
        self.assertIn("Human review approval is required", refused.json["error"])

        # And the pipeline status, which is what the studio actually shows,
        # refuses to call the stale cache "ready".
        self.assertEqual(self.detail()["pipeline_stage"], STAGE_AWAITING_APPROVAL)

        # The first review action recomputes the cache and the stale "allowed" is gone.
        self.client.post("/api/finding/%d/review" % self.finding_id("turkish_national_id"), json={"action": "approve"})
        self.assertFalse(self.gate()["allowed"])
        self.assertEqual(self.gate()["failed_conditions"], ["Human review approval is required."])

    def test_review_action_still_accepts_the_actions_that_remain(self):
        """Guard against the check above passing because the endpoint rejects everything."""
        for action in ("approve", "reject", "reset"):
            with self.subTest(action=action):
                response = self.client.post("/api/document/1/review", json={"action": action})
                self.assertEqual(response.status_code, 200, response.json)


class GatePolicyUnitTests(unittest.TestCase):
    """The gate function itself, with every other condition handed to it as met."""

    SATISFIED = {
        "residual_risk": {"level": "Low"},
        "findings": [],
        "extraction_status": {"status": "Complete", "blocks_external_llm": False},
    }

    def policy(self, **overrides):
        kwargs = {
            "redaction_completed": True,
            "human_review_approved": True,
            "unresolved_critical_count": 0,
            "direct_identifiers_remaining": False,
            "ocr_status": "not_required",
        }
        kwargs.update(overrides)
        return privacy.external_llm_gate_policy(
            self.SATISFIED["residual_risk"],
            self.SATISFIED["findings"],
            self.SATISFIED["extraction_status"],
            **kwargs,
        )

    def test_everything_else_satisfied_still_fails_without_approval(self):
        gate = self.policy(human_review_approved=False)
        self.assertFalse(gate["allowed"])
        self.assertEqual(gate["failed_conditions"], ["Human review approval is required."])

    def test_the_same_inputs_pass_with_approval(self):
        gate = self.policy()
        self.assertTrue(gate["allowed"], gate["failed_conditions"])
        self.assertEqual(gate["failed_conditions"], [])

    def test_gate_functions_reject_an_auto_mode_argument(self):
        """A reintroduction by keyword has to fail loudly rather than be ignored.

        `**kwargs`-style tolerance here would let a caller pass
        auto_mode_enabled=True, see no error, and reasonably believe it did
        something.
        """
        for func in (privacy.external_llm_gate_policy, privacy.refresh_release_state, privacy.analyze_privacy):
            with self.subTest(func=func.__name__):
                self.assertNotIn("auto_mode_enabled", inspect.signature(func).parameters)

        with self.assertRaises(TypeError):
            self.policy(auto_mode_enabled=True)

    def test_policy_description_promises_an_unconditional_approval(self):
        """The landing page and the studio quote this list to users."""
        gate = self.policy()
        self.assertIn("Human review approved", gate["policy"])
        self.assertFalse(
            [item for item in gate["policy"] if "auto" in item.lower()],
            gate["policy"],
        )

    def test_release_controls_no_longer_carry_the_flag(self):
        profile = privacy.analyze_privacy("note.txt", "Bir dilekce metni.", None)
        self.assertEqual(
            set(profile["release_controls"]),
            {"redaction_completed", "human_review_approved"},
        )


class NoRemainingReadsTests(unittest.TestCase):
    """A static sweep, so a read reintroduced anywhere at all is caught.

    The column is retired rather than dropped (db/migrations/006_retire_auto_mode_bypass.sql
    says why), which means a future change could quietly start reading it again
    and every behavioural test above would still pass. This is the test that
    would not.
    """

    # A read is what matters: doc["auto_mode_enabled"], .get("auto_mode_enabled"),
    # auto_mode_enabled=..., a bare SELECT of it. The migration's UPDATEs and the
    # schema's column definition are the two places it is allowed to appear, and
    # neither is a read by application code.
    READ_PATTERN = re.compile(
        r"""\[\s*["']auto_mode_enabled["']\s*\]"""      # row["auto_mode_enabled"]
        r"""|get\(\s*["']auto_mode_enabled["']"""        # .get("auto_mode_enabled")
        r"""|auto_mode_enabled\s*="""                    # kwarg or assignment
        r"""|\bd?\.?auto_mode_enabled\b\s*(?:,|\)|$)""", # SELECT ... auto_mode_enabled,
        re.MULTILINE,
    )

    ALLOWED = {
        Path("db/schema.sql"),                                   # the retired column definition
        Path("db/migrations/006_retire_auto_mode_bypass.sql"),   # the retirement itself
    }

    def source_files(self):
        root = Path(app_module.__file__).resolve().parent
        for name in SOURCE_ROOTS:
            path = root / name
            if path.exists():
                yield path.relative_to(root), path
        for directory in SOURCE_DIRS:
            for path in sorted((root / directory).rglob("*")):
                if not path.is_file() or "vendor" in path.parts:
                    continue
                if path.suffix not in {".py", ".sql", ".html", ".js"}:
                    continue
                yield path.relative_to(root), path

    def test_no_source_file_reads_the_retired_column(self):
        offenders = []
        scanned = 0
        for relative, path in self.source_files():
            scanned += 1
            if relative in self.ALLOWED:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for match in self.READ_PATTERN.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{relative}:{line}: {match.group(0)!r}")
        self.assertGreater(scanned, 20, "the sweep found almost nothing to scan; the paths are wrong")
        self.assertEqual(offenders, [], "auto_mode_enabled is read again:\n" + "\n".join(offenders))

    def test_the_sweep_can_actually_see_a_read(self):
        """Otherwise the test above passes because the pattern matches nothing."""
        samples = [
            'if not (doc["human_review_approved"] or doc["auto_mode_enabled"]):',
            'auto_mode = bool(data.get("auto_mode_enabled"))',
            "        auto_mode_enabled=bool(doc[\"auto_mode_enabled\"]),",
            "            d.redaction_completed, d.human_review_approved, d.auto_mode_enabled,",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(self.READ_PATTERN.search(sample), sample)

    def test_the_enable_auto_mode_action_is_not_routable(self):
        review_source = (Path(app_module.__file__).resolve().parent / "blueprints" / "review.py").read_text(
            encoding="utf-8"
        )
        # The name may survive in the comment that records the removal; it must
        # not survive in a string literal the action check compares against.
        code = "\n".join(line for line in review_source.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn('"enable_auto_mode"', code)
        self.assertNotIn("'enable_auto_mode'", code)


if __name__ == "__main__":
    unittest.main()
