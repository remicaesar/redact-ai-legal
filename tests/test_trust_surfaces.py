"""What the studio *says* about safety, and where that text comes from.

Four display defects an independent UX study measured on this product, each
pinned so it cannot come back:

1. Every page declared Turkish while its copy is English, so `text-transform:
   uppercase` rendered CATEGORİES / RİSK / FİNDİNGS under the Turkish casing
   rules.
2. "Review complete" read as "the document has been checked", and the detected
   document language -- which is what bounds how much the rules can find -- was
   stored and never shown.
3. The export question and the external-LLM question were one undifferentiated
   stack, with the export half re-derived in the browser from a shorter list of
   conditions than the server's.
4. `post_review_residual_risk` -- the level the release gate was actually
   decided against -- was computed and rendered nowhere, so a cleared document
   still read "High risk".

None of these tests touch what a gate permits. The parity tests below assert
the opposite: that the panel and the endpoint still answer identically.
"""

import json
import re
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
import app as app_module
from blueprints.auth import LOGIN_PAGE
from legal_analyzer import privacy
from legal_analyzer.privacy import analyze_privacy, external_llm_gate_policy, refresh_release_state
from werkzeug.security import generate_password_hash

TEMPLATE_DIR = Path("templates")
STUDIO = TEMPLATE_DIR / "studio.html"


def make_docx(path: Path, text: str) -> None:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>",
        )
        archive.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            "</Relationships>",
        )
        archive.writestr(
            "word/document.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>",
        )


class DocumentLanguageAttributeTests(unittest.TestCase):
    """Item 1. The copy is English; the document must say so.

    Under a Turkish locale `i` uppercases to `İ`, so a mislabelled document
    corrupts every `text-transform: uppercase` label on the page. The study
    counted 10 on the dashboard alone.
    """

    def test_every_rendered_page_declares_the_language_of_its_copy(self) -> None:
        for template in sorted(TEMPLATE_DIR.glob("*.html")):
            with self.subTest(template=template.name):
                markup = template.read_text(encoding="utf-8")
                declared = re.findall(r"<html[^>]*\blang=\"([^\"]+)\"", markup)
                self.assertEqual(declared, ["en"], f"{template.name} declares {declared}")

    def test_the_login_page_declares_it_too(self) -> None:
        """It is not a template file, and it is the first page a visitor sees."""
        self.assertIn('<html lang="en">', LOGIN_PAGE)
        self.assertNotIn('lang="tr"', LOGIN_PAGE)


class CompletionWordingTests(unittest.TestCase):
    """Item 2. Report the reviewer's action, not a verdict on the document."""

    def setUp(self) -> None:
        self.markup = STUDIO.read_text(encoding="utf-8")

    def test_the_studio_never_claims_the_review_is_complete(self) -> None:
        rendered_copy = re.sub(r"//[^\n]*", "", self.markup)
        self.assertNotIn("Review complete", rendered_copy)

    def test_it_states_how_many_flagged_items_were_decided(self) -> None:
        self.assertIn("flagged item", self.markup)
        self.assertIn("stepper-complete", self.markup)

    def test_the_count_comes_from_the_server_side_totals(self) -> None:
        """finding_count / pending_finding_count are the unbounded counts.

        The findings array the studio receives is capped at 500 rows, so
        counting it would understate a large document's total.
        """
        self.assertIn("doc.finding_count", self.markup)
        self.assertIn("doc.pending_finding_count", self.markup)


class LanguageCoverageNoticeTests(unittest.TestCase):
    """Item 2, second half. Say what the rules do not reach, where it matters."""

    def setUp(self) -> None:
        self.markup = STUDIO.read_text(encoding="utf-8")

    def test_the_notice_exists_and_is_rendered_from_the_stored_language(self) -> None:
        self.assertIn('id="languageCoverageNotice"', self.markup)
        self.assertIn("doc.language", self.markup)

    def test_it_is_shown_on_non_turkish_documents_only(self) -> None:
        """A Turkish document is what the rules are tuned for; no caveat there."""
        notice = self._notice_function()
        self.assertIn("if (language === 'TR')", notice)
        self.assertIn("notice.hidden = true", notice)

    def test_the_wording_does_not_soften_what_the_readme_says(self) -> None:
        """README.md is the source; the screen must not water it down."""
        collapse = lambda text: " ".join(text.split())
        readme = collapse(Path("README.md").read_text(encoding="utf-8"))
        claim = "English name and address coverage is materially lower than Turkish coverage"
        self.assertIn(claim, readme)
        self.assertIn(claim, collapse(self._notice_function()))

    def test_it_does_not_overstate_the_limit_either(self) -> None:
        """The engine is less complete on English, not useless on it."""
        notice = self._notice_function().lower()
        for overstatement in ("cannot detect", "does not work", "no coverage", "unsupported"):
            self.assertNotIn(overstatement, notice)

    def _notice_function(self) -> str:
        start = self.markup.index("function renderLanguageCoverageNotice(")
        return self.markup[start : self.markup.index("\n        }", start)]


class ReleaseGateConditionsTests(unittest.TestCase):
    """Item 3, server half. The gate reports its whole checklist, not just failures."""

    SATISFIED = {
        "residual_risk": {"level": "Low"},
        "findings": [],
        "extraction_status": {"status": "Complete", "blocks_external_llm": False},
    }

    def gate(self, **overrides):
        kwargs = {
            "redaction_completed": True,
            "human_review_approved": True,
            "unresolved_critical_count": 0,
            "direct_identifiers_remaining": False,
            "ocr_status": "not_required",
        }
        kwargs.update(overrides)
        return external_llm_gate_policy(
            overrides.pop("residual_risk", None) or self.SATISFIED["residual_risk"],
            self.SATISFIED["findings"],
            overrides.pop("extraction_status", None) or self.SATISFIED["extraction_status"],
            **{k: v for k, v in kwargs.items() if k not in {"residual_risk", "extraction_status"}},
        )

    def test_a_cleared_document_reports_every_condition_as_passed(self) -> None:
        gate = self.gate()
        self.assertTrue(gate["allowed"])
        self.assertTrue(all(c["passed"] for c in gate["conditions"]), gate["conditions"])
        self.assertEqual(len(gate["conditions"]), 7)

    def test_each_condition_fails_on_its_own_input_and_nothing_else_does(self) -> None:
        """One broken input, one failing row, named by id.

        This is what lets the browser render the checklist without deciding
        anything: every row's `passed` is the gate's own answer.
        """
        cases = {
            "extraction_complete": {"extraction_status": {"status": "Partial", "blocks_external_llm": True}},
            "ocr_resolved": {"ocr_status": "queued"},
            "residual_risk_low": {"residual_risk": {"level": "High"}},
            "no_critical_findings": {"unresolved_critical_count": 2},
            "no_direct_identifiers": {"direct_identifiers_remaining": True},
            "redaction_completed": {"redaction_completed": False},
            "human_review_approved": {"human_review_approved": False},
        }
        for condition_id, override in cases.items():
            with self.subTest(condition=condition_id):
                gate = self.gate(**override)
                failing = [c["id"] for c in gate["conditions"] if not c["passed"]]
                self.assertEqual(failing, [condition_id], gate["conditions"])
                self.assertFalse(gate["allowed"])

    def test_failed_conditions_and_the_checklist_cannot_disagree(self) -> None:
        gate = self.gate(residual_risk={"level": "High"}, human_review_approved=False)
        self.assertEqual(
            gate["failed_conditions"],
            [c["message"] for c in gate["conditions"] if not c["passed"]],
        )
        self.assertEqual(gate["allowed"], not gate["failed_conditions"])

    def test_the_checklist_covers_the_ocr_condition_the_policy_list_omitted(self) -> None:
        ids = [c["id"] for c in self.gate()["conditions"]]
        self.assertIn("ocr_resolved", ids)
        self.assertEqual(len(ids), len(set(ids)))

    def test_refresh_release_state_carries_the_checklist_onto_the_profile(self) -> None:
        profile = analyze_privacy("note.txt", "Bir dilekce metni.", None)
        refreshed = refresh_release_state(profile, redaction_completed=True, human_review_approved=True)
        self.assertTrue(refreshed["external_llm_gate"]["conditions"])


class BrowserDoesNotRebuildTheReleaseGateTests(unittest.TestCase):
    """Item 3, browser half. The studio displays; it does not decide.

    The defect this replaces: `renderExportGate()` built its own row list in
    JavaScript, modelling 5 of the gate's 7 conditions, and produced five green
    ticks directly above the server's red "Blocked".
    """

    def setUp(self) -> None:
        self.markup = STUDIO.read_text(encoding="utf-8")
        start = self.markup.index("function renderReleaseGate(")
        self.renderer = self.markup[start : self.markup.index("\n        }\n", start)]

    def test_the_release_panel_reads_the_servers_conditions(self) -> None:
        self.assertIn("external_llm_gate", self.renderer)
        self.assertIn(".conditions", self.renderer)

    def test_the_release_panel_hardcodes_no_condition_of_its_own(self) -> None:
        """Every condition label must arrive from the server, not the template.

        If a label from external_llm_gate_policy() appears as a literal in the
        renderer, someone has started re-deriving the checklist in the browser.
        """
        gate = external_llm_gate_policy(
            {"level": "Low"},
            [],
            {"status": "Complete", "blocks_external_llm": False},
            redaction_completed=True,
            human_review_approved=True,
        )
        for condition in gate["conditions"]:
            with self.subTest(condition=condition["id"]):
                self.assertNotIn(condition["label"], self.renderer)
                self.assertNotIn(condition["message"], self.renderer)

    def test_the_two_questions_are_titled_separately(self) -> None:
        self.assertIn("This export", self.markup)
        self.assertIn("Sending this to an external AI model", self.markup)
        self.assertIn('id="releaseGatePanel"', self.markup)


class ExportGateParityTests(unittest.TestCase):
    """Item 3, the part that matters most: the panel and the endpoint agree.

    `export_gate_state()` is what the "This export" panel renders and
    `get_exportable_docx()` is what refuses; both resolve through
    `docx_export_conditions()`. If they ever diverge, the studio tells a lawyer
    a file is exportable that the endpoint will not produce.
    """

    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.db_path = self.tmp_path / "test.db"
        self.original_db_path = app_module.DB_PATH
        self.original_export_dir = app_module.EXPORT_DIR
        app_module.DB_PATH = self.db_path
        app_module.EXPORT_DIR = self.tmp_path / "exports"
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        self.addCleanup(self.restore)

        conn = sqlite3.connect(self.db_path)
        conn.executescript(Path("db/schema.sql").read_text(encoding="utf-8"))
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("reviewer", generate_password_hash("secret"), "reviewer"),
        )
        text = "Av. Ayse Demir TCKN 10000000146 tarafindan sunulmustur."
        docx_path = self.tmp_path / "petition.docx"
        make_docx(docx_path, text)
        profile = analyze_privacy("petition.docx", text)
        conn.execute(
            """
            INSERT INTO documents (
                id, filename, filepath, file_extension, file_size, title, language,
                extraction_status, privacy_profile, residual_risk, risk_summary,
                recommended_strategy, external_llm_readiness, human_review_required,
                redaction_status, review_status, ocr_status
            ) VALUES (1, 'petition.docx', ?, '.docx', ?, 'petition', 'TR', 'Complete',
                      ?, ?, ?, ?, ?, 1, ?, 'pending_review', 'not_required')
            """,
            (
                str(docx_path),
                docx_path.stat().st_size,
                json.dumps(profile),
                profile["residual_risk"]["level"],
                profile["residual_risk"]["summary"],
                profile["recommended_strategy"],
                profile["external_llm_readiness"],
                profile["redaction_status"],
            ),
        )
        conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, fingerprint
            ) VALUES
                (1, 'natural_person_name', 'Ayse Demir', 'HIGH', 'Pseudonymize', '[PERSON_1]', '[PERSON_1]', 'pending', 'detector', 'fp1'),
                (1, 'turkish_national_id', '10000000146', 'CRITICAL', 'Redact', '[TCKN_1]', '[TCKN_REDACTED]', 'pending', 'detector', 'fp2')
            """
        )
        conn.commit()
        conn.close()
        self.client = app_module.app.test_client()
        self.client.post("/login", data={"username": "reviewer", "password": "secret"})

    def restore(self) -> None:
        app_module.DB_PATH = self.original_db_path
        app_module.EXPORT_DIR = self.original_export_dir
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())

    def set_state(self, redaction_completed: int, approved: int, finding_status: str) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "UPDATE documents SET redaction_completed = ?, human_review_approved = ? WHERE id = 1",
            (redaction_completed, approved),
        )
        conn.execute("UPDATE privacy_findings SET review_status = ? WHERE document_id = 1", (finding_status,))
        # Every real mutation ends here, and it is what recomputes the release
        # gate and records post_review_residual_risk on the stored profile.
        app_module.refresh_document_state(conn, 1)
        conn.commit()
        conn.close()

    def panel_says_allowed(self) -> bool:
        return bool(self.client.get("/api/document/1").json["export_gate"]["allowed"])

    def endpoint_allows(self) -> bool:
        return self.client.get("/api/document/1/redacted-export?format=docx&style=placeholder").status_code == 200

    def test_the_panel_and_the_endpoint_agree_in_every_state(self) -> None:
        states = [
            (0, 0, "pending"),
            (1, 0, "pending"),
            (1, 1, "pending"),
            (1, 1, "approved"),
            (0, 1, "approved"),
            (1, 0, "approved"),
            (1, 1, "retained"),
            (1, 1, "dismissed"),
        ]
        for redacted, approved, status in states:
            with self.subTest(redaction_completed=redacted, approved=approved, findings=status):
                self.set_state(redacted, approved, status)
                self.assertEqual(self.panel_says_allowed(), self.endpoint_allows())

    def test_the_gate_still_refuses_a_document_that_fails_one_condition(self) -> None:
        """Everything satisfied except the findings; the export must still refuse."""
        self.set_state(1, 1, "approved")
        self.assertTrue(self.endpoint_allows())

        self.set_state(1, 1, "pending")
        response = self.client.get("/api/document/1/redacted-export?format=docx&style=placeholder")
        self.assertEqual(response.status_code, 409)
        self.assertIn("must be decided", response.json["error"])
        self.assertFalse(self.panel_says_allowed())

    def test_the_panel_never_leaks_a_finding_sample(self) -> None:
        self.set_state(1, 1, "pending")
        gate = self.client.get("/api/document/1").json["export_gate"]
        self.assertNotIn("Ayse Demir", json.dumps(gate))
        self.assertNotIn("10000000146", json.dumps(gate))

    def test_the_document_language_reaches_the_studio(self) -> None:
        self.assertEqual(self.client.get("/api/document/1").json["language"], "TR")

    def test_both_residual_risk_figures_reach_the_studio(self) -> None:
        """Item 4. The detection-time figure stays; the decided one is added.

        `residual_risk` is what the accuracy audit and the risk badges are
        calibrated on, so it must not move when a reviewer decides a finding.
        `post_review_residual_risk` is the level the gate was decided against
        and is what makes a cleared document stop reading "High risk".
        """
        self.set_state(1, 1, "approved")
        payload = self.client.get("/api/document/1").json
        self.assertEqual(payload["residual_risk"], "High")
        post_review = payload["privacy_profile"]["post_review_residual_risk"]
        self.assertEqual(post_review["level"], "Low")
        self.assertNotEqual(post_review["level"], payload["residual_risk"])

    def test_the_studio_renders_both_and_labels_the_difference(self) -> None:
        markup = STUDIO.read_text(encoding="utf-8")
        self.assertIn("post_review_residual_risk", markup)
        self.assertIn("at detection", markup)
        self.assertIn("after your decisions", markup)


class DetectionTimeRiskIsNotOverwrittenTests(unittest.TestCase):
    """Item 4's constraint, stated on the module the audit depends on."""

    def test_refresh_leaves_the_detection_time_measurement_alone(self) -> None:
        profile = analyze_privacy("dilekce.docx", "Av. Ayse Demir TCKN 10000000146 basvurmustur.")
        detection_level = profile["residual_risk"]["level"]
        self.assertEqual(detection_level, "High")

        refreshed = refresh_release_state(
            profile,
            redaction_completed=True,
            human_review_approved=True,
            unresolved_critical_count=0,
            direct_identifiers_remaining=False,
            remaining_findings=[],
        )
        self.assertEqual(refreshed["residual_risk"]["level"], detection_level)
        self.assertEqual(refreshed["post_review_residual_risk"]["level"], "Low")

    def test_the_comment_explaining_why_they_are_separate_survives(self) -> None:
        """Load-bearing: it is the reason residual_risk must not be repurposed."""
        source = Path("legal_analyzer/privacy.py").read_text(encoding="utf-8")
        self.assertIn("stays the detection-time measurement the accuracy", source)
        self.assertTrue(hasattr(privacy, "refresh_release_state"))
