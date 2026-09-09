import gc
import json
import sqlite3
import unittest
import warnings
from unittest import mock
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree import ElementTree
from zipfile import ZIP_DEFLATED, ZipFile

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
import app as app_module
import fitz
from blueprints.documents import sanitized_display_filename
from legal_analyzer.docx_quality import analyze_docx_export_quality
from legal_analyzer.docx_redactor import redact_docx
from legal_analyzer.pdf_redactor import extract_pdf_text_from_bytes
from legal_analyzer.taxonomy import CATEGORIES, SUBCATEGORIES
from legal_analyzer.privacy import analyze_privacy
from werkzeug.security import generate_password_hash


def make_docx(path: Path, text: str = "Public template") -> None:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
""",
        )
        archive.writestr(
            "_rels/.rels",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
""",
        )
        archive.writestr(
            "word/document.xml",
            f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>
</w:document>
""",
        )


def make_pdf(path: Path, text: str = "Av. Ayse Demir TCKN 10000000146") -> None:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 96), text, fontsize=12)
    page.add_text_annot((300, 96), "Reviewer comment that must not survive redaction")
    doc.set_metadata({"title": "Sensitive test PDF"})
    doc.save(path)
    doc.close()


class AppWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.db_path = self.tmp_path / "test.db"
        original_db_path = app_module.DB_PATH
        self.original_db_path = original_db_path
        app_module.DB_PATH = self.db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        self.original_export_dir = app_module.EXPORT_DIR
        app_module.EXPORT_DIR = self.tmp_path / "exports"
        self.addCleanup(self.restore_db_path)
        self.addCleanup(self.tmp.cleanup)

        schema = Path("db/schema.sql").read_text(encoding="utf-8")
        conn = sqlite3.connect(self.db_path)
        conn.executescript(schema)
        self.seed_categories(conn)
        self.create_user(conn, "admin", "secret", "admin")
        self.create_user(conn, "reviewer", "secret", "reviewer")
        self.create_user(conn, "viewer", "secret", "viewer")
        docx_path = self.tmp_path / "clean.docx"
        make_docx(docx_path)
        profile = analyze_privacy("clean.docx", "Public template")
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
                "clean.docx",
                str(docx_path),
                ".docx",
                docx_path.stat().st_size,
                "clean",
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
        conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, fingerprint
            ) VALUES
                (1, 'date', '01.01.2026', 'MEDIUM', 'Generalize unless legally necessary', '[DATE_1]', '[DATE_1]', 'pending', 'detector', 'datefp'),
                (1, 'criminal_allegation', 'Şüpheli hakkında suç duyurusu', 'CRITICAL', 'Flag for human legal review', '[CRIMINAL_ALLEGATION_1]', '[CRIMINAL_ALLEGATION_1_REDACTED]', 'pending', 'detector', 'critfp')
            """
        )
        failed_profile = analyze_privacy("scan.pdf", "", "PDF text extraction returned no text; OCR may be required.")
        conn.execute(
            """
            INSERT INTO documents (
                id, filename, filepath, file_extension, file_size, title, extraction_warning,
                extraction_status, privacy_profile, residual_risk, risk_summary,
                recommended_strategy, external_llm_readiness, human_review_required,
                redaction_status, review_status, ocr_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                2,
                "scan.pdf",
                str(self.tmp_path / "scan.pdf"),
                ".pdf",
                10,
                "scan",
                "PDF text extraction returned no text; OCR may be required.",
                "Failed",
                json.dumps(failed_profile),
                failed_profile["residual_risk"]["level"],
                failed_profile["residual_risk"]["summary"],
                failed_profile["recommended_strategy"],
                failed_profile["external_llm_readiness"],
                1,
                failed_profile["redaction_status"],
                "needs_ocr",
                "queued",
            ),
        )
        conn.execute(
            "INSERT OR IGNORE INTO matters (id, name, status, description) VALUES (1, 'Unassigned', 'active', 'Default test matter')"
        )
        conn.execute("INSERT OR IGNORE INTO document_matters (document_id, matter_id) VALUES (1, 1)")
        conn.execute("INSERT OR IGNORE INTO document_matters (document_id, matter_id) VALUES (2, 1)")
        pdf_path = self.tmp_path / "sensitive.pdf"
        make_pdf(pdf_path)
        pdf_profile = analyze_privacy("sensitive.pdf", "Av. Ayse Demir TCKN 10000000146")
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
                3,
                "sensitive.pdf",
                str(pdf_path),
                ".pdf",
                pdf_path.stat().st_size,
                "sensitive",
                "Complete",
                json.dumps(pdf_profile),
                pdf_profile["residual_risk"]["level"],
                pdf_profile["residual_risk"]["summary"],
                pdf_profile["recommended_strategy"],
                pdf_profile["external_llm_readiness"],
                1,
                pdf_profile["redaction_status"],
                "pending_review",
                "not_required",
            ),
        )
        conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, fingerprint
            ) VALUES
                (3, 'natural_person_name', 'Ayse Demir', 'HIGH', 'Pseudonymize consistently', '[PERSON_1]', '[PERSON_1]', 'pending', 'detector', 'pdffp1'),
                (3, 'turkish_national_id', '10000000146', 'CRITICAL', 'Redact direct identifier', '[TCKN_1]', '[TCKN_REDACTED]', 'pending', 'detector', 'pdffp2')
            """
        )
        conn.execute("INSERT OR IGNORE INTO document_matters (document_id, matter_id) VALUES (3, 1)")
        conn.commit()
        conn.close()
        self.client = app_module.app.test_client()
        self.login("reviewer")

    def restore_db_path(self):
        app_module.DB_PATH = self.original_db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        app_module.EXPORT_DIR = self.original_export_dir

    def create_user(self, conn, username: str, password: str, role: str):
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )

    def seed_categories(self, conn):
        for name, name_tr, icon in CATEGORIES:
            conn.execute(
                "INSERT OR IGNORE INTO categories (name, name_tr, icon) VALUES (?, ?, ?)",
                (name, name_tr, icon),
            )
            category_id = conn.execute("SELECT id FROM categories WHERE name = ?", (name,)).fetchone()[0]
            for sub_name, sub_name_tr in SUBCATEGORIES[name]:
                conn.execute(
                    "INSERT OR IGNORE INTO subcategories (category_id, name, name_tr) VALUES (?, ?, ?)",
                    (category_id, sub_name, sub_name_tr),
                )

    def login(self, username: str, password: str = "secret", client=None):
        active_client = client or self.client
        return active_client.post("/login", json={"username": username, "password": password})

    def canvas_segments(self, doc_id: int) -> list[dict]:
        """What the review canvas draws, as the server resolved it.

        `buildDocHtml` in studio.html renders exactly these segments and decides
        nothing itself, and `redacted-export` runs the same resolver, so a claim
        asserted here is a claim about both the surface the lawyer reviews and
        the file they receive.
        """
        plan = self.client.get(f"/api/document/{doc_id}/redaction-plan")
        self.assertEqual(plan.status_code, 200, plan.get_data(as_text=True))
        self.assertTrue(plan.json["has_text"], plan.json)
        return plan.json["segments"]

    def segment_covering(self, segments: list[dict], offset: int) -> dict:
        covering = [segment for segment in segments if segment["start"] <= offset < segment["end"]]
        self.assertEqual(len(covering), 1, f"offset {offset} is not covered exactly once: {segments}")
        return covering[0]

    def test_docx_redacted_export_requires_redaction_and_approval(self):
        blocked = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(blocked.status_code, 409)

        approve_medium = self.client.post(
            "/api/document/1/findings/review-batch",
            json={"action": "approve", "risks": ["MEDIUM"], "only_pending": True},
        )
        self.assertEqual(approve_medium.status_code, 200)
        # Approve rather than reject the CRITICAL findings. This test's subject is
        # the export gate (409 before approval, 200 after), and resolving the
        # CRITICALs by approving them exercises that without depending on what a
        # *rejected* CRITICAL should mean for release — which is a deliberate open
        # question, not settled behaviour. Rejecting is how a reviewer dismisses a
        # false positive (10 of the 58 FPs in the gold set are CRITICAL-risk
        # semantic categories), so "rejected" cannot simply be read as "the
        # reviewer chose to keep a real identifier". Whichever way that is
        # resolved, it gets its own explicit test rather than riding on this one.
        approve_critical = self.client.post(
            "/api/document/1/findings/review-batch",
            json={"action": "approve", "risks": ["CRITICAL"], "only_pending": True},
        )
        self.assertEqual(approve_critical.status_code, 200)
        redacted = self.client.post("/api/document/1/review", json={"action": "mark_redacted"})
        self.assertEqual(redacted.status_code, 200)

        # Redaction complete but human review not approved yet. Without this
        # step the test's name was a claim it never checked: the only 409 it
        # asserted was before redaction was marked complete, so deleting the
        # approval gate left it green.
        before_approval = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(before_approval.status_code, 409)
        self.assertIn("Human review approval", before_approval.json["error"])
        qa_before_approval = self.client.get("/api/document/1/redacted-export/qa?format=docx")
        self.assertEqual(qa_before_approval.status_code, 409)

        approved = self.client.post("/api/document/1/review", json={"action": "approve"})
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json["review_status"], "approved_for_external_llm")

        exported = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.content_type, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")

        masked = self.client.get("/api/document/1/redacted-export?format=docx&style=mask")
        self.assertEqual(masked.status_code, 200)
        self.assertIn("_redacted_mask.docx", masked.headers["Content-Disposition"])

        qa = self.client.get("/api/document/1/redacted-export/qa?format=docx&style=placeholder")
        self.assertEqual(qa.status_code, 200)
        self.assertIn(qa.json["overall_status"], {"pass", "warn"})
        self.assertEqual(qa.json["format"], "docx")
        self.assertEqual(qa.json["style"], "placeholder")
        self.assertIn("checks", qa.json)

        artifacts = self.client.get("/api/document/1/artifacts")
        self.assertEqual(artifacts.status_code, 200)
        artifact_types = {artifact["artifact_type"] for artifact in artifacts.json["artifacts"]}
        self.assertIn("review_snapshot", artifact_types)
        self.assertIn("redacted_docx", artifact_types)
        self.assertIn("docx_qa", artifact_types)

        invalid_style = self.client.get("/api/document/1/redacted-export?format=docx&style=latex")
        self.assertEqual(invalid_style.status_code, 400)
        self.assertIn("placeholder or mask", invalid_style.json["error"])

        admin_client = app_module.app.test_client()
        self.login("admin", client=admin_client)
        audit = admin_client.get("/api/audit-log?action=export.redacted_docx")
        self.assertEqual(audit.status_code, 200)
        self.assertGreaterEqual(audit.json["total"], 1)

    def seed_leaky_docx_document(self, doc_id: int = 4) -> tuple[int, Path]:
        """A DOCX whose text really contains the sample of a CRITICAL finding."""
        text = "Musteri kaydi: TCKN 10000000146 dosyaya eklendi."
        source_path = self.tmp_path / "leaky.docx"
        make_docx(source_path, text)
        profile = analyze_privacy("leaky.docx", text)
        conn = sqlite3.connect(self.db_path)
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
                doc_id,
                "leaky.docx",
                str(source_path),
                ".docx",
                source_path.stat().st_size,
                "leaky",
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
        conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, fingerprint
            ) VALUES (?, 'turkish_national_id', '10000000146', 'CRITICAL', 'Redact direct identifier',
                      '[TCKN_1]', '[TCKN_REDACTED]', 'pending', 'detector', 'leakfp1')
            """,
            (doc_id,),
        )
        conn.commit()
        conn.close()
        return doc_id, source_path

    def finding_id_for(self, doc_id: int, category: str) -> int:
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(
                "SELECT id FROM privacy_findings WHERE document_id = ? AND category = ?",
                (doc_id, category),
            ).fetchone()[0]
        finally:
            conn.close()

    def test_docx_export_blocks_finding_reverted_to_pending_after_redaction_was_marked_complete(self):
        # redaction_completed is a latch: reverting a finding to 'pending' does
        # not clear it, and redaction_targets_for_document() then drops that
        # finding from the targets. Both old gates (docx + redaction_completed)
        # still read as satisfied, so the export carried the TCKN in cleartext.
        doc_id, source_path = self.seed_leaky_docx_document()
        self.client.post(
            f"/api/document/{doc_id}/findings/review-batch",
            json={"action": "approve", "risks": ["CRITICAL"], "only_pending": True},
        )
        self.assertEqual(self.client.post(f"/api/document/{doc_id}/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/document/{doc_id}/review", json={"action": "approve"}).status_code, 200)

        exported = self.client.get(f"/api/document/{doc_id}/redacted-export?format=docx")
        self.assertEqual(exported.status_code, 200)
        with ZipFile(BytesIO(exported.data)) as archive:
            self.assertNotIn("10000000146", archive.read("word/document.xml").decode("utf-8"))

        finding_id = self.finding_id_for(doc_id, "turkish_national_id")
        reverted = self.client.post(f"/api/finding/{finding_id}/review", json={"action": "pending"})
        self.assertEqual(reverted.status_code, 200)
        self.assertEqual(reverted.json["review_status"], "pending")

        blocked = self.client.get(f"/api/document/{doc_id}/redacted-export?format=docx")
        self.assertEqual(blocked.status_code, 409)
        self.assertIn("Every privacy finding must be decided", blocked.json["error"])
        blocked_qa = self.client.get(f"/api/document/{doc_id}/redacted-export/qa?format=docx")
        self.assertEqual(blocked_qa.status_code, 409)

        # And the QA report itself must not call that export clean. Given only
        # the targets it can't see the reverted finding at all; given the
        # document's unrejected findings it can.
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        targets = app_module.redaction_targets_for_document(conn, doc_id)
        samples = app_module.sensitive_samples_for_document(conn, doc_id)
        conn.close()
        self.assertEqual(targets, [])
        self.assertIn("10000000146", samples)

        data = redact_docx(source_path, targets)
        blind_report = analyze_docx_export_quality(source_path, data, targets)
        self.assertEqual(blind_report["overall_status"], "pass")  # the blindness this fix is about
        self.assertEqual(blind_report["leakage_count"], 0)

        report = analyze_docx_export_quality(source_path, data, targets, sensitive_samples=samples)
        self.assertNotEqual(report["overall_status"], "pass")
        self.assertEqual(report["overall_status"], "fail")
        self.assertGreaterEqual(report["leakage_count"], 1)

    def test_docx_export_qa_measures_leakage_against_unrejected_findings(self):
        # A rejected finding is text a reviewer decided not to remove, so its
        # presence in the output is not leakage; an unrejected one is.
        doc_id, source_path = self.seed_leaky_docx_document(doc_id=5)
        self.client.post(
            f"/api/document/{doc_id}/findings/review-batch",
            json={"action": "reject", "risks": ["CRITICAL"], "only_pending": True},
        )
        self.assertEqual(self.client.post(f"/api/document/{doc_id}/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/document/{doc_id}/review", json={"action": "approve"}).status_code, 200)

        qa = self.client.get(f"/api/document/{doc_id}/redacted-export/qa?format=docx")
        self.assertEqual(qa.status_code, 200)
        self.assertEqual(qa.json["leakage_count"], 0)
        self.assertEqual(qa.json["sensitive_sample_count"], 0)
        self.assertEqual(qa.json["overall_status"], "pass")

    def test_docx_export_qa_states_deliberately_retained_identifiers(self):
        # 'retained' means the reviewer decided a real identifier stays in the
        # export, so its presence is not leakage and leakage_count is 0 by
        # construction. Without a distinct count the report would be an
        # unqualified "pass" on a DOCX that still carries a checksum-valid TCKN
        # in cleartext -- exactly the kind of clean-looking QA output the
        # sensitive-sample widening was introduced to prevent.
        doc_id, _ = self.seed_leaky_docx_document(doc_id=6)
        retained = self.client.post(
            f"/api/document/{doc_id}/findings/review-batch",
            json={"action": "retain", "risks": ["CRITICAL"], "only_pending": True},
        )
        self.assertEqual(retained.status_code, 200)
        self.assertEqual(retained.json["review_status"], "retained")
        self.assertEqual(self.client.post(f"/api/document/{doc_id}/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/document/{doc_id}/review", json={"action": "approve"}).status_code, 200)

        qa = self.client.get(f"/api/document/{doc_id}/redacted-export/qa?format=docx")
        self.assertEqual(qa.status_code, 200)
        self.assertEqual(qa.json["leakage_count"], 0)
        self.assertEqual(qa.json["retained_count"], 1)
        self.assertNotEqual(qa.json["overall_status"], "pass")
        retained_checks = [check for check in qa.json["checks"] if check["name"] == "Identifiers deliberately retained"]
        self.assertEqual(len(retained_checks), 1)
        self.assertEqual(retained_checks[0]["status"], "warn")
        self.assertIn("1 finding(s) were retained unredacted", retained_checks[0]["detail"])

        # And the evidence rows must not be stamped "verified redacted" either.
        conn = sqlite3.connect(self.db_path)
        statuses = {
            row[0]
            for row in conn.execute(
                "SELECT verification_status FROM finding_evidence WHERE document_id = ?", (doc_id,)
            )
        }
        conn.close()
        self.assertNotIn("redacted_verified", statuses)

    def approve_pdf_pipeline_and_export(self, doc_id: int = 3) -> None:
        """Drive document 3 through the PDF gates so a saved artifact exists."""
        generated = self.client.post(f"/api/document/{doc_id}/pdf/regions/generate", json={})
        self.assertEqual(generated.status_code, 200)
        for region in generated.json["regions"]:
            self.assertEqual(
                self.client.post(f"/api/document/{doc_id}/pdf/regions/{region['id']}/approve", json={}).status_code, 200
            )
        self.client.post(
            f"/api/document/{doc_id}/findings/review-batch",
            json={"action": "approve", "risks": ["HIGH", "CRITICAL"], "only_pending": True},
        )
        self.assertEqual(self.client.post(f"/api/document/{doc_id}/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/document/{doc_id}/review", json={"action": "approve"}).status_code, 200)
        exported = self.client.get(f"/api/document/{doc_id}/redacted-export?format=pdf&style=black_box")
        self.assertEqual(exported.status_code, 200)

    def test_saved_pdf_artifact_download_leaves_no_open_file_handle(self):
        # send_file(path) opens the file itself and only closes it when the
        # response is closed, so every download of the saved artifact leaked an
        # open handle (ResourceWarning: unclosed file). The warning is raised
        # from __del__, so it never fails a plain test run -- it has to be
        # collected explicitly.
        self.approve_pdf_pipeline_and_export()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            response = self.client.get("/api/document/3/pdf/export-artifact/latest")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content_type, "application/pdf")
            del response
            gc.collect()

        leaked = [str(item.message) for item in caught if item.category is ResourceWarning]
        self.assertEqual(leaked, [])

    def test_document_list_filters_reject_unusable_input_instead_of_failing(self):
        # Each of these used to reach the client as a 500: a quote broke the
        # FTS5 MATCH expression, and a non-numeric filter raised ValueError.
        quoted_search = self.client.get('/api/documents?search=a"')
        self.assertEqual(quoted_search.status_code, 200)
        plain_prefix = self.client.get("/api/documents?search=a")
        self.assertEqual(plain_prefix.status_code, 200)
        # The FTS5 tokenizer drops the quote, so an escaped `a"` has to behave
        # exactly like `a` rather than raising "unterminated string".
        self.assertEqual(
            [doc["id"] for doc in quoted_search.json["documents"]],
            [doc["id"] for doc in plain_prefix.json["documents"]],
        )

        embedded_quote = self.client.get('/api/documents?search=cle"an template')
        self.assertEqual(embedded_quote.status_code, 200)

        plain_search = self.client.get("/api/documents?search=clean")
        self.assertEqual(plain_search.status_code, 200)
        self.assertEqual([doc["filename"] for doc in plain_search.json["documents"]], ["clean.docx"])

        bad_category = self.client.get("/api/documents?category=abc")
        self.assertEqual(bad_category.status_code, 400)
        self.assertIn("numeric", bad_category.json["error"])

        bad_client = self.client.get("/api/documents?client=1;DROP")
        self.assertEqual(bad_client.status_code, 400)

        good_category = self.client.get("/api/documents?category=1")
        self.assertEqual(good_category.status_code, 200)

    def test_upload_rejects_a_file_over_the_size_cap(self):
        upload_dir = self.tmp_path / "uploads"
        with mock.patch.object(app_module, "UPLOAD_DIR", upload_dir):
            with mock.patch.object(app_module, "MAX_UPLOAD_BYTES", 16):
                response = self.client.post(
                    "/api/upload",
                    data={"file": (BytesIO(b"x" * 64), "too_big.txt")},
                    content_type="multipart/form-data",
                )

            self.assertEqual(response.status_code, 413)
            self.assertIn("larger than", response.json["error"])
            # Rejected before uploaded.save(), so nothing was written at all.
            self.assertEqual(sorted(upload_dir.glob("*")) if upload_dir.exists() else [], [])

            accepted = self.client.post(
                "/api/upload",
                data={"file": (BytesIO(b"x" * 64), "small_enough.txt")},
                content_type="multipart/form-data",
            )
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(len(list(upload_dir.glob("*small_enough.txt"))), 1)

    def test_upload_strips_html_breaking_characters_from_the_filename(self):
        # A double quote never survives the multipart Content-Disposition
        # header (werkzeug truncates the filename there), so the reachable
        # characters over HTTP are the apostrophe and the angle brackets; the
        # full set is covered by the unit test below.
        with mock.patch.object(app_module, "UPLOAD_DIR", self.tmp_path / "uploads"):
            response = self.client.post(
                "/api/upload",
                data={"file": (BytesIO(b"Public template"), "di\'lek<b>.txt")},
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 200)
        stored_name = response.json["filename"]
        for char in "\"'<>":
            self.assertNotIn(char, stored_name)
        self.assertEqual(stored_name, "dilekb.txt")

    def test_sanitized_display_filename_drops_every_html_breaking_character(self):
        self.assertEqual(sanitized_display_filename('a"b\'c<d>e.txt'), "abcde.txt")
        self.assertEqual(sanitized_display_filename('"\'<>'), "uploaded_document")
        self.assertEqual(sanitized_display_filename("normal_dosya.docx"), "normal_dosya.docx")

    def test_replacement_text_with_html_breaking_characters_is_rejected(self):
        finding_id = self.finding_id_for(1, "date")
        response = self.client.post(
            f"/api/finding/{finding_id}/review",
            json={"action": "approve", "replacement_text": '[DATE" onmouseover=x]'},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("quotes or angle brackets", response.json["error"])

        added = self.client.post(
            "/api/document/1/findings",
            json={"text": "Gizli metin", "replacement_text": "[X<script>]"},
        )
        self.assertEqual(added.status_code, 400)

        conn = sqlite3.connect(self.db_path)
        stored = conn.execute("SELECT replacement_text FROM privacy_findings WHERE id = ?", (finding_id,)).fetchone()[0]
        conn.close()
        self.assertEqual(stored, "[DATE_1]")

    def test_ocr_run_rejects_an_unknown_language(self):
        self.assertEqual(self.client.post("/api/document/2/ocr/queue", json={}).status_code, 200)

        response = self.client.post("/api/document/2/ocr/run", json={"language": "tur; rm -rf /"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported OCR language", response.json["error"])
        detail = self.client.get("/api/document/2")
        self.assertEqual(detail.json["ocr_status"], "queued")  # not left mid-flight in 'processing'

    def test_non_docx_actual_redacted_export_is_unsupported(self):
        response = self.client.get("/api/document/2/redacted-export?format=docx")
        self.assertEqual(response.status_code, 415)

        qa = self.client.get("/api/document/2/redacted-export/qa?format=docx")
        self.assertEqual(qa.status_code, 415)

    def test_pdf_regions_generate_review_export_and_qa(self):
        generated = self.client.post("/api/document/3/pdf/regions/generate", json={})
        self.assertEqual(generated.status_code, 200)
        self.assertGreaterEqual(generated.json["total"], 2)
        self.assertTrue(all(region["source"] == "detected_text" for region in generated.json["regions"]))

        blocked = self.client.get("/api/document/3/redacted-export?format=pdf&style=black_box")
        self.assertEqual(blocked.status_code, 409)

        for region in generated.json["regions"]:
            approved = self.client.post(f"/api/document/3/pdf/regions/{region['id']}/approve", json={})
            self.assertEqual(approved.status_code, 200)
        self.client.post("/api/document/3/findings/review-batch", json={"action": "approve", "risks": ["HIGH", "CRITICAL"], "only_pending": True})
        redacted = self.client.post("/api/document/3/review", json={"action": "mark_redacted"})
        self.assertEqual(redacted.status_code, 200)
        reviewed = self.client.post("/api/document/3/review", json={"action": "approve"})
        self.assertEqual(reviewed.status_code, 200)

        no_artifact_yet = self.client.get("/api/document/3/pdf/export-artifact/latest")
        self.assertEqual(no_artifact_yet.status_code, 404)

        qa = self.client.get("/api/document/3/redacted-export/qa?format=pdf&style=black_box")
        self.assertEqual(qa.status_code, 200)
        self.assertEqual(qa.json["format"], "pdf")
        self.assertEqual(qa.json["leakage_count"], 0)
        self.assertEqual(qa.json["leaked_regions"], [])
        self.assertEqual(qa.json["qa_target"], "freshly_generated")
        self.assertEqual(qa.json["annotation_count"], 0)
        self.assertEqual(qa.json["region_state"]["pending"], 0)
        check_names = {check["name"] for check in qa.json["checks"]}
        self.assertIn("No annotations or comments remain", check_names)
        self.assertIn("All PDF boxes reviewed", check_names)
        self.assertIn(qa.json["visual_qa"]["status"], {"rendered", "skipped"})

        exported = self.client.get("/api/document/3/redacted-export?format=pdf&style=black_box")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.content_type, "application/pdf")
        text = extract_pdf_text_from_bytes(exported.data)
        self.assertNotIn("Ayse Demir", text)
        self.assertNotIn("10000000146", text)

        artifacts = self.client.get("/api/document/3/artifacts")
        artifact_types = {artifact["artifact_type"] for artifact in artifacts.json["artifacts"]}
        self.assertIn("pdf_region_snapshot", artifact_types)
        self.assertIn("redacted_pdf", artifact_types)
        self.assertIn("pdf_qa", artifact_types)
        saved = [a for a in artifacts.json["artifacts"] if a["artifact_type"] == "redacted_pdf" and a.get("file_path")]
        self.assertTrue(saved)
        saved_path = Path(saved[0]["file_path"])
        self.assertTrue(saved_path.exists())
        self.assertTrue(saved_path.is_relative_to(app_module.EXPORT_DIR))
        self.assertNotIn("Ayse Demir", extract_pdf_text_from_bytes(saved_path.read_bytes()))

        latest = self.client.get("/api/document/3/pdf/export-artifact/latest")
        self.assertEqual(latest.status_code, 200)
        self.assertEqual(latest.content_type, "application/pdf")
        self.assertNotIn("10000000146", extract_pdf_text_from_bytes(latest.data))

        qa_after_export = self.client.get("/api/document/3/redacted-export/qa?format=pdf&style=black_box")
        self.assertEqual(qa_after_export.status_code, 200)
        self.assertEqual(qa_after_export.json["qa_target"], "saved_artifact")

        qa_latest = self.client.get("/api/document/3/pdf/qa/latest")
        self.assertEqual(qa_latest.status_code, 200)
        self.assertEqual(qa_latest.json["metadata"]["qa_target"], "saved_artifact")
        self.assertIn(qa_latest.json["qa_status"], {"pass", "warn"})

        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        viewer_blocked = viewer_client.get("/api/document/3/pdf/export-artifact/latest")
        self.assertEqual(viewer_blocked.status_code, 403)
        viewer_qa = viewer_client.get("/api/document/3/pdf/qa/latest")
        self.assertEqual(viewer_qa.status_code, 200)

    def test_pdf_manual_region_and_viewer_rbac(self):
        manual = self.client.post(
            "/api/document/3/pdf/regions",
            json={"page_number": 1, "rect": {"x0": 0.1, "y0": 0.1, "x1": 0.4, "y1": 0.16}, "category": "manual_sensitive_text"},
        )
        self.assertEqual(manual.status_code, 200)
        self.assertEqual(manual.json["regions"][0]["source"], "manual")

        duplicate = self.client.post(
            "/api/document/3/pdf/regions",
            json={"page_number": 1, "rect": {"x0": 0.1, "y0": 0.1, "x1": 0.4, "y1": 0.16}, "category": "manual_sensitive_text"},
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertIn("already exists", duplicate.json["error"])
        regions = self.client.get("/api/document/3/pdf/regions")
        self.assertEqual(regions.json["total"], 1)

        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        readable = viewer_client.get("/api/document/3/pdf/regions")
        self.assertEqual(readable.status_code, 200)
        blocked = viewer_client.post("/api/document/3/pdf/regions/generate", json={})
        self.assertEqual(blocked.status_code, 403)
        export = viewer_client.get("/api/document/3/redacted-export?format=pdf&style=black_box")
        self.assertEqual(export.status_code, 403)

    def test_pdf_region_batch_review_with_filters(self):
        generated = self.client.post("/api/document/3/pdf/regions/generate", json={})
        self.assertEqual(generated.status_code, 200)
        manual = self.client.post(
            "/api/document/3/pdf/regions",
            json={"page_number": 1, "rect": {"x0": 0.5, "y0": 0.5, "x1": 0.7, "y1": 0.55}, "category": "manual_sensitive_text"},
        )
        self.assertEqual(manual.status_code, 200)

        bad_action = self.client.post("/api/document/3/pdf/regions/review-batch", json={"action": "purge"})
        self.assertEqual(bad_action.status_code, 400)

        detected = self.client.post(
            "/api/document/3/pdf/regions/review-batch",
            json={"action": "approve", "source": "detected_text", "only_pending": True},
        )
        self.assertEqual(detected.status_code, 200)
        self.assertGreaterEqual(detected.json["updated"], 2)

        regions = self.client.get("/api/document/3/pdf/regions").json["regions"]
        for region in regions:
            expected = "approved" if region["source"] == "detected_text" else "pending"
            self.assertEqual(region["review_status"], expected)

        rejected = self.client.post(
            "/api/document/3/pdf/regions/review-batch",
            json={"action": "reject", "page_number": 1, "only_pending": True},
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.json["updated"], 1)

        noop = self.client.post(
            "/api/document/3/pdf/regions/review-batch",
            json={"action": "approve", "category": "no_such_category"},
        )
        self.assertEqual(noop.status_code, 200)
        self.assertEqual(noop.json["updated"], 0)

        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        blocked = viewer_client.post("/api/document/3/pdf/regions/review-batch", json={"action": "approve"})
        self.assertEqual(blocked.status_code, 403)

    def make_blank_scan_pdf(self):
        scan_path = self.tmp_path / "scan.pdf"
        doc = fitz.open()
        doc.new_page()
        doc.save(scan_path)
        doc.close()
        return scan_path

    def ocr_tokens_payload(self):
        words = ["Av.", "Ayse", "Demir", "TCKN", "10000000146", "Sorusturma", "No:", "2026/456"]
        tokens = []
        x = 0.1
        for word in words:
            width = 0.02 + 0.012 * len(word)
            tokens.append({"text": word, "x0": x, "y0": 0.2, "x1": x + width, "y1": 0.23, "confidence": 0.94})
            x += width + 0.01
        return {
            "pages": [
                {
                    "page_number": 1,
                    "text": "Av. Ayse Demir TCKN 10000000146 Sorusturma No: 2026/456",
                    "confidence": 0.94,
                    "tokens": tokens,
                }
            ]
        }

    def drive_ocr_pdf_to_reviewable_regions(self) -> list[dict]:
        """Doc 2 through OCR run/accept, returning its generated PDF regions.

        The OCR accept path is what creates the finding_evidence rows the export
        QA later stamps, so the retained-identifier tests below have to come
        through here rather than seeding evidence by hand.
        """
        self.make_blank_scan_pdf()
        self.assertEqual(self.client.post("/api/document/2/ocr/queue", json={}).status_code, 200)
        self.assertEqual(self.client.post("/api/document/2/ocr/run", json=self.ocr_tokens_payload()).status_code, 200)
        self.assertEqual(self.client.post("/api/document/2/ocr/accept", json={}).status_code, 200)
        regions = self.client.get("/api/document/2/pdf/regions").json["regions"]
        self.assertTrue(regions)
        return regions

    def evidence_verification_statuses(self, doc_id: int) -> set[str]:
        conn = sqlite3.connect(self.db_path)
        statuses = {
            row[0]
            for row in conn.execute(
                "SELECT verification_status FROM finding_evidence WHERE document_id = ?", (doc_id,)
            )
        }
        conn.close()
        return statuses

    def critical_finding_id(self, doc_id: int) -> int:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT id FROM privacy_findings WHERE document_id = ? AND category = 'turkish_national_id'",
            (doc_id,),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        return row[0]

    def test_pdf_export_qa_states_deliberately_retained_identifiers(self):
        # The PDF twin of test_docx_export_qa_states_deliberately_retained_identifiers.
        # 'retained' means the reviewer decided a real identifier stays in the
        # export, so it is excluded from the leakage set and leakage_count is 0
        # by construction. Keying the finding_evidence write off leakage_count
        # alone therefore stamped "verified redacted" on a PDF the reviewer had
        # just chosen to leave a national ID in.
        regions = self.drive_ocr_pdf_to_reviewable_regions()
        tckn_finding_id = self.critical_finding_id(2)

        # The box over the retained identifier is rejected -- a reviewer who
        # keeps the text does not black it out -- and the rest are approved, so
        # the export still has an approved box and clears the PDF gates.
        rejected = 0
        for region in regions:
            action = "reject" if region["finding_id"] == tckn_finding_id else "approve"
            rejected += action == "reject"
            self.assertEqual(
                self.client.post(f"/api/document/2/pdf/regions/{region['id']}/{action}", json={}).status_code, 200
            )
        self.assertTrue(rejected)

        # One finding retained, by id: doc 2 carries two CRITICAL findings, and
        # retaining by risk would make the "1 finding(s)" wording below pass for
        # the wrong reason.
        retained = self.client.post(f"/api/finding/{tckn_finding_id}/review", json={"action": "retain"})
        self.assertEqual(retained.status_code, 200)
        self.client.post(
            "/api/document/2/findings/review-batch",
            json={"action": "approve", "risks": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "only_pending": True},
        )
        self.assertEqual(self.client.post("/api/document/2/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post("/api/document/2/review", json={"action": "approve"}).status_code, 200)
        self.assertEqual(self.client.get("/api/document/2/redacted-export?format=pdf&style=black_box").status_code, 200)

        # leakage_count is 0 here BY CONSTRUCTION, not because the identifier
        # was removed: a retained sample is excluded from the leakage set, and
        # its box was rejected, so nothing in the QA looks for it at all.
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        self.assertNotIn("10000000146", app_module.sensitive_samples_for_document(conn, 2))
        conn.close()

        qa = self.client.get("/api/document/2/redacted-export/qa?format=pdf&style=black_box")
        self.assertEqual(qa.status_code, 200)
        self.assertEqual(qa.json["leakage_count"], 0)
        self.assertEqual(qa.json["retained_count"], 1)
        self.assertNotEqual(qa.json["overall_status"], "pass")
        retained_checks = [check for check in qa.json["checks"] if check["name"] == "Identifiers deliberately retained"]
        self.assertEqual(len(retained_checks), 1)
        self.assertEqual(retained_checks[0]["status"], "warn")
        self.assertIn("1 finding(s) were retained unredacted", retained_checks[0]["detail"])

        # The report warning is not the point on its own -- this write is.
        statuses = self.evidence_verification_statuses(2)
        self.assertTrue(statuses)  # there are evidence rows to stamp
        self.assertNotIn("redacted_verified", statuses)

    def test_pdf_export_qa_verifies_an_export_with_nothing_retained(self):
        # Anti-vacuity for the test above: with every finding approved and no
        # leakage the stamp must still be applied, or "not verified" would be
        # unfalsifiable and the check above would prove nothing.
        regions = self.drive_ocr_pdf_to_reviewable_regions()
        for region in regions:
            self.assertEqual(
                self.client.post(f"/api/document/2/pdf/regions/{region['id']}/approve", json={}).status_code, 200
            )
        self.client.post(
            "/api/document/2/findings/review-batch",
            json={"action": "approve", "risks": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "only_pending": True},
        )
        self.assertEqual(self.client.post("/api/document/2/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post("/api/document/2/review", json={"action": "approve"}).status_code, 200)
        self.assertEqual(self.client.get("/api/document/2/redacted-export?format=pdf&style=black_box").status_code, 200)

        qa = self.client.get("/api/document/2/redacted-export/qa?format=pdf&style=black_box")
        self.assertEqual(qa.status_code, 200)
        self.assertEqual(qa.json["leakage_count"], 0)
        self.assertEqual(qa.json["retained_count"], 0)
        retained_checks = [check for check in qa.json["checks"] if check["name"] == "Identifiers deliberately retained"]
        self.assertEqual([check["status"] for check in retained_checks], ["pass"])

        self.assertIn("redacted_verified", self.evidence_verification_statuses(2))

    def test_scanned_pdf_ocr_tokens_generate_regions_and_export(self):
        self.make_blank_scan_pdf()
        self.assertEqual(self.client.post("/api/document/2/ocr/queue", json={}).status_code, 200)
        run = self.client.post("/api/document/2/ocr/run", json=self.ocr_tokens_payload())
        self.assertEqual(run.status_code, 200)

        accept = self.client.post("/api/document/2/ocr/accept", json={})
        self.assertEqual(accept.status_code, 200)

        regions = self.client.get("/api/document/2/pdf/regions").json["regions"]
        self.assertTrue(regions)
        self.assertTrue(all(region["source"] == "ocr" for region in regions))
        self.assertTrue(all(region["finding_id"] for region in regions))
        self.assertTrue(all(region["review_status"] == "pending" for region in regions))

        blocked = self.client.get("/api/document/2/redacted-export?format=pdf&style=black_box")
        self.assertEqual(blocked.status_code, 409)

        approved = self.client.post(
            "/api/document/2/pdf/regions/review-batch",
            json={"action": "approve", "source": "ocr", "only_pending": True},
        )
        self.assertEqual(approved.status_code, 200)
        self.assertGreaterEqual(approved.json["updated"], 2)
        self.client.post(
            "/api/document/2/findings/review-batch",
            json={"action": "approve", "risks": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "only_pending": True},
        )
        self.assertEqual(self.client.post("/api/document/2/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post("/api/document/2/review", json={"action": "approve"}).status_code, 200)

        exported = self.client.get("/api/document/2/redacted-export?format=pdf&style=black_box")
        self.assertEqual(exported.status_code, 200)
        qa = self.client.get("/api/document/2/redacted-export/qa?format=pdf&style=black_box")
        self.assertEqual(qa.status_code, 200)
        self.assertEqual(qa.json["leakage_count"], 0)

    def test_ocr_without_coordinates_fails_closed_for_pdf_export(self):
        self.make_blank_scan_pdf()
        self.assertEqual(self.client.post("/api/document/2/ocr/queue", json={}).status_code, 200)
        run = self.client.post(
            "/api/document/2/ocr/run",
            json={"text": "Av. Ayse Demir TCKN 10000000146", "confidence": 0.9},
        )
        self.assertEqual(run.status_code, 200)
        self.assertEqual(self.client.post("/api/document/2/ocr/accept", json={}).status_code, 200)

        self.assertEqual(self.client.get("/api/document/2/pdf/regions").json["total"], 0)
        self.client.post(
            "/api/document/2/findings/review-batch",
            json={"action": "approve", "risks": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "only_pending": True},
        )
        self.assertEqual(self.client.post("/api/document/2/review", json={"action": "mark_redacted"}).status_code, 200)
        self.assertEqual(self.client.post("/api/document/2/review", json={"action": "approve"}).status_code, 200)

        blocked = self.client.get("/api/document/2/redacted-export?format=pdf&style=black_box")
        self.assertEqual(blocked.status_code, 409)

        manual = self.client.post(
            "/api/document/2/pdf/regions",
            json={"page_number": 1, "rect": {"x0": 0.1, "y0": 0.18, "x1": 0.9, "y1": 0.26}, "category": "manual_sensitive_text"},
        )
        self.assertEqual(manual.status_code, 200)
        region_id = manual.json["regions"][0]["id"]
        still_blocked = self.client.get("/api/document/2/redacted-export?format=pdf&style=black_box")
        self.assertEqual(still_blocked.status_code, 409)

        self.assertEqual(self.client.post(f"/api/document/2/pdf/regions/{region_id}/approve", json={}).status_code, 200)
        exported = self.client.get("/api/document/2/redacted-export?format=pdf&style=black_box")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.content_type, "application/pdf")

    def test_documents_api_pagination_and_backward_compat(self):
        unpaged = self.client.get("/api/documents")
        self.assertEqual(unpaged.status_code, 200)
        total = unpaged.json["total"]
        self.assertGreaterEqual(total, 3)
        self.assertNotIn("pages", unpaged.json)
        self.assertEqual(len(unpaged.json["documents"]), total)

        page1 = self.client.get("/api/documents?page=1&page_size=2")
        self.assertEqual(page1.status_code, 200)
        self.assertEqual(page1.json["total"], total)
        self.assertEqual(len(page1.json["documents"]), 2)
        self.assertEqual(page1.json["pages"], -(-total // 2))

        page2 = self.client.get("/api/documents?page=2&page_size=2")
        self.assertEqual(page2.status_code, 200)
        page1_ids = {d["id"] for d in page1.json["documents"]}
        page2_ids = {d["id"] for d in page2.json["documents"]}
        self.assertFalse(page1_ids & page2_ids)

        filtered = self.client.get("/api/documents?page=1&page_size=50&review_status=needs_ocr")
        self.assertEqual(filtered.status_code, 200)
        self.assertTrue(all(d["review_status"] == "needs_ocr" for d in filtered.json["documents"]))
        self.assertEqual(filtered.json["total"], len(filtered.json["documents"]))

        bad = self.client.get("/api/documents?page=abc&page_size=xyz")
        self.assertEqual(bad.status_code, 200)

    def seed_failed_zip_document(self, doc_id=90):
        import zipfile as zf
        inner = self.tmp_path / "inner.docx"
        make_docx(inner, "Muvekkil Ayse Demir TCKN 10000000146")
        bundle = self.tmp_path / "bundle.zip"
        with zf.ZipFile(bundle, "w") as archive:
            archive.write(inner, "docs/inner.docx")
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            INSERT INTO documents (
                id, filename, filepath, file_extension, file_size, title, extraction_warning,
                extraction_status, privacy_profile, residual_risk, risk_summary, recommended_strategy,
                external_llm_readiness, human_review_required, redaction_status, review_status, ocr_status
            ) VALUES (?, 'bundle.zip', ?, '.zip', ?, 'bundle', 'Text extraction is not enabled for this file type.',
                      'Failed', '{}', 'Unknown', 'x', 'x', 'Blocked', 1, 'none', 'needs_ocr', 'queued')
            """,
            (doc_id, str(bundle), bundle.stat().st_size),
        )
        conn.commit()
        conn.close()
        return doc_id

    def test_reextract_recovers_failed_zip_document(self):
        doc_id = self.seed_failed_zip_document()

        response = self.client.post(f"/api/document/{doc_id}/reextract", json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["extraction_status"], "Complete")
        self.assertEqual(response.json["review_status"], "pending_review")
        self.assertEqual(response.json["ocr_status"], "not_required")
        samples = {f["sample"] for f in response.json["findings"]}
        self.assertIn("10000000146", samples)
        artifact_types = {a["artifact_type"] for a in response.json["artifacts"]}
        self.assertIn("reextraction", artifact_types)

    def test_reextract_blocked_for_ocr_accepted_documents(self):
        self.make_blank_scan_pdf()
        self.client.post("/api/document/2/ocr/queue", json={})
        self.client.post("/api/document/2/ocr/run", json={"text": "Av. Ayse Demir", "confidence": 0.9})
        self.client.post("/api/document/2/ocr/accept", json={})

        blocked = self.client.post("/api/document/2/reextract", json={})
        self.assertEqual(blocked.status_code, 409)
        self.assertIn("OCR", blocked.json["error"])

    def test_bulk_reextract_failed_documents(self):
        self.seed_failed_zip_document(doc_id=91)

        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        self.assertEqual(viewer_client.post("/api/documents/reextract-failed", json={}).status_code, 403)

        response = self.client.post("/api/documents/reextract-failed", json={})
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json["attempted"], 2)
        self.assertGreaterEqual(response.json["recovered"], 1)
        self.assertGreaterEqual(response.json["missing_file"], 1)

    def test_ocr_queue_only_for_incomplete_extraction(self):
        complete = self.client.post("/api/document/1/ocr/queue", json={})
        self.assertEqual(complete.status_code, 409)

        failed = self.client.post("/api/document/2/ocr/queue", json={})
        self.assertEqual(failed.status_code, 200)
        self.assertEqual(failed.json["ocr_status"], "queued")
        self.assertEqual(failed.json["review_status"], "needs_ocr")

    def test_completed_ocr_blocks_redaction_until_accepted(self):
        run = self.client.post(
            "/api/document/2/ocr/run",
            json={"text": "Av. Ayse Demir icin Soruşturma No: 2026/456 bulundu.", "confidence": 0.98},
        )
        self.assertEqual(run.status_code, 200)
        self.assertEqual(run.json["ocr_status"], "completed")

        blocked = self.client.post("/api/document/2/review", json={"action": "mark_redacted"})
        self.assertEqual(blocked.status_code, 409)
        self.assertIn("OCR output must be accepted", blocked.json["error"])

    def test_accepting_ocr_reruns_detection_with_ocr_source(self):
        self.client.post(
            "/api/document/2/ocr/run",
            json={"text": "Av. Ayse Demir icin Soruşturma No: 2026/456 bulundu.", "confidence": 0.98},
        )
        accepted = self.client.post("/api/document/2/ocr/accept", json={"reviewer_note": "Readable scan"})
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json["ocr_status"], "accepted")
        self.assertEqual(accepted.json["extraction_status"], "Complete")
        self.assertGreater(accepted.json["ocr_summary"]["ocr_finding_count"], 0)
        self.assertTrue(any(finding["source"] == "ocr" for finding in accepted.json["findings"]))

    def test_rejected_ocr_does_not_create_findings(self):
        self.client.post(
            "/api/document/2/ocr/run",
            json={"text": "Av. Ayse Demir icin Soruşturma No: 2026/456 bulundu.", "confidence": 0.98},
        )
        rejected = self.client.post("/api/document/2/ocr/reject", json={"reviewer_note": "Unreadable"})
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.json["ocr_status"], "rejected")
        self.assertEqual(rejected.json["ocr_summary"]["ocr_finding_count"], 0)
        self.assertFalse(any(finding["source"] == "ocr" for finding in rejected.json["findings"]))

    def test_unauthenticated_api_is_blocked(self):
        anonymous_client = app_module.app.test_client()
        response = anonymous_client.get("/api/documents")
        self.assertEqual(response.status_code, 401)

    def test_viewer_can_read_but_cannot_review_or_export(self):
        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)

        readable = viewer_client.get("/api/documents")
        self.assertEqual(readable.status_code, 200)

        matters = viewer_client.get("/api/matters")
        self.assertEqual(matters.status_code, 200)

        matrix = viewer_client.get("/api/matter/1/review-matrix")
        self.assertEqual(matrix.status_code, 200)

        review = viewer_client.post("/api/document/1/review", json={"action": "approve"})
        self.assertEqual(review.status_code, 403)

        # The reviewer-only download. (This used to check the lower-assurance
        # `/export?format=txt` preview, which no longer exists; the role
        # boundary it was covering is the one asserted here.)
        export = viewer_client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(export.status_code, 403)

        audit = viewer_client.get("/api/audit-log")
        self.assertEqual(audit.status_code, 403)

        create_matter = viewer_client.post("/api/matters", json={"name": "Viewer Matter"})
        self.assertEqual(create_matter.status_code, 403)

        assign = viewer_client.post("/api/document/1/matter", json={"matter_id": 1})
        self.assertEqual(assign.status_code, 403)

    def test_api_me_reports_role_for_navigation(self):
        response = self.client.get("/api/me")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["authenticated"])
        self.assertEqual(response.json["user"]["role"], "reviewer")

    def test_workstation_shell_is_role_aware(self):
        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        viewer_home = viewer_client.get("/")
        self.assertEqual(viewer_home.status_code, 200)
        self.assertIn(b"Redact AI", viewer_home.data)
        self.assertIn(b"Matters", viewer_home.data)
        self.assertIn(b"Viewer role is read-only", viewer_home.data)
        self.assertNotIn(b"Upload & Analyze", viewer_home.data)
        self.assertNotIn(b"Audit Log", viewer_home.data)

        reviewer_home = self.client.get("/")
        self.assertEqual(reviewer_home.status_code, 200)
        self.assertIn(b"Upload & Analyze", reviewer_home.data)
        self.assertIn(b"Privacy-reviewed legal workflow", reviewer_home.data)

        admin_client = app_module.app.test_client()
        self.login("admin", client=admin_client)
        admin_home = admin_client.get("/")
        self.assertEqual(admin_home.status_code, 200)
        self.assertIn(b"Audit Log", admin_home.data)
        self.assertIn(b"Settings", admin_home.data)

    def test_admin_can_access_audit_log_without_sensitive_metadata(self):
        add = self.client.post(
            "/api/document/1/findings",
            json={"text": "Sensitive Original", "category": "manual_sensitive_text", "replacement_text": "[MASKED]"},
        )
        self.assertEqual(add.status_code, 200)

        admin_client = app_module.app.test_client()
        self.login("admin", client=admin_client)
        response = admin_client.get("/api/audit-log?action=finding.add_manual")
        self.assertEqual(response.status_code, 200)
        metadata = response.json["audit_log"][0]["metadata"]
        self.assertNotIn("Sensitive Original", metadata)
        self.assertNotIn("[MASKED]", metadata)

    def test_reviewer_can_upload_and_analyze_document(self):
        response = self.client.post(
            "/api/upload",
            data={
                "file": (
                    BytesIO("Av. Ayse Demir T.C. Kimlik No: 10000000146".encode("utf-8")),
                    "yeni_dilekce.txt",
                )
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["filename"], "yeni_dilekce.txt")
        self.assertEqual(response.json["file_extension"], ".txt")
        self.assertTrue(response.json["filepath"].endswith("yeni_dilekce.txt"))
        self.assertEqual(response.json["matter"]["name"], "Unassigned")
        self.assertTrue(any(finding["category"] == "turkish_national_id" for finding in response.json["findings"]))
        self.assertTrue(any(artifact["artifact_type"] == "original_upload" for artifact in response.json["artifacts"]))

        stored_path = Path(response.json["filepath"])
        self.assertTrue(stored_path.exists())

        admin_client = app_module.app.test_client()
        self.login("admin", client=admin_client)
        audit = admin_client.get("/api/audit-log?action=document.upload")
        self.assertEqual(audit.status_code, 200)
        self.assertGreaterEqual(audit.json["total"], 1)

    def test_address_context_boundary_survives_review_preview_and_docx_export(self):
        for trigger, category in (
            ("hasta", "health_data"),
            ("şüpheli", "criminal_allegation"),
            ("ticari sır", "privileged_or_confidential"),
        ):
            with self.subTest(trigger=trigger):
                text = f"{trigger} Gül Sok. 5 adresinde ikamet etmektedir"
                source = self.tmp_path / "boundary.docx"
                make_docx(source, text)
                with mock.patch.object(app_module, "UPLOAD_DIR", self.tmp_path / "uploads"):
                    uploaded = self.client.post(
                        "/api/upload",
                        data={"file": (BytesIO(source.read_bytes()), source.name)},
                        content_type="multipart/form-data",
                    )
                self.assertEqual(uploaded.status_code, 200)
                doc = uploaded.json
                base = f"/api/document/{doc['id']}"
                address = [f for f in doc["findings"] if f["category"] == "address"]
                self.assertEqual([(f["sample"], f["start_offset"], f["end_offset"]) for f in address],
                                 [("Gül Sok", len(trigger) + 1, len(trigger) + 8)])
                contexts = [f for f in doc["findings"] if f["category"] == category]
                leading = [f for f in contexts if f["sample"] == trigger]
                self.assertEqual(len(leading), 1, contexts)
                self.assertEqual((leading[0]["start_offset"], leading[0]["end_offset"]), (0, len(trigger)))
                self.assertEqual(leading[0]["risk"], "CRITICAL")
                # The clause after the address keeps a CRITICAL finding, and it
                # starts on the "5" -- not on the "Sok." period the address rule
                # leaves outside its own span. No finding reaching a reviewer
                # may open on whitespace or a clause separator.
                tail_start = text.index(". 5") + len(". ")
                tail = [f for f in contexts
                        if (f["start_offset"], f["end_offset"]) == (tail_start, len(text))]
                self.assertEqual(len(tail), 1, contexts)
                self.assertEqual([], [f["sample"] for f in doc["findings"]
                                      if f["sample"][:1] in ".,;: "])

                preview = doc["privacy_profile"]["redacted_preview"]
                self.assertIn(leading[0]["replacement_text"], preview)
                self.assertIn(address[0]["replacement_text"], preview)
                self.assertNotIn(trigger, preview)
                self.assertNotIn("Gül Sok", preview)

                # The three invariants above are measured on the detector's own
                # output. They are only worth anything if they survive to what
                # the reviewer decides against and to what the reviewer
                # receives, so they are re-asserted on both of those surfaces.
                #
                # This used to be `GET /export?format=txt` compared against the
                # detection-time `redacted_preview` string. That route is gone:
                # it was the ungated "Preview TXT (lower assurance)" download,
                # and it handed out a file named `<name>_redacted.txt` headed
                # "PRIVACY-REVIEWED REDACTED EXPORT" whose body, before any
                # review decision, was the complete unredacted source. What
                # remains is the contract the shared resolver established -- the
                # review canvas and the exported reviewed DOCX are one
                # rendering -- so the guarantee is pinned there instead, on both
                # sides of review. Do NOT re-point this at `redacted_preview`
                # alone: that snapshot is taken at detection time and moves with
                # the detector, so it agrees with a broken boundary just as
                # readily as with a correct one.
                pre_review = self.canvas_segments(doc["id"])
                # (i) the address span the reviewer can see and click begins AT
                #     the address, not inside the trigger word before it;
                self.assertEqual(
                    [(s["start"], s["end"], s["source_text"]) for s in pre_review if s["category"] == "address"],
                    [(len(trigger) + 1, len(trigger) + 8, "Gül Sok")], pre_review)
                # (ii) the trigger keeps a span of its own, carrying the CRITICAL
                #      finding that covers it whole -- it is not folded into the
                #      HIGH address span next to it;
                trigger_span = self.segment_covering(pre_review, 0)
                self.assertEqual((trigger_span["start"], trigger_span["end"], trigger_span["source_text"]),
                                 (0, len(trigger), trigger), pre_review)
                self.assertIn(leading[0]["id"], trigger_span["finding_ids"], pre_review)
                # (iii) nothing the reviewer is shown as a finding opens on
                #       whitespace or a clause separator.
                self.assertEqual([], [s["source_text"] for s in pre_review
                                      if s["kind"] != "text" and s["source_text"][:1] in ".,;: "], pre_review)
                self.assertEqual(self.client.get(base + "/redacted-export?format=docx").status_code, 409)

                # Deciding the address alone cannot clear the context finding.
                reviewed = self.client.post(f"/api/finding/{address[0]['id']}/review", json={"action": "approve"})
                self.assertEqual(reviewed.status_code, 200)
                self.assertEqual(self.client.post(base + "/review", json={"action": "mark_redacted"}).status_code, 409)
                pending = self.client.get(base).json["privacy_profile"]["external_llm_gate"]
                self.assertFalse(pending["allowed"])
                self.assertGreater(pending["critical_count"], 0)

                reviewed = self.client.post(base + "/findings/review-batch", json={"action": "approve"})
                self.assertEqual(reviewed.status_code, 200)
                self.assertEqual(self.client.post(base + "/review", json={"action": "mark_redacted"}).status_code, 200)
                self.assertEqual(self.client.get(base + "/redacted-export?format=docx").status_code, 409)
                self.assertEqual(self.client.post(base + "/review", json={"action": "approve"}).status_code, 200)
                with self.client.get(base + "/redacted-export?format=docx") as exported:
                    self.assertEqual(exported.status_code, 200)
                    with ZipFile(BytesIO(exported.data)) as archive:
                        xml = ElementTree.fromstring(archive.read("word/document.xml"))
                        exported_text = "".join(xml.itertext()).strip()
                # The same three invariants, now on the delivered rendering. The
                # canvas and the exported DOCX are the same resolved text, and
                # in it each of the trigger, the address and the tail clause
                # leaves the document under its OWN placeholder over its own
                # exact span. The trigger under a CRITICAL context placeholder
                # rather than swallowed into the HIGH `[ADDRESS_*]` one is the
                # whole of PR #11's guarantee, stated where it is cashed.
                delivered = self.canvas_segments(doc["id"])
                self.assertEqual("".join(s["text"] for s in delivered), exported_text)
                self.assertEqual(
                    [(s["start"], s["end"], s["source_text"], s["text"]) for s in delivered
                     if s["kind"] == "redacted"],
                    [(0, len(trigger), trigger, leading[0]["replacement_text"]),
                     (len(trigger) + 1, len(trigger) + 8, "Gül Sok", address[0]["replacement_text"]),
                     (tail_start, len(text), text[tail_start:], tail[0]["replacement_text"])],
                    delivered)
                self.assertEqual([], [s["source_text"] for s in delivered
                                      if s["kind"] != "text" and s["source_text"][:1] in ".,;: "], delivered)
                # Everything was approved, so the post-decision rendering and the
                # detection-time snapshot must now coincide as well.
                self.assertEqual(exported_text, preview)
                qa = self.client.get(base + "/redacted-export/qa?format=docx")
                self.assertEqual(qa.status_code, 200)
                self.assertEqual((qa.json["leakage_count"], qa.json["unapplied_target_count"]), (0, 0))

                conn = sqlite3.connect(self.db_path)
                try:
                    metadata = " ".join(row[0] or "" for row in conn.execute(
                        "SELECT metadata FROM audit_log WHERE document_id = ?", (doc["id"],)))
                finally:
                    conn.close()
                for finding in doc["findings"]:
                    self.assertNotIn(finding["sample"], metadata)
                    self.assertNotIn(finding["replacement_text"], metadata)

    def test_upload_requires_reviewer_role(self):
        anonymous_client = app_module.app.test_client()
        anonymous = anonymous_client.post(
            "/api/upload",
            data={"file": (BytesIO(b"test"), "test.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(anonymous.status_code, 401)

        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        viewer = viewer_client.post(
            "/api/upload",
            data={"file": (BytesIO(b"test"), "test.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(viewer.status_code, 403)

    def test_upload_blocks_unsupported_file_type(self):
        response = self.client.post(
            "/api/upload",
            data={"file": (BytesIO(b"not supported"), "script.exe")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 415)

    def test_matter_workspace_create_assign_upload_and_matrix(self):
        created = self.client.post("/api/matters", json={"name": "Acme Privacy Review", "description": "Quarterly review"})
        self.assertEqual(created.status_code, 200)
        matter_id = created.json["id"]

        assigned = self.client.post("/api/document/1/matter", json={"matter_id": matter_id})
        self.assertEqual(assigned.status_code, 200)
        self.assertEqual(assigned.json["matter"]["id"], matter_id)

        matters = self.client.get("/api/matters")
        self.assertEqual(matters.status_code, 200)
        self.assertTrue(any(matter["name"] == "Acme Privacy Review" for matter in matters.json["matters"]))

        detail = self.client.get(f"/api/matter/{matter_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json["summary"]["document_count"], 1)

        matrix = self.client.get(f"/api/matter/{matter_id}/review-matrix")
        self.assertEqual(matrix.status_code, 200)
        self.assertGreaterEqual(matrix.json["total"], 1)
        self.assertTrue(any(row["filename"] == "clean.docx" for row in matrix.json["rows"]))

        upload = self.client.post(
            "/api/upload",
            data={
                "matter_id": str(matter_id),
                "file": (BytesIO("Av. Ayse Demir".encode("utf-8")), "matter_doc.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 200)
        self.assertEqual(upload.json["matter"]["id"], matter_id)

    def test_matter_pages_render(self):
        matters_page = self.client.get("/matters")
        self.assertEqual(matters_page.status_code, 200)
        self.assertIn(b"Matters", matters_page.data)

        matter_page = self.client.get("/matter/1")
        self.assertEqual(matter_page.status_code, 200)
        self.assertIn(b"Review Matrix", matter_page.data)

    def test_studio_workspace_renders_for_viewer(self):
        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)

        response = viewer_client.get("/studio/1")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Redaction Studio", response.data)
        self.assertIn(b"Findings", response.data)
        self.assertIn(b"Read-only Access", response.data)
        self.assertNotIn(b"Reviewed DOCX redaction", response.data)
        self.assertNotIn(b"Approve Low/Medium", response.data)

    def test_document_text_endpoint_returns_extracted_text(self):
        response = self.client.get("/api/document/1/text")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["source"], "extraction")
        self.assertIn("Public template", response.json["text"])

        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        viewer_response = viewer_client.get("/api/document/1/text")
        self.assertEqual(viewer_response.status_code, 200)

        missing = self.client.get("/api/document/999/text")
        self.assertEqual(missing.status_code, 404)

    def test_document_text_endpoint_prefers_accepted_ocr_text(self):
        self.make_blank_scan_pdf()
        self.client.post("/api/document/2/ocr/queue", json={})
        self.client.post("/api/document/2/ocr/run", json={"text": "Av. Ayse Demir TCKN 10000000146", "confidence": 0.9})
        self.client.post("/api/document/2/ocr/accept", json={})

        response = self.client.get("/api/document/2/text")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["source"], "ocr_accepted")
        self.assertIn("Ayse Demir", response.json["text"])

    def test_studio_renders_document_view_and_export_gate(self):
        page = self.client.get("/studio/1")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'class="workspace-panel workspace-left"', page.data)
        self.assertIn(b'class="workspace-panel workspace-center', page.data)
        self.assertIn(b'class="workspace-panel review-assistant"', page.data)
        self.assertIn(b'id="matterDocumentSearch"', page.data)
        self.assertIn(b'id="assistantCurrentFinding"', page.data)
        # One review pane, no mode switcher. The three panes it replaced were
        # all mounted at once and differed in capability, so choosing between
        # them was a decision the reviewer should never have had to make.
        self.assertIn(b'id="reviewPane"', page.data)
        self.assertIn(b'id="reviewGroups"', page.data)
        for retired in (b"guidedModeButton", b"groupModeButton", b"bulkModeButton", b"setReviewMode"):
            self.assertNotIn(retired, page.data, retired.decode("utf-8"))
        self.assertEqual(page.data.count(b'class="panel-resizer"'), 2)
        self.assertIn(b'id="docPaper"', page.data)
        self.assertIn(b'id="exportGatePanel"', page.data)
        self.assertIn(b'id="docStyleToggle"', page.data)
        self.assertIn(b'id="manualText"', page.data)
        self.assertIn(b'id="reviewActionsPanel"', page.data)
        self.assertIn(b"/api/document/", page.data)

    def test_studio_pdf_review_controls_are_role_aware(self):
        reviewer_page = self.client.get("/studio/3")
        self.assertEqual(reviewer_page.status_code, 200)
        self.assertIn(b'id="pdfDrawCategory"', reviewer_page.data)
        self.assertIn(b'id="pdfSelectionPanel"', reviewer_page.data)
        self.assertIn(b"pdf/regions/review-batch", reviewer_page.data)
        self.assertIn(b'id="pdfPageInput"', reviewer_page.data)
        self.assertIn(b'id="pdfShowAllBtn"', reviewer_page.data)

        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        viewer_page = viewer_client.get("/studio/3")
        self.assertEqual(viewer_page.status_code, 200)
        self.assertIn(b'id="pdfPageInput"', viewer_page.data)
        self.assertNotIn(b'id="pdfDrawCategory"', viewer_page.data)
        self.assertNotIn(b'id="pdfSelectionPanel"', viewer_page.data)

    def test_studio_pdf_viewer_is_served_locally(self):
        response = self.client.get("/studio/3")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"/static/vendor/pdfjs/pdf.min.js", response.data)
        self.assertIn(b"/static/vendor/pdfjs/pdf.worker.min.js", response.data)
        self.assertNotIn(b"cdnjs.cloudflare.com", response.data)

        for asset in ("vendor/pdfjs/pdf.min.js", "vendor/pdfjs/pdf.worker.min.js"):
            served = self.client.get(f"/static/{asset}")
            self.assertEqual(served.status_code, 200, asset)
            self.assertGreater(len(served.data), 100_000, asset)
            served.close()

    def test_workspace_opening_and_rendering_contracts(self):
        matter = self.client.get("/api/matter/1")
        self.assertEqual(matter.status_code, 200)
        self.assertEqual({document["id"] for document in matter.json["documents"]}, {1, 2, 3})

        docx_page = self.client.get("/studio/1")
        self.assertEqual(docx_page.status_code, 200)
        self.assertIn(b'id="docPaper"', docx_page.data)
        self.assertIn(b'id="docViewToggle"', docx_page.data)
        # The canvas draws the server-resolved plan; it does not fetch the raw
        # text and derive a redacted rendering of its own any more. That
        # derivation is what made the reviewed document differ from the
        # delivered one -- see tests/test_redaction_parity.py.
        self.assertIn(b"/api/document/${docId}/redaction-plan", docx_page.data)
        self.assertNotIn(b"buildDocHtml(docText", docx_page.data)

        pdf_page = self.client.get("/studio/3")
        self.assertEqual(pdf_page.status_code, 200)
        self.assertIn(b'id="pdfPages"', pdf_page.data)
        self.assertIn(b'id="pdfPageInput"', pdf_page.data)
        self.assertIn(b"pdfPrevPage()", pdf_page.data)
        self.assertIn(b"pdfNextPage()", pdf_page.data)
        self.assertIn(b"/api/document/${docId}/source-file", pdf_page.data)

        source = self.client.get("/api/document/3/source-file")
        self.assertEqual(source.status_code, 200)
        self.assertEqual(source.content_type, "application/pdf")
        self.assertTrue(source.data.startswith(b"%PDF"))
        source.close()

        missing = self.client.get("/studio/999")
        self.assertEqual(missing.status_code, 404)

    def test_workspace_single_finding_lifecycle_persists_and_audits_safely(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        findings = conn.execute(
            "SELECT id, category FROM privacy_findings WHERE document_id = 1 ORDER BY id"
        ).fetchall()
        approved_id, rejected_id = findings[0]["id"], findings[1]["id"]
        conn.execute(
            """
            INSERT INTO pseudonym_mappings (
                document_id, finding_id, original_text, replacement_text, category, restricted
            ) VALUES (?, ?, ?, ?, ?, 1)
            """,
            (1, approved_id, "Synthetic date value", "[DATE_1]", findings[0]["category"]),
        )
        conn.commit()
        conn.close()

        approved = self.client.post(f"/api/finding/{approved_id}/review", json={"action": "approve"})
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json["review_status"], "approved")

        # 'reject' is kept as an API alias for the false-positive decision, so
        # what it writes is 'dismissed' -- see the alias test in
        # tests/test_gate_reachability.py for why it must not be 'retained'.
        rejected = self.client.post(f"/api/finding/{rejected_id}/review", json={"action": "reject"})
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.json["review_status"], "dismissed")

        replacement = "[SYNTHETIC_DATE_REDACTED]"
        reviewer_note = "Synthetic fixture confirmed by reviewer"
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE documents SET external_llm_readiness = 'SENTINEL' WHERE id = 1"
        )
        conn.commit()
        conn.close()
        edited = self.client.post(
            f"/api/finding/{approved_id}/review",
            json={
                "action": "update",
                "review_status": "approved",
                "replacement_text": replacement,
                "reviewer_note": reviewer_note,
            },
        )
        self.assertEqual(edited.status_code, 200)
        self.assertEqual(edited.json["review_status"], "approved")

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        stored = conn.execute(
            "SELECT review_status, replacement_text, reviewer_note FROM privacy_findings WHERE id = ?",
            (approved_id,),
        ).fetchone()
        rejected_status = conn.execute(
            "SELECT review_status FROM privacy_findings WHERE id = ?", (rejected_id,)
        ).fetchone()[0]
        mapping = conn.execute(
            "SELECT replacement_text FROM pseudonym_mappings WHERE finding_id = ?", (approved_id,)
        ).fetchone()[0]
        audit_rows = conn.execute(
            """
            SELECT action, actor_username, actor_role, metadata
            FROM audit_log
            WHERE document_id = 1 AND action LIKE 'finding_review.%'
            ORDER BY id
            """
        ).fetchall()
        readiness = conn.execute(
            "SELECT external_llm_readiness FROM documents WHERE id = 1"
        ).fetchone()[0]
        conn.close()

        self.assertEqual(dict(stored), {
            "review_status": "approved",
            "replacement_text": replacement,
            "reviewer_note": reviewer_note,
        })
        self.assertEqual(rejected_status, "dismissed")
        self.assertEqual(mapping, replacement)
        self.assertTrue(readiness)
        self.assertNotEqual(readiness, "SENTINEL")
        self.assertEqual(
            [row["action"] for row in audit_rows],
            ["finding_review.approve", "finding_review.reject", "finding_review.update"],
        )
        self.assertTrue(all(row["actor_username"] == "reviewer" for row in audit_rows))
        self.assertTrue(all(row["actor_role"] == "reviewer" for row in audit_rows))
        audit_metadata = " ".join(row["metadata"] or "" for row in audit_rows)
        self.assertNotIn(replacement, audit_metadata)
        self.assertNotIn(reviewer_note, audit_metadata)
        self.assertNotIn("Synthetic date value", audit_metadata)

    def test_workspace_mutations_enforce_viewer_permissions(self):
        conn = sqlite3.connect(self.db_path)
        finding_id = conn.execute(
            "SELECT id FROM privacy_findings WHERE document_id = 1 ORDER BY id LIMIT 1"
        ).fetchone()[0]
        conn.close()
        region = self.client.post(
            "/api/document/3/pdf/regions",
            json={
                "page_number": 1,
                "rect": {"x0": 0.1, "y0": 0.1, "x1": 0.4, "y1": 0.16},
                "category": "manual_sensitive_text",
            },
        )
        self.assertEqual(region.status_code, 200)
        region_id = region.json["regions"][0]["id"]

        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)
        attempts = [
            ("approve finding", viewer_client.post(f"/api/finding/{finding_id}/review", json={"action": "approve"})),
            (
                "edit finding",
                viewer_client.post(
                    f"/api/finding/{finding_id}/review",
                    json={"action": "update", "replacement_text": "[UNAUTHORIZED]"},
                ),
            ),
            (
                "edit PDF region",
                viewer_client.patch(
                    f"/api/document/3/pdf/regions/{region_id}",
                    json={"rect": {"x0": 0.2, "y0": 0.2, "x1": 0.5, "y1": 0.25}},
                ),
            ),
            ("approve PDF region", viewer_client.post(f"/api/document/3/pdf/regions/{region_id}/approve", json={})),
            ("reject PDF region", viewer_client.post(f"/api/document/3/pdf/regions/{region_id}/reject", json={})),
            ("run OCR", viewer_client.post("/api/document/2/ocr/run", json=self.ocr_tokens_payload())),
            ("accept OCR", viewer_client.post("/api/document/2/ocr/accept", json={})),
            ("reject OCR", viewer_client.post("/api/document/2/ocr/reject", json={})),
        ]
        for label, response in attempts:
            with self.subTest(label=label):
                self.assertEqual(response.status_code, 403)

        conn = sqlite3.connect(self.db_path)
        finding = conn.execute(
            "SELECT review_status, replacement_text FROM privacy_findings WHERE id = ?", (finding_id,)
        ).fetchone()
        stored_region = conn.execute(
            "SELECT x0, y0, x1, y1, review_status FROM pdf_redaction_regions WHERE id = ?", (region_id,)
        ).fetchone()
        ocr_status = conn.execute("SELECT ocr_status FROM documents WHERE id = 2").fetchone()[0]
        conn.close()
        self.assertEqual(finding, ("pending", "[DATE_1]"))
        self.assertEqual(stored_region, (0.1, 0.1, 0.4, 0.16, "pending"))
        self.assertEqual(ocr_status, "queued")

    def test_workspace_client_contract_keeps_review_and_keyboard_wiring(self):
        page = self.client.get("/studio/3")
        self.assertEqual(page.status_code, 200)
        required_fragments = [
            b"/api/matter/${matterId}",
            b"/api/finding/${finding.id}/review",
            b"/api/document/${docId}/pdf/regions",
            b"function selectAdjacentFinding(direction)",
            b"function reviewAssistantAction(action)",
            b"function selectPdfRegion(regionId, jumpToPage)",
            b"function initializePanelResizers()",
            b"event.key === 'j'",
            b"event.key === 'k'",
            b"event.key === 'e'",
            b"reviewAssistantAction('approve')",
            # The single reject control was split: both decisions must be wired
            # into the guided pane, not just the permissive one.
            b"reviewAssistantAction('dismiss')",
            b"reviewAssistantAction('retain')",
            b"aria-label=\"Resize matter panel\"",
            b"aria-label=\"Resize review assistant\"",
        ]
        for fragment in required_fragments:
            self.assertIn(fragment, page.data, fragment.decode("utf-8"))

    def test_workspace_json_review_action_rejects_simple_form_submission(self):
        conn = sqlite3.connect(self.db_path)
        finding_id = conn.execute(
            "SELECT id FROM privacy_findings WHERE document_id = 1 ORDER BY id LIMIT 1"
        ).fetchone()[0]
        conn.close()

        response = self.client.post(
            f"/api/finding/{finding_id}/review",
            data={"action": "approve"},
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 400)

        conn = sqlite3.connect(self.db_path)
        status = conn.execute(
            "SELECT review_status FROM privacy_findings WHERE id = ?", (finding_id,)
        ).fetchone()[0]
        conn.close()
        self.assertEqual(status, "pending")

    def test_admin_pages_render_workstation_shell(self):
        admin_client = app_module.app.test_client()
        self.login("admin", client=admin_client)

        audit_page = admin_client.get("/audit-log")
        self.assertEqual(audit_page.status_code, 200)
        self.assertIn(b"Audit metadata is sanitized", audit_page.data)

        settings_page = admin_client.get("/settings")
        self.assertEqual(settings_page.status_code, 200)
        self.assertIn(b"Access Model", settings_page.data)
        self.assertIn(b"Output Terminology", settings_page.data)

    def test_batch_review_updates_pending_low_medium_only(self):
        response = self.client.post(
            "/api/document/1/findings/review-batch",
            json={"action": "approve", "risks": ["LOW", "MEDIUM"], "only_pending": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["updated"], 1)

        detail = self.client.get("/api/document/1")
        statuses = {finding["category"]: finding["review_status"] for finding in detail.json["findings"]}
        self.assertEqual(statuses["date"], "approved")
        self.assertEqual(statuses["criminal_allegation"], "pending")

    def test_viewer_cannot_batch_review(self):
        viewer_client = app_module.app.test_client()
        self.login("viewer", client=viewer_client)

        response = viewer_client.post(
            "/api/document/1/findings/review-batch",
            json={"action": "approve", "risks": ["MEDIUM"]},
        )

        self.assertEqual(response.status_code, 403)

    def test_batch_review_with_finding_ids_updates_only_those_ids(self):
        # Seed more pending findings in one category than are supplied, so a
        # regression to "resolve the whole category" (rather than exactly the
        # given ids) would show up as updated == 3, not 2.
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, fingerprint
            ) VALUES
                (1, 'health_data', 'Sample A', 'CRITICAL', 'Flag for review', '[HD_1]', '[HD_1]', 'pending', 'detector', 'hd1'),
                (1, 'health_data', 'Sample B', 'CRITICAL', 'Flag for review', '[HD_2]', '[HD_2]', 'pending', 'detector', 'hd2'),
                (1, 'health_data', 'Sample C', 'CRITICAL', 'Flag for review', '[HD_3]', '[HD_3]', 'pending', 'detector', 'hd3')
            """
        )
        conn.commit()
        conn.row_factory = sqlite3.Row
        ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM privacy_findings WHERE document_id = 1 AND category = 'health_data' ORDER BY id"
            ).fetchall()
        ]
        conn.close()
        self.assertEqual(len(ids), 3)

        response = self.client.post(
            "/api/document/1/findings/review-batch",
            json={"action": "approve", "finding_ids": ids[:2], "only_pending": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["updated"], 2)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        statuses = {
            row["id"]: row["review_status"]
            for row in conn.execute(
                f"SELECT id, review_status FROM privacy_findings WHERE id IN ({','.join('?' for _ in ids)})",
                ids,
            ).fetchall()
        }
        conn.close()
        self.assertEqual(statuses[ids[0]], "approved")
        self.assertEqual(statuses[ids[1]], "approved")
        self.assertEqual(statuses[ids[2]], "pending")

    def test_finding_update_rejects_invalid_review_status(self):
        conn = sqlite3.connect(self.db_path)
        finding_id = conn.execute(
            "SELECT id FROM privacy_findings WHERE document_id = 1 ORDER BY id LIMIT 1"
        ).fetchone()[0]
        conn.close()

        response = self.client.post(
            f"/api/finding/{finding_id}/review",
            json={"action": "update", "review_status": "banana"},
        )
        self.assertEqual(response.status_code, 400)

        conn = sqlite3.connect(self.db_path)
        status = conn.execute(
            "SELECT review_status FROM privacy_findings WHERE id = ?", (finding_id,)
        ).fetchone()[0]
        conn.close()
        self.assertEqual(status, "pending")

    def test_bogus_review_status_keeps_release_gate_blocked(self):
        # Bypass the (now-validated) API and write a non-standard status
        # directly, the way a future code path or a manual DB fix might.
        # redaction_completed is also set directly (bypassing mark_redacted)
        # so this test isolates review_gate_counts() in app.py specifically —
        # see test_mark_redacted_blocks_on_bogus_review_status for the
        # separate mark_redacted fail-closed fix.
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE privacy_findings SET review_status = 'banana' WHERE document_id = 1")
        conn.execute("UPDATE documents SET redaction_completed = 1 WHERE id = 1")
        conn.commit()
        conn.close()

        approved = self.client.post("/api/document/1/review", json={"action": "approve"})
        self.assertEqual(approved.status_code, 200)
        self.assertNotEqual(approved.json["review_status"], "approved_for_external_llm")
        gate = approved.json["privacy_profile"]["external_llm_gate"]
        self.assertFalse(gate["allowed"])
        self.assertIn("Critical findings must be zero.", gate["failed_conditions"])

    def test_null_review_status_counts_as_unresolved(self):
        # Same isolation as above: set redaction_completed directly so this
        # exercises review_gate_counts()'s NULL handling on its own.
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE privacy_findings SET review_status = NULL WHERE document_id = 1")
        conn.execute("UPDATE documents SET redaction_completed = 1 WHERE id = 1")
        conn.commit()
        conn.close()

        approved = self.client.post("/api/document/1/review", json={"action": "approve"})
        self.assertEqual(approved.status_code, 200)
        gate = approved.json["privacy_profile"]["external_llm_gate"]
        self.assertFalse(gate["allowed"])
        self.assertIn("Critical findings must be zero.", gate["failed_conditions"])

    def test_mark_redacted_blocks_on_bogus_review_status(self):
        # mark_redacted has its own, separate "everything must be reviewed"
        # check (review.py); it must fail closed the same way, or redaction_
        # completed can flip to True — and get_exportable_docx gates the
        # actual redacted-export download on redaction_completed alone — with
        # a finding that was never actually approved or rejected.
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE privacy_findings SET review_status = 'banana' WHERE document_id = 1")
        conn.commit()
        conn.close()

        redacted = self.client.post("/api/document/1/review", json={"action": "mark_redacted"})
        self.assertEqual(redacted.status_code, 409)

        export = self.client.get("/api/document/1/redacted-export?format=docx")
        self.assertEqual(export.status_code, 409)

    def test_add_finding_rejects_invalid_category_and_risk(self):
        bad_category = self.client.post(
            "/api/document/1/findings",
            json={"text": "some sensitive text", "category": "x'),alert(1),('", "risk": "HIGH"},
        )
        self.assertEqual(bad_category.status_code, 400)

        bad_risk = self.client.post(
            "/api/document/1/findings",
            json={"text": "some other sensitive text", "category": "manual_sensitive_text", "risk": "SUPER_CRITICAL"},
        )
        self.assertEqual(bad_risk.status_code, 400)

        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM privacy_findings WHERE document_id = 1 AND sample IN (?, ?)",
            ("some sensitive text", "some other sensitive text"),
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
