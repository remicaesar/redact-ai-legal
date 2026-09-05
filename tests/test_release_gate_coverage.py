"""Regression guard: every mutation endpoint must recompute the release gate.

Each test stamps a sentinel value into ``documents.external_llm_readiness``
directly in SQLite, calls one findings/OCR/PDF-region mutation endpoint, and
asserts the sentinel was overwritten. ``refresh_document_state`` (and the
review/OCR-accept paths that rewrite the privacy profile directly) always
rewrite that column, so a surviving sentinel means the endpoint mutated
review state without refreshing the external-LLM release gate — the exact
bug class this suite exists to catch. If you add a mutation endpoint, add it
here.
"""

import json
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import tests.env_setup  # noqa: F401  -- sets LEGAL_ANALYZER_SECRET_KEY before app is imported
import app as app_module
from legal_analyzer.privacy import analyze_privacy
from legal_analyzer.taxonomy import CATEGORIES, SUBCATEGORIES
from tests.test_app_workflow import make_docx, make_pdf
from werkzeug.security import generate_password_hash

SENTINEL = "SENTINEL_STALE_READINESS"


class ReleaseGateCoverageTests(unittest.TestCase):
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

        docx_path = self.tmp_path / "contract.docx"
        make_docx(docx_path, "Av. Ayse Demir 01.01.2026")
        self.insert_document(conn, 1, "contract.docx", docx_path, ".docx", "Complete", "not_required")
        conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, fingerprint
            ) VALUES
                (1, 'natural_person_name', 'Ayse Demir', 'HIGH', 'Pseudonymize consistently', '[PERSON_1]', '[PERSON_1]', 'pending', 'detector', 'gatefp1'),
                (1, 'date', '01.01.2026', 'MEDIUM', 'Generalize unless legally necessary', '[DATE_1]', '[DATE_1]', 'pending', 'detector', 'gatefp2')
            """
        )

        scan_path = self.tmp_path / "scan.pdf"
        make_pdf(scan_path)
        self.insert_document(
            conn, 2, "scan.pdf", scan_path, ".pdf", "Failed", "queued",
            warning="PDF text extraction returned no text; OCR may be required.",
            review_status="needs_ocr",
        )

        pdf_path = self.tmp_path / "sensitive.pdf"
        make_pdf(pdf_path)
        self.insert_document(conn, 3, "sensitive.pdf", pdf_path, ".pdf", "Complete", "not_required")
        conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, fingerprint
            ) VALUES
                (3, 'turkish_national_id', '10000000146', 'CRITICAL', 'Redact direct identifier', '[TCKN_1]', '[TCKN_REDACTED]', 'pending', 'detector', 'gatefp3')
            """
        )
        conn.commit()
        conn.close()
        self.client = app_module.app.test_client()
        self.client.post("/login", json={"username": "reviewer", "password": "secret"})

    def restore_db_path(self):
        app_module.DB_PATH = self.original_db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        app_module.EXPORT_DIR = self.original_export_dir

    def insert_document(self, conn, doc_id, filename, path, extension, extraction_status, ocr_status,
                        warning=None, review_status="pending_review"):
        profile = analyze_privacy(filename, "Av. Ayse Demir", warning)
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
                doc_id,
                filename,
                str(path),
                extension,
                path.stat().st_size,
                Path(filename).stem,
                warning,
                extraction_status,
                json.dumps(profile),
                profile["residual_risk"]["level"],
                profile["residual_risk"]["summary"],
                profile["recommended_strategy"],
                profile["external_llm_readiness"],
                1,
                profile["redaction_status"],
                review_status,
                ocr_status,
            ),
        )

    def db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def stamp_sentinel(self, doc_id: int):
        conn = self.db()
        conn.execute("UPDATE documents SET external_llm_readiness = ? WHERE id = ?", (SENTINEL, doc_id))
        conn.commit()
        conn.close()

    def readiness(self, doc_id: int) -> str:
        conn = self.db()
        value = conn.execute("SELECT external_llm_readiness FROM documents WHERE id = ?", (doc_id,)).fetchone()[0]
        conn.close()
        return value

    def finding_id(self, doc_id: int) -> int:
        conn = self.db()
        value = conn.execute(
            "SELECT id FROM privacy_findings WHERE document_id = ? ORDER BY id LIMIT 1", (doc_id,)
        ).fetchone()[0]
        conn.close()
        return value

    def assert_gate_refreshed(self, doc_id: int, endpoint_label: str):
        value = self.readiness(doc_id)
        self.assertNotEqual(
            value,
            SENTINEL,
            f"{endpoint_label} mutated review state without recomputing the release gate "
            "(external_llm_readiness was not rewritten — refresh_document_state did not run).",
        )
        self.assertTrue(value, f"{endpoint_label} left external_llm_readiness empty.")

    def test_finding_review_refreshes_gate(self):
        finding_id = self.finding_id(1)
        self.stamp_sentinel(1)
        response = self.client.post(f"/api/finding/{finding_id}/review", json={"action": "approve"})
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(1, "POST /api/finding/<id>/review")

    def test_finding_batch_review_refreshes_gate(self):
        self.stamp_sentinel(1)
        response = self.client.post(
            "/api/document/1/findings/review-batch",
            json={"action": "approve", "risks": ["MEDIUM", "HIGH"], "only_pending": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.json["updated"], 0)
        self.assert_gate_refreshed(1, "POST /api/document/<id>/findings/review-batch")

    def test_add_manual_finding_refreshes_gate(self):
        self.stamp_sentinel(1)
        response = self.client.post(
            "/api/document/1/findings",
            json={"text": "Gizli Tanik", "category": "manual_sensitive_text"},
        )
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(1, "POST /api/document/<id>/findings")

    def test_document_review_action_refreshes_gate(self):
        self.stamp_sentinel(1)
        response = self.client.post("/api/document/1/review", json={"action": "reject"})
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(1, "POST /api/document/<id>/review")

    def test_ocr_queue_refreshes_gate(self):
        self.stamp_sentinel(2)
        response = self.client.post("/api/document/2/ocr/queue", json={})
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(2, "POST /api/document/<id>/ocr/queue")

    def test_ocr_run_refreshes_gate(self):
        self.stamp_sentinel(2)
        response = self.client.post(
            "/api/document/2/ocr/run",
            json={"text": "Taranmis dilekce metni Av. Ayse Demir", "confidence": 0.9},
        )
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(2, "POST /api/document/<id>/ocr/run")

    def test_ocr_accept_refreshes_gate(self):
        run = self.client.post(
            "/api/document/2/ocr/run",
            json={"text": "Taranmis dilekce metni Av. Ayse Demir", "confidence": 0.9},
        )
        self.assertEqual(run.status_code, 200)
        self.stamp_sentinel(2)
        response = self.client.post("/api/document/2/ocr/accept", json={})
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(2, "POST /api/document/<id>/ocr/accept")

    def test_ocr_reject_refreshes_gate(self):
        run = self.client.post(
            "/api/document/2/ocr/run",
            json={"text": "Taranmis dilekce metni Av. Ayse Demir", "confidence": 0.9},
        )
        self.assertEqual(run.status_code, 200)
        self.stamp_sentinel(2)
        response = self.client.post("/api/document/2/ocr/reject", json={})
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(2, "POST /api/document/<id>/ocr/reject")

    def create_pdf_region(self) -> int:
        response = self.client.post(
            "/api/document/3/pdf/regions",
            json={"page_number": 1, "rect": {"x0": 0.1, "y0": 0.1, "x1": 0.4, "y1": 0.15}, "category": "manual_sensitive_text"},
        )
        self.assertEqual(response.status_code, 200)
        return response.json["regions"][0]["id"]

    def test_pdf_region_create_refreshes_gate(self):
        self.stamp_sentinel(3)
        self.create_pdf_region()
        self.assert_gate_refreshed(3, "POST /api/document/<id>/pdf/regions")

    def test_pdf_region_update_refreshes_gate(self):
        region_id = self.create_pdf_region()
        self.stamp_sentinel(3)
        response = self.client.patch(
            f"/api/document/3/pdf/regions/{region_id}",
            json={"rect": {"x0": 0.2, "y0": 0.2, "x1": 0.5, "y1": 0.25}},
        )
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(3, "PATCH /api/document/<id>/pdf/regions/<region_id>")

    def test_pdf_region_approve_refreshes_gate(self):
        region_id = self.create_pdf_region()
        self.stamp_sentinel(3)
        response = self.client.post(f"/api/document/3/pdf/regions/{region_id}/approve")
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(3, "POST /api/document/<id>/pdf/regions/<region_id>/approve")

    def test_pdf_region_reject_refreshes_gate(self):
        region_id = self.create_pdf_region()
        self.stamp_sentinel(3)
        response = self.client.post(f"/api/document/3/pdf/regions/{region_id}/reject")
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(3, "POST /api/document/<id>/pdf/regions/<region_id>/reject")

    def test_pdf_regions_generate_refreshes_gate(self):
        self.stamp_sentinel(3)
        response = self.client.post("/api/document/3/pdf/regions/generate")
        self.assertEqual(response.status_code, 200)
        self.assert_gate_refreshed(3, "POST /api/document/<id>/pdf/regions/generate")

    def test_pdf_regions_batch_review_refreshes_gate(self):
        self.create_pdf_region()
        self.stamp_sentinel(3)
        response = self.client.post(
            "/api/document/3/pdf/regions/review-batch",
            json={"action": "approve", "only_pending": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.json["updated"], 0)
        self.assert_gate_refreshed(3, "POST /api/document/<id>/pdf/regions/review-batch")


if __name__ == "__main__":
    unittest.main()
