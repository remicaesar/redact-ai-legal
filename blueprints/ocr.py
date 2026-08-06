"""OCR queue/run/accept/reject routes. OCR output never affects findings or
release readiness until a reviewer explicitly accepts it."""

from __future__ import annotations

import json

from flask import Blueprint, jsonify, request

from app import (
    audit_and_commit,
    audited_error,
    get_db,
    insert_pending_pdf_regions,
    ocr_token_regions,
    record_document_artifact,
    refresh_document_state,
    replace_detector_findings,
    require_roles,
    resolve_document_path,
    review_gate_counts,
)
from blueprints.documents import api_document_detail
from legal_analyzer.ocr import OCRPage, OCRToken, ocr_from_review_text, run_local_ocr
from legal_analyzer.privacy import analyze_privacy, refresh_release_state

ocr_bp = Blueprint("ocr", __name__)


@ocr_bp.route("/api/document/<int:doc_id>/ocr/queue", methods=["POST"])
@require_roles("reviewer", "admin")
def api_ocr_queue(doc_id: int):
    payload = request.get_json(silent=True) or {}
    reviewer_note = payload.get("reviewer_note")
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    if doc["extraction_status"] == "Complete":
        return audited_error(
            conn,
            "OCR may only be queued for Partial, Failed, or Unknown extraction documents.",
            409,
            "ocr.queue",
            doc_id,
            {"extraction_status": doc["extraction_status"]},
        )

    conn.execute(
        """
        UPDATE documents
        SET ocr_status = 'queued',
            review_status = 'needs_ocr',
            redaction_completed = 0,
            human_review_approved = 0,
            reviewed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (doc_id,),
    )
    if reviewer_note:
        conn.execute(
            """
            INSERT INTO ocr_pages (document_id, page_number, text, confidence, status, source, reviewer_note)
            VALUES (?, 0, '', NULL, 'queued', 'reviewer_note', ?)
            ON CONFLICT(document_id, page_number) DO UPDATE SET
                status = 'queued',
                reviewer_note = excluded.reviewer_note,
                reviewed_at = NULL
            """,
            (doc_id, reviewer_note),
        )
    refresh_document_state(conn, doc_id, ocr_status="queued")
    audit_and_commit(conn, "ocr.queue", document_id=doc_id, metadata={"ocr_status": "queued"})
    conn.close()
    return api_document_detail(doc_id)


@ocr_bp.route("/api/document/<int:doc_id>/ocr/run", methods=["POST"])
@require_roles("reviewer", "admin")
def api_ocr_run(doc_id: int):
    payload = request.get_json(silent=True) or {}
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    if doc["ocr_status"] not in {"queued", "failed", "rejected"}:
        return audited_error(
            conn,
            "OCR must be queued before running.",
            409,
            "ocr.run",
            doc_id,
            {"ocr_status": doc["ocr_status"]},
        )

    conn.execute(
        """
        UPDATE documents
        SET ocr_status = 'processing',
            review_status = 'needs_ocr',
            redaction_completed = 0,
            human_review_approved = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (doc_id,),
    )
    conn.commit()

    try:
        review_text = payload.get("text")
        if review_text is not None:
            pages = ocr_from_review_text(review_text, payload.get("confidence", 1.0))
        elif payload.get("pages"):
            pages = [
                OCRPage(
                    page_number=int(page.get("page_number") or index),
                    text=page.get("text", "").strip(),
                    confidence=page.get("confidence"),
                    source="reviewer_supplied",
                    tokens=tuple(
                        OCRToken(
                            text=str(token["text"]).strip(),
                            x0=float(token["x0"]),
                            y0=float(token["y0"]),
                            x1=float(token["x1"]),
                            y1=float(token["y1"]),
                            confidence=token.get("confidence"),
                            source="reviewer_supplied",
                        )
                        for token in page.get("tokens") or []
                        if isinstance(token, dict) and str(token.get("text") or "").strip()
                    ),
                )
                for index, page in enumerate(payload.get("pages", []), start=1)
                if isinstance(page, dict) and (page.get("text") or "").strip()
            ]
        else:
            pages = run_local_ocr(resolve_document_path(doc["filepath"]), payload.get("language", "tur+eng"))

        if not pages:
            raise RuntimeError("OCR produced no reviewable text.")

        conn.execute("DELETE FROM ocr_pages WHERE document_id = ?", (doc_id,))
        conn.execute("DELETE FROM ocr_tokens WHERE document_id = ?", (doc_id,))
        token_count = 0
        for page in pages:
            cursor = conn.execute(
                """
                INSERT INTO ocr_pages (document_id, page_number, text, confidence, status, source)
                VALUES (?, ?, ?, ?, 'completed', ?)
                """,
                (doc_id, page.page_number, page.text, page.confidence, page.source),
            )
            ocr_page_id = cursor.lastrowid
            for token in page.tokens:
                conn.execute(
                    """
                    INSERT INTO ocr_tokens (
                        document_id, ocr_page_id, page_number, text, confidence, x0, y0, x1, y1, source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        doc_id,
                        ocr_page_id,
                        page.page_number,
                        token.text,
                        token.confidence,
                        max(0, min(1, token.x0)),
                        max(0, min(1, token.y0)),
                        max(0, min(1, token.x1)),
                        max(0, min(1, token.y1)),
                        token.source,
                    ),
                )
                token_count += 1
        conn.execute(
            """
            UPDATE documents
            SET ocr_status = 'completed',
                review_status = 'needs_ocr',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (doc_id,),
        )
        refresh_document_state(conn, doc_id, ocr_status="completed")
        audit_and_commit(
            conn,
            "ocr.run",
            document_id=doc_id,
            metadata={"pages": len(pages), "source": pages[0].source, "token_count": token_count},
        )
        conn.close()
        return api_document_detail(doc_id)
    except Exception as exc:
        conn.execute(
            """
            UPDATE documents
            SET ocr_status = 'failed',
                review_status = 'needs_ocr',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (doc_id,),
        )
        conn.execute(
            """
            INSERT INTO ocr_pages (document_id, page_number, text, confidence, status, source, reviewer_note)
            VALUES (?, 0, '', NULL, 'failed', 'local', ?)
            ON CONFLICT(document_id, page_number) DO UPDATE SET
                text = '',
                confidence = NULL,
                status = 'failed',
                source = 'local',
                reviewer_note = excluded.reviewer_note
            """,
            (doc_id, str(exc)),
        )
        refresh_document_state(conn, doc_id, ocr_status="failed")
        audit_and_commit(conn, "ocr.run", document_id=doc_id, result="failed", metadata={"error": str(exc)})
        conn.close()
        return jsonify({"error": str(exc)}), 424


@ocr_bp.route("/api/document/<int:doc_id>/ocr/accept", methods=["POST"])
@require_roles("reviewer", "admin")
def api_ocr_accept(doc_id: int):
    payload = request.get_json(silent=True) or {}
    reviewer_note = payload.get("reviewer_note")
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    if doc["ocr_status"] != "completed":
        return audited_error(
            conn,
            "Only completed OCR output can be accepted.",
            409,
            "ocr.accept",
            doc_id,
            {"ocr_status": doc["ocr_status"]},
        )

    pages = conn.execute(
        """
        SELECT page_number, text
        FROM ocr_pages
        WHERE document_id = ? AND status = 'completed' AND text IS NOT NULL AND text != ''
        ORDER BY page_number
        """,
        (doc_id,),
    ).fetchall()
    accepted_text = "\n\n".join(row["text"] for row in pages).strip()
    if not accepted_text:
        return audited_error(conn, "OCR output has no text to accept.", 409, "ocr.accept", doc_id)

    profile = analyze_privacy(doc["filename"], accepted_text, None, ocr_status="accepted")
    replace_detector_findings(conn, doc_id, profile["risk_map"], source="ocr", part_name_prefix="ocr_page", source_text=accepted_text)
    profile["ocr"] = {
        "status": "accepted",
        "text_chars": len(accepted_text),
        "page_count": len(pages),
        "reviewer_note": reviewer_note,
    }
    profile = refresh_release_state(
        profile,
        redaction_completed=False,
        human_review_approved=False,
        auto_mode_enabled=bool(doc["auto_mode_enabled"]),
        ocr_status="accepted",
        **review_gate_counts(conn, doc_id),
    )

    conn.execute(
        """
        UPDATE ocr_pages
        SET status = 'accepted',
            reviewer_note = COALESCE(?, reviewer_note),
            reviewed_at = CURRENT_TIMESTAMP
        WHERE document_id = ? AND status = 'completed'
        """,
        (reviewer_note, doc_id),
    )
    conn.execute(
        """
        UPDATE documents
        SET privacy_profile = ?,
            extraction_warning = NULL,
            extraction_status = 'Complete',
            residual_risk = ?,
            risk_summary = ?,
            recommended_strategy = ?,
            external_llm_readiness = ?,
            human_review_required = ?,
            redaction_status = ?,
            redaction_completed = 0,
            human_review_approved = 0,
            review_status = 'pending_review',
            ocr_status = 'accepted',
            reviewed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            json.dumps(profile, ensure_ascii=False),
            profile["residual_risk"]["level"],
            profile["residual_risk"]["summary"],
            profile["recommended_strategy"],
            profile["external_llm_readiness"],
            1 if profile["human_review_required"] else 0,
            profile["redaction_status"],
            doc_id,
        ),
    )
    mapped_regions = 0
    if doc["file_extension"] == ".pdf":
        conn.execute(
            """
            DELETE FROM pdf_redaction_regions
            WHERE document_id = ? AND source = 'ocr' AND review_status = 'pending' AND finding_id IS NULL
            """,
            (doc_id,),
        )
        ocr_findings = [
            dict(row)
            for row in conn.execute(
                """
                SELECT id, category, sample, source
                FROM privacy_findings
                WHERE document_id = ? AND source = 'ocr' AND sample IS NOT NULL AND sample != ''
                """,
                (doc_id,),
            ).fetchall()
        ]
        mapped_regions = insert_pending_pdf_regions(conn, doc_id, ocr_token_regions(conn, doc_id, ocr_findings))
    record_document_artifact(
        conn,
        doc_id,
        "ocr_accepted",
        "Accepted OCR text",
        metadata={
            "page_count": len(pages),
            "text_chars": len(accepted_text),
            "finding_count": len(profile["risk_map"]),
            "mapped_pdf_regions": mapped_regions,
        },
    )
    audit_and_commit(
        conn,
        "ocr.accept",
        document_id=doc_id,
        metadata={
            "page_count": len(pages),
            "text_chars": len(accepted_text),
            "finding_count": len(profile["risk_map"]),
            "mapped_pdf_regions": mapped_regions,
        },
    )
    conn.close()
    return api_document_detail(doc_id)


@ocr_bp.route("/api/document/<int:doc_id>/ocr/reject", methods=["POST"])
@require_roles("reviewer", "admin")
def api_ocr_reject(doc_id: int):
    payload = request.get_json(silent=True) or {}
    reviewer_note = payload.get("reviewer_note")
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    if doc["ocr_status"] != "completed":
        return audited_error(
            conn,
            "Only completed OCR output can be rejected.",
            409,
            "ocr.reject",
            doc_id,
            {"ocr_status": doc["ocr_status"]},
        )

    conn.execute(
        """
        UPDATE ocr_pages
        SET status = 'rejected',
            reviewer_note = COALESCE(?, reviewer_note),
            reviewed_at = CURRENT_TIMESTAMP
        WHERE document_id = ? AND status = 'completed'
        """,
        (reviewer_note, doc_id),
    )
    conn.execute(
        """
        UPDATE documents
        SET ocr_status = 'rejected',
            review_status = 'needs_ocr',
            redaction_completed = 0,
            human_review_approved = 0,
            reviewed_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (doc_id,),
    )
    refresh_document_state(conn, doc_id, ocr_status="rejected")
    audit_and_commit(conn, "ocr.reject", document_id=doc_id)
    conn.close()
    return api_document_detail(doc_id)
