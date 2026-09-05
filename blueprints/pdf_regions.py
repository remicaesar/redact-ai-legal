"""PDF coordinate-redaction region CRUD, review, and generation routes."""

from __future__ import annotations

import json
import sqlite3
from io import BytesIO
from pathlib import Path

from flask import Blueprint, g, jsonify, request, send_file

from app import (
    audit_and_commit,
    audited_error,
    get_db,
    get_pdf_document,
    insert_pending_pdf_regions,
    latest_redacted_pdf_artifact,
    ocr_token_regions,
    pdf_export_blockers,
    pdf_region_fingerprint,
    pdf_region_row_to_dict,
    record_document_artifact,
    refresh_document_state,
    require_roles,
    resolve_document_path,
)
from legal_analyzer.pdf_redactor import PdfRegion, find_pdf_regions

pdf_regions_bp = Blueprint("pdf_regions", __name__)


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/regions")
@require_roles("viewer", "reviewer", "admin")
def api_pdf_regions(doc_id: int):
    conn = get_db()
    doc = get_pdf_document(conn, doc_id, "pdf_regions.view")
    if not isinstance(doc, sqlite3.Row):
        return doc
    rows = [
        pdf_region_row_to_dict(row)
        for row in conn.execute(
            """
            SELECT r.*, pf.sample, pf.risk, pf.review_status AS finding_review_status
            FROM pdf_redaction_regions r
            LEFT JOIN privacy_findings pf ON pf.id = r.finding_id
            WHERE r.document_id = ?
            ORDER BY r.page_number, r.id
            """,
            (doc_id,),
        ).fetchall()
    ]
    conn.close()
    return jsonify({"regions": rows, "total": len(rows)})


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/regions", methods=["POST"])
@require_roles("reviewer", "admin")
def api_pdf_region_create(doc_id: int):
    payload = request.get_json(silent=True) or {}
    rect = payload.get("rect") or payload
    category = str(payload.get("category") or "manual_sensitive_text").strip()
    source = str(payload.get("source") or "manual").strip()
    if source not in {"manual", "detected_text", "ocr", "qa"}:
        source = "manual"
    try:
        region = PdfRegion(
            page_number=int(payload.get("page_number") or 1),
            x0=float(rect["x0"]),
            y0=float(rect["y0"]),
            x1=float(rect["x1"]),
            y1=float(rect["y1"]),
            category=category,
            source=source,
            finding_id=int(payload["finding_id"]) if payload.get("finding_id") else None,
        )
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "PDF region requires page_number and normalized x0, y0, x1, y1."}), 400
    if region.page_number < 1 or abs(region.x1 - region.x0) <= 0 or abs(region.y1 - region.y0) <= 0:
        return jsonify({"error": "PDF region has invalid page or rectangle dimensions."}), 400
    conn = get_db()
    doc = get_pdf_document(conn, doc_id, "pdf_region.create")
    if not isinstance(doc, sqlite3.Row):
        return doc
    try:
        cursor = conn.execute(
            """
            INSERT INTO pdf_redaction_regions (
                document_id, finding_id, page_number, x0, y0, x1, y1, category, source,
                review_status, reviewer_note, confidence, fingerprint, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
            """,
            (
                doc_id,
                region.finding_id,
                region.page_number,
                max(0, min(1, region.x0)),
                max(0, min(1, region.y0)),
                max(0, min(1, region.x1)),
                max(0, min(1, region.y1)),
                region.category,
                region.source,
                payload.get("reviewer_note"),
                payload.get("confidence"),
                pdf_region_fingerprint(doc_id, region),
                g.current_user["id"],
            ),
        )
    except sqlite3.IntegrityError:
        return audited_error(
            conn,
            "An identical PDF redaction box already exists for this document.",
            409,
            "pdf_region.create",
            doc_id,
            metadata={"category": category, "source": source, "page_number": region.page_number},
        )
    refresh_document_state(conn, doc_id)
    audit_and_commit(conn, "pdf_region.create", document_id=doc_id, metadata={"region_id": cursor.lastrowid, "category": category, "source": source})
    conn.close()
    return api_pdf_regions(doc_id)


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/regions/<int:region_id>", methods=["PATCH"])
@require_roles("reviewer", "admin")
def api_pdf_region_update(doc_id: int, region_id: int):
    payload = request.get_json(silent=True) or {}
    rect = payload.get("rect") or payload
    allowed_status = {"pending", "approved", "rejected"}
    conn = get_db()
    doc = get_pdf_document(conn, doc_id, "pdf_region.update")
    if not isinstance(doc, sqlite3.Row):
        return doc
    row = conn.execute("SELECT * FROM pdf_redaction_regions WHERE id = ? AND document_id = ?", (region_id, doc_id)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "PDF region not found"}), 404
    values = {
        "page_number": int(payload.get("page_number", row["page_number"])),
        "x0": float(rect.get("x0", row["x0"])),
        "y0": float(rect.get("y0", row["y0"])),
        "x1": float(rect.get("x1", row["x1"])),
        "y1": float(rect.get("y1", row["y1"])),
        "category": str(payload.get("category", row["category"])).strip(),
        "review_status": str(payload.get("review_status", row["review_status"])).strip(),
        "reviewer_note": payload.get("reviewer_note", row["reviewer_note"]),
    }
    if values["review_status"] not in allowed_status:
        conn.close()
        return jsonify({"error": "Unsupported PDF region review status."}), 400
    conn.execute(
        """
        UPDATE pdf_redaction_regions
        SET page_number = ?, x0 = ?, y0 = ?, x1 = ?, y1 = ?, category = ?,
            review_status = ?, reviewer_note = ?, reviewed_by = CASE WHEN ? != 'pending' THEN ? ELSE reviewed_by END,
            reviewed_at = CASE WHEN ? != 'pending' THEN CURRENT_TIMESTAMP ELSE reviewed_at END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND document_id = ?
        """,
        (
            values["page_number"],
            max(0, min(1, values["x0"])),
            max(0, min(1, values["y0"])),
            max(0, min(1, values["x1"])),
            max(0, min(1, values["y1"])),
            values["category"],
            values["review_status"],
            values["reviewer_note"],
            values["review_status"],
            g.current_user["id"],
            values["review_status"],
            region_id,
            doc_id,
        ),
    )
    refresh_document_state(conn, doc_id)
    audit_and_commit(conn, "pdf_region.update", document_id=doc_id, metadata={"region_id": region_id, "review_status": values["review_status"], "category": values["category"]})
    conn.close()
    return api_pdf_regions(doc_id)


def pdf_region_review_action(doc_id: int, region_id: int, review_status: str):
    conn = get_db()
    doc = get_pdf_document(conn, doc_id, f"pdf_region.{review_status}")
    if not isinstance(doc, sqlite3.Row):
        return doc
    row = conn.execute("SELECT id FROM pdf_redaction_regions WHERE id = ? AND document_id = ?", (region_id, doc_id)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "PDF region not found"}), 404
    conn.execute(
        """
        UPDATE pdf_redaction_regions
        SET review_status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND document_id = ?
        """,
        (review_status, g.current_user["id"], region_id, doc_id),
    )
    refresh_document_state(conn, doc_id)
    audit_and_commit(conn, f"pdf_region.{review_status}", document_id=doc_id, metadata={"region_id": region_id})
    conn.close()
    return api_pdf_regions(doc_id)


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/regions/<int:region_id>/approve", methods=["POST"])
@require_roles("reviewer", "admin")
def api_pdf_region_approve(doc_id: int, region_id: int):
    return pdf_region_review_action(doc_id, region_id, "approved")


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/regions/<int:region_id>/reject", methods=["POST"])
@require_roles("reviewer", "admin")
def api_pdf_region_reject(doc_id: int, region_id: int):
    return pdf_region_review_action(doc_id, region_id, "rejected")


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/regions/generate", methods=["POST"])
@require_roles("reviewer", "admin")
def api_pdf_regions_generate(doc_id: int):
    conn = get_db()
    doc = get_pdf_document(conn, doc_id, "pdf_regions.generate")
    if not isinstance(doc, sqlite3.Row):
        return doc
    source_path = resolve_document_path(doc["filepath"])
    if not source_path.exists():
        return audited_error(conn, "Source PDF was not found.", 404, "pdf_regions.generate", doc_id)
    findings = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, category, sample, source
            FROM privacy_findings
            WHERE document_id = ?
              AND sample IS NOT NULL
              AND sample != ''
            """,
            (doc_id,),
        ).fetchall()
    ]
    text_regions = [(region, 1.0) for region in find_pdf_regions(source_path, findings)]
    token_regions = ocr_token_regions(conn, doc_id, findings)
    regions = text_regions + token_regions
    inserted = insert_pending_pdf_regions(conn, doc_id, regions)
    record_document_artifact(
        conn,
        doc_id,
        "pdf_region_snapshot",
        "PDF coordinate review snapshot",
        metadata={
            "generated_regions": len(regions),
            "inserted_regions": inserted,
            "finding_count": len(findings),
            "ocr_token_regions": len(token_regions),
        },
    )
    refresh_document_state(conn, doc_id)
    audit_and_commit(conn, "pdf_regions.generate", document_id=doc_id, metadata={"generated_regions": len(regions), "inserted_regions": inserted})
    conn.close()
    return api_pdf_regions(doc_id)


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/export-artifact/latest")
@require_roles("reviewer", "admin")
def api_pdf_export_artifact_latest(doc_id: int):
    conn = get_db()
    doc = get_pdf_document(conn, doc_id, "export.redacted_pdf_artifact")
    if not isinstance(doc, sqlite3.Row):
        return doc
    blockers = pdf_export_blockers(conn, doc)
    if blockers:
        return audited_error(
            conn,
            "The saved reviewed redacted PDF stays blocked until PDF redaction review gates pass.",
            409,
            "export.redacted_pdf_artifact",
            doc_id,
            metadata={"blocker_count": len(blockers), "blockers": blockers},
        )
    artifact = latest_redacted_pdf_artifact(conn, doc_id)
    if not artifact:
        return audited_error(conn, "No saved reviewed redacted PDF artifact exists yet.", 404, "export.redacted_pdf_artifact", doc_id)
    artifact_path = Path(artifact["file_path"])
    if not artifact_path.exists():
        return audited_error(conn, "The saved reviewed redacted PDF file was not found on disk.", 404, "export.redacted_pdf_artifact", doc_id)
    audit_and_commit(conn, "export.redacted_pdf_artifact", document_id=doc_id, metadata={"artifact_id": artifact["id"]})
    conn.close()
    # Read the artifact under a with block rather than handing send_file the
    # path: send_file opens the file itself and only closes it when the
    # response is closed, which leaked an open handle per download
    # (ResourceWarning: unclosed file) whenever a caller did not close it.
    with artifact_path.open("rb") as handle:
        data = handle.read()
    return send_file(BytesIO(data), as_attachment=True, download_name=artifact_path.name, mimetype="application/pdf")


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/qa/latest")
@require_roles("viewer", "reviewer", "admin")
def api_pdf_qa_latest(doc_id: int):
    conn = get_db()
    doc = get_pdf_document(conn, doc_id, "pdf_qa.view_latest")
    if not isinstance(doc, sqlite3.Row):
        return doc
    artifact = conn.execute(
        """
        SELECT id, label, metadata, qa_status, created_at, actor_username
        FROM document_artifacts
        WHERE document_id = ? AND artifact_type = 'pdf_qa'
        ORDER BY id DESC LIMIT 1
        """,
        (doc_id,),
    ).fetchone()
    conn.close()
    if not artifact:
        return jsonify({"error": "No PDF QA run has been recorded yet."}), 404
    return jsonify(
        {
            "artifact_id": artifact["id"],
            "label": artifact["label"],
            "qa_status": artifact["qa_status"],
            "created_at": artifact["created_at"],
            "actor_username": artifact["actor_username"],
            "metadata": json.loads(artifact["metadata"] or "{}"),
        }
    )


@pdf_regions_bp.route("/api/document/<int:doc_id>/pdf/regions/review-batch", methods=["POST"])
@require_roles("reviewer", "admin")
def api_pdf_regions_batch_review(doc_id: int):
    payload = request.get_json(silent=True) or {}
    action = payload.get("action")
    if action not in {"approve", "reject", "pending"}:
        return jsonify({"error": "Unsupported batch PDF region action"}), 400

    conn = get_db()
    doc = get_pdf_document(conn, doc_id, f"pdf_region_batch.{action}")
    if not isinstance(doc, sqlite3.Row):
        return doc

    page_number = int(payload["page_number"]) if str(payload.get("page_number") or "").isdigit() else None
    source = str(payload.get("source") or "").strip() or None
    category = str(payload.get("category") or "").strip() or None
    only_pending = bool(payload.get("only_pending", True))
    region_ids = [int(item) for item in payload.get("region_ids", []) if str(item).isdigit()]

    query = "SELECT id FROM pdf_redaction_regions WHERE document_id = ?"
    params: list[object] = [doc_id]
    if region_ids:
        query += f" AND id IN ({','.join('?' for _ in region_ids)})"
        params.extend(region_ids)
    if page_number:
        query += " AND page_number = ?"
        params.append(page_number)
    if source:
        query += " AND source = ?"
        params.append(source)
    if category:
        query += " AND category = ?"
        params.append(category)
    if only_pending:
        query += " AND review_status = 'pending'"

    ids = [row["id"] for row in conn.execute(query, params).fetchall()]
    filters_metadata = {
        "page_number": page_number,
        "source": source,
        "category": category,
        "only_pending": only_pending,
        "region_id_count": len(region_ids),
    }
    if not ids:
        audit_and_commit(conn, f"pdf_region_batch.{action}", document_id=doc_id, result="noop", metadata=filters_metadata)
        conn.close()
        return jsonify({"ok": True, "updated": 0})

    placeholders = ",".join("?" for _ in ids)
    review_status = {"approve": "approved", "reject": "rejected", "pending": "pending"}[action]
    conn.execute(
        f"""
        UPDATE pdf_redaction_regions
        SET review_status = ?,
            reviewed_by = CASE WHEN ? != 'pending' THEN ? ELSE reviewed_by END,
            reviewed_at = CASE WHEN ? != 'pending' THEN CURRENT_TIMESTAMP ELSE reviewed_at END,
            updated_at = CURRENT_TIMESTAMP
        WHERE document_id = ? AND id IN ({placeholders})
        """,
        (review_status, review_status, g.current_user["id"], review_status, doc_id, *ids),
    )
    refresh_document_state(conn, doc_id)
    audit_and_commit(
        conn,
        f"pdf_region_batch.{action}",
        document_id=doc_id,
        metadata={"updated": len(ids), **filters_metadata},
    )
    conn.close()
    return jsonify({"ok": True, "updated": len(ids), "review_status": review_status})
