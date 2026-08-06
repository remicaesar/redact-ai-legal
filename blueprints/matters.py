"""Matter workspace pages and matter/document assignment routes.

Relocated verbatim from app.py during the blueprint split; no behavior change.
"""

from __future__ import annotations

import sqlite3

from flask import Blueprint, g, jsonify, render_template, render_template_string, request

from app import (
    assign_document_to_matter,
    audit_and_commit,
    ensure_unassigned_matter,
    get_db,
    require_roles,
    template_user_context,
    valid_matter_id,
)
from blueprints.documents import api_document_detail
from legal_analyzer.taxonomy import OUTPUT_POSITIONING

matters_bp = Blueprint("matters", __name__)


@matters_bp.route("/matters")
@require_roles("viewer", "reviewer", "admin")
def matters_page():
    return render_template("matters.html", positioning=OUTPUT_POSITIONING, **template_user_context())


@matters_bp.route("/matter/<int:matter_id>")
@require_roles("viewer", "reviewer", "admin")
def matter_page(matter_id: int):
    conn = get_db()
    matter = conn.execute("SELECT id, name FROM matters WHERE id = ?", (matter_id,)).fetchone()
    conn.close()
    if not matter:
        return render_template_string("<p>Matter not found.</p><p><a href='/matters'>Back to matters</a></p>"), 404
    return render_template("matter.html", matter_id=matter_id, matter_name=matter["name"], positioning=OUTPUT_POSITIONING, **template_user_context())


@matters_bp.route("/api/matters")
@require_roles("viewer", "reviewer", "admin")
def api_matters():
    conn = get_db()
    ensure_unassigned_matter(conn)
    rows = conn.execute(
        """
        SELECT
            m.id, m.name, m.status, m.description, m.created_at, m.updated_at,
            c.name AS client_name,
            COUNT(DISTINCT dm.document_id) AS document_count,
            COUNT(DISTINCT CASE WHEN d.review_status = 'needs_ocr' THEN d.id END) AS needs_ocr_count,
            COUNT(DISTINCT CASE WHEN d.review_status IN ('pending_review', 'redaction_complete', 'reviewed_blocked') THEN d.id END) AS review_queue_count,
            COUNT(DISTINCT CASE WHEN pf.risk = 'CRITICAL' THEN pf.id END) AS critical_finding_count,
            COUNT(DISTINCT da.id) AS artifact_count
        FROM matters m
        LEFT JOIN clients c ON c.id = m.client_id
        LEFT JOIN document_matters dm ON dm.matter_id = m.id
        LEFT JOIN documents d ON d.id = dm.document_id
        LEFT JOIN privacy_findings pf ON pf.document_id = d.id
        LEFT JOIN document_artifacts da ON da.matter_id = m.id
        GROUP BY m.id
        ORDER BY CASE WHEN m.name = 'Unassigned' THEN 1 ELSE 0 END, m.updated_at DESC, m.name
        """
    ).fetchall()
    conn.commit()
    conn.close()
    return jsonify({"matters": [dict(row) for row in rows], "total": len(rows)})


@matters_bp.route("/api/matters", methods=["POST"])
@require_roles("reviewer", "admin")
def api_create_matter():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Matter name is required"}), 400
    description = str(payload.get("description") or "").strip() or None
    client_id = payload.get("client_id")
    conn = get_db()
    try:
        cursor = conn.execute(
            """
            INSERT INTO matters (name, client_id, status, description, created_by)
            VALUES (?, ?, 'active', ?, ?)
            """,
            (name, int(client_id) if client_id else None, description, g.current_user["id"]),
        )
        matter_id = cursor.lastrowid
        audit_and_commit(conn, "matter.create", metadata={"matter_id": matter_id})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Matter name already exists"}), 409
    conn.close()
    return api_matter_detail(matter_id)


@matters_bp.route("/api/matter/<int:matter_id>")
@require_roles("viewer", "reviewer", "admin")
def api_matter_detail(matter_id: int):
    conn = get_db()
    matter = conn.execute(
        """
        SELECT m.*, c.name AS client_name
        FROM matters m
        LEFT JOIN clients c ON c.id = m.client_id
        WHERE m.id = ?
        """,
        (matter_id,),
    ).fetchone()
    if not matter:
        conn.close()
        return jsonify({"error": "Matter not found"}), 404
    documents = [
        dict(row)
        for row in conn.execute(
            """
            SELECT
                d.id, d.filename, d.title, d.file_extension, d.residual_risk,
                d.review_status, d.ocr_status, d.extraction_status, d.external_llm_readiness,
                COUNT(pf.id) AS finding_count,
                SUM(CASE WHEN pf.risk = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
                COUNT(da.id) AS artifact_count
            FROM document_matters dm
            JOIN documents d ON d.id = dm.document_id
            LEFT JOIN privacy_findings pf ON pf.document_id = d.id
            LEFT JOIN document_artifacts da ON da.document_id = d.id
            WHERE dm.matter_id = ?
            GROUP BY d.id
            ORDER BY d.updated_at DESC, d.filename
            """,
            (matter_id,),
        ).fetchall()
    ]
    artifacts = [
        dict(row)
        for row in conn.execute(
            """
            SELECT da.id, da.document_id, d.filename, da.artifact_type, da.label, da.export_style,
                   da.qa_status, da.metadata, da.actor_username, da.created_at
            FROM document_artifacts da
            JOIN documents d ON d.id = da.document_id
            WHERE da.matter_id = ?
            ORDER BY da.created_at DESC, da.id DESC
            LIMIT 100
            """,
            (matter_id,),
        ).fetchall()
    ]
    result = dict(matter)
    result["documents"] = documents
    result["artifacts"] = artifacts
    result["summary"] = {
        "document_count": len(documents),
        "review_queue_count": sum(1 for doc in documents if doc["review_status"] in {"pending_review", "redaction_complete", "reviewed_blocked"}),
        "needs_ocr_count": sum(1 for doc in documents if doc["review_status"] == "needs_ocr"),
        "artifact_count": len(artifacts),
    }
    conn.close()
    return jsonify(result)


@matters_bp.route("/api/document/<int:doc_id>/matter", methods=["POST"])
@require_roles("reviewer", "admin")
def api_assign_document_matter(doc_id: int):
    payload = request.get_json(silent=True) or {}
    requested_matter_id = payload.get("matter_id")
    conn = get_db()
    doc = conn.execute("SELECT id FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    matter_id = valid_matter_id(conn, int(requested_matter_id) if requested_matter_id else None)
    assign_document_to_matter(conn, doc_id, matter_id)
    conn.execute("UPDATE documents SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (doc_id,))
    audit_and_commit(conn, "document.assign_matter", document_id=doc_id, metadata={"matter_id": matter_id})
    conn.close()
    return api_document_detail(doc_id)


@matters_bp.route("/api/document/<int:doc_id>/artifacts")
@require_roles("viewer", "reviewer", "admin")
def api_document_artifacts(doc_id: int):
    conn = get_db()
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, artifact_type, label, file_path, metadata, export_style, qa_status,
                   actor_username, created_at
            FROM document_artifacts
            WHERE document_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (doc_id,),
        ).fetchall()
    ]
    conn.close()
    return jsonify({"artifacts": rows, "total": len(rows)})


@matters_bp.route("/api/matter/<int:matter_id>/review-matrix")
@require_roles("viewer", "reviewer", "admin")
def api_matter_review_matrix(matter_id: int):
    conn = get_db()
    matter = conn.execute("SELECT id FROM matters WHERE id = ?", (matter_id,)).fetchone()
    if not matter:
        conn.close()
        return jsonify({"error": "Matter not found"}), 404
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT
                d.id AS document_id,
                d.filename,
                d.residual_risk,
                d.review_status AS document_review_status,
                d.redaction_completed,
                d.ocr_status,
                pf.id AS finding_id,
                pf.category,
                pf.risk,
                pf.source,
                pf.review_status AS finding_review_status,
                pf.reviewer_note,
                pf.part_name,
                fe.source_part,
                fe.page_number,
                fe.context,
                fe.verification_status,
                latest_qa.qa_status AS latest_qa_status,
                latest_qa.created_at AS latest_qa_at
            FROM document_matters dm
            JOIN documents d ON d.id = dm.document_id
            LEFT JOIN privacy_findings pf ON pf.document_id = d.id
            LEFT JOIN finding_evidence fe ON fe.finding_id = pf.id
            LEFT JOIN (
                SELECT da1.document_id, da1.qa_status, da1.created_at
                FROM document_artifacts da1
                WHERE da1.artifact_type = 'docx_qa'
                  AND da1.id = (
                    SELECT da2.id
                    FROM document_artifacts da2
                    WHERE da2.document_id = da1.document_id AND da2.artifact_type = 'docx_qa'
                    ORDER BY da2.created_at DESC, da2.id DESC
                    LIMIT 1
                  )
            ) latest_qa ON latest_qa.document_id = d.id
            WHERE dm.matter_id = ?
            ORDER BY d.filename, pf.risk DESC, pf.id
            """,
            (matter_id,),
        ).fetchall()
    ]
    conn.close()
    return jsonify({"rows": rows, "total": len(rows)})
