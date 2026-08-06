"""Redaction Studio page, admin pages, terminology, and audit-log routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, render_template_string, request

from app import audit_event, get_db, require_roles, template_user_context
from legal_analyzer.privacy import finding_explanations
from legal_analyzer.taxonomy import OUTPUT_POSITIONING, TERMINOLOGY

studio_bp = Blueprint("studio", __name__)


@studio_bp.route("/studio/<int:doc_id>")
@require_roles("viewer", "reviewer", "admin")
def studio(doc_id: int):
    conn = get_db()
    doc = conn.execute("SELECT id, filename FROM documents WHERE id = ?", (doc_id,)).fetchone()
    conn.close()
    if not doc:
        return render_template_string("<p>Document not found.</p><p><a href='/'>Back to dashboard</a></p>"), 404
    return render_template(
        "studio.html",
        doc_id=doc_id,
        filename=doc["filename"],
        positioning=OUTPUT_POSITIONING,
        terminology=TERMINOLOGY,
        finding_explanations=finding_explanations(),
        **template_user_context(),
    )


@studio_bp.route("/audit-log")
@require_roles("admin")
def audit_log_page():
    return render_template("audit.html", positioning=OUTPUT_POSITIONING, **template_user_context())


@studio_bp.route("/settings")
@require_roles("admin")
def settings_page():
    return render_template("settings.html", positioning=OUTPUT_POSITIONING, terminology=TERMINOLOGY, **template_user_context())


@studio_bp.route("/api/terminology")
def api_terminology():
    return jsonify({"terminology": TERMINOLOGY, "positioning": OUTPUT_POSITIONING})


@studio_bp.route("/api/audit-log")
@require_roles("admin")
def api_audit_log():
    conn = get_db()
    query = """
        SELECT id, actor_username, actor_role, action, document_id, result, metadata, created_at
        FROM audit_log
        WHERE 1=1
    """
    params: list[object] = []
    for key, column in {
        "document_id": "document_id",
        "actor": "actor_username",
        "action": "action",
    }.items():
        value = request.args.get(key)
        if value:
            query += f" AND {column} = ?"
            params.append(value)
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    if date_from:
        query += " AND created_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND created_at <= ?"
        params.append(date_to)
    query += " ORDER BY created_at DESC, id DESC LIMIT 500"
    rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    audit_event(conn, "audit_log.view", metadata={"filters": {key: request.args.get(key) for key in request.args}})
    conn.commit()
    conn.close()
    return jsonify({"audit_log": rows, "total": len(rows)})
