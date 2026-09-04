"""Dashboard page, document listing/detail, upload, and re-extraction routes."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

import app as app_module
from app import (
    apply_reextraction,
    audit_and_commit,
    audited_error,
    format_size,
    get_db,
    matter_for_document,
    require_roles,
    resolve_document_path,
    save_uploaded_document,
    template_user_context,
)
from legal_analyzer.classifier import supported_file
from legal_analyzer.extraction import extract_text
from legal_analyzer.status import compute_pipeline_status
from legal_analyzer.taxonomy import OUTPUT_POSITIONING, TERMINOLOGY

documents_bp = Blueprint("documents", __name__)


@documents_bp.route("/")
@require_roles("viewer", "reviewer", "admin", anonymous_redirect="landing.welcome")
def index():
    conn = get_db()
    stats = {
        "total": conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
        "categories": conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0],
        "clients": conn.execute("SELECT COUNT(DISTINCT client_id) FROM documents WHERE client_id IS NOT NULL").fetchone()[0],
        "high_risk": conn.execute("SELECT COUNT(*) FROM documents WHERE residual_risk = 'High'").fetchone()[0],
        "blocked": conn.execute("SELECT COUNT(*) FROM documents WHERE external_llm_readiness LIKE 'Blocked%'").fetchone()[0],
        "review_required": conn.execute("SELECT COUNT(*) FROM documents WHERE human_review_required = 1").fetchone()[0],
        "needs_ocr": conn.execute("SELECT COUNT(*) FROM documents WHERE review_status = 'needs_ocr'").fetchone()[0],
        "approved": conn.execute("SELECT COUNT(*) FROM documents WHERE review_status = 'approved_for_external_llm'").fetchone()[0],
    }
    category_stats = conn.execute(
        """
        SELECT cat.id, cat.name_tr, cat.icon, COUNT(d.id) AS cnt
        FROM categories cat
        LEFT JOIN documents d ON cat.id = d.category_id
        GROUP BY cat.id
        HAVING cnt > 0
        ORDER BY cnt DESC
        """
    ).fetchall()
    client_stats = conn.execute(
        """
        SELECT c.id, c.name, COUNT(d.id) AS cnt
        FROM clients c
        JOIN documents d ON c.id = d.client_id
        GROUP BY c.id
        ORDER BY cnt DESC
        LIMIT 20
        """
    ).fetchall()
    conn.close()
    return render_template(
        "index.html",
        stats=stats,
        category_stats=category_stats,
        client_stats=client_stats,
        terminology=TERMINOLOGY,
        positioning=OUTPUT_POSITIONING,
        **template_user_context(),
    )


@documents_bp.route("/api/document/<int:doc_id>/source-file")
@require_roles("viewer", "reviewer", "admin")
def api_document_source_file(doc_id: int):
    conn = get_db()
    doc = conn.execute("SELECT filename, filepath, file_extension FROM documents WHERE id = ?", (doc_id,)).fetchone()
    conn.close()
    if not doc:
        return jsonify({"error": "Document not found"}), 404
    path = resolve_document_path(doc["filepath"])
    if not path.exists():
        return jsonify({"error": "Source file was not found"}), 404
    if doc["file_extension"] != ".pdf":
        return jsonify({"error": "Inline source preview currently supports PDF only."}), 415
    return send_file(path, mimetype="application/pdf", download_name=doc["filename"], as_attachment=False)


@documents_bp.route("/api/document/<int:doc_id>/text")
@require_roles("viewer", "reviewer", "admin")
def api_document_text(doc_id: int):
    conn = get_db()
    doc = conn.execute(
        "SELECT filename, filepath, file_extension, ocr_status FROM documents WHERE id = ?",
        (doc_id,),
    ).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    if (doc["ocr_status"] or "not_required") == "accepted":
        pages = conn.execute(
            """
            SELECT text FROM ocr_pages
            WHERE document_id = ? AND status = 'accepted' AND text IS NOT NULL AND text != ''
            ORDER BY page_number
            """,
            (doc_id,),
        ).fetchall()
        conn.close()
        return jsonify({"text": "\n\n".join(row["text"] for row in pages), "source": "ocr_accepted", "warning": None})
    conn.close()
    path = resolve_document_path(doc["filepath"])
    if not path.exists():
        return jsonify({"error": "Source file was not found"}), 404
    text, warning = extract_text(path)
    return jsonify({"text": text, "source": "extraction", "warning": warning})


@documents_bp.route("/api/documents")
@require_roles("viewer", "reviewer", "admin")
def api_documents():
    conn = get_db()
    search = request.args.get("search", "").strip()
    category_id = request.args.get("category", "")
    client_id = request.args.get("client", "")
    file_type = request.args.get("file_type", "")
    risk = request.args.get("risk", "")
    readiness = request.args.get("readiness", "")
    extraction_status = request.args.get("extraction_status", "")
    review_status = request.args.get("review_status", "")
    ocr_status = request.args.get("ocr_status", "")

    query = """
        SELECT
            d.id, d.filename, d.filepath, d.file_extension, d.file_size,
            c.name AS client_name,
            cat.name_tr AS category_name, cat.icon AS category_icon,
            sub.name_tr AS subcategory_name,
            d.title, d.language, d.version, d.date_detected,
            d.residual_risk, d.recommended_strategy, d.extraction_warning, d.extraction_status,
            d.external_llm_readiness, d.human_review_required, d.redaction_status,
            d.redaction_completed, d.human_review_approved, d.auto_mode_enabled,
            d.review_status, d.ocr_status, d.reviewed_at,
            m.id AS matter_id,
            m.name AS matter_name,
            COUNT(pf.id) AS finding_count,
            SUM(CASE WHEN pf.risk = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN pf.risk = 'HIGH' THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN pf.review_status = 'pending' THEN 1 ELSE 0 END) AS pending_finding_count,
            (SELECT COUNT(*) FROM pdf_redaction_regions r
             WHERE r.document_id = d.id AND r.review_status = 'pending') AS pending_pdf_region_count
        FROM documents d
        LEFT JOIN clients c ON d.client_id = c.id
        LEFT JOIN categories cat ON d.category_id = cat.id
        LEFT JOIN subcategories sub ON d.subcategory_id = sub.id
        LEFT JOIN document_matters dm ON dm.document_id = d.id
        LEFT JOIN matters m ON m.id = dm.matter_id
        LEFT JOIN privacy_findings pf ON d.id = pf.document_id
        WHERE 1=1
    """
    params: list[object] = []

    if search:
        query += " AND d.id IN (SELECT rowid FROM documents_fts WHERE documents_fts MATCH ?)"
        params.append(" OR ".join(f'"{word}"*' for word in search.split() if word))
    if category_id:
        query += " AND d.category_id = ?"
        params.append(int(category_id))
    if client_id:
        query += " AND d.client_id = ?"
        params.append(int(client_id))
    if file_type:
        query += " AND d.file_extension = ?"
        params.append(file_type)
    if risk:
        query += " AND d.residual_risk = ?"
        params.append(risk)
    if readiness:
        query += " AND d.external_llm_readiness LIKE ?"
        params.append(f"{readiness}%")
    if extraction_status:
        query += " AND d.extraction_status = ?"
        params.append(extraction_status)
    if review_status:
        query += " AND d.review_status = ?"
        params.append(review_status)
    if ocr_status:
        query += " AND d.ocr_status = ?"
        params.append(ocr_status)

    query += " GROUP BY d.id ORDER BY d.residual_risk DESC, cat.name_tr, d.filename"

    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(200, max(0, int(request.args.get("page_size", 0))))
    except ValueError:
        page, page_size = 1, 0

    total = None
    if page_size:
        count_query = "SELECT COUNT(*) FROM documents d WHERE 1=1" + query.split("WHERE 1=1", 1)[1].split("GROUP BY", 1)[0]
        total = conn.execute(count_query, params).fetchone()[0]
        query += " LIMIT ? OFFSET ?"
        params = [*params, page_size, (page - 1) * page_size]

    rows = conn.execute(query, params).fetchall()
    conn.close()

    documents = []
    for row in rows:
        doc = dict(row)
        doc["file_size_formatted"] = format_size(doc.get("file_size") or 0)
        doc.update(
            compute_pipeline_status(
                doc,
                pending_findings=doc.get("pending_finding_count") or 0,
                pending_pdf_regions=doc.get("pending_pdf_region_count") or 0,
            )
        )
        documents.append(doc)
    if total is None:
        total = len(documents)
    result = {"documents": documents, "total": total}
    if page_size:
        result.update({"page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))})
    return jsonify(result)


@documents_bp.route("/api/document/<int:doc_id>")
@require_roles("viewer", "reviewer", "admin")
def api_document_detail(doc_id: int):
    conn = get_db()
    doc = conn.execute(
        """
        SELECT
            d.*,
            c.name AS client_name,
            cat.name_tr AS category_name,
            cat.icon AS category_icon,
            sub.name_tr AS subcategory_name
        FROM documents d
        LEFT JOIN clients c ON d.client_id = c.id
        LEFT JOIN categories cat ON d.category_id = cat.id
        LEFT JOIN subcategories sub ON d.subcategory_id = sub.id
        WHERE d.id = ?
        """,
        (doc_id,),
    ).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404

    findings = [dict(row) for row in conn.execute(
        """
        SELECT id, category, sample, risk, recommended_action, placeholder, replacement_text,
               review_status, reviewer_note, source, part_name, start_offset, end_offset
        FROM privacy_findings
        WHERE document_id = ?
        ORDER BY id
        LIMIT 500
        """,
        (doc_id,),
    ).fetchall()]
    ocr_pages = [dict(row) for row in conn.execute(
        """
        SELECT id, page_number, text, confidence, status, source, reviewer_note, created_at, reviewed_at
        FROM ocr_pages
        WHERE document_id = ?
        ORDER BY page_number
        """,
        (doc_id,),
    ).fetchall()]
    ocr_summary = conn.execute(
        """
        SELECT
            COUNT(*) AS page_count,
            COALESCE(SUM(LENGTH(text)), 0) AS text_chars,
            AVG(confidence) AS average_confidence,
            SUM(CASE WHEN status = 'accepted' THEN LENGTH(text) ELSE 0 END) AS accepted_text_chars
        FROM ocr_pages
        WHERE document_id = ?
        """,
        (doc_id,),
    ).fetchone()
    ocr_finding_count = conn.execute(
        "SELECT COUNT(*) FROM privacy_findings WHERE document_id = ? AND source = 'ocr'",
        (doc_id,),
    ).fetchone()[0]
    finding_count = conn.execute(
        "SELECT COUNT(*) FROM privacy_findings WHERE document_id = ?",
        (doc_id,),
    ).fetchone()[0]
    pending_finding_count = conn.execute(
        "SELECT COUNT(*) FROM privacy_findings WHERE document_id = ? AND review_status = 'pending'",
        (doc_id,),
    ).fetchone()[0]
    pdf_region_summary = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN review_status = 'pending' THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN review_status = 'approved' THEN 1 ELSE 0 END) AS approved,
            SUM(CASE WHEN review_status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
            SUM(CASE WHEN source = 'manual' THEN 1 ELSE 0 END) AS manual
        FROM pdf_redaction_regions
        WHERE document_id = ?
        """,
        (doc_id,),
    ).fetchone()
    tags = [row["tag"] for row in conn.execute("SELECT tag FROM document_tags WHERE document_id = ?", (doc_id,)).fetchall()]
    matter = matter_for_document(conn, doc_id)
    artifacts = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, artifact_type, label, file_path, metadata, export_style, qa_status,
                   actor_username, created_at
            FROM document_artifacts
            WHERE document_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 50
            """,
            (doc_id,),
        ).fetchall()
    ]
    evidence_rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT finding_id, source_part, page_number, start_offset, end_offset, context, verification_status
            FROM finding_evidence
            WHERE document_id = ?
            """,
            (doc_id,),
        ).fetchall()
    ]
    evidence_by_finding = {row["finding_id"]: row for row in evidence_rows}
    for finding in findings:
        finding["evidence"] = evidence_by_finding.get(finding["id"])
    result = dict(doc)
    result["tags"] = tags
    result["findings"] = findings
    # `findings` above is capped at 500 rows; these two are true, unbounded
    # counts so the client can tell when a review group's members, count, and
    # risk badge describe only part of the document (see the LIMIT above).
    result["finding_count"] = finding_count
    result["pending_finding_count"] = pending_finding_count
    result["matter"] = dict(matter) if matter else None
    result["artifacts"] = artifacts
    result["ocr_pages"] = ocr_pages
    result["ocr_summary"] = {
        "page_count": ocr_summary["page_count"],
        "text_chars": ocr_summary["text_chars"],
        "accepted_text_chars": ocr_summary["accepted_text_chars"] or 0,
        "average_confidence": ocr_summary["average_confidence"],
        "ocr_finding_count": ocr_finding_count,
    }
    result["pdf_region_summary"] = {
        "total": pdf_region_summary["total"] or 0,
        "pending": pdf_region_summary["pending"] or 0,
        "approved": pdf_region_summary["approved"] or 0,
        "rejected": pdf_region_summary["rejected"] or 0,
        "manual": pdf_region_summary["manual"] or 0,
    }
    result["privacy_profile"] = json.loads(result["privacy_profile"] or "{}")
    result.update(
        compute_pipeline_status(
            result,
            pending_findings=pending_finding_count,
            pending_pdf_regions=result["pdf_region_summary"]["pending"],
        )
    )
    conn.close()
    return jsonify(result)


@documents_bp.route("/api/upload", methods=["POST"])
@require_roles("reviewer", "admin")
def api_upload_document():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        conn = get_db()
        return audited_error(conn, "No file was uploaded.", 400, "document.upload")

    original_name = Path(uploaded.filename).name
    if not supported_file(original_name):
        conn = get_db()
        return audited_error(
            conn,
            "Unsupported file type for upload.",
            415,
            "document.upload",
            metadata={"filename": original_name, "extension": Path(original_name).suffix.lower()},
        )

    requested_matter_id = request.form.get("matter_id")
    matter_id = int(requested_matter_id) if requested_matter_id and requested_matter_id.isdigit() else None
    app_module.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = secure_filename(original_name) or "uploaded_document"
    unique_prefix = f"{int(time.time() * 1000)}_{hashlib.sha256(original_name.encode('utf-8')).hexdigest()[:8]}"
    stored_path = app_module.UPLOAD_DIR / f"{unique_prefix}_{safe_name}"
    uploaded.save(stored_path)

    conn = get_db()
    try:
        document_id = save_uploaded_document(stored_path, original_name, conn, matter_id=matter_id)
        assigned_matter = matter_for_document(conn, document_id)
        audit_and_commit(
            conn,
            "document.upload",
            document_id=document_id,
            metadata={
                "filename_hash": hashlib.sha256(original_name.encode("utf-8")).hexdigest()[:12],
                "extension": stored_path.suffix.lower(),
                "file_size": stored_path.stat().st_size,
                "matter_id": assigned_matter["id"] if assigned_matter else None,
            },
        )
    except Exception as exc:
        if stored_path.exists():
            stored_path.unlink()
        audit_and_commit(
            conn,
            "document.upload",
            result="failed",
            metadata={
                "filename_hash": hashlib.sha256(original_name.encode("utf-8")).hexdigest()[:12],
                "extension": Path(original_name).suffix.lower(),
                "error": str(exc),
            },
        )
        conn.close()
        return jsonify({"error": f"Upload analysis failed: {exc}"}), 500
    conn.close()
    return api_document_detail(document_id)


@documents_bp.route("/api/document/<int:doc_id>/reextract", methods=["POST"])
@require_roles("reviewer", "admin")
def api_document_reextract(doc_id: int):
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    if (doc["ocr_status"] or "not_required") == "accepted":
        return audited_error(
            conn,
            "This document uses reviewer-accepted OCR text; reject the OCR output first if you want to re-extract.",
            409,
            "document.reextract",
            doc_id,
        )
    try:
        summary = apply_reextraction(conn, doc)
    except FileNotFoundError as exc:
        return audited_error(conn, str(exc), 404, "document.reextract", doc_id)
    audit_and_commit(conn, "document.reextract", document_id=doc_id, metadata=summary)
    conn.close()
    return api_document_detail(doc_id)


@documents_bp.route("/api/documents/reextract-failed", methods=["POST"])
@require_roles("reviewer", "admin")
def api_documents_reextract_failed():
    conn = get_db()
    docs = conn.execute(
        """
        SELECT * FROM documents
        WHERE extraction_status != 'Complete'
          AND (ocr_status IS NULL OR ocr_status != 'accepted')
        ORDER BY id
        """
    ).fetchall()
    results = {"attempted": 0, "recovered": 0, "still_incomplete": 0, "missing_file": 0}
    for doc in docs:
        results["attempted"] += 1
        try:
            summary = apply_reextraction(conn, doc)
        except FileNotFoundError:
            results["missing_file"] += 1
            continue
        if summary["extraction_status"] == "Complete":
            results["recovered"] += 1
        else:
            results["still_incomplete"] += 1
    audit_and_commit(conn, "documents.reextract_failed", metadata=results)
    conn.close()
    return jsonify(results)
