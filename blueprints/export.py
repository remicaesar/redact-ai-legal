"""Reviewed redacted export (DOCX/PDF), export QA, and preview export routes."""

from __future__ import annotations

import json
import sqlite3
from io import BytesIO
from pathlib import Path

from flask import Blueprint, Response, jsonify, request, send_file

from app import (
    audit_and_commit,
    audited_error,
    build_docx,
    get_db,
    get_exportable_docx,
    get_pdf_document,
    latest_redacted_pdf_artifact,
    pdf_export_blockers,
    record_document_artifact,
    redaction_targets_for_document,
    require_roles,
    resolve_document_path,
    retained_sample_count_for_document,
    reviewed_pdf_regions,
    save_redacted_pdf_artifact_file,
    sensitive_samples_for_document,
)
from legal_analyzer.docx_quality import analyze_docx_export_quality
from legal_analyzer.docx_redactor import redact_docx
from legal_analyzer.pdf_redactor import analyze_pdf_redaction_quality, redact_pdf

export_bp = Blueprint("export", __name__)


@export_bp.route("/api/document/<int:doc_id>/redacted-export")
@require_roles("reviewer", "admin")
def api_document_redacted_export(doc_id: int):
    export_format = request.args.get("format", "docx").lower()
    redaction_style = request.args.get("style", "placeholder").lower()
    if export_format == "pdf":
        if redaction_style not in {"black_box", "placeholder"}:
            conn = get_db()
            return audited_error(
                conn,
                "Unsupported PDF redaction style. Use black_box.",
                400,
                "export.redacted_pdf",
                doc_id,
                metadata={"style": redaction_style},
            )
        conn = get_db()
        doc = get_pdf_document(conn, doc_id, "export.redacted_pdf")
        if not isinstance(doc, sqlite3.Row):
            return doc
        blockers = pdf_export_blockers(conn, doc)
        if blockers:
            return audited_error(
                conn,
                "Reviewed PDF export is blocked until PDF redaction review gates pass.",
                409,
                "export.redacted_pdf",
                doc_id,
                metadata={"blocker_count": len(blockers), "blockers": blockers},
            )
        regions = reviewed_pdf_regions(conn, doc_id)
        audit_and_commit(conn, "export.redacted_pdf", document_id=doc_id, metadata={"region_count": len(regions), "style": "black_box"})
        conn.close()

        source_path = resolve_document_path(doc["filepath"])
        if not source_path.exists():
            return jsonify({"error": f"Source PDF was not found: {source_path}"}), 404
        safe_stem = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in Path(doc["filename"]).stem)[:120] or "document"
        data = redact_pdf(source_path, regions)
        saved_path = save_redacted_pdf_artifact_file(doc_id, safe_stem, data)
        artifact_conn = get_db()
        record_document_artifact(
            artifact_conn,
            doc_id,
            "redacted_pdf",
            "Reviewed PDF redaction",
            file_path=str(saved_path),
            metadata={"region_count": len(regions), "byte_size": len(data)},
            export_style="black_box",
        )
        artifact_conn.commit()
        artifact_conn.close()
        return send_file(
            BytesIO(data),
            as_attachment=True,
            download_name=f"{safe_stem}_redacted.pdf",
            mimetype="application/pdf",
        )

    if export_format != "docx":
        conn = get_db()
        return audited_error(conn, "Actual redacted export supports reviewed DOCX and PDF only.", 415, "export.redacted_docx", doc_id)
    if redaction_style not in {"placeholder", "mask"}:
        conn = get_db()
        return audited_error(
            conn,
            "Unsupported DOCX redaction style. Use placeholder or mask.",
            400,
            "export.redacted_docx",
            doc_id,
            metadata={"style": redaction_style},
        )

    conn = get_db()
    doc = get_exportable_docx(conn, doc_id, "export.redacted_docx")
    if not isinstance(doc, sqlite3.Row):
        return doc
    targets = redaction_targets_for_document(conn, doc_id)
    audit_and_commit(
        conn,
        "export.redacted_docx",
        document_id=doc_id,
        metadata={"target_count": len(targets), "style": redaction_style},
    )
    conn.close()

    source_path = resolve_document_path(doc["filepath"])
    if not source_path.exists():
        return jsonify({"error": f"Source DOCX was not found: {source_path}"}), 404

    safe_stem = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in Path(doc["filename"]).stem)[:120]
    data = redact_docx(source_path, targets, style=redaction_style)
    style_suffix = "" if redaction_style == "placeholder" else "_mask"
    artifact_conn = get_db()
    record_document_artifact(
        artifact_conn,
        doc_id,
        "redacted_docx",
        "Reviewed DOCX redaction",
        metadata={"target_count": len(targets), "byte_size": len(data)},
        export_style=redaction_style,
    )
    artifact_conn.commit()
    artifact_conn.close()
    return send_file(
        BytesIO(data),
        as_attachment=True,
        download_name=f"{safe_stem}_redacted{style_suffix}.docx",
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


@export_bp.route("/api/document/<int:doc_id>/redacted-export/qa")
@require_roles("reviewer", "admin")
def api_document_redacted_export_qa(doc_id: int):
    export_format = request.args.get("format", "docx").lower()
    redaction_style = request.args.get("style", "placeholder").lower()
    if export_format == "pdf":
        if redaction_style not in {"black_box", "placeholder"}:
            conn = get_db()
            return audited_error(
                conn,
                "Unsupported PDF redaction style. Use black_box.",
                400,
                "export.redacted_pdf_qa",
                doc_id,
                metadata={"style": redaction_style},
            )
        conn = get_db()
        doc = get_pdf_document(conn, doc_id, "export.redacted_pdf_qa")
        if not isinstance(doc, sqlite3.Row):
            return doc
        blockers = pdf_export_blockers(conn, doc)
        if blockers:
            return audited_error(
                conn,
                "PDF export QA is blocked until PDF redaction review gates pass.",
                409,
                "export.redacted_pdf_qa",
                doc_id,
                metadata={"blocker_count": len(blockers), "blockers": blockers},
            )
        regions = reviewed_pdf_regions(conn, doc_id)
        region_state = {
            key: conn.execute(
                "SELECT COUNT(*) FROM pdf_redaction_regions WHERE document_id = ? AND review_status = ?",
                (doc_id, key),
            ).fetchone()[0]
            for key in ("pending", "approved", "rejected")
        }
        artifact = latest_redacted_pdf_artifact(conn, doc_id)
        # Same argument as the DOCX QA below: leakage measured only against the
        # approved regions cannot see a finding no region covers, so a second
        # occurrence of the same identifier elsewhere in the PDF was never
        # searched for at all. Retained/dismissed findings are excluded by
        # sensitive_samples_for_document, since for those the text remaining is
        # the expected outcome.
        pdf_sensitive_samples = sensitive_samples_for_document(conn, doc_id)
        pdf_retained_count = retained_sample_count_for_document(conn, doc_id)
        audit_and_commit(conn, "export.redacted_pdf_qa", document_id=doc_id, metadata={"region_count": len(regions), "style": "black_box"})
        conn.close()

        source_path = resolve_document_path(doc["filepath"])
        if not source_path.exists():
            return jsonify({"error": f"Source PDF was not found: {source_path}"}), 404
        artifact_path = Path(artifact["file_path"]) if artifact else None
        if artifact_path and artifact_path.exists():
            data = artifact_path.read_bytes()
            qa_target = "saved_artifact"
        else:
            data = redact_pdf(source_path, regions)
            qa_target = "freshly_generated"
        report = analyze_pdf_redaction_quality(
            source_path,
            data,
            regions,
            region_state=region_state,
            qa_target=qa_target,
            sensitive_samples=pdf_sensitive_samples,
            retained_count=pdf_retained_count,
        )
        report["document_id"] = doc_id
        artifact_conn = get_db()
        artifact_conn.execute(
            """
            UPDATE finding_evidence
            SET verification_status = ?
            WHERE document_id = ?
            """,
            # Same reason as the DOCX path below: a retained finding produces no
            # leakage by construction, so keying this off leakage_count alone
            # stamped "Verified redacted (QA passed)" on a PDF whose reviewer
            # chose to leave identifiers in it.
            (
                "redacted_verified"
                if report["leakage_count"] == 0 and not report["retained_count"]
                else "qa_warning",
                doc_id,
            ),
        )
        record_document_artifact(
            artifact_conn,
            doc_id,
            "pdf_qa",
            "PDF export QA",
            metadata={
                "overall_status": report["overall_status"],
                "leakage_count": report["leakage_count"],
                "retained_count": report["retained_count"],
                "region_count": report["region_count"],
                "qa_target": report["qa_target"],
                "annotation_count": report["annotation_count"],
            },
            export_style="black_box",
            qa_status=report["overall_status"],
        )
        artifact_conn.commit()
        artifact_conn.close()
        return jsonify(report)

    if export_format != "docx":
        conn = get_db()
        return audited_error(conn, "Reviewed export QA supports DOCX and PDF only.", 415, "export.redacted_docx_qa", doc_id)
    if redaction_style not in {"placeholder", "mask"}:
        conn = get_db()
        return audited_error(
            conn,
            "Unsupported DOCX redaction style. Use placeholder or mask.",
            400,
            "export.redacted_docx_qa",
            doc_id,
            metadata={"style": redaction_style},
        )

    conn = get_db()
    doc = get_exportable_docx(conn, doc_id, "export.redacted_docx_qa")
    if not isinstance(doc, sqlite3.Row):
        return doc
    targets = redaction_targets_for_document(conn, doc_id)
    # Leakage is measured against every finding whose text remaining would be
    # unexpected, not just the approved targets: a finding that was never made a
    # target is exactly the one the redactor cannot have removed. Findings the
    # reviewer deliberately retained are excluded from that set and counted
    # separately, so the report states them instead of reading as a clean pass.
    sensitive_samples = sensitive_samples_for_document(conn, doc_id)
    retained_count = retained_sample_count_for_document(conn, doc_id)
    audit_and_commit(
        conn,
        "export.redacted_docx_qa",
        document_id=doc_id,
        metadata={"target_count": len(targets), "style": redaction_style},
    )
    conn.close()

    source_path = resolve_document_path(doc["filepath"])
    if not source_path.exists():
        return jsonify({"error": f"Source DOCX was not found: {source_path}"}), 404

    data = redact_docx(source_path, targets, style=redaction_style)
    report = analyze_docx_export_quality(
        source_path, data, targets, sensitive_samples=sensitive_samples, retained_count=retained_count
    )
    report["style"] = redaction_style
    report["format"] = "docx"
    report["document_id"] = doc_id
    artifact_conn = get_db()
    artifact_conn.execute(
        """
        UPDATE finding_evidence
        SET verification_status = ?
        WHERE document_id = ?
        """,
        # A retained finding produces no leakage by construction, so keying this
        # off leakage_count alone stamped "Verified redacted (QA passed)" on a
        # document whose reviewer chose to leave identifiers in it.
        (
            "redacted_verified" if report["leakage_count"] == 0 and not report["retained_count"] else "qa_warning",
            doc_id,
        ),
    )
    record_document_artifact(
        artifact_conn,
        doc_id,
        "docx_qa",
        "DOCX export QA",
        metadata={
            "overall_status": report["overall_status"],
            "leakage_count": report["leakage_count"],
            "retained_count": report["retained_count"],
            "target_count": report.get("target_count", len(targets)),
        },
        export_style=redaction_style,
        qa_status=report["overall_status"],
    )
    artifact_conn.commit()
    artifact_conn.close()
    return jsonify(report)


@export_bp.route("/api/document/<int:doc_id>/export")
@require_roles("reviewer", "admin")
def api_document_export(doc_id: int):
    export_format = request.args.get("format", "txt").lower()
    conn = get_db()
    doc = conn.execute("SELECT id, filename, title, privacy_profile FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    audit_and_commit(conn, "export.preview", document_id=doc_id, metadata={"format": export_format})
    conn.close()

    profile = json.loads(doc["privacy_profile"] or "{}")
    redacted_text = profile.get("redacted_preview") or "No redacted preview available."
    safe_stem = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in Path(doc["filename"]).stem)[:120]

    if export_format == "txt":
        body = "\n".join(
            [
                "PRIVACY-REVIEWED REDACTED EXPORT",
                "LOWER-ASSURANCE PREVIEW EXPORT. This is not the layout-preserving reviewed DOCX redaction.",
                "This is an anonymization-assisted, risk-reduced preview; it is not guaranteed anonymous.",
                "",
                redacted_text,
            ]
        )
        return Response(
            body,
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={safe_stem}_redacted.txt"},
        )
    if export_format == "docx":
        data = build_docx(redacted_text)
        return send_file(
            BytesIO(data),
            as_attachment=True,
            download_name=f"{safe_stem}_redacted.docx",
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    return jsonify({"error": "Unsupported export format"}), 400
