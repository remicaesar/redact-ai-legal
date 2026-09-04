#!/usr/bin/env python3
"""Flask app core for legal document classification and privacy risk review.

This module owns shared infrastructure — the Flask app object, DB access,
auth/RBAC decorators, audit logging, document persistence helpers, and the
release-gate refresh (`refresh_document_state`). HTTP routes live in the
``blueprints`` package and import these helpers; any endpoint that mutates
findings, OCR state, or PDF regions must call ``refresh_document_state`` so
the external-LLM release gate stays accurate.
"""

from __future__ import annotations

import sys

if __name__ == "__main__":
    # Running as a script: alias this module as "app" so blueprint modules
    # importing "app" share this instance instead of importing a duplicate.
    sys.modules.setdefault("app", sys.modules[__name__])

import json
import hashlib
import os
import sqlite3
import time
from functools import wraps
from pathlib import Path
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile
from io import BytesIO

from flask import Flask, g, jsonify, redirect, request, session, url_for
from werkzeug.security import generate_password_hash

from classify import DEFAULT_STOCK_DIR, detect_client
from db.migrate import apply_migrations
from legal_analyzer.classifier import classify_document, detect_date, detect_language, detect_version, generate_title
from legal_analyzer.docx_redactor import RedactionTarget
from legal_analyzer.extraction import extract_text
from legal_analyzer.ocr import OCRToken, token_regions_for_sample
from legal_analyzer.pdf_redactor import PdfRegion
from legal_analyzer.privacy import DIRECT_IDENTIFIER_CATEGORIES, analyze_privacy, refresh_release_state

PROJECT_DIR = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv

    # Existing shell env vars win over .env values (override=False default).
    load_dotenv(PROJECT_DIR / ".env")
except ImportError:
    pass

DB_PATH = PROJECT_DIR / "db" / "legal_documents.db"
UPLOAD_DIR = PROJECT_DIR / "data" / "uploads"
EXPORT_DIR = PROJECT_DIR / "data" / "exports"
READY_DB_PATHS: set[Path] = set()

app = Flask(__name__)
app.secret_key = os.environ.get("LEGAL_ANALYZER_SECRET_KEY", "local-dev-secret-change-before-production")


def get_db() -> sqlite3.Connection:
    ensure_db_ready()
    # timeout: with a threaded server, concurrent writers must wait for the
    # single SQLite write lock instead of failing immediately with
    # "database is locked". WAL lets readers proceed while one writer holds
    # the lock, so a slow OCR/export write no longer blocks dashboard reads.
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    bootstrap_admin_from_env(conn)
    return conn


def ensure_db_ready() -> None:
    resolved = DB_PATH.resolve()
    if resolved in READY_DB_PATHS:
        return
    if DB_PATH.exists():
        apply_migrations(DB_PATH)
    READY_DB_PATHS.add(resolved)


def bootstrap_admin_from_env(conn: sqlite3.Connection) -> None:
    username = os.environ.get("LEGAL_ANALYZER_ADMIN_USERNAME", "admin").strip()
    password = os.environ.get("LEGAL_ANALYZER_ADMIN_PASSWORD", "").strip()
    if not password:
        return
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
        (username, generate_password_hash(password)),
    )
    conn.commit()


@app.before_request
def load_current_user() -> None:
    g.current_user = None
    user_id = session.get("user_id")
    if not user_id:
        return
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, role, active FROM users WHERE id = ? AND active = 1",
        (user_id,),
    ).fetchone()
    conn.close()
    if user:
        g.current_user = dict(user)


def require_roles(*roles: str, anonymous_redirect: str = "auth.login"):
    """Gate a route on an authenticated user holding one of ``roles``.

    ``anonymous_redirect`` names the endpoint anonymous visitors are sent to.
    It exists so the dashboard can show the public landing page instead of a
    bare login form; every other route still goes straight to /login, which is
    what a deep link should do.
    """
    allowed = set(roles)

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if not user:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for(anonymous_redirect))
            if user["role"] not in allowed:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Insufficient role"}), 403
                return redirect(url_for("documents.index"))
            return func(*args, **kwargs)

        return wrapper

    return decorator


def audit_event(
    conn: sqlite3.Connection,
    action: str,
    document_id: int | None = None,
    result: str = "success",
    metadata: dict | None = None,
) -> None:
    user = getattr(g, "current_user", None) or {}
    conn.execute(
        """
        INSERT INTO audit_log (
            actor_id, actor_username, actor_role, action, document_id, result, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user.get("id"),
            user.get("username", "anonymous"),
            user.get("role", "anonymous"),
            action,
            document_id,
            result,
            json.dumps(sanitize_audit_metadata(metadata or {}), ensure_ascii=False),
        ),
    )


def sanitize_audit_metadata(metadata: dict) -> dict:
    blocked_keys = {"text", "sample", "original_text", "replacement_text", "privacy_profile", "ocr_text", "password", "filename"}
    clean = {}
    for key, value in metadata.items():
        if key in blocked_keys:
            clean[key] = "[redacted]"
        elif isinstance(value, str) and len(value) > 200:
            clean[key] = value[:200]
        else:
            clean[key] = value
    return clean


def audit_and_commit(
    conn: sqlite3.Connection,
    action: str,
    document_id: int | None = None,
    result: str = "success",
    metadata: dict | None = None,
) -> None:
    audit_event(conn, action, document_id=document_id, result=result, metadata=metadata)
    conn.commit()


def audited_error(
    conn: sqlite3.Connection,
    message: str,
    status: int,
    action: str,
    document_id: int | None = None,
    metadata: dict | None = None,
):
    audit_and_commit(conn, action, document_id=document_id, result="blocked", metadata=metadata)
    conn.close()
    return jsonify({"error": message}), status


def template_user_context() -> dict:
    user = getattr(g, "current_user", None)
    role = user["role"] if user else ""
    return {
        "current_user": user,
        "current_role": role,
        "can_review": role in {"reviewer", "admin"},
        "can_admin": role == "admin",
    }


def ensure_unassigned_matter(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT id FROM matters WHERE name = 'Unassigned'").fetchone()
    if row:
        return row["id"]
    cursor = conn.execute(
        """
        INSERT INTO matters (name, status, description)
        VALUES ('Unassigned', 'active', 'Default local matter for documents without an explicit matter selection.')
        """
    )
    return cursor.lastrowid


def valid_matter_id(conn: sqlite3.Connection, matter_id: int | None) -> int:
    if matter_id:
        row = conn.execute("SELECT id FROM matters WHERE id = ?", (matter_id,)).fetchone()
        if row:
            return row["id"]
    return ensure_unassigned_matter(conn)


def matter_for_document(conn: sqlite3.Connection, doc_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT m.*
        FROM document_matters dm
        JOIN matters m ON m.id = dm.matter_id
        WHERE dm.document_id = ?
        """,
        (doc_id,),
    ).fetchone()


def assign_document_to_matter(conn: sqlite3.Connection, doc_id: int, matter_id: int) -> None:
    conn.execute(
        """
        INSERT INTO document_matters (document_id, matter_id)
        VALUES (?, ?)
        ON CONFLICT(document_id) DO UPDATE SET
            matter_id = excluded.matter_id,
            assigned_at = CURRENT_TIMESTAMP
        """,
        (doc_id, matter_id),
    )


def safe_json_metadata(metadata: dict | None) -> str:
    return json.dumps(sanitize_audit_metadata(metadata or {}), ensure_ascii=False)


def record_document_artifact(
    conn: sqlite3.Connection,
    doc_id: int,
    artifact_type: str,
    label: str,
    *,
    file_path: str | None = None,
    metadata: dict | None = None,
    export_style: str | None = None,
    qa_status: str | None = None,
) -> None:
    user = getattr(g, "current_user", None) or {}
    matter = matter_for_document(conn, doc_id)
    conn.execute(
        """
        INSERT INTO document_artifacts (
            document_id, matter_id, artifact_type, label, file_path, metadata,
            export_style, qa_status, actor_id, actor_username
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            doc_id,
            matter["id"] if matter else None,
            artifact_type,
            label,
            file_path,
            safe_json_metadata(metadata),
            export_style,
            qa_status,
            user.get("id"),
            user.get("username"),
        ),
    )


def evidence_context(text: str, start: int | None, end: int | None, sample: str | None) -> str:
    if start is not None and end is not None and 0 <= start <= end <= len(text):
        left = max(0, start - 48)
        right = min(len(text), end + 48)
        return text[left:right].replace("\n", " ").strip()
    return (sample or "")[:160]


def pdf_region_row_to_dict(row: sqlite3.Row) -> dict:
    data = dict(row)
    data["rect"] = {
        "x0": data.pop("x0"),
        "y0": data.pop("y0"),
        "x1": data.pop("x1"),
        "y1": data.pop("y1"),
    }
    return data


def pdf_region_from_row(row: sqlite3.Row) -> PdfRegion:
    return PdfRegion(
        page_number=row["page_number"],
        x0=row["x0"],
        y0=row["y0"],
        x1=row["x1"],
        y1=row["y1"],
        category=row["category"],
        source=row["source"],
        finding_id=row["finding_id"],
        sample=row["sample"],
        region_id=row["id"],
    )


def reviewed_pdf_regions(conn: sqlite3.Connection, doc_id: int) -> list[PdfRegion]:
    return [
        pdf_region_from_row(row)
        for row in conn.execute(
            """
            SELECT r.*, pf.sample
            FROM pdf_redaction_regions r
            LEFT JOIN privacy_findings pf ON pf.id = r.finding_id
            WHERE r.document_id = ?
              AND r.review_status = 'approved'
            ORDER BY r.page_number, r.id
            """,
            (doc_id,),
        ).fetchall()
    ]


def pdf_region_fingerprint(doc_id: int, region: PdfRegion) -> str:
    payload = f"{doc_id}:{region.finding_id}:{region.page_number}:{region.x0:.6f}:{region.y0:.6f}:{region.x1:.6f}:{region.y1:.6f}:{region.category}:{region.source}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def get_pdf_document(conn: sqlite3.Connection, doc_id: int, audit_action: str):
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    if doc["file_extension"] != ".pdf":
        return audited_error(conn, "PDF coordinate redaction supports PDF source files only.", 415, audit_action, doc_id)
    return doc


def ocr_tokens_for_document(conn: sqlite3.Connection, doc_id: int) -> dict[int, list[OCRToken]]:
    by_page: dict[int, list[OCRToken]] = {}
    for row in conn.execute(
        "SELECT page_number, text, confidence, x0, y0, x1, y1, source FROM ocr_tokens WHERE document_id = ? ORDER BY page_number, id",
        (doc_id,),
    ).fetchall():
        by_page.setdefault(row["page_number"], []).append(
            OCRToken(
                text=row["text"],
                x0=row["x0"],
                y0=row["y0"],
                x1=row["x1"],
                y1=row["y1"],
                confidence=row["confidence"],
                source=row["source"],
            )
        )
    return by_page


def ocr_token_regions(conn: sqlite3.Connection, doc_id: int, findings: list[dict]) -> list[tuple[PdfRegion, float | None]]:
    tokens_by_page = ocr_tokens_for_document(conn, doc_id)
    if not tokens_by_page:
        return []
    regions: list[tuple[PdfRegion, float | None]] = []
    for finding in findings:
        sample = (finding.get("sample") or "").strip()
        if not sample:
            continue
        for page_number, tokens in tokens_by_page.items():
            for rect in token_regions_for_sample(tokens, sample):
                regions.append(
                    (
                        PdfRegion(
                            page_number=page_number,
                            x0=rect["x0"],
                            y0=rect["y0"],
                            x1=rect["x1"],
                            y1=rect["y1"],
                            category=finding.get("category") or "sensitive_text",
                            source="ocr",
                            finding_id=finding.get("id"),
                            sample=sample,
                        ),
                        rect.get("confidence"),
                    )
                )
    return regions


def insert_pending_pdf_regions(conn: sqlite3.Connection, doc_id: int, regions: list[tuple[PdfRegion, float | None]]) -> int:
    inserted = 0
    for region, confidence in regions:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO pdf_redaction_regions (
                document_id, finding_id, page_number, x0, y0, x1, y1, category, source,
                review_status, confidence, fingerprint, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
            """,
            (
                doc_id,
                region.finding_id,
                region.page_number,
                region.x0,
                region.y0,
                region.x1,
                region.y1,
                region.category,
                region.source,
                confidence,
                pdf_region_fingerprint(doc_id, region),
                g.current_user["id"],
            ),
        )
        inserted += cursor.rowcount
    return inserted


def pdf_export_blockers(conn: sqlite3.Connection, doc: sqlite3.Row) -> list[str]:
    blockers: list[str] = []
    doc_id = doc["id"]
    if ocr_blocks_redaction(doc["ocr_status"]):
        blockers.append("OCR output must be accepted or not required before PDF redaction export.")
    if not doc["redaction_completed"]:
        blockers.append("Redaction must be marked complete before reviewed PDF export.")
    if not doc["human_review_approved"]:
        blockers.append("Human review approval is required before reviewed PDF export.")
    pending_regions = conn.execute(
        "SELECT COUNT(*) FROM pdf_redaction_regions WHERE document_id = ? AND review_status = 'pending'",
        (doc_id,),
    ).fetchone()[0]
    approved_regions = conn.execute(
        "SELECT COUNT(*) FROM pdf_redaction_regions WHERE document_id = ? AND review_status = 'approved'",
        (doc_id,),
    ).fetchone()[0]
    pending_findings = conn.execute(
        "SELECT COUNT(*) FROM privacy_findings WHERE document_id = ? AND review_status = 'pending'",
        (doc_id,),
    ).fetchone()[0]
    if pending_regions:
        blockers.append("All PDF redaction boxes must be approved or rejected.")
    if pending_findings:
        blockers.append("All privacy findings must be approved or rejected before reviewed PDF export.")
    if not approved_regions:
        blockers.append("At least one approved PDF redaction box is required.")
    if (doc["ocr_status"] or "not_required") == "accepted":
        token_count = conn.execute(
            "SELECT COUNT(*) FROM ocr_tokens WHERE document_id = ?",
            (doc_id,),
        ).fetchone()[0]
        if not token_count:
            approved_manual = conn.execute(
                "SELECT COUNT(*) FROM pdf_redaction_regions WHERE document_id = ? AND source = 'manual' AND review_status = 'approved'",
                (doc_id,),
            ).fetchone()[0]
            if not approved_manual:
                blockers.append(
                    "Accepted OCR text has no coordinate data; add and approve manual PDF redaction boxes before native redacted export."
                )
    return blockers


def save_redacted_pdf_artifact_file(doc_id: int, safe_stem: str, data: bytes) -> Path:
    export_dir = EXPORT_DIR / f"document_{doc_id}"
    export_dir.mkdir(parents=True, exist_ok=True)
    saved_path = export_dir / f"{safe_stem}_redacted_{time.strftime('%Y%m%d_%H%M%S')}_{os.urandom(3).hex()}.pdf"
    saved_path.write_bytes(data)
    return saved_path


def latest_redacted_pdf_artifact(conn: sqlite3.Connection, doc_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM document_artifacts
        WHERE document_id = ? AND artifact_type = 'redacted_pdf' AND file_path IS NOT NULL
        ORDER BY id DESC LIMIT 1
        """,
        (doc_id,),
    ).fetchone()


def get_exportable_docx(conn: sqlite3.Connection, doc_id: int, audit_action: str):
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404
    if doc["file_extension"] != ".docx":
        return audited_error(conn, "Actual redacted export currently supports DOCX only.", 415, audit_action, doc_id)
    if not doc["redaction_completed"]:
        return audited_error(conn, "Redaction must be completed before actual redacted export.", 409, audit_action, doc_id)
    return doc


def redaction_targets_for_document(conn: sqlite3.Connection, doc_id: int) -> list[RedactionTarget]:
    return [
        RedactionTarget(row["sample"], row["replacement_text"] or row["placeholder"] or "[REDACTED]")
        for row in conn.execute(
            """
            SELECT sample, replacement_text, placeholder
            FROM privacy_findings
            WHERE document_id = ?
              AND review_status IN ('approved', 'added_by_reviewer')
              AND sample IS NOT NULL
              AND sample != ''
            """,
            (doc_id,),
        ).fetchall()
    ]


def format_size(size: int) -> str:
    if size > 1_048_576:
        return f"{size / 1_048_576:.1f} MB"
    if size > 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size} B"


def build_docx(text: str) -> bytes:
    def paragraph_xml(line: str) -> str:
        return f"<w:p><w:r><w:t xml:space=\"preserve\">{escape(line)}</w:t></w:r></w:p>"

    body = "\n".join(paragraph_xml(line) for line in text.splitlines() or [""])
    document_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    {body}
    <w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>
  </w:body>
</w:document>
"""
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document_xml)
    return buffer.getvalue()


def review_gate_counts(conn: sqlite3.Connection, doc_id: int) -> dict:
    """Count findings the release gate must still treat as unresolved.

    Fails closed: a finding only counts as resolved when its review_status is
    one of the known terminal states (approved/rejected/added_by_reviewer).
    NULL, 'pending', and any unrecognized value (e.g. written directly via SQL,
    or a value that slips past input validation in the future) all count as
    unresolved rather than being silently dropped from the gate.
    """
    unresolved_critical_count = conn.execute(
        """
        SELECT COUNT(*)
        FROM privacy_findings
        WHERE document_id = ?
          AND COALESCE(review_status, 'pending') NOT IN ('approved', 'rejected', 'added_by_reviewer')
          AND risk = 'CRITICAL'
        """,
        (doc_id,),
    ).fetchone()[0]
    direct_identifiers_remaining = conn.execute(
        f"""
        SELECT COUNT(*)
        FROM privacy_findings
        WHERE document_id = ?
          AND COALESCE(review_status, 'pending') NOT IN ('approved', 'rejected', 'added_by_reviewer')
          AND category IN ({','.join('?' for _ in DIRECT_IDENTIFIER_CATEGORIES)})
        """,
        (doc_id, *sorted(DIRECT_IDENTIFIER_CATEGORIES)),
    ).fetchone()[0] > 0
    return {
        "unresolved_critical_count": unresolved_critical_count,
        "direct_identifiers_remaining": direct_identifiers_remaining,
    }


def ocr_blocks_redaction(ocr_status: str | None) -> bool:
    return (ocr_status or "not_required") not in {"not_required", "accepted"}


def refresh_document_state(conn: sqlite3.Connection, doc_id: int, ocr_status: str | None = None) -> None:
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not doc:
        return
    status = ocr_status if ocr_status is not None else (doc["ocr_status"] or "not_required")
    profile = refresh_release_state(
        json.loads(doc["privacy_profile"] or "{}"),
        redaction_completed=bool(doc["redaction_completed"]),
        human_review_approved=bool(doc["human_review_approved"]),
        auto_mode_enabled=bool(doc["auto_mode_enabled"]),
        ocr_status=status,
        **review_gate_counts(conn, doc_id),
    )
    conn.execute(
        """
        UPDATE documents
        SET privacy_profile = ?,
            external_llm_readiness = ?,
            human_review_required = ?,
            redaction_status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            json.dumps(profile, ensure_ascii=False),
            profile["external_llm_readiness"],
            1 if profile["human_review_required"] else 0,
            profile["redaction_status"],
            doc_id,
        ),
    )


def replace_detector_findings(
    conn: sqlite3.Connection,
    doc_id: int,
    findings: list[dict],
    source: str,
    part_name_prefix: str,
    source_text: str = "",
) -> None:
    old_finding_ids = [
        row["id"]
        for row in conn.execute(
            "SELECT id FROM privacy_findings WHERE document_id = ? AND source IN ('detector', 'ocr')",
            (doc_id,),
        ).fetchall()
    ]
    if old_finding_ids:
        placeholders = ",".join("?" for _ in old_finding_ids)
        conn.execute(
            f"DELETE FROM pseudonym_mappings WHERE document_id = ? AND finding_id IN ({placeholders})",
            (doc_id, *old_finding_ids),
        )
        conn.execute(
            f"DELETE FROM privacy_findings WHERE document_id = ? AND id IN ({placeholders})",
            (doc_id, *old_finding_ids),
        )

    for finding in findings:
        cursor = conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, part_name, start_offset, end_offset, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
            """,
            (
                doc_id,
                finding["category"],
                finding["sample"],
                finding["risk"],
                finding["recommended_action"],
                finding["placeholder"],
                replacement_for_finding(finding),
                source,
                f"{part_name_prefix}_accepted_text",
                finding.get("start"),
                finding.get("end"),
                finding["fingerprint"],
            ),
        )
        finding_id = cursor.lastrowid
        part_name = f"{part_name_prefix}_accepted_text"
        conn.execute(
            """
            INSERT INTO finding_evidence (
                finding_id, document_id, source_part, start_offset, end_offset, context, verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending_export')
            """,
            (
                finding_id,
                doc_id,
                part_name,
                finding.get("start"),
                finding.get("end"),
                evidence_context(source_text, finding.get("start"), finding.get("end"), finding.get("sample")),
            ),
        )
        conn.execute(
            """
            INSERT INTO pseudonym_mappings (
                document_id, finding_id, original_text, replacement_text, category, restricted
            ) VALUES (?, ?, ?, ?, ?, 1)
            """,
            (
                doc_id,
                finding_id,
                finding["sample"],
                replacement_for_finding(finding),
                finding["category"],
            ),
        )


def apply_reextraction(conn: sqlite3.Connection, doc: sqlite3.Row) -> dict:
    """Re-run extraction + detection for a document and refresh its review state."""
    path = resolve_document_path(doc["filepath"])
    if not path.exists():
        raise FileNotFoundError(f"Source file was not found: {path}")
    text, warning = extract_text(path)
    privacy = analyze_privacy(doc["filename"], text, warning)
    replace_detector_findings(conn, doc["id"], privacy["risk_map"], source="detector", part_name_prefix="reextract", source_text=text)
    status = privacy["extraction_status"]["status"]
    review_status = "needs_ocr" if status in {"Partial", "Failed"} else "pending_review"
    ocr_status = "queued" if status in {"Partial", "Failed"} else "not_required"
    conn.execute(
        """
        UPDATE documents
        SET extraction_warning = ?,
            extraction_status = ?,
            privacy_profile = ?,
            residual_risk = ?,
            risk_summary = ?,
            recommended_strategy = ?,
            external_llm_readiness = ?,
            human_review_required = ?,
            redaction_status = ?,
            redaction_completed = 0,
            human_review_approved = 0,
            review_status = ?,
            ocr_status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            warning,
            status,
            json.dumps(privacy, ensure_ascii=False),
            privacy["residual_risk"]["level"],
            privacy["residual_risk"]["summary"],
            privacy["recommended_strategy"],
            privacy["external_llm_readiness"],
            1 if privacy["human_review_required"] else 0,
            privacy["redaction_status"],
            review_status,
            ocr_status,
            doc["id"],
        ),
    )
    record_document_artifact(
        conn,
        doc["id"],
        "reextraction",
        "Extraction re-run",
        metadata={"extraction_status": status, "finding_count": len(privacy["risk_map"]), "text_chars": len(text)},
    )
    return {"document_id": doc["id"], "extraction_status": status, "finding_count": len(privacy["risk_map"])}


def save_uploaded_document(path: Path, original_name: str, conn: sqlite3.Connection, matter_id: int | None = None) -> int:
    text, warning = extract_text(path)
    classification = classify_document(original_name, text)
    category_row = conn.execute("SELECT id FROM categories WHERE name = ?", (classification["category"],)).fetchone()
    if not category_row:
        category_row = conn.execute("SELECT id FROM categories WHERE name = 'other'").fetchone()
    if not category_row:
        raise RuntimeError("Category seed data is missing. Run db/init_db.py before uploading documents.")
    category_id = category_row[0]
    subcategory_row = conn.execute(
        "SELECT id FROM subcategories WHERE category_id = ? AND name = ?",
        (category_id, classification["subcategory"]),
    ).fetchone()
    subcategory_id = subcategory_row[0] if subcategory_row else None
    privacy = analyze_privacy(original_name, text, warning)
    client_id = detect_client(original_name, text, conn)
    review_status = "needs_ocr" if privacy["extraction_status"]["status"] in {"Partial", "Failed"} else "pending_review"
    ocr_status = "queued" if privacy["extraction_status"]["status"] in {"Partial", "Failed"} else "not_required"

    cursor = conn.execute(
        """
        INSERT INTO documents (
            filename, filepath, file_extension, file_size, client_id, category_id, subcategory_id,
            title, language, version, date_detected, extraction_warning, extraction_status, privacy_profile,
            residual_risk, risk_summary, recommended_strategy, external_llm_readiness,
            human_review_required, redaction_status, redaction_completed, human_review_approved,
            auto_mode_enabled, review_status, ocr_status, is_archive
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            original_name,
            str(path.resolve()),
            path.suffix.lower(),
            path.stat().st_size,
            client_id,
            category_id,
            subcategory_id,
            generate_title(original_name),
            detect_language(original_name),
            detect_version(original_name),
            detect_date(original_name),
            warning,
            privacy["extraction_status"]["status"],
            json.dumps(privacy, ensure_ascii=False),
            privacy["residual_risk"]["level"],
            privacy["residual_risk"]["summary"],
            privacy["recommended_strategy"],
            privacy["external_llm_readiness"],
            1 if privacy["human_review_required"] else 0,
            privacy["redaction_status"],
            1 if privacy["release_controls"]["redaction_completed"] else 0,
            1 if privacy["release_controls"]["human_review_approved"] else 0,
            1 if privacy["release_controls"]["auto_mode_enabled"] else 0,
            review_status,
            ocr_status,
            1 if path.suffix.lower() == ".zip" else 0,
        ),
    )
    document_id = cursor.lastrowid
    assigned_matter_id = valid_matter_id(conn, matter_id)
    assign_document_to_matter(conn, document_id, assigned_matter_id)
    record_document_artifact(
        conn,
        document_id,
        "original_upload",
        "Original upload",
        file_path=str(path.resolve()),
        metadata={"extension": path.suffix.lower(), "file_size": path.stat().st_size},
    )

    for tag in classification["tags"]:
        conn.execute("INSERT OR IGNORE INTO document_tags (document_id, tag) VALUES (?, ?)", (document_id, tag))

    replace_detector_findings(conn, document_id, privacy["risk_map"], source="detector", part_name_prefix="uploaded", source_text=text)
    return document_id


def replacement_for_finding(finding: dict) -> str:
    if finding.get("risk") == "CRITICAL" and "review" in finding.get("recommended_action", "").lower():
        return f"[{finding['placeholder'].strip('[]')}_REDACTED]"
    return finding.get("placeholder") or "[REDACTED]"


def resolve_document_path(filepath: str) -> Path:
    path = Path(filepath)
    if path.is_absolute():
        return path
    return DEFAULT_STOCK_DIR / path


# Route blueprints import the helpers above, so they must be imported after
# every helper is defined. documents must register before the blueprints that
# call its api_document_detail.
from blueprints.auth import auth_bp  # noqa: E402
from blueprints.documents import documents_bp  # noqa: E402
from blueprints.export import export_bp  # noqa: E402
from blueprints.landing import landing_bp  # noqa: E402
from blueprints.matters import matters_bp  # noqa: E402
from blueprints.ocr import ocr_bp  # noqa: E402
from blueprints.pdf_regions import pdf_regions_bp  # noqa: E402
from blueprints.review import review_bp  # noqa: E402
from blueprints.studio import studio_bp  # noqa: E402

app.register_blueprint(auth_bp)
app.register_blueprint(landing_bp)
app.register_blueprint(documents_bp)
app.register_blueprint(studio_bp)
app.register_blueprint(matters_bp)
app.register_blueprint(review_bp)
app.register_blueprint(ocr_bp)
app.register_blueprint(pdf_regions_bp)
app.register_blueprint(export_bp)


if __name__ == "__main__":
    if not DB_PATH.exists():
        raise SystemExit("Database not found. Run: python3 db/init_db.py && python3 classify.py")
    # threaded=True: serve requests concurrently so a slow OCR/PDF-export
    # request no longer freezes the whole app. (`flask run` is already
    # threaded by default; this covers the `python3 app.py` script path.)
    app.run(debug=True, port=5000, threaded=True)
