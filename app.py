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
import secrets
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
from legal_analyzer.privacy import (
    DIRECT_IDENTIFIER_CATEGORIES,
    REDACTED_REVIEW_STATUSES,
    RELEASE_CLEARED_REVIEW_STATUSES,
    RESOLVED_REVIEW_STATUSES,
    analyze_privacy,
    refresh_release_state,
)
from legal_analyzer.redaction_plan import plan_segments

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

SECRET_KEY_ENV_VAR = "LEGAL_ANALYZER_SECRET_KEY"

# Ceiling on a request body, matching the ceiling the ZIP extractor is willing
# to read back (ZIP_MAX_TOTAL_BYTES), so an upload cannot claim more disk than
# extraction will process. blueprints/documents.py checks the received file
# size against this same number, so an oversized upload is audited instead of
# surfacing as a bare Werkzeug 413.
MAX_UPLOAD_BYTES = int(os.environ.get("LEGAL_ANALYZER_MAX_UPLOAD_BYTES", "100000000"))

# Characters that let stored free text (an uploaded filename, a reviewer's
# replacement text) break out of an HTML attribute or text node in the
# templates that render it. static/escape.js escapes them at render time; they
# are also kept out of the database at the write, so a stored value cannot rely
# on a single call site remembering to escape.
UNSAFE_HTML_CHARS = "\"'<>"


def strip_unsafe_html_chars(value: str) -> str:
    return "".join(char for char in value if char not in UNSAFE_HTML_CHARS)


def has_unsafe_html_chars(value: str) -> bool:
    return any(char in UNSAFE_HTML_CHARS for char in value)


def resolve_secret_key() -> str:
    """Return the Flask session secret, or refuse to start without one.

    This used to fall back to a hard-coded default that shipped in the
    repository. Session cookies are signed with this value, so anyone holding
    the published default could mint a cookie for any user id and role — an
    admin session was forgeable from a checkout. There is no safe default, so
    an unset key is a startup failure rather than a warning: a process that
    refuses to boot cannot serve a forgeable session, whereas a per-process
    ephemeral key leaves a running app whose sessions silently disagree across
    gunicorn workers. Supersedes ADR-007.
    """
    secret = os.environ.get(SECRET_KEY_ENV_VAR, "").strip()
    if not secret:
        raise SystemExit(
            f"{SECRET_KEY_ENV_VAR} is not set.\n"
            "Session cookies are signed with it, so there is no safe default: a known key lets\n"
            "anyone forge an admin session. Generate one and put it in your environment or .env:\n"
            '  python3 -c "import secrets; print(secrets.token_hex(32))"'
        )
    return secret


app = Flask(__name__)
app.secret_key = resolve_secret_key()

# Werkzeug aborts with 413 past this; blueprints/documents.py checks the same
# ceiling first so the rejection is audited rather than opaque.
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# Session cookie hardening. SameSite=Strict because nothing legitimately
# navigates into this app from another site; CSRF protection is enforced
# independently (ADR-008) rather than relying on the browser default. Secure is
# opt-in rather than on by default because the documented local setup is plain
# http on 127.0.0.1, where a Secure cookie is never sent and login would fail
# with no visible reason. Any deployment behind TLS should set
# LEGAL_ANALYZER_HTTPS=1.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("LEGAL_ANALYZER_HTTPS", "").strip().lower() in {"1", "true", "yes"}


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


CSRF_HEADER = "X-CSRF-Token"
CSRF_FIELD = "csrf_token"
# Methods that must not change state, so they carry no token requirement. A
# handler that mutates on GET would sit outside this protection entirely.
CSRF_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
FORM_MIMETYPES = frozenset({"application/x-www-form-urlencoded", "multipart/form-data"})


def issue_csrf_token() -> str:
    """Return this session's CSRF token, minting one on first use.

    Registered as a Jinja global so templates can emit it, and called on login
    so the token rotates when the session's privilege level changes.
    """
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def submitted_csrf_token() -> str:
    """The token the caller presented, from the header or a form field."""
    header = (request.headers.get(CSRF_HEADER) or "").strip()
    if header:
        return header
    # Only touch request.form for form-encoded bodies. Reading it on a JSON
    # request is harmless but pointless, and the API is JSON everywhere except
    # the login form.
    if request.mimetype in FORM_MIMETYPES:
        return (request.form.get(CSRF_FIELD) or "").strip()
    return ""


@app.before_request
def csrf_protect():
    """Reject state-changing requests that do not carry the session's token.

    SameSite=Strict already blocks the cross-site POST, but it is a browser
    behaviour, not a property of this app: it does nothing for an older browser,
    and nothing for a sibling subdomain that can write the cookie. The token is
    the check that does not depend on either.

    Deliberately not audited. This runs before authentication on every request,
    so writing a row here would let an unauthenticated caller drive database
    writes by sending bad tokens in a loop. A rejected request has changed
    nothing, which is the thing worth knowing.
    """
    if not app.config.get("CSRF_PROTECTION", True):
        return None
    if request.method in CSRF_SAFE_METHODS:
        return None

    expected = session.get("csrf_token") or ""
    submitted = submitted_csrf_token()
    if expected and submitted and secrets.compare_digest(expected, submitted):
        return None

    message = "CSRF token missing or invalid. Reload the page and try again."
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": message}), 403
    return message, 403


app.jinja_env.globals["csrf_token"] = issue_csrf_token


def login_throttle_limits() -> tuple[int, int, int]:
    """(per-pair cap, per-address cap, window seconds), all env-overridable."""
    return (
        int(os.environ.get("LEGAL_ANALYZER_LOGIN_MAX_ATTEMPTS", "5")),
        int(os.environ.get("LEGAL_ANALYZER_LOGIN_MAX_ATTEMPTS_PER_ADDR", "20")),
        int(os.environ.get("LEGAL_ANALYZER_LOGIN_WINDOW_SECONDS", "900")),
    )


def record_failed_login(conn: sqlite3.Connection, username: str, remote_addr: str) -> None:
    conn.execute(
        "INSERT INTO login_attempts (username, remote_addr) VALUES (?, ?)",
        (username, remote_addr or ""),
    )


def clear_login_attempts(conn: sqlite3.Connection, username: str, remote_addr: str) -> None:
    """Drop a caller's failures once they prove they know the password."""
    conn.execute(
        "DELETE FROM login_attempts WHERE username = ? AND remote_addr = ?",
        (username, remote_addr or ""),
    )


def login_lockout_seconds(conn: sqlite3.Connection, username: str, remote_addr: str) -> int:
    """Seconds until this caller may try again; 0 when they are not locked out.

    Counted per (username, address) rather than per username alone, so someone
    who knows a username cannot lock its owner out from somewhere else. The
    per-address cap is the second half of that trade: it stops one address
    spraying one attempt each across many usernames and never tripping the
    pair limit.

    remote_addr is whatever the WSGI layer reports. Behind a reverse proxy that
    is the proxy unless it is configured to pass the client through, in which
    case every caller shares one bucket -- size the per-address cap for that.
    """
    pair_cap, addr_cap, window = login_throttle_limits()
    offset = f"-{window} seconds"
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < datetime('now', ?)", (offset,))

    remaining = 0
    for sql, params, cap in (
        (
            "SELECT COUNT(*), MIN(attempted_at) FROM login_attempts "
            "WHERE username = ? AND remote_addr = ? AND attempted_at >= datetime('now', ?)",
            (username, remote_addr or "", offset),
            pair_cap,
        ),
        (
            "SELECT COUNT(*), MIN(attempted_at) FROM login_attempts "
            "WHERE remote_addr = ? AND attempted_at >= datetime('now', ?)",
            (remote_addr or "", offset),
            addr_cap,
        ),
    ):
        count, first_attempt = conn.execute(sql, params).fetchone()
        if count < cap or not first_attempt:
            continue
        elapsed = conn.execute(
            "SELECT CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', ?) AS INTEGER)",
            (first_attempt,),
        ).fetchone()[0]
        remaining = max(remaining, window - int(elapsed))

    return max(remaining, 0)


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


def pdf_export_conditions(conn: sqlite3.Connection, doc: sqlite3.Row) -> list[dict]:
    """Every condition the reviewed-PDF export enforces, stated once, as data.

    pdf_export_blockers() refuses on these and the studio's "this export" panel
    renders these; neither restates them. The browser used to recompute an
    approximation of the export conditions itself, which is how a lawyer got a
    row of green ticks next to an endpoint that would have refused.

    Order is load-bearing: pdf_export_blockers() preserves the message sequence
    its callers and tests already read.
    """
    doc_id = doc["id"]
    ocr_state = doc["ocr_status"] or "not_required"
    pending_regions = conn.execute(
        "SELECT COUNT(*) FROM pdf_redaction_regions WHERE document_id = ? AND review_status = 'pending'",
        (doc_id,),
    ).fetchone()[0]
    approved_regions = conn.execute(
        "SELECT COUNT(*) FROM pdf_redaction_regions WHERE document_id = ? AND review_status = 'approved'",
        (doc_id,),
    ).fetchone()[0]
    # Fails closed the same way as review_gate_counts(): "not pending" is not
    # the same question as "decided", and a NULL or unrecognised status (the
    # pre-migration-005 'rejected' included) must block rather than pass.
    undecided_findings = conn.execute(
        f"""
        SELECT COUNT(*) FROM privacy_findings
        WHERE document_id = ?
          AND COALESCE(review_status, 'pending') NOT IN ({','.join('?' for _ in RESOLVED_REVIEW_STATUSES)})
        """,
        (doc_id, *sorted(RESOLVED_REVIEW_STATUSES)),
    ).fetchone()[0]
    conditions = [
        {
            "id": "ocr_resolved",
            "label": "OCR accepted or not required",
            "passed": not ocr_blocks_redaction(doc["ocr_status"]),
            "detail": ocr_state,
            "message": "OCR output must be accepted or not required before PDF redaction export.",
        },
        {
            "id": "redaction_completed",
            "label": "Redaction marked complete",
            "passed": bool(doc["redaction_completed"]),
            "detail": "done" if doc["redaction_completed"] else "required",
            "message": "Redaction must be marked complete before reviewed PDF export.",
        },
        {
            "id": "human_review_approved",
            "label": "Human review approved",
            "passed": bool(doc["human_review_approved"]),
            "detail": "approved" if doc["human_review_approved"] else "required",
            "message": "Human review approval is required before reviewed PDF export.",
        },
        {
            "id": "no_pending_regions",
            "label": "Every redaction box decided",
            "passed": not pending_regions,
            "detail": "clear" if not pending_regions else f"{pending_regions} pending",
            "message": "All PDF redaction boxes must be approved or rejected.",
        },
        {
            "id": "findings_decided",
            "label": "Every finding decided",
            "passed": not undecided_findings,
            "detail": "clear" if not undecided_findings else f"{undecided_findings} undecided",
            "message": (
                "Every privacy finding must be decided — approved, dismissed as not sensitive, or "
                "retained unredacted — before reviewed PDF export."
            ),
        },
        {
            "id": "approved_region_exists",
            "label": "At least one approved redaction box",
            "passed": bool(approved_regions),
            "detail": f"{approved_regions} approved",
            "message": "At least one approved PDF redaction box is required.",
        },
    ]
    if ocr_state == "accepted":
        token_count = conn.execute(
            "SELECT COUNT(*) FROM ocr_tokens WHERE document_id = ?",
            (doc_id,),
        ).fetchone()[0]
        if not token_count:
            approved_manual = conn.execute(
                "SELECT COUNT(*) FROM pdf_redaction_regions WHERE document_id = ? AND source = 'manual' AND review_status = 'approved'",
                (doc_id,),
            ).fetchone()[0]
            conditions.append(
                {
                    "id": "ocr_coordinates_available",
                    "label": "Accepted OCR has coordinates or approved manual boxes",
                    "passed": bool(approved_manual),
                    "detail": "no OCR coordinate data" if not approved_manual else "manual boxes approved",
                    "message": (
                        "Accepted OCR text has no coordinate data; add and approve manual PDF redaction "
                        "boxes before native redacted export."
                    ),
                }
            )
    return conditions


def pdf_export_blockers(conn: sqlite3.Connection, doc: sqlite3.Row) -> list[str]:
    return [c["message"] for c in pdf_export_conditions(conn, doc) if not c["passed"]]


def docx_export_conditions(conn: sqlite3.Connection, doc: sqlite3.Row) -> list[dict]:
    """Every condition the reviewed-DOCX export enforces, stated once, as data.

    get_exportable_docx() refuses on the first unmet entry here and the studio's
    "this export" panel renders the same list, so the panel and the endpoint
    cannot drift. `status` and `metadata` belong to the refusal, not the panel.
    """
    doc_id = doc["id"]
    undecided_findings = conn.execute(
        f"""
        SELECT COUNT(*) FROM privacy_findings
        WHERE document_id = ?
          AND COALESCE(review_status, 'pending') NOT IN ({','.join('?' for _ in RESOLVED_REVIEW_STATUSES)})
        """,
        (doc_id, *sorted(RESOLVED_REVIEW_STATUSES)),
    ).fetchone()[0]
    return [
        {
            "id": "docx_source",
            "label": "Source file is a DOCX",
            "passed": doc["file_extension"] == ".docx",
            "detail": doc["file_extension"] or "unknown",
            "message": "Actual redacted export currently supports DOCX only.",
            "status": 415,
            "metadata": None,
        },
        {
            "id": "redaction_completed",
            "label": "Redaction marked complete",
            "passed": bool(doc["redaction_completed"]),
            "detail": "done" if doc["redaction_completed"] else "required",
            "message": "Redaction must be completed before actual redacted export.",
            "status": 409,
            "metadata": None,
        },
        # The same condition as the release gate's (external_llm_gate_policy in
        # privacy.py), and it has to stay the same one: when the two disagree the
        # UI tells a lawyer the document is releasable while this endpoint refuses
        # it. Both require a real human approval and nothing else.
        {
            "id": "human_review_approved",
            "label": "Human review approved",
            "passed": bool(doc["human_review_approved"]),
            "detail": "approved" if doc["human_review_approved"] else "required",
            "message": "Human review approval is required before actual redacted export.",
            "status": 409,
            "metadata": None,
        },
        # redaction_completed is a latch: reverting a finding to 'pending' (via
        # /api/finding/<id>/review) does not clear it, and only the OCR/reset
        # transitions do. redaction_targets_for_document() then drops that finding
        # from the target list, so it was never redacted and the exported DOCX
        # carried it in cleartext while both gates above still read as satisfied.
        # Re-check the findings themselves, the way pdf_export_conditions() does.
        {
            "id": "findings_decided",
            "label": "Every finding decided",
            "passed": not undecided_findings,
            "detail": "clear" if not undecided_findings else f"{undecided_findings} undecided",
            "message": (
                "Every privacy finding must be decided — approved, dismissed as not sensitive, or "
                "retained unredacted — before actual redacted export."
            ),
            "status": 409,
            "metadata": {"unreviewed_findings": undecided_findings},
        },
    ]


def export_gate_state(conn: sqlite3.Connection, doc: sqlite3.Row) -> dict:
    """What the reviewed-export endpoint would do with this document, right now.

    A separate question from the external-LLM release gate: a reviewer who
    deliberately kept an identifier is still entitled to the file that reflects
    their decisions. The studio renders the two as two named panels because the
    same screen used to answer both at once and say which was which nowhere.
    """
    extension = (doc["file_extension"] or "").lower()
    if extension == ".pdf":
        conditions = pdf_export_conditions(conn, doc)
        export_format = "pdf"
    else:
        conditions = docx_export_conditions(conn, doc)
        export_format = "docx" if extension == ".docx" else None
    return {
        "format": export_format,
        "supported": extension in {".docx", ".pdf"},
        "allowed": all(condition["passed"] for condition in conditions),
        "conditions": [
            {key: condition[key] for key in ("id", "label", "passed", "detail")}
            for condition in conditions
        ],
        "failed_conditions": [c["message"] for c in conditions if not c["passed"]],
    }


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
    # Refuse on the first unmet condition in docx_export_conditions(), which is
    # also the list the studio's "this export" panel renders. One source, so the
    # panel a lawyer reads and the endpoint that refuses cannot disagree.
    for condition in docx_export_conditions(conn, doc):
        if not condition["passed"]:
            return audited_error(
                conn,
                condition["message"],
                condition["status"],
                audit_action,
                doc_id,
                condition["metadata"],
            )
    return doc


def document_source_text(conn: sqlite3.Connection, doc_id: int, doc: sqlite3.Row) -> tuple[str, str, str | None]:
    """The text every rendering of this document resolves against: (text, source, warning).

    Accepted OCR replaces the extraction, because that is the decision the
    reviewer made: `ocr/accept` is the point at which OCR text is allowed to
    affect findings, redaction and release readiness at all.
    """
    if (doc["ocr_status"] or "not_required") == "accepted":
        pages = conn.execute(
            """
            SELECT text FROM ocr_pages
            WHERE document_id = ? AND status = 'accepted' AND text IS NOT NULL AND text != ''
            ORDER BY page_number
            """,
            (doc_id,),
        ).fetchall()
        return "\n\n".join(row["text"] for row in pages), "ocr_accepted", None
    path = resolve_document_path(doc["filepath"])
    if not path.exists():
        return "", "extraction", "Source file was not found."
    text, warning = extract_text(path)
    return text, "extraction", warning


def document_plan_segments(conn: sqlite3.Connection, doc_id: int, text: str, style: str = "placeholder"):
    """The post-decision rendering of `text`, resolved server-side for every surface.

    The browser canvas and the reviewed DOCX export both read this. Keeping the
    resolution in one place is the point: they used to disagree about the same
    document under the same decisions, and a lawyer was approving a rendering
    that was not the deliverable.
    """
    findings = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, category, sample, placeholder, replacement_text, review_status,
                   start_offset, end_offset
            FROM privacy_findings
            WHERE document_id = ?
            ORDER BY COALESCE(start_offset, 0), id
            """,
            (doc_id,),
        ).fetchall()
    ]
    return plan_segments(text, findings, REDACTED_REVIEW_STATUSES, style)


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


def sensitive_samples_for_document(conn: sqlite3.Connection, doc_id: int) -> list[str]:
    """Every finding sample whose presence in the export would be unexpected.

    This is deliberately wider than redaction_targets_for_document(): export QA
    that measures leakage only against the targets it was handed cannot see a
    finding that was never made a target, so a finding reverted to 'pending'
    after redaction was marked complete leaked in cleartext with
    leakage_count 0 and overall_status "pass".

    Both terminal "the text stays" decisions are excluded, because for both of
    them the text remaining is the expected outcome rather than a leak:
    'dismissed' (a false positive) and 'retained' (a real identifier the
    reviewer chose to leave in). Retained findings are counted separately by
    retained_sample_count_for_document() so the QA report can say how many
    identifiers were deliberately kept instead of reporting a bare pass.
    """
    return [
        row["sample"]
        for row in conn.execute(
            """
            SELECT sample
            FROM privacy_findings
            WHERE document_id = ?
              AND COALESCE(review_status, 'pending') NOT IN ('dismissed', 'retained')
              AND sample IS NOT NULL
              AND sample != ''
            """,
            (doc_id,),
        ).fetchall()
    ]


def retained_sample_count_for_document(conn: sqlite3.Connection, doc_id: int) -> int:
    """How many findings the reviewer deliberately left unredacted.

    sensitive_samples_for_document() excludes these from the leakage set, so
    without this count an export carrying a retained TCKN would report zero
    leakage and nothing else — a clean-looking QA report for a document that
    still contains a national ID. The count is surfaced in the QA report and
    keeps its overall status off "pass".
    """
    return conn.execute(
        """
        SELECT COUNT(*)
        FROM privacy_findings
        WHERE document_id = ?
          AND COALESCE(review_status, 'pending') = 'retained'
        """,
        (doc_id,),
    ).fetchone()[0]


def format_size(size: int) -> str:
    if size > 1_048_576:
        return f"{size / 1_048_576:.1f} MB"
    if size > 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size} B"


def build_docx(text: str) -> bytes:
    """Build a minimal DOCX package from plain text.

    No production route calls this any more: its one caller was the deleted
    "Preview DOCX (rebuilt, lower assurance)" export, and a REBUILT package is
    exactly what must not be handed to a lawyer as a deliverable -- the reviewed
    export (`legal_analyzer/docx_redactor.py`) redacts the source package in
    place instead. It is kept as a test fixture builder (`tests/test_exports.py`,
    `tests/test_extraction.py`). Do not wire it back into an export route.
    """

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
    """Gate inputs the stored privacy profile cannot know: the review outcome.

    Fails closed: a finding only counts as resolved when its review_status is
    one of the known terminal states (RESOLVED_REVIEW_STATUSES). NULL,
    'pending', and any unrecognized value (e.g. written directly via SQL, the
    pre-migration-005 'rejected', or a value that slips past input validation in
    the future) all count as unresolved rather than being silently dropped from
    the gate.

    unresolved_critical_count counts only genuinely unresolved findings:
    'retained' is a decision, not an omission. A retained CRITICAL is caught by
    the two measurements below instead.

    "remaining_findings" and direct_identifiers_remaining are both the
    complement of RELEASE_CLEARED_REVIEW_STATUSES, so both include 'retained':
    the reviewer decided that identifier stays in the document, and
    redaction_targets_for_document() therefore never redacts it. Residual risk
    is recomputed from remaining_findings in refresh_release_state(). The two
    are deliberately redundant for a retained direct identifier — the gate
    condition "No direct identifiers may remain in detected findings" is true of
    it on its own terms, and defence in depth here is cheap.
    """
    unresolved_critical_count = conn.execute(
        f"""
        SELECT COUNT(*)
        FROM privacy_findings
        WHERE document_id = ?
          AND COALESCE(review_status, 'pending') NOT IN ({','.join('?' for _ in RESOLVED_REVIEW_STATUSES)})
          AND risk = 'CRITICAL'
        """,
        (doc_id, *sorted(RESOLVED_REVIEW_STATUSES)),
    ).fetchone()[0]
    direct_identifiers_remaining = conn.execute(
        f"""
        SELECT COUNT(*)
        FROM privacy_findings
        WHERE document_id = ?
          AND COALESCE(review_status, 'pending') NOT IN ({','.join('?' for _ in RELEASE_CLEARED_REVIEW_STATUSES)})
          AND category IN ({','.join('?' for _ in DIRECT_IDENTIFIER_CATEGORIES)})
        """,
        (doc_id, *sorted(RELEASE_CLEARED_REVIEW_STATUSES), *sorted(DIRECT_IDENTIFIER_CATEGORIES)),
    ).fetchone()[0] > 0
    remaining_findings = [
        {"category": row["category"], "risk": row["risk"], "sample": row["sample"]}
        for row in conn.execute(
            f"""
            SELECT category, risk, sample
            FROM privacy_findings
            WHERE document_id = ?
              AND COALESCE(review_status, 'pending') NOT IN ({','.join('?' for _ in RELEASE_CLEARED_REVIEW_STATUSES)})
            """,
            (doc_id, *sorted(RELEASE_CLEARED_REVIEW_STATUSES)),
        ).fetchall()
    ]
    return {
        "unresolved_critical_count": unresolved_critical_count,
        "direct_identifiers_remaining": direct_identifiers_remaining,
        "remaining_findings": remaining_findings,
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
            review_status, ocr_status, is_archive
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    # debug is opt-in. The Werkzeug debugger executes arbitrary code from the
    # browser on any traceback, so having it on by default in the command the
    # README tells people to run puts an RCE console in front of a database of
    # privileged documents. LEGAL_ANALYZER_DEBUG=1 turns it back on locally.
    debug = os.environ.get("LEGAL_ANALYZER_DEBUG", "").strip().lower() in {"1", "true", "yes"}
    # threaded=True: serve requests concurrently so a slow OCR/PDF-export
    # request no longer freezes the whole app. (`flask run` is already
    # threaded by default; this covers the `python3 app.py` script path.)
    # host stays on loopback: this server is single-process and unhardened,
    # and `wsgi.py` behind gunicorn is the supported way to serve it elsewhere.
    app.run(host="127.0.0.1", port=5000, debug=debug, threaded=True)
