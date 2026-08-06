#!/usr/bin/env python3
"""Scan a legal document folder and build a privacy-reviewed risk index."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path

from legal_analyzer.classifier import (
    classify_document,
    detect_date,
    detect_language,
    detect_version,
    generate_title,
    should_skip,
    supported_file,
)
from legal_analyzer.extraction import extract_text
from legal_analyzer.privacy import analyze_privacy

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = PROJECT_DIR / "db" / "legal_documents.db"
# Scan locations are environment-specific and can name real matters, so they are
# configured rather than hardcoded. Defaults stay inside the project.
#   LEGAL_ANALYZER_STOCK_DIR   - directory to index
#   LEGAL_ANALYZER_EXTRA_FILES - os.pathsep-separated list of individual files
DEFAULT_STOCK_DIR = Path(os.environ.get("LEGAL_ANALYZER_STOCK_DIR", PROJECT_DIR / "documents"))
DEFAULT_EXTRA_FILES = [
    Path(item)
    for item in os.environ.get("LEGAL_ANALYZER_EXTRA_FILES", "").split(os.pathsep)
    if item.strip()
]


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def detect_client(filename: str, text: str, conn: sqlite3.Connection) -> int | None:
    haystack = f"{filename}\n{text[:3000]}".lower()
    for client_id, name, aliases_json in conn.execute("SELECT id, name, aliases FROM clients"):
        if name.lower() in haystack:
            return client_id
        for alias in json.loads(aliases_json or "[]"):
            if alias.lower() in haystack:
                return client_id
    return None


def scan_paths(stock_dir: Path, extra_files: list[Path]) -> list[Path]:
    paths: list[Path] = []
    if stock_dir.exists():
        for root, dirs, files in os.walk(stock_dir):
            dirs[:] = [d for d in dirs if d not in {"db", "templates", "__pycache__", ".git", "node_modules", ".tritium"}]
            for filename in files:
                if should_skip(filename):
                    continue
                path = Path(root) / filename
                if supported_file(path):
                    paths.append(path)
    for path in extra_files:
        if path.exists() and path not in paths and supported_file(path):
            paths.append(path)
    return paths


def save_document(path: Path, base_dir: Path, conn: sqlite3.Connection) -> int:
    text, warning = extract_text(path)
    classification = classify_document(path.name, text)
    category_id = conn.execute("SELECT id FROM categories WHERE name = ?", (classification["category"],)).fetchone()[0]
    subcategory_row = conn.execute(
        "SELECT id FROM subcategories WHERE category_id = ? AND name = ?",
        (category_id, classification["subcategory"]),
    ).fetchone()
    subcategory_id = subcategory_row[0] if subcategory_row else None
    privacy = analyze_privacy(path.name, text, warning)
    client_id = detect_client(path.name, text, conn)

    try:
        relative_path = str(path.relative_to(base_dir))
    except ValueError:
        relative_path = str(path)

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
            path.name,
            relative_path,
            path.suffix.lower(),
            path.stat().st_size,
            client_id,
            category_id,
            subcategory_id,
            generate_title(path.name),
            detect_language(path.name),
            detect_version(path.name),
            detect_date(path.name),
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
            "needs_ocr" if privacy["extraction_status"]["status"] in {"Partial", "Failed"} else "pending_review",
            "queued" if privacy["extraction_status"]["status"] in {"Partial", "Failed"} else "not_required",
            1 if path.suffix.lower() == ".zip" else 0,
        ),
    )
    document_id = cursor.lastrowid

    for tag in classification["tags"]:
        conn.execute("INSERT OR IGNORE INTO document_tags (document_id, tag) VALUES (?, ?)", (document_id, tag))

    for finding in privacy["risk_map"]:
        cursor = conn.execute(
            """
            INSERT INTO privacy_findings (
                document_id, category, sample, risk, recommended_action, placeholder,
                replacement_text, review_status, source, start_offset, end_offset, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document_id,
                finding["category"],
                finding["sample"],
                finding["risk"],
                finding["recommended_action"],
                finding["placeholder"],
                replacement_for_finding(finding),
                "pending",
                "detector",
                finding.get("start"),
                finding.get("end"),
                finding["fingerprint"],
            ),
        )
        finding_id = cursor.lastrowid
        conn.execute(
            """
            INSERT INTO pseudonym_mappings (
                document_id, finding_id, original_text, replacement_text, category, restricted
            ) VALUES (?, ?, ?, ?, ?, 1)
            """,
            (
                document_id,
                finding_id,
                finding["sample"],
                replacement_for_finding(finding),
                finding["category"],
            ),
        )

    return document_id


def scan_and_classify(stock_dir: Path, extra_files: list[Path]) -> dict:
    if not DB_PATH.exists():
        raise SystemExit("Database not found. Run: python3 db/init_db.py")

    conn = get_conn()
    paths = scan_paths(stock_dir, extra_files)
    processed = 0
    errors: list[str] = []

    for path in paths:
        try:
            save_document(path, stock_dir, conn)
            processed += 1
        except sqlite3.IntegrityError:
            continue
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    conn.commit()
    report = generate_report(conn, processed, errors)
    conn.close()
    return report


def generate_report(conn: sqlite3.Connection, processed: int, errors: list[str]) -> dict:
    report = {
        "summary": {
            "processed_this_run": processed,
            "total_documents": conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
            "high_or_critical_documents": conn.execute("SELECT COUNT(*) FROM documents WHERE residual_risk IN ('High')").fetchone()[0],
            "unknown_extraction_gated_documents": conn.execute("SELECT COUNT(*) FROM documents WHERE residual_risk = 'Unknown'").fetchone()[0],
            "external_llm_blocked_documents": conn.execute("SELECT COUNT(*) FROM documents WHERE external_llm_readiness LIKE 'Blocked%'").fetchone()[0],
            "needs_ocr_documents": conn.execute("SELECT COUNT(*) FROM documents WHERE review_status = 'needs_ocr'").fetchone()[0],
        },
        "by_category": [dict_row(row) for row in conn.execute("SELECT * FROM v_category_stats WHERE document_count > 0").fetchall()],
        "by_client": [dict_row(row) for row in conn.execute("SELECT * FROM v_client_stats WHERE document_count > 0 LIMIT 20").fetchall()],
        "by_risk": [
            {"risk": risk, "count": count}
            for risk, count in conn.execute("SELECT residual_risk, COUNT(*) FROM documents GROUP BY residual_risk ORDER BY COUNT(*) DESC")
        ],
        "by_extraction_status": [
            {"status": status, "count": count}
            for status, count in conn.execute("SELECT extraction_status, COUNT(*) FROM documents GROUP BY extraction_status ORDER BY COUNT(*) DESC")
        ],
        "errors": errors,
        "terminology_note": "Use de-identified, redacted, pseudonymized, privacy-reviewed, or anonymization-assisted unless true anonymization has been assessed.",
    }
    return report


def replacement_for_finding(finding: dict) -> str:
    if finding.get("risk") == "CRITICAL" and "review" in finding.get("recommended_action", "").lower():
        return f"[{finding['placeholder'].strip('[]')}_REDACTED]"
    return finding.get("placeholder") or "[REDACTED]"


def dict_row(row: sqlite3.Row | tuple) -> dict:
    return {key: row[key] for key in row.keys()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-dir", type=Path, default=DEFAULT_STOCK_DIR)
    parser.add_argument("--extra-file", action="append", type=Path, default=DEFAULT_EXTRA_FILES)
    parser.add_argument("--report", type=Path, default=PROJECT_DIR / "classification_report.json")
    args = parser.parse_args()

    report = scan_and_classify(args.stock_dir, args.extra_file)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    print(f"Report written: {args.report}")


if __name__ == "__main__":
    main()
