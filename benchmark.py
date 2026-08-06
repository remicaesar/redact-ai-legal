#!/usr/bin/env python3
"""Run repeatable performance and safety benchmarks for the analyzer."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import sqlite3
import statistics
import time
from pathlib import Path
from typing import Callable, TypeVar

from app import app
from classify import DEFAULT_EXTRA_FILES, DEFAULT_STOCK_DIR, DB_PATH, scan_paths
from legal_analyzer.classifier import classify_document
from legal_analyzer.extraction import extract_text
from legal_analyzer.privacy import EXTERNAL_LLM_BLOCKED, analyze_privacy
from werkzeug.security import generate_password_hash

SEARCH_PROBE_TERM = os.environ.get("LEGAL_ANALYZER_SEARCH_PROBE", "sozlesme")

PROJECT_DIR = Path(__file__).resolve().parent
T = TypeVar("T")
BENCHMARK_USERNAME = "benchmark_viewer"


def canary_document_check(conn: sqlite3.Connection) -> dict:
    """Assert that one known-sensitive document still trips every release gate.

    A regression that silently downgrades risk is the failure worth catching, so
    the benchmark pins one document and checks it stays High-risk, CRITICAL, and
    blocked for external LLM use.

    The document is named by environment variable rather than hardcoded: a real
    filename or client name is confidential and must not live in a public repo.

        LEGAL_ANALYZER_CANARY_PATTERN        SQL LIKE pattern for documents.filename
        LEGAL_ANALYZER_CANARY_EXPECT_CLIENT  optional expected client name

    Unset means "not configured" -- reported as skipped, never as a pass.
    """
    pattern = os.environ.get("LEGAL_ANALYZER_CANARY_PATTERN", "").strip()
    if not pattern:
        return {"configured": False, "skipped": True, "passes": None}

    expected_client = os.environ.get("LEGAL_ANALYZER_CANARY_EXPECT_CLIENT", "").strip()
    row = conn.execute(
        """
        SELECT d.id, d.residual_risk, d.recommended_strategy, c.name AS client_name,
               COUNT(pf.id) AS finding_count,
               SUM(CASE WHEN pf.risk = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count
        FROM documents d
        LEFT JOIN clients c ON c.id = d.client_id
        LEFT JOIN privacy_findings pf ON pf.document_id = d.id
        WHERE d.filename LIKE ?
        GROUP BY d.id
        """,
        (pattern,),
    ).fetchone()
    if not row:
        return {"configured": True, "found": False, "passes": False}

    profile = json.loads(conn.execute("SELECT privacy_profile FROM documents WHERE id = ?", (row["id"],)).fetchone()[0])
    external_llm = profile.get("llm_ingestion", {}).get("external_hosted_llm_api")
    return {
        "configured": True,
        "found": True,
        "client_name": row["client_name"],
        "residual_risk": row["residual_risk"],
        "finding_count": row["finding_count"],
        "critical_count": row["critical_count"],
        "external_llm": external_llm,
        "external_llm_readiness": profile.get("external_llm_readiness"),
        "passes": bool(
            (not expected_client or row["client_name"] == expected_client)
            and row["residual_risk"] == "High"
            and (row["critical_count"] or 0) > 0
            and external_llm == EXTERNAL_LLM_BLOCKED
        ),
    }


def timed(label: str, fn: Callable[[], T]) -> tuple[T, dict]:
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    return result, {"label": label, "seconds": elapsed}


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = min(len(sorted_values) - 1, max(0, round((percent / 100) * (len(sorted_values) - 1))))
    return sorted_values[index]


def summarize_times(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "total_seconds": 0.0, "mean_ms": 0.0, "median_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    return {
        "count": len(values),
        "total_seconds": round(sum(values), 4),
        "mean_ms": round(statistics.mean(values) * 1000, 2),
        "median_ms": round(statistics.median(values) * 1000, 2),
        "p95_ms": round(percentile(values, 95) * 1000, 2),
        "max_ms": round(max(values) * 1000, 2),
    }


def ensure_benchmark_user() -> int | None:
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'reviewer', 'viewer')),
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login_at TIMESTAMP
            )
            """
        )
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (BENCHMARK_USERNAME,)).fetchone()
        if existing:
            return existing["id"]
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'viewer')",
            (BENCHMARK_USERNAME, generate_password_hash("benchmark-local-only")),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def authenticated_client(user_id: int | None):
    client = app.test_client()
    if user_id:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = BENCHMARK_USERNAME
            sess["role"] = "viewer"
    return client


def benchmark_pipeline(paths: list[Path]) -> dict:
    extraction_times: list[float] = []
    analysis_times: list[float] = []
    classification_times: list[float] = []
    chars = 0
    extracted_docs = 0
    warnings = 0
    finding_counts: list[int] = []
    residual_risks: dict[str, int] = {}

    for path in paths:
        start = time.perf_counter()
        text, warning = extract_text(path)
        extraction_times.append(time.perf_counter() - start)
        warnings += 1 if warning else 0
        chars += len(text)
        extracted_docs += 1 if text else 0

        start = time.perf_counter()
        classify_document(path.name, text)
        classification_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        privacy = analyze_privacy(path.name, text, warning)
        analysis_times.append(time.perf_counter() - start)

        finding_counts.append(len(privacy["risk_map"]))
        risk = privacy["residual_risk"]["level"]
        residual_risks[risk] = residual_risks.get(risk, 0) + 1

    total_seconds = sum(extraction_times) + sum(classification_times) + sum(analysis_times)
    docs_per_second = len(paths) / total_seconds if total_seconds else 0.0
    chars_per_second = chars / total_seconds if total_seconds else 0.0

    return {
        "documents": len(paths),
        "documents_with_extracted_text": extracted_docs,
        "extraction_warnings": warnings,
        "characters_processed": chars,
        "docs_per_second_stage_time": round(docs_per_second, 2),
        "chars_per_second_stage_time": round(chars_per_second, 2),
        "extraction": summarize_times(extraction_times),
        "classification": summarize_times(classification_times),
        "privacy_analysis": summarize_times(analysis_times),
        "findings_per_document": {
            "mean": round(statistics.mean(finding_counts), 2) if finding_counts else 0.0,
            "median": round(statistics.median(finding_counts), 2) if finding_counts else 0.0,
            "max": max(finding_counts) if finding_counts else 0,
        },
        "residual_risk_distribution": residual_risks,
    }


def benchmark_api(iterations: int) -> dict:
    user_id = ensure_benchmark_user()
    endpoints = [
        ("index", "/"),
        ("documents_all", "/api/documents"),
        ("documents_search", f"/api/documents?search={SEARCH_PROBE_TERM}"),
        ("documents_blocked", "/api/documents?readiness=Blocked"),
        ("documents_extraction_failed", "/api/documents?extraction_status=Failed"),
        ("terminology", "/api/terminology"),
    ]

    results = {}
    for name, path in endpoints:
        timings = []
        status_codes = []
        payload_sizes = []
        for _ in range(iterations):
            start = time.perf_counter()
            with authenticated_client(user_id) as client:
                response = client.get(path)
            timings.append(time.perf_counter() - start)
            status_codes.append(response.status_code)
            payload_sizes.append(len(response.data))
        results[name] = {
            **summarize_times(timings),
            "status_codes": sorted(set(status_codes)),
            "mean_payload_bytes": round(statistics.mean(payload_sizes), 2) if payload_sizes else 0,
        }
    return results


def benchmark_api_concurrent(iterations: int, concurrency: int) -> dict:
    if concurrency <= 1:
        return {"enabled": False, "reason": "Set --api-concurrency above 1 to run concurrent API checks."}

    paths = [
        "/",
        "/api/documents",
        f"/api/documents?search={SEARCH_PROBE_TERM}",
        "/api/documents?readiness=Blocked",
        "/api/documents?extraction_status=Failed",
        "/api/terminology",
    ]
    request_paths = [paths[index % len(paths)] for index in range(iterations)]
    user_id = ensure_benchmark_user()

    def one_request(path: str) -> tuple[float, int, int]:
        start = time.perf_counter()
        with authenticated_client(user_id) as client:
            response = client.get(path)
            payload_size = len(response.data)
            status_code = response.status_code
        return time.perf_counter() - start, status_code, payload_size

    timings = []
    status_codes = []
    payload_sizes = []
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(one_request, path) for path in request_paths]
        for future in as_completed(futures):
            elapsed, status_code, payload_size = future.result()
            timings.append(elapsed)
            status_codes.append(status_code)
            payload_sizes.append(payload_size)
    wall_time = time.perf_counter() - start

    return {
        "enabled": True,
        "requests": iterations,
        "concurrency": concurrency,
        "wall_seconds": round(wall_time, 4),
        "requests_per_second": round(iterations / wall_time, 2) if wall_time else 0.0,
        **summarize_times(timings),
        "status_codes": sorted(set(status_codes)),
        "mean_payload_bytes": round(statistics.mean(payload_sizes), 2) if payload_sizes else 0,
    }


def benchmark_database() -> dict:
    if not DB_PATH.exists():
        return {"available": False, "reason": f"Database not found: {DB_PATH}"}

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        summary = {
            "available": True,
            "document_count": conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
            "privacy_finding_count": conn.execute("SELECT COUNT(*) FROM privacy_findings").fetchone()[0],
            "external_llm_blocked_count": conn.execute("SELECT COUNT(*) FROM documents WHERE external_llm_readiness LIKE 'Blocked%'").fetchone()[0],
            "human_review_required_count": conn.execute("SELECT COUNT(*) FROM documents WHERE human_review_required = 1").fetchone()[0],
            "risk_distribution": {
                row["residual_risk"]: row["count"]
                for row in conn.execute("SELECT residual_risk, COUNT(*) AS count FROM documents GROUP BY residual_risk")
            },
            "extraction_status_distribution": {
                row["extraction_status"]: row["count"]
                for row in conn.execute("SELECT extraction_status, COUNT(*) AS count FROM documents GROUP BY extraction_status")
            },
        }
        summary["canary_document_check"] = canary_document_check(conn)
        return summary
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-dir", type=Path, default=DEFAULT_STOCK_DIR)
    parser.add_argument("--extra-file", action="append", type=Path, default=DEFAULT_EXTRA_FILES)
    parser.add_argument("--limit", type=int, default=0, help="Limit documents for a faster benchmark. 0 means all.")
    parser.add_argument("--api-iterations", type=int, default=10)
    parser.add_argument("--api-concurrency", type=int, default=1)
    parser.add_argument("--output", type=Path, default=PROJECT_DIR / "benchmark_report.json")
    args = parser.parse_args()

    discovered, discovery_timing = timed("document_discovery", lambda: scan_paths(args.stock_dir, args.extra_file))
    paths = discovered[: args.limit] if args.limit else discovered
    pipeline, pipeline_timing = timed("pipeline", lambda: benchmark_pipeline(paths))
    api, api_timing = timed("api", lambda: benchmark_api(args.api_iterations))
    api_concurrent, api_concurrent_timing = timed(
        "api_concurrent",
        lambda: benchmark_api_concurrent(args.api_iterations, args.api_concurrency),
    )
    database, database_timing = timed("database", benchmark_database)

    report = {
        "input": {
            "stock_dir": str(args.stock_dir),
            "extra_files": [str(path) for path in args.extra_file],
            "discovered_documents": len(discovered),
            "benchmarked_documents": len(paths),
            "api_iterations": args.api_iterations,
            "api_concurrency": args.api_concurrency,
        },
        "wall_clock": {
            "discovery_seconds": round(discovery_timing["seconds"], 4),
            "pipeline_seconds": round(pipeline_timing["seconds"], 4),
            "api_seconds": round(api_timing["seconds"], 4),
            "api_concurrent_seconds": round(api_concurrent_timing["seconds"], 4),
            "database_seconds": round(database_timing["seconds"], 4),
        },
        "pipeline": pipeline,
        "api": api,
        "api_concurrent": api_concurrent,
        "database": database,
    }

    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Benchmark report written: {args.output}")


if __name__ == "__main__":
    main()
