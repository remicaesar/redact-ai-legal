#!/usr/bin/env python3
"""Initialize the legal document analyzer database."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from legal_analyzer.taxonomy import CATEGORIES, KNOWN_CLIENTS, SUBCATEGORIES
from db.migrate import apply_migrations

DB_DIR = Path(__file__).resolve().parent
DB_PATH = DB_DIR / "legal_documents.db"
SCHEMA_PATH = DB_DIR / "schema.sql"


def init_database(reset: bool = False) -> None:
    """Create or top up the database. Only deletes it when ``reset`` is True.

    This used to default to deleting db/legal_documents.db (opt out with
    KEEP_DB=1), while being documented as an ordinary setup step — so running
    the documented command a second time silently destroyed every reviewed
    document, finding and audit-log row. Deleting now requires --reset, and
    prints what is about to be lost first.
    """
    if DB_PATH.exists():
        if not reset:
            print(f"Existing database kept: {DB_PATH}")
            print("Applying schema and seed data without deleting anything (pass --reset to rebuild from scratch).")
        else:
            report_rows_at_risk(DB_PATH)
            DB_PATH.unlink()
            print(f"Removed existing database: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as handle:
        conn.executescript(handle.read())
    seed_categories(conn)
    seed_clients(conn)
    conn.commit()
    conn.close()
    apply_migrations(DB_PATH)
    print(f"Database ready: {DB_PATH}")


def row_counts(path: Path) -> dict[str, int]:
    """Row count per non-empty user table, so a reset can say what it destroys."""
    conn = sqlite3.connect(path)
    try:
        names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            # FTS5 shadow tables mirror rows that are already counted via their
            # content table, so listing them would double-report.
            if "_fts" not in row[0]
        ]
        counts = {}
        for name in names:
            try:
                count = conn.execute(f"SELECT COUNT(*) FROM \"{name}\"").fetchone()[0]
            except sqlite3.DatabaseError:
                continue
            if count:
                counts[name] = count
        return counts
    finally:
        conn.close()


def report_rows_at_risk(path: Path) -> None:
    counts = row_counts(path)
    if not counts:
        print(f"--reset: {path} exists but holds no rows.")
        return
    print(f"--reset: about to DELETE {path}, destroying:")
    for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        print(f"  {count:>8} row(s) in {name}")


def seed_categories(conn: sqlite3.Connection) -> None:
    for name, name_tr, icon in CATEGORIES:
        conn.execute(
            "INSERT OR IGNORE INTO categories (name, name_tr, icon) VALUES (?, ?, ?)",
            (name, name_tr, icon),
        )
        category_id = conn.execute("SELECT id FROM categories WHERE name = ?", (name,)).fetchone()[0]
        for sub_name, sub_name_tr in SUBCATEGORIES[name]:
            conn.execute(
                "INSERT OR IGNORE INTO subcategories (category_id, name, name_tr) VALUES (?, ?, ?)",
                (category_id, sub_name, sub_name_tr),
            )


def seed_clients(conn: sqlite3.Connection) -> None:
    for name, aliases in KNOWN_CLIENTS:
        conn.execute(
            "INSERT OR IGNORE INTO clients (name, aliases) VALUES (?, ?)",
            (name, json.dumps(aliases, ensure_ascii=False)),
        )


if __name__ == "__main__":
    init_database(reset="--reset" in sys.argv[1:])
