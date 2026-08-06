#!/usr/bin/env python3
"""Initialize the legal document analyzer database."""

from __future__ import annotations

import json
import os
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


def init_database(reset: bool = True) -> None:
    if reset and DB_PATH.exists():
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
    init_database(reset=os.environ.get("KEEP_DB") != "1")
