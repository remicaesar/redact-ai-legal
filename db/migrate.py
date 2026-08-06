#!/usr/bin/env python3
"""Apply lightweight SQLite migrations for the legal document analyzer."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

DB_DIR = Path(__file__).resolve().parent
DB_PATH = DB_DIR / "legal_documents.db"
MIGRATIONS_DIR = DB_DIR / "migrations"


def connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_migration_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def applied_versions(conn: sqlite3.Connection) -> set[str]:
    ensure_migration_table(conn)
    return {row["version"] for row in conn.execute("SELECT version FROM schema_migrations")}


def apply_migrations(db_path: Path = DB_PATH) -> list[str]:
    conn = connect(db_path)
    ensure_migration_table(conn)
    applied = applied_versions(conn)
    newly_applied: list[str] = []

    for path in migration_files():
        version = path.stem
        if version in applied:
            continue
        conn.executescript(path.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO schema_migrations (version) VALUES (?)", (version,))
        newly_applied.append(version)

    conn.commit()
    conn.close()
    return newly_applied


def migration_status(db_path: Path = DB_PATH) -> list[dict]:
    conn = connect(db_path)
    applied = applied_versions(conn)
    status = [{"version": path.stem, "applied": path.stem in applied} for path in migration_files()]
    conn.close()
    return status


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()

    if args.status:
        for item in migration_status(args.db):
            marker = "applied" if item["applied"] else "pending"
            print(f"{item['version']}: {marker}")
        return

    applied = apply_migrations(args.db)
    if applied:
        print("Applied migrations:")
        for version in applied:
            print(f"- {version}")
    else:
        print("No pending migrations.")


if __name__ == "__main__":
    main()
