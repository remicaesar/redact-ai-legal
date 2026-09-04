"""Login throttling: guessing has to get expensive, without becoming a lockout tool."""

import os
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from werkzeug.security import generate_password_hash

import app as app_module


class LoginThrottleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "test.db"
        conn = sqlite3.connect(self.db_path)
        conn.executescript(Path("db/schema.sql").read_text(encoding="utf-8"))
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("reviewer", generate_password_hash("secret"), "reviewer"),
        )
        conn.commit()
        conn.close()

        self.original_db_path = app_module.DB_PATH
        app_module.DB_PATH = self.db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())
        self.addCleanup(self.restore)
        self.client = app_module.app.test_client()

    def restore(self) -> None:
        app_module.DB_PATH = self.original_db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())

    def attempt(self, password: str = "wrong", username: str = "reviewer", client=None):
        return (client or self.client).post("/login", json={"username": username, "password": password})

    def attempt_count(self) -> int:
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]
        finally:
            conn.close()

    def test_wrong_passwords_are_rejected_until_the_cap_then_throttled(self) -> None:
        for _ in range(5):
            self.assertEqual(self.attempt().status_code, 401)
        self.assertEqual(self.attempt().status_code, 429)

    def test_throttle_response_says_when_to_retry(self) -> None:
        for _ in range(5):
            self.attempt()
        throttled = self.attempt()
        self.assertEqual(throttled.status_code, 429)
        self.assertIn("Retry-After", throttled.headers)
        self.assertGreater(int(throttled.headers["Retry-After"]), 0)

    def test_the_right_password_stops_working_once_throttled(self) -> None:
        """The lockout must not be bypassable by finally guessing correctly.

        Otherwise the throttle only slows down wrong guesses, which is the half
        that does not matter.
        """
        for _ in range(5):
            self.attempt()
        self.assertEqual(self.attempt(password="secret").status_code, 429)

    def test_a_successful_login_clears_the_record(self) -> None:
        for _ in range(3):
            self.attempt()
        self.assertEqual(self.attempt_count(), 3)
        self.assertEqual(self.attempt(password="secret").status_code, 200)
        self.assertEqual(self.attempt_count(), 0)

    def test_failures_do_not_lock_a_user_out_from_another_address(self) -> None:
        """Counting per username alone would make this an account-lockout tool."""
        for _ in range(5):
            self.attempt()
        self.assertEqual(self.attempt().status_code, 429)

        elsewhere = app_module.app.test_client()
        response = elsewhere.post(
            "/login",
            json={"username": "reviewer", "password": "secret"},
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        self.assertEqual(response.status_code, 200)

    def test_one_address_spraying_many_usernames_is_capped(self) -> None:
        """Under the pair cap for each name, but well over the address cap."""
        for index in range(20):
            self.attempt(username=f"user{index}")
        self.assertEqual(self.attempt(username="someone-new").status_code, 429)

    def test_attempts_outside_the_window_do_not_count(self) -> None:
        for _ in range(5):
            self.attempt()
        self.assertEqual(self.attempt().status_code, 429)

        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE login_attempts SET attempted_at = datetime('now', '-2 hours')")
        conn.commit()
        conn.close()

        self.assertEqual(self.attempt(password="secret").status_code, 200)

    def test_aged_out_rows_are_pruned(self) -> None:
        self.attempt()
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE login_attempts SET attempted_at = datetime('now', '-2 hours')")
        conn.commit()
        conn.close()

        # Any throttle check prunes before counting, so the aged row goes and
        # only the attempt just made survives. Without pruning the table grows
        # forever on a host that gets scanned.
        self.attempt()
        self.assertEqual(self.attempt_count(), 1)

    def test_caps_are_configurable(self) -> None:
        with mock.patch.dict(os.environ, {"LEGAL_ANALYZER_LOGIN_MAX_ATTEMPTS": "2"}, clear=False):
            self.assertEqual(self.attempt().status_code, 401)
            self.assertEqual(self.attempt().status_code, 401)
            self.assertEqual(self.attempt().status_code, 429)

    def test_throttling_is_audited(self) -> None:
        for _ in range(6):
            self.attempt()
        conn = sqlite3.connect(self.db_path)
        try:
            throttled = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'login' AND result = 'throttled'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertGreaterEqual(throttled, 1)

    def test_audit_metadata_carries_no_password(self) -> None:
        self.attempt(password="hunter2-should-never-be-stored")
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute("SELECT metadata FROM audit_log WHERE action = 'login'").fetchall()
        finally:
            conn.close()
        for (metadata,) in rows:
            self.assertNotIn("hunter2", metadata or "")


if __name__ == "__main__":
    unittest.main()
