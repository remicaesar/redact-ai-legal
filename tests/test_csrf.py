"""CSRF enforcement, tested with clients that do NOT carry a token.

The rest of the suite runs through tests/__init__.py's CSRFAwareClient, which
presents a valid token the way a browser does. That proves the check accepts
what it should. These tests use a raw FlaskClient to prove it rejects what it
should — without them, removing the whole before_request hook would leave the
suite green.
"""

import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from flask.testing import FlaskClient
from werkzeug.security import generate_password_hash

import app as app_module


class CSRFEnforcementTests(unittest.TestCase):
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

        # Raw client: no token unless a test supplies one explicitly.
        self.client = FlaskClient(app_module.app)

    def restore(self) -> None:
        app_module.DB_PATH = self.original_db_path
        app_module.READY_DB_PATHS.discard(self.db_path.resolve())

    def session_token(self) -> str:
        with self.client.session_transaction() as sess:
            return sess.get("csrf_token") or ""

    def test_post_without_a_token_is_rejected(self) -> None:
        response = self.client.post("/login", json={"username": "reviewer", "password": "secret"})
        self.assertEqual(response.status_code, 403)

    def test_post_with_a_wrong_token_is_rejected(self) -> None:
        self.client.get("/login")
        response = self.client.post(
            "/login",
            json={"username": "reviewer", "password": "secret"},
            headers={"X-CSRF-Token": "not-the-session-token"},
        )
        self.assertEqual(response.status_code, 403)

    def test_a_token_from_another_session_is_rejected(self) -> None:
        """A valid-looking token is not enough; it must be *this* session's."""
        other = FlaskClient(app_module.app)
        other.get("/login")
        with other.session_transaction() as sess:
            stolen = sess["csrf_token"]

        self.client.get("/login")
        response = self.client.post(
            "/login",
            json={"username": "reviewer", "password": "secret"},
            headers={"X-CSRF-Token": stolen},
        )
        self.assertEqual(response.status_code, 403)

    def test_header_token_is_accepted(self) -> None:
        self.client.get("/login")
        response = self.client.post(
            "/login",
            json={"username": "reviewer", "password": "secret"},
            headers={"X-CSRF-Token": self.session_token()},
        )
        self.assertEqual(response.status_code, 200)

    def test_form_field_token_is_accepted(self) -> None:
        """The login page is a real form, so the field path has to work too."""
        self.client.get("/login")
        response = self.client.post(
            "/login",
            data={"username": "reviewer", "password": "secret", "csrf_token": self.session_token()},
        )
        self.assertEqual(response.status_code, 302)

    def test_login_form_embeds_the_token(self) -> None:
        page = self.client.get("/login").get_data(as_text=True)
        self.assertIn('name="csrf_token"', page)
        self.assertIn(self.session_token(), page)

    def test_safe_methods_need_no_token(self) -> None:
        for path in ("/login", "/welcome"):
            with self.subTest(path=path):
                self.assertNotEqual(self.client.get(path).status_code, 403)

    def test_token_rotates_on_login(self) -> None:
        """A session that gains privileges should not keep its anonymous token."""
        self.client.get("/login")
        before = self.session_token()
        self.client.post(
            "/login",
            json={"username": "reviewer", "password": "secret"},
            headers={"X-CSRF-Token": before},
        )
        self.assertNotEqual(self.session_token(), before)
        self.assertTrue(self.session_token())

    def test_authenticated_api_write_still_needs_a_token(self) -> None:
        """The check must not be satisfied merely by being logged in."""
        self.client.get("/login")
        self.client.post(
            "/login",
            json={"username": "reviewer", "password": "secret"},
            headers={"X-CSRF-Token": self.session_token()},
        )
        # Logged in, valid session cookie, no token on this request.
        response = self.client.post("/api/document/1/mark-redacted", json={})
        self.assertEqual(response.status_code, 403)
        self.assertIn("CSRF", response.get_data(as_text=True))

    def test_api_rejection_is_json(self) -> None:
        response = self.client.post("/api/document/1/mark-redacted", json={})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.mimetype, "application/json")
        self.assertIn("error", response.get_json())


class CSRFCoverageTests(unittest.TestCase):
    def test_every_page_template_ships_the_token_and_wrapper(self) -> None:
        """Any authenticated page whose JS posts needs both, or its buttons 403.

        landing.html is exempt: it is the unauthenticated marketing page and
        makes no state-changing request.
        """
        for template in sorted(Path("templates").glob("*.html")):
            if template.name == "landing.html":
                continue
            body = template.read_text(encoding="utf-8")
            with self.subTest(template=template.name):
                self.assertIn('name="csrf-token"', body)
                self.assertIn("/static/csrf.js", body)

    def test_landing_page_makes_no_state_changing_request(self) -> None:
        """The premise of the exemption above, asserted rather than assumed."""
        body = Path("templates/landing.html").read_text(encoding="utf-8")
        self.assertNotIn("method:", body)


if __name__ == "__main__":
    unittest.main()
