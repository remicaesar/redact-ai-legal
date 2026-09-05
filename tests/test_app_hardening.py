"""Deployment-surface guards: session key, request cap, cookie flags.

None of these change what the release gate decides. They cover the layer
underneath it — the process serving the gate — where a published signing key or
a Secure-less cookie hands someone an admin session without ever going through
review.
"""

import os
import unittest
from importlib import reload
from unittest import mock

import app as app_module
from tests import install_csrf_client


def reload_app():
    """reload app.py and restore the CSRF-aware test client on the new object."""
    module = reload(app_module)
    install_csrf_client()
    return module


class SecretKeyTests(unittest.TestCase):
    def reload_under(self, env: dict[str, str]):
        """Re-import app.py under a patched environment and hand back the module."""
        with mock.patch.dict(os.environ, env, clear=False):
            return reload_app()

    def tearDown(self) -> None:
        # Leave the module as the rest of the suite expects to find it.
        reload_app()

    def test_configured_key_is_used_verbatim(self) -> None:
        module = self.reload_under({"LEGAL_ANALYZER_SECRET_KEY": "configured-key-from-env"})
        self.assertEqual(module.app.secret_key, "configured-key-from-env")

    # An unset or blank key is a startup failure, not an ephemeral key — see
    # tests/test_app_config.py (unset, blank, and the subprocess import) for the
    # fail-fast guards. Two designs for this shipped on separate branches; the
    # refuse-to-start one won when they were reconciled, superseding ADR-007.

    def test_no_hardcoded_fallback_survives_in_the_source(self) -> None:
        source = (app_module.PROJECT_DIR / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("local-dev-secret-change-before-production", source)


class RequestLimitTests(unittest.TestCase):
    def tearDown(self) -> None:
        # Unconditional: a failing assertion inside a patched environment would
        # otherwise leave the reloaded module configured for the next test.
        reload_app()

    def test_upload_body_is_capped(self) -> None:
        self.assertEqual(app_module.app.config["MAX_CONTENT_LENGTH"], 100_000_000)

    def test_cap_is_overridable(self) -> None:
        with mock.patch.dict(os.environ, {"LEGAL_ANALYZER_MAX_UPLOAD_BYTES": "2048"}, clear=False):
            self.assertEqual(reload_app().app.config["MAX_CONTENT_LENGTH"], 2048)

    def test_oversized_body_is_rejected_by_the_server(self) -> None:
        """413 must come from the request layer, not from a handler that opted in.

        Asserted through /login because it is unauthenticated: on an endpoint
        behind @require_roles the 401 lands first — correctly — and would hide
        whether the cap works at all. The abort happens while the form is being
        parsed, so the handler's DB query is never reached. That the 413 tracks
        the configured size rather than the route is covered by
        test_cap_is_overridable.
        """
        with mock.patch.dict(os.environ, {"LEGAL_ANALYZER_MAX_UPLOAD_BYTES": "1024"}, clear=False):
            client = reload_app().app.test_client()
            oversized = client.post(
                "/login",
                data={"username": "admin", "password": "x" * 4096},
                content_type="application/x-www-form-urlencoded",
            )
            self.assertEqual(oversized.status_code, 413)


class SessionCookieTests(unittest.TestCase):
    def tearDown(self) -> None:
        reload_app()

    def test_httponly_and_samesite_are_set(self) -> None:
        self.assertTrue(app_module.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(app_module.app.config["SESSION_COOKIE_SAMESITE"], "Strict")

    def test_secure_defaults_off_so_local_http_login_works(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LEGAL_ANALYZER_HTTPS", None)
            self.assertFalse(reload_app().app.config["SESSION_COOKIE_SECURE"])

    def test_secure_turns_on_for_tls_deployments(self) -> None:
        for value in ("1", "true", "YES"):
            with self.subTest(value=value):
                with mock.patch.dict(os.environ, {"LEGAL_ANALYZER_HTTPS": value}, clear=False):
                    self.assertTrue(reload_app().app.config["SESSION_COOKIE_SECURE"])


class DebugServerTests(unittest.TestCase):
    def test_script_entry_point_does_not_hardcode_debug(self) -> None:
        """The Werkzeug debugger is an RCE console; it must not be on by default.

        Asserted against the source because the __main__ block does not run
        under the test suite.
        """
        source = (app_module.PROJECT_DIR / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("app.run(debug=True", source)
        self.assertIn("LEGAL_ANALYZER_DEBUG", source)


if __name__ == "__main__":
    unittest.main()
