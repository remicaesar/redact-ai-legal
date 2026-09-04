"""Test-package setup: make the default test client CSRF-aware.

CSRF protection is on by default in the app, so every state-changing request in
the suite needs a token. The alternative — turning protection off under test —
would mean no test ever exercises the enforced path, and the first thing anyone
would learn about a broken token check is in production.

So instead of disabling it, the client presents a valid token the way a browser
does: it reads the session's token (minting one into the session if the client
has not been anywhere yet, which is what a GET would have done) and sends it as
the X-CSRF-Token header on unsafe methods.

Tests that need to prove the check actually rejects things use a raw
`FlaskClient` instead — see tests/test_csrf.py.
"""

import secrets

from flask.testing import FlaskClient

import app as app_module


class CSRFAwareClient(FlaskClient):
    """A test client that carries the session CSRF token on unsafe methods."""

    def _with_csrf(self, kwargs: dict) -> dict:
        headers = dict(kwargs.get("headers") or {})
        if "X-CSRF-Token" not in headers:
            with self.session_transaction() as sess:
                token = sess.get("csrf_token")
                if not token:
                    token = secrets.token_urlsafe(32)
                    sess["csrf_token"] = token
            headers["X-CSRF-Token"] = token
        kwargs["headers"] = headers
        return kwargs

    def post(self, *args, **kwargs):
        return super().post(*args, **self._with_csrf(kwargs))

    def put(self, *args, **kwargs):
        return super().put(*args, **self._with_csrf(kwargs))

    def patch(self, *args, **kwargs):
        return super().patch(*args, **self._with_csrf(kwargs))

    def delete(self, *args, **kwargs):
        return super().delete(*args, **self._with_csrf(kwargs))


def install_csrf_client() -> None:
    """Point the current app object at the CSRF-aware client.

    Call this again after any reload(app_module): reloading builds a fresh Flask
    instance, and the default client it comes with sends no token, so every
    later test in the run would get a 403.
    """
    app_module.app.test_client_class = CSRFAwareClient


install_csrf_client()
