"""WSGI entry point for serving the app under a real server.

`python3 app.py` runs Flask's development server: single process, no request
limits, and not written to face anything but localhost. Anything longer-lived
should go through a WSGI server instead:

    pip install gunicorn
    export LEGAL_ANALYZER_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    gunicorn --workers 4 --bind 127.0.0.1:5000 wsgi:application

LEGAL_ANALYZER_SECRET_KEY is not optional anywhere: with it unset, `import app`
raises SystemExit (see `resolve_secret_key` in app.py), so every gunicorn worker
fails to boot with the same message rather than each minting a key of its own
and rejecting the others' sessions.

This does not make the app multi-tenant. Every authenticated user still sees
every document — there is no per-user or per-organisation scoping in the schema
— so it belongs behind TLS on a network you control, serving one firm, with
LEGAL_ANALYZER_HTTPS=1 set so the session cookie carries the Secure flag.
"""

from __future__ import annotations

from app import app as application

__all__ = ["application"]
