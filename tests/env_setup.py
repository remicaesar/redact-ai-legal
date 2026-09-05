"""Environment every test module must have in place before importing ``app``.

app.py refuses to start without LEGAL_ANALYZER_SECRET_KEY (it used to fall back
to a published default that made an admin session forgeable), and that check
runs at import time, so setUp is too late. Import this module before ``app``:

    import tests.env_setup  # noqa: F401  -- must precede "import app"

setdefault, not assignment: a real shell value still wins, and the fail-fast
itself is exercised in tests/test_app_config.py with the variable removed.
"""

from __future__ import annotations

import os

os.environ.setdefault("LEGAL_ANALYZER_SECRET_KEY", "test-only-secret-not-for-deployment")
