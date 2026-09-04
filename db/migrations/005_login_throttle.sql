-- Failed-login records backing the /login throttle.
--
-- A table rather than an in-process counter because the supported deployment is
-- gunicorn with several workers (see wsgi.py): a dict in one worker's memory
-- lets an attacker get N attempts per worker and resets every restart.
--
-- Separate from audit_log on purpose. audit_log is append-only evidence and
-- must not be pruned; these rows are operational state and are deleted once
-- they age out of the window or the user signs in successfully. Failed logins
-- are still audited as before -- this table does not replace that record.
--
-- No username index alone: lookups are always (username, remote_addr) or
-- remote_addr, so an attacker who knows a username cannot lock its owner out
-- from a different address.

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    remote_addr TEXT NOT NULL DEFAULT '',
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_pair ON login_attempts(username, remote_addr, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_addr ON login_attempts(remote_addr, attempted_at);
