"""Login, logout, and session identity routes."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash

from app import (
    audit_event,
    clear_login_attempts,
    get_db,
    issue_csrf_token,
    login_lockout_seconds,
    record_failed_login,
    require_roles,
)

auth_bp = Blueprint("auth", __name__)

LOGIN_PAGE = """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Redact AI — Sign in</title>
        <link rel="stylesheet" href="/static/workstation.css">
        <style>
            :root {
                --bg: var(--color-canvas); --panel: var(--color-surface); --text: var(--color-text);
                --muted: var(--color-text-muted); --line: var(--color-border);
                --blue: var(--color-accent); --red: var(--color-danger); --red-bg: var(--color-danger-soft);
            }
            * { box-sizing: border-box; }
            body {
                margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
                background: var(--bg); color: var(--text);
                font-family: var(--font-ui); -webkit-font-smoothing: antialiased;
            }
            .card {
                width: 100%; max-width: 380px; margin: 24px; padding: 28px;
                background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius-lg);
                box-shadow: var(--shadow-md);
            }
            .brand { display: flex; align-items: center; gap: 11px; margin-bottom: 22px; }
            .brand .logo {
                width: 36px; height: 36px; border-radius: var(--radius); background: var(--blue); color: #fff;
                display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: var(--text-lg);
            }
            .brand .name { margin: 0; font-size: var(--text-lg); font-weight: 600; letter-spacing: -0.01em; }
            .brand .sub { font-size: var(--text-sm); color: var(--muted); margin-top: 1px; }
            label { display: block; font-size: var(--text-sm); font-weight: 600; color: var(--muted); margin-bottom: 6px; }
            input {
                display: block; width: 100%; margin-bottom: 16px;
            }
            button {
                width: 100%; border-color: var(--blue); background: var(--blue); color: #fff; margin-top: 4px;
            }
            button:hover { border-color: var(--color-accent-hover); background: var(--color-accent-hover); color: #fff; }
            .error {
                background: var(--red-bg); color: var(--red); border: 1px solid #e3b5b2;
                border-radius: var(--radius); padding: 10px 12px; font-size: var(--text-sm); margin-bottom: 16px;
            }
            .foot { margin-top: 18px; font-size: var(--text-xs); color: var(--muted); text-align: center; }
            @media (max-width: 480px) { .card { margin: 16px; padding: 24px 20px; } }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="brand">
                <div class="logo">R</div>
                <div>
                    <h1 class="name">Redact AI</h1>
                    <div class="sub">Privacy review workstation</div>
                </div>
            </div>
            {% if throttled %}
            <div class="error">Too many failed sign-in attempts. Wait a few minutes and try again.</div>
            {% elif error %}<div class="error">Invalid username or password.</div>{% endif %}
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <label for="username">Username</label>
                <input id="username" name="username" autocomplete="username" autofocus>
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password">
                <button class="primary" type="submit">Sign in</button>
            </form>
            <div class="foot">Local only · data stays on this device</div>
        </div>
    </body>
    </html>
    """


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Minting the token here is what lets the form below post it back; a
        # POST that arrives without a prior GET has no session token to match.
        issue_csrf_token()
        return render_template_string(LOGIN_PAGE, error=False, throttled=False)

    payload = request.get_json(silent=True) or request.form
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    remote_addr = request.remote_addr or ""
    conn = get_db()

    # Throttle before touching the password hash: check_password_hash is
    # deliberately slow, so an unthrottled endpoint is both a guessing oracle
    # and a way to spend the server's CPU.
    locked_for = login_lockout_seconds(conn, username, remote_addr)
    if locked_for > 0:
        audit_event(conn, "login", result="throttled", metadata={"username": username})
        conn.commit()
        conn.close()
        retry_after = str(locked_for)
        if request.is_json:
            response = jsonify({"error": "Too many failed sign-in attempts. Try again later."})
            response.headers["Retry-After"] = retry_after
            return response, 429
        return render_template_string(LOGIN_PAGE, error=True, throttled=True), 429, {"Retry-After": retry_after}

    user = conn.execute("SELECT * FROM users WHERE username = ? AND active = 1", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        record_failed_login(conn, username, remote_addr)
        audit_event(conn, "login", result="failed", metadata={"username": username})
        conn.commit()
        conn.close()
        if request.is_json:
            return jsonify({"error": "Invalid credentials"}), 401
        return render_template_string(LOGIN_PAGE, error=True), 401

    clear_login_attempts(conn, username, remote_addr)
    session.clear()
    # session.clear() drops the pre-login CSRF token; mint a fresh one rather
    # than carrying the anonymous session's token into an authenticated one.
    issue_csrf_token()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    g.current_user = {"id": user["id"], "username": user["username"], "role": user["role"], "active": user["active"]}
    conn.execute("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
    audit_event(conn, "login", result="success")
    conn.commit()
    conn.close()
    if request.is_json:
        return jsonify({"ok": True, "user": {"username": user["username"], "role": user["role"]}})
    return redirect(url_for("documents.index"))


@auth_bp.route("/logout", methods=["POST"])
@require_roles("viewer", "reviewer", "admin")
def logout():
    # POST only: a GET logout can be triggered by any third-party page that
    # gets the browser to fetch the URL (an <img> tag is enough). Every UI call
    # site already posts.
    conn = get_db()
    audit_event(conn, "logout")
    conn.commit()
    conn.close()
    session.clear()
    return jsonify({"ok": True})


@auth_bp.route("/api/me")
def api_me():
    user = getattr(g, "current_user", None)
    if not user:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "user": {"username": user["username"], "role": user["role"]}})
