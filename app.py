
import os
import sqlite3
import secrets
import hmac
import logging
from datetime import timedelta
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------
# Application paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "users.db"
LOG_PATH = BASE_DIR / "security.log"


# --------------------------------------------------
# Dedicated security logger
# --------------------------------------------------

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

if not security_logger.handlers:
    log_handler = logging.FileHandler(
        LOG_PATH,
        encoding="utf-8",
    )
    log_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s"
        )
    )
    security_logger.addHandler(log_handler)


# --------------------------------------------------
# Flask configuration
# --------------------------------------------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "local-development-key-change-before-deployment",
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_REFRESH_EACH_REQUEST=False,
)


# --------------------------------------------------
# Rate limiting
# --------------------------------------------------

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)


# Dummy hash helps reduce timing differences for
# login attempts using usernames that do not exist.
DUMMY_PASSWORD_HASH = generate_password_hash(
    secrets.token_urlsafe(24)
)


# --------------------------------------------------
# HTML templates
# --------------------------------------------------

PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure Authentication Lab</title>
</head>
<body>
    <h1>Secure Authentication Lab</h1>

    {% for message in get_flashed_messages() %}
        <p role="status">{{ message }}</p>
    {% endfor %}

    {{ content|safe }}
</body>
</html>
"""


DASHBOARD_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard - Secure Authentication Lab</title>
</head>
<body>
    <h1>Secure Authentication Lab</h1>
    <h2>Welcome, {{ username }}!</h2>
    <p>You are logged in.</p>

    <form method="post" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit">Log out</button>
    </form>
</body>
</html>
"""


# --------------------------------------------------
# Database functions
# --------------------------------------------------

def connect_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)


# --------------------------------------------------
# Input validation
# --------------------------------------------------

def valid_credentials(username, password):
    return (
        3 <= len(username) <= 40
        and username.isascii()
        and username.isalnum()
        and 8 <= len(password) <= 128
    )


# --------------------------------------------------
# CSRF protection
# --------------------------------------------------

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


def check_csrf_token():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")

    if (
        not submitted
        or not expected
        or not hmac.compare_digest(submitted, expected)
    ):
        security_logger.warning(
            "event=csrf_validation_failed endpoint=%s",
            request.endpoint,
        )
        abort(
            400,
            "Invalid request. Please reload the page and try again.",
        )


# --------------------------------------------------
# Home page
# --------------------------------------------------

@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    csrf_token = get_csrf_token()

    content = """
    <h2>Register</h2>

    <form method="post" action="/register">
        <input type="hidden" name="csrf_token"
               value="{{ csrf_token }}">

        <label>Username (3–40 letters or digits)
            <input name="username"
                   required minlength="3" maxlength="40">
        </label><br>

        <label>Password (8–128 characters)
            <input type="password" name="password"
                   required minlength="8" maxlength="128">
        </label><br>

        <button type="submit">Register</button>
    </form>

    <h2>Login</h2>

    <form method="post" action="/login">
        <input type="hidden" name="csrf_token"
               value="{{ csrf_token }}">

        <label>Username
            <input name="username"
                   required maxlength="40">
        </label><br>

        <label>Password
            <input type="password" name="password"
                   required maxlength="128">
        </label><br>

        <button type="submit">Login</button>
    </form>
    """

    content = render_template_string(
        content,
        csrf_token=csrf_token,
    )

    return render_template_string(
        PAGE,
        content=content,
    )


# --------------------------------------------------
# Registration
# --------------------------------------------------

@app.route("/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    check_csrf_token()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not valid_credentials(username, password):
        security_logger.warning(
            "event=registration_rejected reason=invalid_input"
        )
        abort(400, "Invalid input. Check the required format.")

    password_hash = generate_password_hash(password)

    try:
        with connect_db() as db:
            db.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (username, password_hash),
            )

    except sqlite3.IntegrityError:
        security_logger.warning(
            "event=registration_rejected reason=duplicate_username"
        )
        return "Unable to register with those details.", 400

    security_logger.info("event=registration_success")

    flash("Registration successful. You can now log in.")
    return redirect(url_for("home"))


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    check_csrf_token()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if (
        not username
        or len(username) > 40
        or not password
        or len(password) > 128
    ):
        security_logger.warning(
            "event=login_failure reason=invalid_input"
        )
        return "Invalid username or password.", 401

    with connect_db() as db:
        user = db.execute(
            """
            SELECT id, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    if user is None:
        check_password_hash(DUMMY_PASSWORD_HASH, password)

        security_logger.warning(
            "event=login_failure reason=invalid_credentials"
        )
        return "Invalid username or password.", 401

    if not check_password_hash(user["password_hash"], password):
        security_logger.warning(
            "event=login_failure reason=invalid_credentials"
        )
        return "Invalid username or password.", 401

    # Start a fresh session after successful authentication.
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)

    security_logger.info("event=login_success")

    return redirect(url_for("dashboard"))


# --------------------------------------------------
# Protected dashboard
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if not user_id:
        return redirect(url_for("home"))

    with connect_db() as db:
        user = db.execute(
            "SELECT username FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("home"))

    return render_template_string(
        DASHBOARD_PAGE,
        username=user["username"],
        csrf_token=get_csrf_token(),
    )


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
def logout():
    check_csrf_token()

    was_logged_in = bool(session.get("user_id"))
    session.clear()

    if was_logged_in:
        security_logger.info("event=logout_success")

    flash("You have been logged out.")
    return redirect(url_for("home"))


# --------------------------------------------------
# Rate-limit error handler
# --------------------------------------------------

@app.errorhandler(429)
def too_many_requests(error):
    security_logger.warning(
        "event=rate_limit_triggered endpoint=%s",
        request.endpoint,
    )

    return "Too many attempts. Please try again later.", 429


# --------------------------------------------------
# Run the application
# --------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=False)
