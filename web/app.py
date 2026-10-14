"""Flask web admin panel for TGInvestmentBot.

Security hardened:
  - Security headers on every response (CSP, X-Frame-Options, HSTS, etc.)
  - Rate limiting on auth and mutation endpoints (flask-limiter)
  - Session cookie hardening (HttpOnly, SameSite=Lax, Secure flag configurable)
  - CSRF double-submit cookie on all state-changing POSTs
  - Input length limits + sanitisation helpers
  - Constant-time password comparison
  - Referrer / origin check on sensitive admin POSTs
  - Withdrawal race-condition fix (atomic DB check)

Run standalone for development:
    python -m web.app

In production, start alongside the bot from bot.py.
"""
from __future__ import annotations

import hashlib
import hmac
import functools
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from flask import (
    Flask,
    abort,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import get_db

log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Rate limiter — uses Redis on Railway (REDIS_URL env var), memory fallback
# ---------------------------------------------------------------------------

def _make_storage_uri() -> str:
    """Return Redis URI if available (Railway injects REDIS_URL), else memory."""
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if redis_url:
        log.info("Rate limiter: using Redis at %s", redis_url[:30] + "…")
        return redis_url
    return "memory://"


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],          # no global limit; apply selectively per route
    storage_uri=_make_storage_uri(),
    strategy="fixed-window",
)

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

# Patterns for basic input sanity
_PHONE_RE = re.compile(r"^\+?[\d\s\-\(\)\.]{7,20}$")
_SAFE_TEXT_RE = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]{0,500}$")


def _is_safe_text(value: str, max_len: int = 500) -> bool:
    """Return True if text contains no control characters and is within length."""
    if len(value) > max_len:
        return False
    return bool(_SAFE_TEXT_RE.match(value))


def _sanitize(value: Optional[str], max_len: int = 500) -> str:
    """Strip leading/trailing whitespace and truncate to max_len."""
    if not value:
        return ""
    return str(value).strip()[:max_len]


def _csrf_token() -> str:
    """Return (and store) the per-session CSRF token."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


def _validate_csrf() -> bool:
    """
    Validate CSRF token submitted via form field '_csrf_token' or
    X-CSRFToken header against the session token.
    Skips validation for GET / HEAD / OPTIONS / TRACE (safe methods).
    """
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return True
    token = (
        request.form.get("_csrf_token")
        or request.headers.get("X-CSRFToken")
        or ""
    )
    expected = session.get("_csrf", "")
    if not expected or not token:
        return False
    # Constant-time comparison
    return hmac.compare_digest(expected, token)


def csrf_protect(f):
    """Decorator: validate CSRF token, return 403 on failure."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not _validate_csrf():
            log.warning(
                "CSRF check failed: %s %s from %s",
                request.method, request.path, request.remote_addr,
            )
            abort(403, "CSRF validation failed.")
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    # ── Secret key — MUST be set via env var in production ──────────
    secret = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if not secret:
        secret = secrets.token_hex(32)
        log.warning(
            "FLASK_SECRET_KEY not set — using a per-process random key. "
            "Sessions will be invalidated on every restart. "
            "Set FLASK_SECRET_KEY in your .env file."
        )
    app.secret_key = secret

    # ── Railway / reverse-proxy trust ───────────────────────────────
    # Railway terminates TLS at the edge and forwards requests over HTTP
    # internally. Trust one hop of X-Forwarded-For / X-Forwarded-Proto
    # so rate-limiter IPs and url_for() scheme are correct.
    _on_railway = bool(os.environ.get("RAILWAY_ENVIRONMENT", "").strip())
    if _on_railway or os.environ.get("TRUST_PROXY", "").lower() in ("1", "true", "yes"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
        log.info("ProxyFix enabled (Railway / reverse-proxy mode)")

    # Auto-enable Secure cookies when behind Railway HTTPS proxy
    _is_https = (
        _on_railway
        or os.environ.get("SESSION_COOKIE_SECURE", "").lower() == "true"
        or os.environ.get("HTTPS", "").lower() in ("1", "true", "on")
    )

    # ── Session cookie hardening ─────────────────────────────────────
    app.config.update(
        PERMANENT_SESSION_LIFETIME=86400,           # 24 hours
        SESSION_COOKIE_HTTPONLY=True,               # no JS access
        SESSION_COOKIE_SAMESITE="Lax",              # CSRF mitigation
        SESSION_COOKIE_SECURE=_is_https,            # auto-true on Railway
        SESSION_COOKIE_NAME="gyo_sess",             # avoid default "session"
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,        # 16 MB max upload
    )

    # ── Rate limiter ─────────────────────────────────────────────────
    limiter.init_app(app)

    # ── Allow negative integers in URL routes ────────────────────────
    from werkzeug.routing import IntegerConverter
    class SignedIntConverter(IntegerConverter):
        regex = r"-?\d+"
        num_convert = int
    app.url_map.converters["sint"] = SignedIntConverter

    # ── Register blueprints ──────────────────────────────────────────
    from web.routes import bp
    app.register_blueprint(bp)

    from web.user_portal import portal, root_bp
    app.register_blueprint(portal)
    app.register_blueprint(root_bp)

    # ── Security headers on every response ──────────────────────────
    @app.after_request
    def set_security_headers(response):
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # XSS filter (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Referrer policy — don't leak URL to third parties
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissions policy — disable unnecessary browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=()"
        )
        # Content-Security-Policy
        # — allows same-origin scripts/styles + Google Fonts + Bootstrap CDN
        # — blocks inline eval() and object embeds
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        # HSTS — Railway always serves HTTPS; enable when secure flag is on
        if _is_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        # Remove server fingerprint
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response

    # ── Inject CSRF token + globals into all templates ───────────────
    @app.context_processor
    def inject_globals():
        from config import BRAND_NAME, BRAND_TAGLINE, BRAND_WEBSITE
        return {
            "now": datetime.now(timezone.utc),
            "app_name": BRAND_NAME,
            "brand_tagline": BRAND_TAGLINE,
            "brand_website": BRAND_WEBSITE,
            "csrf_token": _csrf_token,          # callable — use {{ csrf_token() }}
        }

    # ── Template filters ─────────────────────────────────────────────
    @app.template_filter("ts_to_date")
    def ts_to_date(ts):
        if not ts:
            return "-"
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    @app.template_filter("ts_to_input_val")
    def ts_to_input_val(ts):
        if not ts:
            return ""
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M")

    @app.template_filter("money")
    def money_filter(amount, currency="PHP"):
        if amount is None:
            amount = 0
        sign = "-" if amount < 0 else ""
        return f"{sign}₱{abs(float(amount)):,.2f}"

    @app.template_filter("money_php")
    def money_php_filter(amount):
        return money_filter(amount)

    @app.template_filter("timeago")
    def timeago_filter(ts):
        if not ts:
            return "never"
        diff = int(time.time()) - int(ts)
        if diff < 60:
            return "just now"
        if diff < 3600:
            return f"{diff // 60}m ago"
        if diff < 86400:
            return f"{diff // 3600}h ago"
        return f"{diff // 86400}d ago"

    @app.template_filter("abs")
    def abs_filter(n):
        try:
            return abs(float(n))
        except (TypeError, ValueError):
            return 0

    # ── Rate-limit error handler ─────────────────────────────────────
    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path.startswith("/app/"):
            return render_template(
                "portal/login.html",
                bot_username="GyokuroBot",
                error="Too many requests. Please wait a minute and try again.",
                mode="login",
            ), 429
        return render_template("login.html", error="Too many requests. Try again shortly."), 429

    # ── Generic error handlers ───────────────────────────────────────
    @app.errorhandler(403)
    def forbidden_handler(e):
        log.warning("403 Forbidden: %s %s from %s — %s",
                    request.method, request.path, request.remote_addr, e)
        if request.path.startswith("/app/"):
            return render_template(
                "portal/login.html",
                bot_username="GyokuroBot",
                error="Access denied. Please try again.",
                mode="login",
            ), 403
        return render_template("login.html", error="Access denied. Please try again."), 403

    @app.errorhandler(404)
    def not_found_handler(e):
        if request.path.startswith("/app/"):
            return render_template(
                "portal/login.html",
                bot_username="GyokuroBot",
                error="Page not found.",
                mode="login",
            ), 404
        return render_template("login.html", error="Page not found."), 404

    @app.errorhandler(500)
    def server_error_handler(e):
        log.exception("500 Internal Server Error: %s %s from %s",
                      request.method, request.path, request.remote_addr)
        if request.path.startswith("/app/"):
            return render_template(
                "portal/login.html",
                bot_username="GyokuroBot",
                error="An unexpected error occurred. Please try again.",
                mode="login",
            ), 500
        return render_template("login.html", error="An unexpected error occurred. Please try again."), 500

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        log.exception("Unhandled exception: %s %s from %s — %s",
                      request.method, request.path, request.remote_addr, e)
        if request.path.startswith("/app/"):
            return render_template(
                "portal/login.html",
                bot_username="GyokuroBot",
                error="An unexpected error occurred. Please try again.",
                mode="login",
            ), 500
        return render_template("login.html", error="An unexpected error occurred. Please try again."), 500

    return app


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

SALT = b"tginvestbot_salt_v1"


def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100_000).hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    computed = hash_password(password)
    return hmac.compare_digest(computed, stored_hash)


def login_required(f):
    """Redirect to admin login if session lacks admin_id."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("main.login"))
        return f(*args, **kwargs)
    return decorated


def get_current_admin() -> Optional[dict]:
    admin_id = session.get("admin_id")
    if not admin_id:
        return None
    # Cache in request context (g) to avoid redundant DB hits
    if not hasattr(g, "_current_admin"):
        g._current_admin = get_db().get_web_admin_by_id(admin_id)
    return g._current_admin


# ---------------------------------------------------------------------------
# Public limiter shortcuts (imported by routes.py and user_portal.py)
# ---------------------------------------------------------------------------

def make_limiter():
    """Return the module-level limiter so blueprints can decorate routes."""
    return limiter


# ---------------------------------------------------------------------------
# Standalone run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
