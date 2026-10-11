"""Flask web admin panel for TGInvestmentBot.

Provides a full-featured admin dashboard to manage the bot without Telegram,
configure API keys and wallets, view user profiles with security data, and
handle deposits/withdrawals.

Run standalone for development:
    python -m web.app

In production, it's started alongside the bot from bot.py.
"""
from __future__ import annotations

import hashlib
import functools
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)

from database import get_db

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
    app.config["PERMANENT_SESSION_LIFETIME"] = 86400  # 24 hours

    # Register blueprints
    from web.routes import bp
    app.register_blueprint(bp)

    from web.user_portal import portal
    app.register_blueprint(portal)

    # Context processors
    @app.context_processor
    def inject_globals():
        from config import BRAND_NAME, BRAND_TAGLINE, BRAND_WEBSITE
        return {
            "now": datetime.now(timezone.utc),
            "app_name": BRAND_NAME,
            "brand_tagline": BRAND_TAGLINE,
            "brand_website": BRAND_WEBSITE,
        }
    # Template filters
    @app.template_filter("ts_to_date")
    def ts_to_date(ts):
        if not ts:
            return "-"
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

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

    return app


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

SALT = b"tginvestbot_salt_v1"


def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()


def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash


def login_required(f):
    """Decorator that redirects to login if not authenticated."""
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
    return get_db().get_web_admin_by_id(admin_id)


# ---------------------------------------------------------------------------
# Standalone run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
