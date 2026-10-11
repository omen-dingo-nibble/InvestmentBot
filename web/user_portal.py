"""User-facing investment portal for Gyokuro.

Users log in via a one-time link sent to them by the Telegram bot (/weblogin).
After the link is consumed the user_id is stored in the session.
All routes here are behind the `portal_login_required` decorator.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
    abort,
)

from database import get_db, Database

log = logging.getLogger(__name__)
portal = Blueprint("portal", __name__, url_prefix="/app")


# ---------------------------------------------------------------------------
# Root landing page — redirect / to user portal
# ---------------------------------------------------------------------------

from flask import Blueprint as _BP
root_bp = _BP("root", __name__)

@root_bp.route("/")
def root_index():
    """Default page: if user is logged in to portal → home, else → user portal login."""
    if "portal_user_id" in session:
        return redirect(url_for("portal.home"))
    return redirect(url_for("portal.portal_login_page"))


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def portal_login_required(f):
    import functools
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "portal_user_id" not in session:
            return redirect(url_for("portal.portal_login_page"))
        return f(*args, **kwargs)
    return decorated


def get_portal_user():
    uid = session.get("portal_user_id")
    if not uid:
        return None
    return get_db().get_user(uid)


# ---------------------------------------------------------------------------
# Login via one-time token (sent by bot)
# ---------------------------------------------------------------------------

@portal.route("/login")
def portal_login_page():
    """Show a landing page for users who haven't received their link yet."""
    if "portal_user_id" in session:
        return redirect(url_for("portal.home"))
    db = get_db()
    bot_username = db.get_setting("bot_username", "GyokuroBot")
    return render_template("portal/login.html", bot_username=bot_username)


@portal.route("/auth")
def portal_auth():
    """Consume a one-time token and create a portal session."""
    token = request.args.get("token", "").strip()
    if not token:
        flash("Invalid or missing login link.", "danger")
        return redirect(url_for("portal.portal_login_page"))

    db = get_db()
    user_id = db.consume_web_login_token(token)
    if not user_id:
        flash("This login link has expired or already been used. Use /weblogin in Telegram to get a new one.", "danger")
        return redirect(url_for("portal.portal_login_page"))

    user = db.get_user(user_id)
    if not user or user.get("is_banned"):
        flash("Your account is not accessible.", "danger")
        return redirect(url_for("portal.portal_login_page"))

    session.permanent = True
    session["portal_user_id"] = user_id
    session["portal_user_name"] = user.get("full_name") or user.get("username") or f"User {user_id}"

    db.log_user_session(
        user_id=user_id,
        action="web_login",
        ip_address=request.remote_addr,
        platform="web",
        details=f"Web portal login from {request.remote_addr}",
    )
    return redirect(url_for("portal.home"))


@portal.route("/logout")
def portal_logout():
    session.pop("portal_user_id", None)
    session.pop("portal_user_name", None)
    flash("You've been logged out.", "info")
    return redirect(url_for("portal.portal_login_page"))


# ---------------------------------------------------------------------------
# Home / Dashboard
# ---------------------------------------------------------------------------

@portal.route("/")
@portal_login_required
def home():
    db = get_db()
    user = get_portal_user()
    if not user:
        return redirect(url_for("portal.portal_logout"))

    # Active investments with live earnings
    investments = db.list_investments(user_id=user["user_id"], status="active", limit=10)
    for inv in investments:
        inv["_earned_today"] = db.compute_investment_earnings_to_date(inv)
        total = db.compute_investment_total_earnings(inv)
        inv["_progress_pct"] = min(100, int((inv["_earned_today"] / total * 100) if total > 0 else 0))
        inv["_days_left"] = max(0, int((inv["expires_at"] - int(time.time())) / 86400))

    # Recent transactions
    recent_tx = db.list_transactions(user_id=user["user_id"], limit=5)

    # Today's earnings (sum of earning txs today)
    today_start = int(datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    today_earnings_row = db.query_one(
        """SELECT COALESCE(SUM(amount), 0) AS v FROM transactions
           WHERE user_id = ? AND tx_type = 'earning'
           AND status = 'completed' AND created_at >= ?""",
        (user["user_id"], today_start),
    )
    today_earnings = float(today_earnings_row["v"] if today_earnings_row else 0)

    # Referral info
    ref_info = db.referral_stats(user["user_id"])

    # Settings
    min_wd = float(db.get_setting("min_withdrawal_usd", 5.0))
    signup_bonus = float(db.get_setting("signup_bonus_php", 50.0))

    # Announcement
    announcement = db.get_setting("welcome_message", "")
    ref_bonus_pct = float(db.get_setting("referral_bonus_percent", 5.0))

    # Bot username for links
    bot_username = db.get_setting("bot_username", "GyokuroBot")

    return render_template(
        "portal/home.html",
        user=user,
        investments=investments,
        recent_tx=recent_tx,
        today_earnings=today_earnings,
        ref_info=ref_info,
        min_wd=min_wd,
        signup_bonus=signup_bonus,
        announcement=announcement,
        ref_bonus_pct=ref_bonus_pct,
        bot_username=bot_username,
    )


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------

@portal.route("/plans")
@portal_login_required
def plans():
    db = get_db()
    user = get_portal_user()
    all_plans = db.list_plans(active_only=True)
    bot_username = db.get_setting("bot_username", "GyokuroBot")

    # Enrich with total return calculation
    for p in all_plans:
        p["_total_return"] = round(p["min_amount"] * p["daily_roi_percent"] / 100.0 * p["duration_days"], 2)
        p["_total_return_max"] = round(p["max_amount"] * p["daily_roi_percent"] / 100.0 * p["duration_days"], 2)

    return render_template("portal/plans.html", user=user, plans=all_plans, bot_username=bot_username)


# ---------------------------------------------------------------------------
# Rewards
# ---------------------------------------------------------------------------

@portal.route("/rewards")
@portal_login_required
def rewards():
    db = get_db()
    user = get_portal_user()

    ref_info = db.referral_stats(user["user_id"])
    ref_bonus_pct = float(db.get_setting("referral_bonus_percent", 5.0))
    bot_username = db.get_setting("bot_username", "GyokuroBot")

    # Check-in history (last 7 days of earning txs as proxy)
    today_start = int(datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    today_earnings_row = db.query_one(
        """SELECT COALESCE(SUM(amount), 0) AS v FROM transactions
           WHERE user_id = ? AND tx_type IN ('earning', 'referral')
           AND status = 'completed' AND created_at >= ?""",
        (user["user_id"], today_start),
    )
    today_earned = float(today_earnings_row["v"] if today_earnings_row else 0)

    # Count active investments
    active_inv_count = db.count_investments_for_user(user["user_id"], status="active")

    return render_template(
        "portal/rewards.html",
        user=user,
        ref_info=ref_info,
        ref_bonus_pct=ref_bonus_pct,
        bot_username=bot_username,
        today_earned=today_earned,
        active_inv_count=active_inv_count,
    )


# ---------------------------------------------------------------------------
# Invite / Referral
# ---------------------------------------------------------------------------

@portal.route("/invite")
@portal_login_required
def invite():
    db = get_db()
    user = get_portal_user()
    ref_info = db.referral_stats(user["user_id"])
    ref_bonus_pct = float(db.get_setting("referral_bonus_percent", 5.0))
    bot_username = db.get_setting("bot_username", "GyokuroBot")
    min_plan = db.list_plans(active_only=True)
    first_plan = min_plan[0] if min_plan else None

    return render_template(
        "portal/invite.html",
        user=user,
        ref_info=ref_info,
        ref_bonus_pct=ref_bonus_pct,
        bot_username=bot_username,
        first_plan=first_plan,
    )


# ---------------------------------------------------------------------------
# Me / Profile
# ---------------------------------------------------------------------------

@portal.route("/me")
@portal_login_required
def me():
    db = get_db()
    user = get_portal_user()

    # Enrich investments with live earnings (same as home)
    investments = db.list_investments(user_id=user["user_id"], limit=50)
    for inv in investments:
        inv["_earned_to_date"] = db.compute_investment_earnings_to_date(inv)
        total = db.compute_investment_total_earnings(inv)
        inv["_progress_pct"] = min(100, int((inv["_earned_to_date"] / total * 100) if total > 0 else 0))
        inv["_days_left"] = max(0, int((inv["expires_at"] - int(time.time())) / 86400))
        inv["_daily_earn"] = round(float(inv["principal"]) * float(inv["daily_roi_percent"]) / 100.0, 2)

    # Split by type for the wallet history tabs
    deposit_txs = db.list_transactions(user_id=user["user_id"], tx_type="deposit", limit=20)
    withdrawal_txs = db.list_transactions(user_id=user["user_id"], tx_type="withdrawal", limit=20)
    all_txs = db.list_transactions(user_id=user["user_id"], limit=30)

    ref_info = db.referral_stats(user["user_id"])
    min_wd = float(db.get_setting("min_withdrawal_usd", 5.0))
    min_dep = float(db.get_setting("min_deposit_usd", 500.0))
    bot_username = db.get_setting("bot_username", "GyokuroBot")
    support = db.get_setting("support_handle", "@GyokuroSupport")

    # Withdrawal readiness
    balance = float(user["balance"])
    wd_gap = max(0.0, min_wd - balance)
    wd_pct = min(100, int(balance / min_wd * 100)) if min_wd > 0 else 100

    return render_template(
        "portal/me.html",
        user=user,
        investments=investments,
        deposit_txs=deposit_txs,
        withdrawal_txs=withdrawal_txs,
        all_txs=all_txs,
        ref_info=ref_info,
        min_wd=min_wd,
        min_dep=min_dep,
        wd_gap=wd_gap,
        wd_pct=wd_pct,
        bot_username=bot_username,
        support=support,
    )


# ---------------------------------------------------------------------------
# API endpoints (for AJAX refreshes)
# ---------------------------------------------------------------------------

@portal.route("/api/balance")
@portal_login_required
def api_balance():
    db = get_db()
    user = get_portal_user()
    if not user:
        return jsonify({"error": "not found"}), 404
    ref_info = db.referral_stats(user["user_id"])
    investments = db.list_investments(user_id=user["user_id"], status="active", limit=20)
    live_earnings = sum(db.compute_investment_earnings_to_date(inv) for inv in investments)
    return jsonify({
        "balance": float(user["balance"]),
        "total_earned": float(user["total_earned"]),
        "total_invested": float(user["total_invested"]),
        "total_deposited": float(user["total_deposited"]),
        "total_withdrawn": float(user["total_withdrawn"]),
        "referral_bonus": float(ref_info["bonus"]),
        "live_earnings": round(live_earnings, 2),
        "active_investments": len(investments),
    })


@portal.route("/api/investments")
@portal_login_required
def api_investments():
    db = get_db()
    user = get_portal_user()
    if not user:
        return jsonify({"error": "not found"}), 404
    investments = db.list_investments(user_id=user["user_id"], status="active", limit=20)
    result = []
    for inv in investments:
        earned = db.compute_investment_earnings_to_date(inv)
        total = db.compute_investment_total_earnings(inv)
        result.append({
            "id": inv["id"],
            "plan_name": inv["plan_name"],
            "principal": float(inv["principal"]),
            "daily_roi_percent": float(inv["daily_roi_percent"]),
            "earned_to_date": round(earned, 2),
            "total_earnings": round(total, 2),
            "progress_pct": min(100, int(earned / total * 100) if total > 0 else 0),
            "days_left": max(0, int((inv["expires_at"] - int(time.time())) / 86400)),
            "status": inv["status"],
        })
    return jsonify(result)
