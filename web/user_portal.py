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
    current_app,
)

from database import get_db, Database
from web.app import csrf_protect, limiter, _sanitize

log = logging.getLogger(__name__)
portal = Blueprint("portal", __name__, url_prefix="/app")


# ---------------------------------------------------------------------------
# Async Telegram admin notification (fire-and-forget via bot token)
# ---------------------------------------------------------------------------

def _notify_admins_async(message: str, parse_mode: str = "Markdown") -> None:
    """Send a Telegram message to all configured admin IDs in a background
    thread so it never blocks the web request.  Uses the bot token from DB
    settings (falls back to CONFIG.bot_token)."""
    import threading

    def _send():
        try:
            import urllib.request
            import urllib.parse
            from config import CONFIG
            db = get_db()
            token = db.get_setting("bot_token", "") or CONFIG.bot_token
            if not token:
                return
            admin_ids = CONFIG.admin_ids or []
            # Also read admin IDs from settings (comma-separated)
            setting_ids_raw = db.get_setting("admin_ids", "")
            if setting_ids_raw:
                try:
                    extra = [int(x.strip()) for x in str(setting_ids_raw).replace(";", ",").split(",") if x.strip().lstrip("-").isdigit()]
                    admin_ids = list(set(list(admin_ids) + extra))
                except Exception:
                    pass
            for admin_id in admin_ids:
                try:
                    params = urllib.parse.urlencode({
                        "chat_id": admin_id,
                        "text": message,
                        "parse_mode": parse_mode,
                    }).encode()
                    req = urllib.request.Request(
                        f"https://api.telegram.org/bot{token}/sendMessage",
                        data=params,
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=8):
                        pass
                except Exception as e:
                    log.debug("Admin notify failed for %s: %s", admin_id, e)
        except Exception as e:
            log.debug("_notify_admins_async error: %s", e)

    threading.Thread(target=_send, daemon=True).start()



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
        # Maintenance mode — block portal actions but not the login page itself
        db = get_db()
        if db.get_setting("maintenance_mode", False):
            return render_template(
                "portal/login.html",
                bot_username=db.get_setting("bot_username", "GyokuroBot"),
                error="The platform is currently under maintenance. Please check back soon.",
                mode="login",
            ), 503
        return f(*args, **kwargs)
    return decorated


def get_portal_user():
    uid = session.get("portal_user_id")
    if not uid:
        return None
    user = get_db().get_user(uid)
    if user and user.get("is_influencer"):
        # Overlay the display balance so the portal shows the fake amount.
        # We clone the dict to avoid mutating the cached row.
        user = dict(user)
        user["balance"] = float(user.get("influencer_display_balance") or 10000.0)
    return user


# ---------------------------------------------------------------------------
# Login — phone+password OR one-time token (sent by bot)
# ---------------------------------------------------------------------------

@portal.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per minute; 60 per hour", error_message="Too many login attempts.")
def portal_login_page():
    if "portal_user_id" in session:
        return redirect(url_for("portal.home"))

    db = get_db()
    bot_username = db.get_setting("bot_username", "GyokuroBot")
    error = None

    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        if not phone or not password:
            error = "Please enter your phone number and password."
        else:
            user = db.verify_phone_password(phone, password)
            if not user:
                error = "Incorrect phone number or password."
                # Don't log failed attempts with user_id=0 (FK violation).
                # Just continue — no session log for unknown users.
            elif user.get("is_banned"):
                error = "Your account has been suspended. Contact support."
            else:
                session.permanent = True
                session["portal_user_id"] = user["user_id"]
                session["portal_user_name"] = (
                    user.get("full_name") or user.get("username") or phone
                )
                db.log_user_session(
                    user_id=user["user_id"],
                    action="phone_login",
                    ip_address=request.remote_addr,
                    platform="web",
                    details=f"Phone login from {request.remote_addr}",
                )
                return redirect(url_for("portal.home"))

    return render_template("portal/login.html",
                           bot_username=bot_username,
                           error=error,
                           mode="login")


@portal.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour", error_message="Too many registrations from this IP.")
def portal_register():
    if "portal_user_id" in session:
        return redirect(url_for("portal.home"))

    db = get_db()
    bot_username = db.get_setting("bot_username", "GyokuroBot")
    error = None
    success = None

    # Accept ?ref= from web mirror invite links (same as ?start=ref_<code> in Telegram)
    ref_code_from_url = request.args.get("ref", "").strip()

    if request.method == "POST":
        # The form submits a hidden 'phone' field built by JS (prefix + number).
        # Fall back to combining prefix + phone_number when JS is disabled.
        phone = request.form.get("phone", "").strip()
        if not phone:
            prefix = request.form.get("phone_prefix", "+63").strip()
            number = request.form.get("phone_number", "").strip().lstrip("0")
            if number:
                phone = prefix + number

        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        # ref_code can come from form field or URL param
        ref_code = request.form.get("ref_code", "").strip() or ref_code_from_url

        if not phone or not password:
            error = "Phone number and password are required."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            try:
                user = db.register_phone_user(
                    phone=phone,
                    password=password,
                    full_name=full_name,
                    referral_code_used=ref_code or None,
                )
                # Grant signup bonus
                signup_bonus = float(db.get_setting("signup_bonus_php", 50))
                if signup_bonus > 0:
                    db.grant_signup_bonus(user["user_id"], signup_bonus)

                session.permanent = True
                session["portal_user_id"] = user["user_id"]
                session["portal_user_name"] = full_name or phone
                db.log_user_session(
                    user_id=user["user_id"],
                    action="phone_register",
                    ip_address=request.remote_addr,
                    platform="web",
                    details=f"New phone registration from {request.remote_addr}",
                )
                return redirect(url_for("portal.home"))
            except ValueError as e:
                if "phone_taken" in str(e):
                    error = "This phone number is already registered. Please sign in."
                else:
                    error = "Registration failed. Please try again."

    return render_template("portal/login.html",
                           bot_username=bot_username,
                           error=error,
                           mode="register",
                           ref_code=request.form.get("ref_code", ref_code_from_url))


@portal.route("/auth")
@limiter.limit("20 per minute", error_message="Too many token attempts.")
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


@portal.route("/change-password", methods=["POST"])
@portal_login_required
@csrf_protect
def change_password():
    user = get_portal_user()
    db = get_db()
    current = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if not user.get("password_hash"):
        flash("No password set on this account yet.", "danger")
    elif db.verify_phone_password(user["phone"] or "", current) is None:
        # Also check via direct hash compare for safety
        from database import Database as _DB
        if user["password_hash"] != _DB._hash_password(current):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("portal.me"))
    if new_pw and len(new_pw) < 6:
        flash("New password must be at least 6 characters.", "danger")
    elif new_pw and new_pw != confirm:
        flash("New passwords do not match.", "danger")
    elif new_pw:
        db.update_user_password(user["user_id"], new_pw)
        flash("Password updated successfully.", "success")

    return redirect(url_for("portal.me"))


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
# Invest — buy a plan directly from the web portal
# ---------------------------------------------------------------------------

@portal.route("/invest", methods=["GET", "POST"])
@portal_login_required
@csrf_protect
def invest():
    db = get_db()
    user = get_portal_user()
    fresh_user = db.get_user(user["user_id"])
    real_balance = float(fresh_user["balance"]) if fresh_user else 0.0
    bot_username = db.get_setting("bot_username", "GyokuroBot")
    all_plans = db.list_plans(active_only=True)

    # Enrich plans
    for p in all_plans:
        p["_total_return"] = round(p["min_amount"] * p["daily_roi_percent"] / 100.0 * p["duration_days"], 2)
        p["_total_return_max"] = round(p["max_amount"] * p["daily_roi_percent"] / 100.0 * p["duration_days"], 2)

    # Pre-select plan from query string (e.g. ?plan_id=3)
    preselect_id = request.args.get("plan_id", type=int)
    selected_plan = None
    if preselect_id:
        selected_plan = next((p for p in all_plans if p["id"] == preselect_id), None)

    error = None
    success = None
    confirm_data = None  # dict shown in the confirm step

    if request.method == "POST":
        step = request.form.get("step", "select")

        if step == "select":
            # User chose a plan and entered an amount — show confirm screen
            plan_id = request.form.get("plan_id", type=int)
            amount_str = request.form.get("amount", "").strip()
            selected_plan = next((p for p in all_plans if p["id"] == plan_id), None)

            if not selected_plan:
                error = "Plan not found. Please select a valid plan."
            elif not amount_str:
                error = "Please enter the amount you want to invest."
            else:
                try:
                    amount_val = float(amount_str)
                    if amount_val <= 0:
                        error = "Amount must be positive."
                    elif amount_val < selected_plan["min_amount"]:
                        error = f"Minimum for this plan is ₱{selected_plan['min_amount']:,.2f}."
                    elif amount_val > selected_plan["max_amount"]:
                        error = f"Maximum for this plan is ₱{selected_plan['max_amount']:,.2f}."
                    elif amount_val > real_balance:
                        error = f"Insufficient balance. Your balance is ₱{real_balance:,.2f}."
                    else:
                        # Show confirm step
                        total_return = round(amount_val * selected_plan["daily_roi_percent"] / 100.0 * selected_plan["duration_days"], 2)
                        daily_earn = round(amount_val * selected_plan["daily_roi_percent"] / 100.0, 2)
                        confirm_data = {
                            "plan_id": selected_plan["id"],
                            "plan_name": selected_plan["name"],
                            "amount": amount_val,
                            "daily_roi_percent": selected_plan["daily_roi_percent"],
                            "duration_days": selected_plan["duration_days"],
                            "capital_return": selected_plan["capital_return"],
                            "daily_earn": daily_earn,
                            "total_return": total_return,
                        }
                except (ValueError, TypeError):
                    error = "Please enter a valid amount."

        elif step == "confirm":
            # User confirmed — execute the investment
            plan_id = request.form.get("plan_id", type=int)
            amount_str = request.form.get("amount", "").strip()
            selected_plan = next((p for p in all_plans if p["id"] == plan_id), None)

            if not selected_plan:
                error = "Plan not found."
            elif not amount_str:
                error = "Invalid investment data."
            else:
                try:
                    amount_val = float(amount_str)
                    # Re-validate everything server-side (never trust form hidden fields)
                    fresh_user = db.get_user(user["user_id"])
                    real_balance = float(fresh_user["balance"]) if fresh_user else 0.0

                    if amount_val <= 0:
                        error = "Amount must be positive."
                    elif amount_val < selected_plan["min_amount"]:
                        error = f"Minimum for this plan is ₱{selected_plan['min_amount']:,.2f}."
                    elif amount_val > selected_plan["max_amount"]:
                        error = f"Maximum for this plan is ₱{selected_plan['max_amount']:,.2f}."
                    elif amount_val > real_balance:
                        error = f"Insufficient balance. Your balance is ₱{real_balance:,.2f}."
                    else:
                        inv = db.create_investment(user["user_id"], selected_plan, amount_val)
                        db.log_user_session(
                            user_id=user["user_id"],
                            action="invest_web",
                            ip_address=request.remote_addr,
                            platform="web",
                            details=f"Invested ₱{amount_val:.2f} in {selected_plan['name']}, inv_id={inv['id']}",
                        )
                        # Check if balance was actually deducted (insufficient balance guard)
                        after = db.get_user(user["user_id"])
                        if after and abs(float(after["balance"]) - (real_balance - amount_val)) > 0.01:
                            error = "Investment failed — insufficient balance. Please try again."
                        else:
                            total_return = round(amount_val * selected_plan["daily_roi_percent"] / 100.0 * selected_plan["duration_days"], 2)
                            # Notify Telegram admins
                            _notify_admins_async(
                                f"📈 *New web investment* `#{inv['id']}`\n\n"
                                f"User: `{user['user_id']}` {user.get('full_name') or user.get('username') or ''}\n"
                                f"Plan: *{selected_plan['name']}*\n"
                                f"Amount: *₱{amount_val:,.2f}*\n"
                                f"Daily ROI: {selected_plan['daily_roi_percent']}% × {selected_plan['duration_days']}d\n"
                                f"Expected return: ₱{total_return:,.2f}\n"
                                f"Source: 🌐 Web Portal"
                            )
                            success = (
                                f"✅ Investment #{inv['id']} created! "
                                f"₱{amount_val:,.2f} in {selected_plan['name']} is now active. "
                                f"You'll earn ₱{round(amount_val * selected_plan['daily_roi_percent'] / 100, 2):,.2f}/day."
                            )
                            selected_plan = None  # clear so we go back to plan list

                except (ValueError, TypeError):
                    error = "Please enter a valid amount."

    return render_template(
        "portal/invest.html",
        user=user,
        plans=all_plans,
        selected_plan=selected_plan,
        real_balance=real_balance,
        bot_username=bot_username,
        error=error,
        success=success,
        confirm_data=confirm_data,
    )


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

    # Build multi-mirror invite links
    # Telegram bot link (always present)
    tg_link = f"https://t.me/{bot_username}?start=ref_{user['referral_code']}"

    # Web mirror links: read comma-separated site_urls setting
    # e.g. "https://gyokuro.app,https://mirror1.gyokuro.com,https://gyokuro.io"
    site_urls_raw = db.get_setting("site_urls", "").strip()
    web_mirror_links = []
    if site_urls_raw:
        for raw_url in site_urls_raw.replace("\n", ",").split(","):
            url = raw_url.strip().rstrip("/")
            if url:
                web_mirror_links.append({
                    "label": url.replace("https://", "").replace("http://", ""),
                    "url": f"{url}/app/register?ref={user['referral_code']}",
                })

    # Also include the current request host as a mirror if not already listed
    current_origin = request.host_url.rstrip("/")
    current_label = request.host
    if current_origin and not any(m["url"].startswith(current_origin) for m in web_mirror_links):
        web_mirror_links.insert(0, {
            "label": current_label,
            "url": f"{current_origin}/app/register?ref={user['referral_code']}",
        })

    return render_template(
        "portal/invite.html",
        user=user,
        ref_info=ref_info,
        ref_bonus_pct=ref_bonus_pct,
        bot_username=bot_username,
        first_plan=first_plan,
        tg_link=tg_link,
        web_mirror_links=web_mirror_links,
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
    user = get_portal_user()   # already applies influencer display balance override
    if not user:
        return jsonify({"error": "not found"}), 404
    ref_info = db.referral_stats(user["user_id"])
    investments = db.list_investments(user_id=user["user_id"], status="active", limit=20)
    live_earnings = sum(db.compute_investment_earnings_to_date(inv) for inv in investments)
    return jsonify({
        "balance": float(user["balance"]),   # display balance for influencers
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


# ---------------------------------------------------------------------------
# Deposit — web form (shows wallet addresses + lets user record a tx hash)
# ---------------------------------------------------------------------------

@portal.route("/deposit", methods=["GET", "POST"])
@portal_login_required
@csrf_protect
def deposit():
    db = get_db()
    user = get_portal_user()
    bot_username = db.get_setting("bot_username", "GyokuroBot")

    # Fetch wallet addresses and QR codes
    crypto_wallets = {
        "BTC": {
            "address": db.get_setting("crypto_btc_address", ""),
            "qr": db.get_setting("qr_btc", ""),
            "label": "Bitcoin (BTC)",
            "icon": "₿",
        },
        "ETH": {
            "address": db.get_setting("crypto_eth_address", ""),
            "qr": db.get_setting("qr_eth", ""),
            "label": "Ethereum (ETH)",
            "icon": "Ξ",
        },
        "USDT-TRC20": {
            "address": db.get_setting("crypto_usdt_trc20_address", ""),
            "qr": db.get_setting("qr_usdt_trc20", ""),
            "label": "USDT (TRC-20 / Tron)",
            "icon": "₮",
        },
        "USDT-ERC20": {
            "address": db.get_setting("crypto_usdt_erc20_address", ""),
            "qr": db.get_setting("qr_usdt_erc20", ""),
            "label": "USDT (ERC-20 / Ethereum)",
            "icon": "₮",
        },
        "LTC": {
            "address": db.get_setting("crypto_ltc_address", ""),
            "qr": db.get_setting("qr_ltc", ""),
            "label": "Litecoin (LTC)",
            "icon": "Ł",
        },
    }
    # Only show wallets that have an address configured
    active_wallets = {k: v for k, v in crypto_wallets.items() if v["address"]}

    min_dep = float(db.get_setting("min_deposit_usd", 10.0))
    usd_rate = float(db.get_setting("usd_to_php_rate", 56.0))
    min_dep_php = round(min_dep * usd_rate, 2)

    error = None
    success = None

    if request.method == "POST":
        crypto = request.form.get("crypto_currency", "").strip().upper()
        tx_hash = request.form.get("tx_hash", "").strip()
        amount_php = request.form.get("amount_php", "").strip()
        note = request.form.get("note", "").strip()

        if not crypto or crypto not in active_wallets:
            error = "Please select a valid payment method."
        elif not amount_php:
            error = "Please enter the amount you sent."
        else:
            try:
                amount_val = float(amount_php)
                if amount_val < min_dep_php:
                    error = f"Minimum deposit is ₱{min_dep_php:,.2f}."
                else:
                    tx_id = db.create_transaction(
                        user_id=user["user_id"],
                        tx_type="deposit",
                        amount=amount_val,
                        currency="PHP",
                        crypto_currency=crypto,
                        wallet_address=active_wallets[crypto]["address"],
                        tx_hash=tx_hash or None,
                        note=note or f"Web deposit via {crypto}",
                    )
                    db.log_user_session(
                        user_id=user["user_id"],
                        action="deposit_submitted",
                        ip_address=request.remote_addr,
                        platform="web",
                        details=f"Deposit ₱{amount_val:.2f} via {crypto}, tx_id={tx_id}",
                    )
                    # Notify Telegram admins about the new web deposit
                    _notify_admins_async(
                        f"💰 *New web deposit request* `#{tx_id}`\n\n"
                        f"User: `{user['user_id']}` {user.get('full_name') or user.get('username') or ''}\n"
                        f"Amount: *₱{amount_val:,.2f}*\n"
                        f"Crypto: {crypto}\n"
                        f"TX hash: `{tx_hash or '-'}`\n"
                        f"Source: 🌐 Web Portal"
                    )
                    success = (
                        f"Deposit of ₱{amount_val:,.2f} submitted (#{tx_id}). "
                        f"Our team will verify and credit your balance within 30 minutes."
                    )
            except (ValueError, TypeError):
                error = "Please enter a valid amount."

    return render_template(
        "portal/deposit.html",
        user=user,
        bot_username=bot_username,
        active_wallets=active_wallets,
        min_dep=min_dep,
        min_dep_php=min_dep_php,
        error=error,
        success=success,
    )


# ---------------------------------------------------------------------------
# Withdrawal request — web form
# ---------------------------------------------------------------------------

@portal.route("/withdraw", methods=["GET", "POST"])
@portal_login_required
@csrf_protect
def withdraw():
    db = get_db()
    user = get_portal_user()
    bot_username = db.get_setting("bot_username", "GyokuroBot")

    min_wd = float(db.get_setting("min_withdrawal_usd", 5.0))
    usd_rate = float(db.get_setting("usd_to_php_rate", 56.0))
    min_wd_php = round(min_wd * usd_rate, 2)
    # Re-fetch balance fresh from DB to avoid stale session data
    fresh_user = db.get_user(user["user_id"])
    balance = float(fresh_user["balance"]) if fresh_user else 0.0
    # For influencer accounts show the display balance on the page,
    # but enforce the REAL balance for the actual withdrawal check.
    real_balance = balance
    if fresh_user and fresh_user.get("is_influencer"):
        balance = float(fresh_user.get("influencer_display_balance") or 10000.0)
    # (real_balance stays as the actual DB balance in both cases)

    error = None
    success = None

    if request.method == "POST":
        amount_str = request.form.get("amount", "").strip()
        wallet_addr = _sanitize(request.form.get("wallet_address", ""), max_len=200)
        crypto = _sanitize(request.form.get("crypto_currency", ""), max_len=20).upper()

        if not amount_str or not wallet_addr or not crypto:
            error = "All fields are required."
        elif not wallet_addr or len(wallet_addr) < 10:
            error = "Please enter a valid wallet address."
        else:
            try:
                amount_val = float(amount_str)
                if amount_val <= 0:
                    error = "Amount must be positive."
                elif amount_val < min_wd_php:
                    error = f"Minimum withdrawal is ₱{min_wd_php:,.2f}."
                elif amount_val > real_balance:
                    error = f"Insufficient balance. Your balance is ₱{balance:,.2f}."
                else:
                    # Atomic deduct — update_balance returns None if it would go negative
                    updated = db.update_balance(user["user_id"], -amount_val)
                    if updated is None:
                        error = "Insufficient balance (concurrent request detected)."
                    else:
                        tx_id = db.create_transaction(
                            user_id=user["user_id"],
                            tx_type="withdrawal",
                            amount=-amount_val,
                            currency="PHP",
                            crypto_currency=crypto,
                            wallet_address=wallet_addr,
                            note=f"Web withdrawal request to {wallet_addr[:16]}…",
                        )
                        db.log_user_session(
                            user_id=user["user_id"],
                            action="withdrawal_submitted",
                            ip_address=request.remote_addr,
                            platform="web",
                            details=f"Withdrawal ₱{amount_val:.2f} via {crypto}, tx_id={tx_id}",
                        )
                        success = (
                            f"Withdrawal of ₱{amount_val:,.2f} submitted (#{tx_id}). "
                            f"It will be processed within 24 hours."
                        )
                        # Refresh balance for template
                        fresh_user = db.get_user(user["user_id"])
                        balance = float(fresh_user["balance"]) if fresh_user else 0.0
            except (ValueError, TypeError):
                error = "Please enter a valid amount."

    return render_template(
        "portal/withdraw.html",
        user=fresh_user or user,
        bot_username=bot_username,
        min_wd=min_wd,
        min_wd_php=min_wd_php,
        balance=balance,
        error=error,
        success=success,
    )
