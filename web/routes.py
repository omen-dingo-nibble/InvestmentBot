"""Web admin routes for High Caliber Construction NW."""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any
from werkzeug.utils import secure_filename

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
    send_from_directory,
)

from database import get_db
from web.app import (
    get_current_admin,
    hash_password,
    login_required,
    verify_password,
)

log = logging.getLogger(__name__)
bp = Blueprint("main", __name__)

BASE_DIR = Path(__file__).resolve().parent
QR_DIR = BASE_DIR / "static" / "qr"
QR_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp"}


def _save_qr(file_field_name: str) -> str | None:
    """Save a QR image upload and return the filename, or None if no upload."""
    f = request.files.get(file_field_name)
    if not f or not f.filename:
        return None
    ext = Path(f.filename).suffix.lower()
    if ext not in ALLOWED_IMAGE_EXT:
        return None
    filename = secure_filename(f"{file_field_name}{ext}")
    f.save(QR_DIR / filename)
    return filename


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@bp.route("/login", methods=["GET", "POST"])
def login():
    if "admin_id" in session:
        return redirect(url_for("main.dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        admin = db.get_web_admin(username)
        if admin and verify_password(password, admin["password"]):
            session.permanent = True
            session["admin_id"] = admin["id"]
            session["admin_name"] = admin["display_name"] or admin["username"]
            db.update_web_admin_login(admin["id"])
            db.log_audit(
                action="login",
                admin_id=admin["id"],
                admin_name=admin["username"],
                ip_address=request.remote_addr,
                details=f"Web panel login from {request.remote_addr}",
            )
            flash("Welcome back!", "success")
            return redirect(url_for("main.dashboard"))
        error = "Invalid username or password"
        db.log_audit(
            action="login_failed",
            admin_name=username,
            ip_address=request.remote_addr,
            details=f"Failed login attempt for '{username}'",
        )
    return render_template("login.html", error=error)


@bp.route("/logout")
def logout():
    admin_id = session.get("admin_id")
    if admin_id:
        db = get_db()
        db.log_audit(
            action="logout",
            admin_id=admin_id,
            admin_name=session.get("admin_name"),
            ip_address=request.remote_addr,
        )
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("main.login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@bp.route("/")
@login_required
def dashboard():
    db = get_db()
    stats = db.admin_stats()
    recent_deposits = db.list_transactions(tx_type="deposit", status="pending", limit=5)
    recent_withdrawals = db.list_transactions(tx_type="withdrawal", status="pending", limit=5)
    recent_logs = db.list_audit_logs(limit=10)
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_deposits=recent_deposits,
        recent_withdrawals=recent_withdrawals,
        recent_logs=recent_logs,
        admin=get_current_admin(),
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@bp.route("/users")
@login_required
def users():
    db = get_db()
    search = request.args.get("q", "").strip()
    page = max(1, int(request.args.get("page", 1)))
    per_page = 25
    if search:
        all_users = db.search_users(search)
        total = len(all_users)
        users_list = all_users[(page - 1) * per_page: page * per_page]
    else:
        total = db.count_users()
        users_list = db.list_users(limit=per_page, offset=(page - 1) * per_page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template(
        "users.html",
        users=users_list,
        total=total,
        page=page,
        total_pages=total_pages,
        search=search,
        admin=get_current_admin(),
    )


@bp.route("/users/<int:user_id>")
@login_required
def user_detail(user_id: int):
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.users"))
    transactions = db.list_transactions(user_id=user_id, limit=50)
    investments = db.list_investments(user_id=user_id, limit=50)
    sessions = db.list_user_sessions(user_id=user_id, limit=50)
    last_session = db.get_user_last_session(user_id)
    referral_info = db.referral_stats(user_id)
    return render_template(
        "user_detail.html",
        user=user,
        transactions=transactions,
        investments=investments,
        sessions=sessions,
        last_session=last_session,
        referral_info=referral_info,
        admin=get_current_admin(),
    )


@bp.route("/users/<int:user_id>/ban", methods=["POST"])
@login_required
def user_ban(user_id: int):
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.users"))
    new_status = not user["is_banned"]
    db.set_ban(user_id, new_status)
    action = "ban_user" if new_status else "unban_user"
    db.log_audit(
        action=action,
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="user",
        target_id=str(user_id),
        ip_address=request.remote_addr,
    )
    flash(f"User {'banned' if new_status else 'unbanned'}.", "success")
    return redirect(url_for("main.user_detail", user_id=user_id))


@bp.route("/users/<int:user_id>/adjust", methods=["POST"])
@login_required
def user_adjust_balance(user_id: int):
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.users"))
    try:
        amount = float(request.form.get("amount", 0))
    except (ValueError, TypeError):
        flash("Invalid amount.", "danger")
        return redirect(url_for("main.user_detail", user_id=user_id))
    note = request.form.get("note", "Web admin adjustment").strip() or "Web admin adjustment"
    result = db.update_balance(user_id, amount)
    if result is None:
        flash("Adjustment would produce negative balance.", "danger")
    else:
        db.create_transaction(
            user_id=user_id,
            tx_type="adjustment",
            amount=amount,
            status="completed",
            note=note,
            admin_id=session.get("admin_id"),
        )
        db.log_audit(
            action="adjust_balance",
            admin_id=session.get("admin_id"),
            admin_name=session.get("admin_name"),
            target_type="user",
            target_id=str(user_id),
            details=f"Adjusted by {amount:+.2f}. Note: {note}",
            ip_address=request.remote_addr,
        )
        flash(f"Balance adjusted by {amount:+.2f}.", "success")
    return redirect(url_for("main.user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Deposits
# ---------------------------------------------------------------------------


@bp.route("/deposits")
@login_required
def deposits():
    db = get_db()
    status_filter = request.args.get("status", "pending")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 25
    if status_filter == "all":
        items = db.list_transactions(tx_type="deposit", limit=per_page, offset=(page - 1) * per_page)
        total = db.count_transactions(tx_type="deposit")
    else:
        items = db.list_transactions(tx_type="deposit", status=status_filter, limit=per_page, offset=(page - 1) * per_page)
        total = db.count_transactions(tx_type="deposit", status=status_filter)
    total_pages = max(1, (total + per_page - 1) // per_page)
    # Attach user info
    for item in items:
        item["_user"] = db.get_user(item["user_id"])
    return render_template(
        "deposits.html",
        deposits=items,
        total=total,
        page=page,
        total_pages=total_pages,
        status_filter=status_filter,
        admin=get_current_admin(),
    )


@bp.route("/deposits/<int:tx_id>/approve", methods=["POST"])
@login_required
def deposit_approve(tx_id: int):
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx or tx["tx_type"] != "deposit" or tx["status"] != "pending":
        flash("Invalid transaction.", "danger")
        return redirect(url_for("main.deposits"))
    db.update_balance(tx["user_id"], float(tx["amount"]))
    db.execute(
        "UPDATE users SET total_deposited = total_deposited + ?, updated_at = ? WHERE user_id = ?",
        (float(tx["amount"]), int(time.time()), tx["user_id"]),
    )
    db.update_transaction(tx_id, "completed", admin_id=session.get("admin_id"), note="Approved via web panel")
    db.log_audit(
        action="approve_deposit",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="transaction",
        target_id=str(tx_id),
        details=f"Approved deposit #{tx_id} for ${tx['amount']:.2f}",
        ip_address=request.remote_addr,
    )
    flash(f"Deposit #{tx_id} approved.", "success")
    return redirect(url_for("main.deposits"))


@bp.route("/deposits/<int:tx_id>/reject", methods=["POST"])
@login_required
def deposit_reject(tx_id: int):
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx or tx["tx_type"] != "deposit" or tx["status"] != "pending":
        flash("Invalid transaction.", "danger")
        return redirect(url_for("main.deposits"))
    db.update_transaction(tx_id, "rejected", admin_id=session.get("admin_id"), note="Rejected via web panel")
    db.log_audit(
        action="reject_deposit",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="transaction",
        target_id=str(tx_id),
        details=f"Rejected deposit #{tx_id}",
        ip_address=request.remote_addr,
    )
    flash(f"Deposit #{tx_id} rejected.", "warning")
    return redirect(url_for("main.deposits"))


# ---------------------------------------------------------------------------
# Withdrawals
# ---------------------------------------------------------------------------


@bp.route("/withdrawals")
@login_required
def withdrawals():
    db = get_db()
    status_filter = request.args.get("status", "pending")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 25
    if status_filter == "all":
        items = db.list_transactions(tx_type="withdrawal", limit=per_page, offset=(page - 1) * per_page)
        total = db.count_transactions(tx_type="withdrawal")
    else:
        items = db.list_transactions(tx_type="withdrawal", status=status_filter, limit=per_page, offset=(page - 1) * per_page)
        total = db.count_transactions(tx_type="withdrawal", status=status_filter)
    total_pages = max(1, (total + per_page - 1) // per_page)
    for item in items:
        item["_user"] = db.get_user(item["user_id"])
    return render_template(
        "withdrawals.html",
        withdrawals=items,
        total=total,
        page=page,
        total_pages=total_pages,
        status_filter=status_filter,
        admin=get_current_admin(),
    )


@bp.route("/withdrawals/<int:tx_id>/approve", methods=["POST"])
@login_required
def withdrawal_approve(tx_id: int):
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx or tx["tx_type"] != "withdrawal" or tx["status"] != "pending":
        flash("Invalid transaction.", "danger")
        return redirect(url_for("main.withdrawals"))
    db.execute(
        "UPDATE users SET total_withdrawn = total_withdrawn + ?, updated_at = ? WHERE user_id = ?",
        (abs(float(tx["amount"])), int(time.time()), tx["user_id"]),
    )
    db.update_transaction(tx_id, "completed", admin_id=session.get("admin_id"), note="Paid via web panel")
    db.log_audit(
        action="approve_withdrawal",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="transaction",
        target_id=str(tx_id),
        details=f"Approved withdrawal #{tx_id} for ${abs(tx['amount']):.2f}",
        ip_address=request.remote_addr,
    )
    flash(f"Withdrawal #{tx_id} marked as paid.", "success")
    return redirect(url_for("main.withdrawals"))


@bp.route("/withdrawals/<int:tx_id>/reject", methods=["POST"])
@login_required
def withdrawal_reject(tx_id: int):
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx or tx["tx_type"] != "withdrawal" or tx["status"] != "pending":
        flash("Invalid transaction.", "danger")
        return redirect(url_for("main.withdrawals"))
    # Refund locked funds
    db.update_balance(tx["user_id"], abs(float(tx["amount"])))
    db.update_transaction(tx_id, "rejected", admin_id=session.get("admin_id"), note="Rejected via web panel, funds returned")
    db.log_audit(
        action="reject_withdrawal",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="transaction",
        target_id=str(tx_id),
        details=f"Rejected withdrawal #{tx_id}, funds returned",
        ip_address=request.remote_addr,
    )
    flash(f"Withdrawal #{tx_id} rejected. Funds returned.", "warning")
    return redirect(url_for("main.withdrawals"))


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------


@bp.route("/plans")
@login_required
def plans():
    db = get_db()
    all_plans = db.list_plans()
    return render_template("plans.html", plans=all_plans, admin=get_current_admin())


@bp.route("/plans/create", methods=["GET", "POST"])
@login_required
def plan_create():
    if request.method == "POST":
        db = get_db()
        try:
            pid = db.create_plan(
                name=request.form["name"].strip(),
                description=request.form.get("description", "").strip(),
                min_amount=float(request.form["min_amount"]),
                max_amount=float(request.form["max_amount"]),
                daily_roi_percent=float(request.form["daily_roi"]),
                duration_days=int(request.form["duration"]),
                capital_return=request.form.get("capital_return") == "on",
                is_active=request.form.get("is_active") == "on",
            )
            db.log_audit(
                action="create_plan",
                admin_id=session.get("admin_id"),
                admin_name=session.get("admin_name"),
                target_type="plan",
                target_id=str(pid),
                details=f"Created plan '{request.form['name']}'",
                ip_address=request.remote_addr,
            )
            flash(f"Plan created (ID: {pid}).", "success")
            return redirect(url_for("main.plans"))
        except (ValueError, KeyError) as e:
            flash(f"Error: {e}", "danger")
    return render_template("plan_form.html", plan=None, admin=get_current_admin())


@bp.route("/plans/<int:plan_id>/edit", methods=["GET", "POST"])
@login_required
def plan_edit(plan_id: int):
    db = get_db()
    plan = db.get_plan(plan_id)
    if not plan:
        flash("Plan not found.", "danger")
        return redirect(url_for("main.plans"))
    if request.method == "POST":
        try:
            db.update_plan(
                plan_id,
                name=request.form["name"].strip(),
                description=request.form.get("description", "").strip(),
                min_amount=float(request.form["min_amount"]),
                max_amount=float(request.form["max_amount"]),
                daily_roi_percent=float(request.form["daily_roi"]),
                duration_days=int(request.form["duration"]),
                capital_return=1 if request.form.get("capital_return") == "on" else 0,
                is_active=1 if request.form.get("is_active") == "on" else 0,
            )
            db.log_audit(
                action="edit_plan",
                admin_id=session.get("admin_id"),
                admin_name=session.get("admin_name"),
                target_type="plan",
                target_id=str(plan_id),
                ip_address=request.remote_addr,
            )
            flash("Plan updated.", "success")
            return redirect(url_for("main.plans"))
        except (ValueError, KeyError) as e:
            flash(f"Error: {e}", "danger")
        plan = db.get_plan(plan_id)
    return render_template("plan_form.html", plan=plan, admin=get_current_admin())


@bp.route("/plans/<int:plan_id>/toggle", methods=["POST"])
@login_required
def plan_toggle(plan_id: int):
    db = get_db()
    plan = db.get_plan(plan_id)
    if not plan:
        flash("Plan not found.", "danger")
        return redirect(url_for("main.plans"))
    new_status = 0 if plan["is_active"] else 1
    db.update_plan(plan_id, is_active=new_status)
    db.log_audit(
        action="toggle_plan",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="plan",
        target_id=str(plan_id),
        details=f"Set plan '{plan['name']}' to {'active' if new_status else 'inactive'}",
        ip_address=request.remote_addr,
    )
    flash(f"Plan {'activated' if new_status else 'deactivated'}.", "success")
    return redirect(url_for("main.plans"))


@bp.route("/plans/<int:plan_id>/delete", methods=["POST"])
@login_required
def plan_delete(plan_id: int):
    db = get_db()
    plan = db.get_plan(plan_id)
    if not plan:
        flash("Plan not found.", "danger")
        return redirect(url_for("main.plans"))
    try:
        db.delete_plan(plan_id)
        db.log_audit(
            action="delete_plan",
            admin_id=session.get("admin_id"),
            admin_name=session.get("admin_name"),
            target_type="plan",
            target_id=str(plan_id),
            details=f"Deleted plan '{plan['name']}'",
            ip_address=request.remote_addr,
        )
        flash("Plan deleted.", "success")
    except Exception as e:
        flash(f"Cannot delete: {e}", "danger")
    return redirect(url_for("main.plans"))


# ---------------------------------------------------------------------------
# Settings / API Configuration
# ---------------------------------------------------------------------------


@bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    db = get_db()
    if request.method == "POST":
        # Handle QR image uploads first
        qr_fields = {
            "qr_btc": "qr_btc",
            "qr_eth": "qr_eth",
            "qr_usdt_trc20": "qr_usdt_trc20",
            "qr_usdt_erc20": "qr_usdt_erc20",
            "qr_ltc": "qr_ltc",
        }
        for field, setting_key in qr_fields.items():
            saved_name = _save_qr(field)
            if saved_name:
                db.set_setting(setting_key, saved_name, admin_id=session.get("admin_id"))

        # Process all text/bool settings from the form
        settings_map = {
            "bot_token": request.form.get("bot_token", "").strip(),
            "bot_username": request.form.get("bot_username", "").strip(),
            "admin_ids": request.form.get("admin_ids", "").strip(),
            "crypto_btc_address": request.form.get("crypto_btc_address", "").strip(),
            "crypto_eth_address": request.form.get("crypto_eth_address", "").strip(),
            "crypto_usdt_trc20_address": request.form.get("crypto_usdt_trc20_address", "").strip(),
            "crypto_usdt_erc20_address": request.form.get("crypto_usdt_erc20_address", "").strip(),
            "crypto_ltc_address": request.form.get("crypto_ltc_address", "").strip(),
            "signup_bonus_php": request.form.get("signup_bonus_php", "50").strip(),
            "usd_to_php_rate": request.form.get("usd_to_php_rate", "56").strip(),
            "min_deposit_usd": request.form.get("min_deposit_usd", "10").strip(),
            "min_withdrawal_usd": request.form.get("min_withdrawal_usd", "5").strip(),
            "referral_bonus_percent": request.form.get("referral_bonus_percent", "5").strip(),
            "deduct_referral_from_investor": request.form.get("deduct_referral_from_investor") == "on",
            "support_handle": request.form.get("support_handle", "@HCCNWAdmin").strip(),
            "maintenance_mode": request.form.get("maintenance_mode") == "on",
            "welcome_message": request.form.get("welcome_message", "").strip(),
        }
        float_keys = {"min_deposit_usd", "min_withdrawal_usd", "referral_bonus_percent", "usd_to_php_rate", "signup_bonus_php"}
        for k, v in settings_map.items():
            if isinstance(v, bool):
                db.set_setting(k, v, admin_id=session.get("admin_id"))
            elif k in float_keys:
                try:
                    db.set_setting(k, float(v), admin_id=session.get("admin_id"))
                except ValueError:
                    pass
            else:
                db.set_setting(k, v, admin_id=session.get("admin_id"))

        db.log_audit(
            action="update_settings",
            admin_id=session.get("admin_id"),
            admin_name=session.get("admin_name"),
            ip_address=request.remote_addr,
            details="Updated bot settings via web panel",
        )
        flash("Settings saved. Bot restart required for token/wallet/QR changes.", "success")
        return redirect(url_for("main.settings"))

    current = db.all_settings()
    return render_template("settings.html", settings=current, admin=get_current_admin())


# ---------------------------------------------------------------------------
# Broadcast
# ---------------------------------------------------------------------------


@bp.route("/broadcast", methods=["GET", "POST"])
@login_required
def broadcast():
    db = get_db()
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if not message:
            flash("Message cannot be empty.", "danger")
        else:
            # Store the broadcast in settings for the bot to pick up
            db.set_setting("_pending_broadcast", json.dumps({
                "message": message,
                "admin_id": session.get("admin_id"),
                "admin_name": session.get("admin_name"),
                "created_at": int(time.time()),
            }), admin_id=session.get("admin_id"))
            db.log_audit(
                action="broadcast",
                admin_id=session.get("admin_id"),
                admin_name=session.get("admin_name"),
                details=f"Queued broadcast: {message[:100]}...",
                ip_address=request.remote_addr,
            )
            flash("Broadcast queued. The bot will deliver it to all active users.", "success")
        return redirect(url_for("main.broadcast"))
    return render_template("broadcast.html", admin=get_current_admin())


# ---------------------------------------------------------------------------
# Audit Logs
# ---------------------------------------------------------------------------


@bp.route("/audit")
@login_required
def audit_logs():
    db = get_db()
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    total = db.count_audit_logs()
    logs = db.list_audit_logs(limit=per_page, offset=(page - 1) * per_page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template(
        "audit.html",
        logs=logs,
        total=total,
        page=page,
        total_pages=total_pages,
        admin=get_current_admin(),
    )


# ---------------------------------------------------------------------------
# Account (change password)
# ---------------------------------------------------------------------------


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    db = get_db()
    admin = get_current_admin()
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        if not verify_password(current_pw, admin["password"]):
            flash("Current password is incorrect.", "danger")
        elif len(new_pw) < 6:
            flash("New password must be at least 6 characters.", "danger")
        elif new_pw != confirm_pw:
            flash("New passwords don't match.", "danger")
        else:
            db.update_web_admin_password(admin["id"], hash_password(new_pw))
            db.log_audit(
                action="change_password",
                admin_id=admin["id"],
                admin_name=admin["username"],
                ip_address=request.remote_addr,
            )
            flash("Password updated.", "success")
        return redirect(url_for("main.account"))
    return render_template("account.html", admin=admin)
