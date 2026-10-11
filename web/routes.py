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
    abort,
)

from database import get_db
from web.app import (
    get_current_admin,
    hash_password,
    login_required,
    verify_password,
    csrf_protect,
    limiter,
    _sanitize,
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


@bp.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("10 per minute; 30 per hour", error_message="Too many login attempts. Try again later.")
def login():
    if "admin_id" in session:
        return redirect(url_for("main.dashboard"))
    error = None
    if request.method == "POST":
        # CSRF validation for login POST (protects against login CSRF)
        from web.app import _validate_csrf
        if not _validate_csrf():
            log.warning("CSRF check failed on admin login from %s", request.remote_addr)
            abort(403, "CSRF validation failed.")
        username = _sanitize(request.form.get("username", ""), max_len=80)
        password = request.form.get("password", "")
        if not username or not password:
            error = "Username and password are required."
        elif len(password) > 200:
            error = "Invalid credentials."
        else:
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
            error = "Invalid username or password."
            db.log_audit(
                action="login_failed",
                admin_name=username,
                ip_address=request.remote_addr,
                details=f"Failed login attempt for '{username}' from {request.remote_addr}",
            )
    return render_template("login.html", error=error)


@bp.route("/login", methods=["GET", "POST"])
def login_compat():
    """Legacy /login redirect for backwards compat."""
    return redirect(url_for("main.login"))


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


@bp.route("/admin")
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


@bp.route("/users/<sint:user_id>")
@login_required
def user_detail(user_id: int):
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.users"))
    transactions = db.list_transactions(user_id=user_id, limit=100)
    investments = db.list_investments(user_id=user_id, limit=100)
    sessions = db.list_user_sessions(user_id=user_id, limit=50)
    last_session = db.get_user_last_session(user_id)
    referral_info = db.referral_stats(user_id)
    plans = db.list_plans()
    return render_template(
        "user_detail.html",
        user=user,
        transactions=transactions,
        investments=investments,
        sessions=sessions,
        last_session=last_session,
        referral_info=referral_info,
        plans=plans,
        admin=get_current_admin(),
    )


@bp.route("/users/<sint:user_id>/ban", methods=["POST"])
@login_required
@csrf_protect
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


@bp.route("/users/<sint:user_id>/adjust", methods=["POST"])
@login_required
@csrf_protect
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
# User — full field editor (super-admin)
# ---------------------------------------------------------------------------

@bp.route("/users/<sint:user_id>/edit", methods=["GET", "POST"])
@login_required
@csrf_protect
def user_edit(user_id: int):
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.users"))

    if request.method == "POST":
        import re
        f = request.form

        # ── Build the fields dict from form ──────────────────────────
        fields: dict = {}

        # Text fields
        for key in ("username", "full_name", "referral_code"):
            val = f.get(key, "").strip()
            if val != str(user.get(key) or ""):
                fields[key] = val or None

        # Phone
        phone_raw = f.get("phone", "").strip()
        if phone_raw and phone_raw != (user.get("phone") or ""):
            # Normalise
            phone_digits = re.sub(r"[\s\-\(\)\.]+", "", phone_raw)
            if not phone_digits.startswith("+"):
                phone_digits = "+" + phone_digits
            fields["phone"] = phone_digits

        # Password (only if filled)
        new_pw = f.get("new_password", "").strip()
        if new_pw:
            if len(new_pw) < 6:
                flash("Password must be at least 6 characters.", "danger")
                return redirect(url_for("main.user_edit", user_id=user_id))
            from database import Database as _DB
            fields["password_hash"] = _DB._hash_password(new_pw)

        # referred_by
        ref_by = f.get("referred_by", "").strip()
        new_ref_by = int(ref_by) if ref_by.lstrip("-").isdigit() else None
        if new_ref_by != user.get("referred_by"):
            fields["referred_by"] = new_ref_by

        # Numeric wallet fields (direct set)
        num_fields = {
            "balance": f.get("balance"),
            "pending_balance": f.get("pending_balance"),
            "total_deposited": f.get("total_deposited"),
            "total_withdrawn": f.get("total_withdrawn"),
            "total_invested": f.get("total_invested"),
            "total_earned": f.get("total_earned"),
        }
        for k, v in num_fields.items():
            if v is not None and v.strip() != "":
                try:
                    fv = float(v)
                    if fv != float(user.get(k) or 0):
                        fields[k] = fv
                except ValueError:
                    flash(f"Invalid value for {k}.", "danger")
                    return redirect(url_for("main.user_edit", user_id=user_id))

        # is_banned / is_admin flags
        new_banned = 1 if f.get("is_banned") == "1" else 0
        new_admin  = 1 if f.get("is_admin")  == "1" else 0
        if new_banned != int(user.get("is_banned") or 0):
            fields["is_banned"] = new_banned
        if new_admin != int(user.get("is_admin") or 0):
            fields["is_admin"] = new_admin

        # created_at (datetime string → timestamp)
        created_str = f.get("created_at", "").strip()
        if created_str:
            try:
                from datetime import datetime, timezone
                dt = datetime.strptime(created_str, "%Y-%m-%dT%H:%M")
                ts = int(dt.replace(tzinfo=timezone.utc).timestamp())
                if ts != int(user.get("created_at") or 0):
                    fields["created_at"] = ts
            except ValueError:
                flash("Invalid date format for Created At.", "danger")
                return redirect(url_for("main.user_edit", user_id=user_id))

        if fields:
            db.update_user_fields(user_id, **fields)
            db.log_audit(
                action="edit_user",
                admin_id=session.get("admin_id"),
                admin_name=session.get("admin_name"),
                target_type="user",
                target_id=str(user_id),
                details=f"Edited fields: {', '.join(fields.keys())}",
                ip_address=request.remote_addr,
            )
            flash(f"User #{user_id} updated — {len(fields)} field(s) changed.", "success")
        else:
            flash("No changes detected.", "info")

        return redirect(url_for("main.user_detail", user_id=user_id))

    # GET — render the edit form
    plans = db.list_plans()
    return render_template(
        "user_edit.html",
        user=user,
        plans=plans,
        admin=get_current_admin(),
    )


# ---------------------------------------------------------------------------
# User — reset password (quick action)
# ---------------------------------------------------------------------------

@bp.route("/users/<sint:user_id>/reset-password", methods=["POST"])
@login_required
@csrf_protect
def user_reset_password(user_id: int):
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.users"))
    new_pw = request.form.get("new_password", "").strip()
    if len(new_pw) < 6:
        flash("Password must be at least 6 characters.", "danger")
    else:
        db.update_user_password(user_id, new_pw)
        db.log_audit(
            action="reset_user_password",
            admin_id=session.get("admin_id"),
            admin_name=session.get("admin_name"),
            target_type="user",
            target_id=str(user_id),
            details="Admin reset user password",
            ip_address=request.remote_addr,
        )
        flash(f"Password for user #{user_id} has been reset.", "success")
    return redirect(url_for("main.user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Transaction — edit
# ---------------------------------------------------------------------------

@bp.route("/users/<sint:user_id>/transactions/<int:tx_id>/edit", methods=["POST"])
@login_required
@csrf_protect
def transaction_edit(user_id: int, tx_id: int):
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx or tx["user_id"] != user_id:
        flash("Transaction not found.", "danger")
        return redirect(url_for("main.user_detail", user_id=user_id))

    f = request.form
    fields: dict = {}

    for key in ("tx_type", "currency", "crypto_currency", "network",
                "wallet_address", "tx_hash", "status", "note"):
        val = f.get(key, "").strip()
        if val != str(tx.get(key) or ""):
            fields[key] = val or None

    amt = f.get("amount", "").strip()
    if amt:
        try:
            fv = float(amt)
            if fv != float(tx.get("amount") or 0):
                fields["amount"] = fv
        except ValueError:
            flash("Invalid amount.", "danger")
            return redirect(url_for("main.user_detail", user_id=user_id))

    created_str = f.get("created_at", "").strip()
    if created_str:
        try:
            from datetime import datetime, timezone
            dt = datetime.strptime(created_str, "%Y-%m-%dT%H:%M")
            ts = int(dt.replace(tzinfo=timezone.utc).timestamp())
            if ts != int(tx.get("created_at") or 0):
                fields["created_at"] = ts
        except ValueError:
            flash("Invalid date format.", "danger")
            return redirect(url_for("main.user_detail", user_id=user_id))

    if fields:
        db.update_transaction_full(tx_id, **fields)
        db.log_audit(
            action="edit_transaction",
            admin_id=session.get("admin_id"),
            admin_name=session.get("admin_name"),
            target_type="transaction",
            target_id=str(tx_id),
            details=f"Edited fields: {', '.join(fields.keys())}",
            ip_address=request.remote_addr,
        )
        flash(f"Transaction #{tx_id} updated.", "success")
    else:
        flash("No changes.", "info")
    return redirect(url_for("main.user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Transaction — delete
# ---------------------------------------------------------------------------

@bp.route("/users/<sint:user_id>/transactions/<int:tx_id>/delete", methods=["POST"])
@login_required
@csrf_protect
def transaction_delete(user_id: int, tx_id: int):
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx or tx["user_id"] != user_id:
        flash("Transaction not found.", "danger")
        return redirect(url_for("main.user_detail", user_id=user_id))
    db.delete_transaction(tx_id)
    db.log_audit(
        action="delete_transaction",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="transaction",
        target_id=str(tx_id),
        details=f"Deleted tx #{tx_id} ({tx['tx_type']} {tx['amount']:+.2f})",
        ip_address=request.remote_addr,
    )
    flash(f"Transaction #{tx_id} deleted.", "warning")
    return redirect(url_for("main.user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Transaction — create (inject new tx for user)
# ---------------------------------------------------------------------------

@bp.route("/users/<sint:user_id>/transactions/create", methods=["POST"])
@login_required
@csrf_protect
def transaction_create(user_id: int):
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.users"))

    f = request.form
    try:
        amount = float(f.get("amount", 0))
    except (ValueError, TypeError):
        flash("Invalid amount.", "danger")
        return redirect(url_for("main.user_detail", user_id=user_id))

    tx_id = db.create_transaction(
        user_id=user_id,
        tx_type=f.get("tx_type", "adjustment").strip(),
        amount=amount,
        status=f.get("status", "completed").strip(),
        currency=f.get("currency", "PHP").strip() or "PHP",
        crypto_currency=f.get("crypto_currency", "").strip() or None,
        wallet_address=f.get("wallet_address", "").strip() or None,
        tx_hash=f.get("tx_hash", "").strip() or None,
        note=f.get("note", "").strip() or f"Admin-injected by {session.get('admin_name')}",
        admin_id=session.get("admin_id"),
    )

    # Optionally apply balance delta when status=completed
    if f.get("apply_balance") == "1":
        db.update_balance(user_id, amount)

    db.log_audit(
        action="create_transaction",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="transaction",
        target_id=str(tx_id),
        details=f"Injected tx #{tx_id} ({f.get('tx_type')} {amount:+.2f}) for user {user_id}",
        ip_address=request.remote_addr,
    )
    flash(f"Transaction #{tx_id} created.", "success")
    return redirect(url_for("main.user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Investment — edit
# ---------------------------------------------------------------------------

@bp.route("/users/<sint:user_id>/investments/<int:inv_id>/edit", methods=["POST"])
@login_required
@csrf_protect
def investment_edit(user_id: int, inv_id: int):
    db = get_db()
    inv = db.get_investment(inv_id)
    if not inv or inv["user_id"] != user_id:
        flash("Investment not found.", "danger")
        return redirect(url_for("main.user_detail", user_id=user_id))

    f = request.form
    fields: dict = {}

    for key in ("plan_name", "status"):
        val = f.get(key, "").strip()
        if val and val != str(inv.get(key) or ""):
            fields[key] = val

    for key in ("principal", "daily_roi_percent", "accrued_earnings", "payout_amount"):
        val = f.get(key, "").strip()
        if val:
            try:
                fv = float(val)
                if fv != float(inv.get(key) or 0):
                    fields[key] = fv
            except ValueError:
                flash(f"Invalid value for {key}.", "danger")
                return redirect(url_for("main.user_detail", user_id=user_id))

    for key in ("duration_days", "capital_return"):
        val = f.get(key, "").strip()
        if val:
            try:
                iv = int(val)
                if iv != int(inv.get(key) or 0):
                    fields[key] = iv
            except ValueError:
                pass

    from datetime import datetime, timezone
    for dt_key in ("started_at", "expires_at", "completed_at"):
        val = f.get(dt_key, "").strip()
        if val:
            try:
                dt = datetime.strptime(val, "%Y-%m-%dT%H:%M")
                ts = int(dt.replace(tzinfo=timezone.utc).timestamp())
                if ts != int(inv.get(dt_key) or 0):
                    fields[dt_key] = ts
            except ValueError:
                pass

    if fields:
        db.update_investment_full(inv_id, **fields)
        db.log_audit(
            action="edit_investment",
            admin_id=session.get("admin_id"),
            admin_name=session.get("admin_name"),
            target_type="investment",
            target_id=str(inv_id),
            details=f"Edited fields: {', '.join(fields.keys())}",
            ip_address=request.remote_addr,
        )
        flash(f"Investment #{inv_id} updated.", "success")
    else:
        flash("No changes.", "info")
    return redirect(url_for("main.user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Investment — delete
# ---------------------------------------------------------------------------

@bp.route("/users/<sint:user_id>/investments/<int:inv_id>/delete", methods=["POST"])
@login_required
@csrf_protect
def investment_delete(user_id: int, inv_id: int):
    db = get_db()
    inv = db.get_investment(inv_id)
    if not inv or inv["user_id"] != user_id:
        flash("Investment not found.", "danger")
        return redirect(url_for("main.user_detail", user_id=user_id))
    db.delete_investment(inv_id)
    db.log_audit(
        action="delete_investment",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="investment",
        target_id=str(inv_id),
        details=f"Deleted investment #{inv_id} ({inv['plan_name']} ₱{inv['principal']:.2f})",
        ip_address=request.remote_addr,
    )
    flash(f"Investment #{inv_id} deleted.", "warning")
    return redirect(url_for("main.user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Investment — create manually
# ---------------------------------------------------------------------------

@bp.route("/users/<sint:user_id>/investments/create", methods=["POST"])
@login_required
@csrf_protect
def investment_create(user_id: int):
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.users"))

    f = request.form
    from datetime import datetime, timezone
    import time as _time

    try:
        principal = float(f.get("principal", 0))
        daily_roi = float(f.get("daily_roi_percent", 1))
        duration  = int(f.get("duration_days", 30))
    except (ValueError, TypeError):
        flash("Invalid principal, ROI or duration.", "danger")
        return redirect(url_for("main.user_detail", user_id=user_id))

    plan_name     = f.get("plan_name", "Custom Plan").strip() or "Custom Plan"
    capital_ret   = 1 if f.get("capital_return") == "1" else 0
    status        = f.get("status", "active").strip()
    deduct_balance= f.get("deduct_balance") == "1"

    started_str = f.get("started_at", "").strip()
    try:
        started_dt = datetime.strptime(started_str, "%Y-%m-%dT%H:%M")
        started_ts = int(started_dt.replace(tzinfo=timezone.utc).timestamp())
    except (ValueError, TypeError):
        started_ts = int(_time.time())

    expires_ts = started_ts + duration * 86400

    if deduct_balance and principal > float(user["balance"]):
        flash("Principal exceeds user balance.", "danger")
        return redirect(url_for("main.user_detail", user_id=user_id))

    from database import _now
    with db._lock:
        cur = db.execute(
            """INSERT INTO investments
               (user_id, plan_id, plan_name, principal, daily_roi_percent,
                duration_days, capital_return, accrued_earnings, payout_amount,
                status, started_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?)""",
            (user_id, 0, plan_name, principal, daily_roi, duration,
             capital_ret, status, started_ts, expires_ts),
        )
        inv_id = cur.lastrowid

    if deduct_balance:
        db.update_balance(user_id, -principal)
        db.execute(
            "UPDATE users SET total_invested = total_invested + ?, updated_at = ? WHERE user_id = ?",
            (principal, _now(), user_id),
        )

    db.log_audit(
        action="create_investment",
        admin_id=session.get("admin_id"),
        admin_name=session.get("admin_name"),
        target_type="investment",
        target_id=str(inv_id),
        details=f"Admin-created investment #{inv_id} ({plan_name} ₱{principal:.2f}) for user {user_id}",
        ip_address=request.remote_addr,
    )
    flash(f"Investment #{inv_id} created.", "success")
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
@csrf_protect
def deposit_approve(tx_id: int):
    db = get_db()
    # Re-check status inside a DB lock to prevent double-approval race
    with db._lock:
        tx = db.get_transaction(tx_id)
        if not tx or tx["tx_type"] != "deposit" or tx["status"] != "pending":
            flash("Invalid transaction or already processed.", "danger")
            return redirect(url_for("main.deposits"))
        # Immediately mark as processing to claim the row
        db.execute(
            "UPDATE transactions SET status = 'processing', updated_at = ? WHERE id = ? AND status = 'pending'",
            (int(time.time()), tx_id),
        )
        affected = db.query_one("SELECT changes() AS c")
        if not affected or affected["c"] == 0:
            flash("Transaction was already processed by another admin.", "warning")
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
@csrf_protect
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
@csrf_protect
def withdrawal_approve(tx_id: int):
    db = get_db()
    # Atomic claim to prevent double-approval
    with db._lock:
        tx = db.get_transaction(tx_id)
        if not tx or tx["tx_type"] != "withdrawal" or tx["status"] != "pending":
            flash("Invalid transaction or already processed.", "danger")
            return redirect(url_for("main.withdrawals"))
        db.execute(
            "UPDATE transactions SET status = 'processing', updated_at = ? WHERE id = ? AND status = 'pending'",
            (int(time.time()), tx_id),
        )
        affected = db.query_one("SELECT changes() AS c")
        if not affected or affected["c"] == 0:
            flash("Transaction was already processed by another admin.", "warning")
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
@csrf_protect
def withdrawal_reject(tx_id: int):
    db = get_db()
    # Atomic status-check + claim to prevent double-refund
    with db._lock:
        tx = db.get_transaction(tx_id)
        if not tx or tx["tx_type"] != "withdrawal" or tx["status"] != "pending":
            flash("Invalid transaction or already processed.", "danger")
            return redirect(url_for("main.withdrawals"))
        db.execute(
            "UPDATE transactions SET status = 'processing', updated_at = ? WHERE id = ? AND status = 'pending'",
            (int(time.time()), tx_id),
        )
        affected = db.query_one("SELECT changes() AS c")
        if not affected or affected["c"] == 0:
            flash("Transaction was already processed by another admin.", "warning")
            return redirect(url_for("main.withdrawals"))

    # Refund locked funds (safe — only reached once per tx)
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
@csrf_protect
def plan_create():
    if request.method == "POST":
        db = get_db()
        try:
            name = _sanitize(request.form.get("name", ""), max_len=120)
            if not name:
                flash("Plan name is required.", "danger")
                return render_template("plan_form.html", plan=None, admin=get_current_admin())
            description = _sanitize(request.form.get("description", ""), max_len=500)
            min_amount = float(request.form["min_amount"])
            max_amount = float(request.form["max_amount"])
            daily_roi = float(request.form["daily_roi"])
            duration = int(request.form["duration"])
            # Sane range guards
            if min_amount < 0 or max_amount < min_amount:
                raise ValueError("min_amount / max_amount out of range")
            if not (0 < daily_roi <= 100):
                raise ValueError("daily_roi_percent must be between 0 and 100")
            if not (1 <= duration <= 3650):
                raise ValueError("duration_days must be between 1 and 3650")
            pid = db.create_plan(
                name=name,
                description=description,
                min_amount=min_amount,
                max_amount=max_amount,
                daily_roi_percent=daily_roi,
                duration_days=duration,
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
@csrf_protect
def plan_edit(plan_id: int):
    db = get_db()
    plan = db.get_plan(plan_id)
    if not plan:
        flash("Plan not found.", "danger")
        return redirect(url_for("main.plans"))
    if request.method == "POST":
        try:
            name = _sanitize(request.form.get("name", ""), max_len=120)
            if not name:
                flash("Plan name is required.", "danger")
                return render_template("plan_form.html", plan=plan, admin=get_current_admin())
            description = _sanitize(request.form.get("description", ""), max_len=500)
            min_amount = float(request.form["min_amount"])
            max_amount = float(request.form["max_amount"])
            daily_roi = float(request.form["daily_roi"])
            duration = int(request.form["duration"])
            if min_amount < 0 or max_amount < min_amount:
                raise ValueError("min_amount / max_amount out of range")
            if not (0 < daily_roi <= 100):
                raise ValueError("daily_roi_percent must be between 0 and 100")
            if not (1 <= duration <= 3650):
                raise ValueError("duration_days must be between 1 and 3650")
            db.update_plan(
                plan_id,
                name=name,
                description=description,
                min_amount=min_amount,
                max_amount=max_amount,
                daily_roi_percent=daily_roi,
                duration_days=duration,
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
@csrf_protect
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
@csrf_protect
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
@csrf_protect
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
@csrf_protect
def broadcast():
    db = get_db()
    if request.method == "POST":
        message = _sanitize(request.form.get("message", ""), max_len=4000)
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
@csrf_protect
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
