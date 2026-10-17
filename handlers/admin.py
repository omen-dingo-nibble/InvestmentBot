"""Admin dashboard conversation + callback handlers.

The dashboard is broken into:
  * Dashboard entry + statistics
  * Plan management (create, toggle, delete)
  * Deposit approvals
  * Withdrawal approvals
  * User management (lookup, ban, balance adjust)
  * Settings editor
  * Broadcast
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from config import CONFIG
from database import get_db
from keyboards.admin_kb import (
    admin_deposit_actions_keyboard,
    admin_home,
    admin_pending_deposits_keyboard,
    admin_pending_withdrawals_keyboard,
    admin_plan_view_keyboard,
    admin_plans_keyboard,
    admin_settings_keyboard,
    admin_user_view_keyboard,
    admin_users_keyboard,
    admin_withdrawal_actions_keyboard,
)
from keyboards.user_kb import back_to_main
from utils.decorators import admin_only
from utils.formatters import (
    fmt_money,
    fmt_percent,
    fmt_short_date,
    fmt_user,
    truncate,
)
from utils.helpers import parse_amount, parse_signed_amount
from utils.states import CB, State

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@admin_only
async def admin_dashboard(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    if query:
        await query.answer()
    db = get_db()
    s = db.admin_stats()
    text = (
        "🛠 *Admin Dashboard*\n\n"
        f"👥 Users: *{s['users']}* (banned: {s['banned']})\n"
        f"📦 Active investments: *{s['active_investments']}*\n"
        f"💰 Pending deposits: *{s['pending_deposits']}*\n"
        f"💸 Pending withdrawals: *{s['pending_withdrawals']}*\n"
        f"💵 Total approved deposits: *{fmt_money(s['total_deposits_approved'])}*\n"
        f"💼 Total completed withdrawals: *{fmt_money(s['total_withdrawals_completed'])}*\n"
        f"📈 Total invested (active+completed): *{fmt_money(s['total_invested'])}*\n"
        f"🏦 Principal currently locked: *{fmt_money(s['total_principal_active'])}*\n"
        f"🪙 Earnings paid: *{fmt_money(s['total_earnings_paid'])}*\n"
        f"🎁 Referral bonuses paid: *{fmt_money(s['total_referral_bonus'])}*\n"
    )
    if query:
        await query.edit_message_text(
            text, reply_markup=admin_home(), parse_mode="Markdown"
        )
    else:
        await update.effective_message.reply_text(
            text, reply_markup=admin_home(), parse_mode="Markdown"
        )
    return -1


@admin_only
async def admin_stats(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    db = get_db()
    s = db.admin_stats()
    # extra: per-plan breakdown
    plans = db.list_plans()
    plan_lines = []
    for p in plans:
        inv_count = db.query_one(
            "SELECT COUNT(*) AS c, COALESCE(SUM(principal),0) AS s "
            "FROM investments WHERE plan_id = ?",
            (p["id"],),
        )
        plan_lines.append(
            f"• *{p['name']}* — inv: {inv_count['c']} · "
            f"capital: {fmt_money(inv_count['s'])} · "
            f"{'🟢' if p['is_active'] else '🔴'}"
        )
    text = (
        "📊 *Detailed statistics*\n\n"
        + "\n".join(plan_lines)
        + "\n\n"
        + f"Users: {s['users']}\n"
        + f"Active investments: {s['active_investments']}\n"
        + f"Pending deposits: {s['pending_deposits']}\n"
        + f"Pending withdrawals: {s['pending_withdrawals']}\n"
        + f"Total deposited (approved): {fmt_money(s['total_deposits_approved'])}\n"
        + f"Total withdrawn (completed): {fmt_money(s['total_withdrawals_completed'])}\n"
        + f"Total principal (active+completed): {fmt_money(s['total_invested'])}\n"
        + f"Active principal: {fmt_money(s['total_principal_active'])}\n"
        + f"Earnings paid out: {fmt_money(s['total_earnings_paid'])}\n"
        + f"Referral bonuses paid: {fmt_money(s['total_referral_bonus'])}\n"
    )
    await query.edit_message_text(
        truncate(text, 3800),
        reply_markup=admin_home(),
        parse_mode="Markdown",
    )
    return -1


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------


@admin_only
async def admin_plans(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    db = get_db()
    plans = db.list_plans()
    lines = ["📦 *Investment plans*", ""]
    if not plans:
        lines.append("_No plans yet. Create one below._")
    else:
        for p in plans:
            lines.append(
                f"• *{p['name']}* — {fmt_percent(p['daily_roi_percent'])} / "
                f"{p['duration_days']}d · ${p['min_amount']:.0f}–${p['max_amount']:.0f} · "
                f"{'🟢 active' if p['is_active'] else '🔴 inactive'}"
            )
    await query.edit_message_text(
        "\n".join(lines),
        reply_markup=admin_plans_keyboard(plans),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_plan_view(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    plan_id = int(query.data.split(":", 1)[1])
    db = get_db()
    plan = db.get_plan(plan_id)
    if not plan:
        await query.edit_message_text("Plan not found.", reply_markup=admin_home())
        return -1
    text = (
        f"📦 *{plan['name']}*\n"
        f"{plan.get('description') or ''}\n\n"
        f"Daily ROI: *{fmt_percent(plan['daily_roi_percent'])}*\n"
        f"Duration: *{plan['duration_days']} days*\n"
        f"Range: *${plan['min_amount']:.2f} – ${plan['max_amount']:.2f}*\n"
        f"Capital return: *{'Yes' if plan['capital_return'] else 'No'}*\n"
        f"Status: *{'🟢 Active' if plan['is_active'] else '🔴 Inactive'}*\n"
    )
    await query.edit_message_text(
        text,
        reply_markup=admin_plan_view_keyboard(plan),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_plan_toggle(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    plan_id = int(query.data.split(":", 2)[2])
    db = get_db()
    plan = db.get_plan(plan_id)
    if not plan:
        return await admin_plans(update, context)
    db.update_plan(plan_id, is_active=0 if plan["is_active"] else 1)
    plan = db.get_plan(plan_id)
    await query.answer(
        f"Plan {plan['name']} is now "
        f"{'active' if plan['is_active'] else 'inactive'}.",
        show_alert=True,
    )
    return await admin_plans(update, context)


@admin_only
async def admin_plan_delete(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    plan_id = int(query.data.split(":", 2)[2])
    db = get_db()
    plan = db.get_plan(plan_id)
    if not plan:
        return await admin_plans(update, context)
    try:
        db.delete_plan(plan_id)
        await query.answer(f"Plan {plan['name']} deleted.", show_alert=True)
    except Exception as e:
        await query.answer(
            f"Could not delete (it likely has active investments): {e}",
            show_alert=True,
        )
    return await admin_plans(update, context)


@admin_only
async def admin_plan_new_start(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["new_plan"] = {}
    await query.edit_message_text(
        "➕ *New plan*\n\nEnter the plan *name*:",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Cancel", callback_data=CB["admin_plans"])]]
        ),
        parse_mode="Markdown",
    )
    return State.ADMIN_PLAN_NAME


@admin_only
async def admin_plan_name(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    text = (update.effective_message.text or "").strip()
    if not text or len(text) > 64:
        await update.effective_message.reply_text(
            "❌ Name must be 1-64 characters.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌ Cancel", callback_data=CB["admin_plans"])]]
            ),
        )
        return State.ADMIN_PLAN_NAME
    context.user_data["new_plan"]["name"] = text
    await update.effective_message.reply_text(
        "Now send a short *description* (or `-` to skip).",
        parse_mode="Markdown",
    )
    return State.ADMIN_PLAN_DESCRIPTION


@admin_only
async def admin_plan_description(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    text = (update.effective_message.text or "").strip()
    context.user_data["new_plan"]["description"] = "" if text == "-" else text
    await update.effective_message.reply_text(
        "Enter the *minimum* deposit amount in USD:",
        parse_mode="Markdown",
    )
    return State.ADMIN_PLAN_MIN


@admin_only
async def admin_plan_min(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    val = parse_amount(update.effective_message.text or "")
    if val is None or val <= 0:
        await update.effective_message.reply_text("❌ Invalid amount.")
        return State.ADMIN_PLAN_MIN
    context.user_data["new_plan"]["min_amount"] = val
    await update.effective_message.reply_text(
        "Enter the *maximum* deposit amount in USD:",
        parse_mode="Markdown",
    )
    return State.ADMIN_PLAN_MAX


@admin_only
async def admin_plan_max(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    val = parse_amount(update.effective_message.text or "")
    np = context.user_data.get("new_plan", {})
    if val is None or val <= 0 or val < np.get("min_amount", 0):
        await update.effective_message.reply_text(
            f"❌ Maximum must be ≥ minimum (${np.get('min_amount', 0):.2f})."
        )
        return State.ADMIN_PLAN_MAX
    context.user_data["new_plan"]["max_amount"] = val
    await update.effective_message.reply_text(
        "Enter the *daily ROI* percentage (e.g. `2.5` for 2.5%/day):",
        parse_mode="Markdown",
    )
    return State.ADMIN_PLAN_DAILY_ROI


@admin_only
async def admin_plan_daily_roi(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    val = parse_amount(update.effective_message.text or "")
    if val is None or val < 0 or val > 100:
        await update.effective_message.reply_text("❌ Enter a number between 0 and 100.")
        return State.ADMIN_PLAN_DAILY_ROI
    context.user_data["new_plan"]["daily_roi_percent"] = val
    await update.effective_message.reply_text(
        "Enter the *duration* in days (e.g. `7`, `14`, `30`):",
        parse_mode="Markdown",
    )
    return State.ADMIN_PLAN_DURATION


@admin_only
async def admin_plan_duration(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    val = parse_amount(update.effective_message.text or "")
    if val is None or val <= 0 or val > 3650:
        await update.effective_message.reply_text("❌ Enter 1-3650 days.")
        return State.ADMIN_PLAN_DURATION
    context.user_data["new_plan"]["duration_days"] = int(val)
    await update.effective_message.reply_text(
        "Should the *principal be returned* at the end? Reply `yes` or `no`.",
        parse_mode="Markdown",
    )
    return State.ADMIN_PLAN_TOGGLE


@admin_only
async def admin_plan_capital(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    np = context.user_data.get("new_plan", {})
    text = (update.effective_message.text or "").strip().lower()
    np["capital_return"] = text in {"yes", "y", "true", "1"}
    db = get_db()
    pid = db.create_plan(
        name=np["name"],
        description=np.get("description", ""),
        min_amount=np["min_amount"],
        max_amount=np["max_amount"],
        daily_roi_percent=np["daily_roi_percent"],
        duration_days=np["duration_days"],
        capital_return=np["capital_return"],
        is_active=True,
    )
    context.user_data.pop("new_plan", None)
    await update.effective_message.reply_text(
        f"✅ Plan *{np['name']}* created (id `{pid}`).",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("📦 Back to plans", callback_data=CB["admin_plans"])]]
        ),
        parse_mode="Markdown",
    )
    return -1


# ---------------------------------------------------------------------------
# Deposits
# ---------------------------------------------------------------------------


@admin_only
async def admin_deposits(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    db = get_db()
    items = db.list_transactions(tx_type="deposit", status="pending", limit=20)
    if not items:
        await query.edit_message_text(
            "💰 *Pending deposits*\n\nNo pending deposits ✅",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("⬅️ Admin Home", callback_data=CB["admin_home"])]
            ]),
            parse_mode="Markdown",
        )
        return -1
    lines = [f"💰 *Pending deposits* ({len(items)})\n"]
    for tx in items:
        u = db.get_user(tx["user_id"])
        lines.append(
            f"`#{tx['id']}` {fmt_user(u) if u else tx['user_id']}\n"
            f"  amount: *${tx['amount']:.2f}* via {tx.get('crypto_currency') or tx.get('currency')}\n"
            f"  network: {tx.get('network') or '-'}  · tx_hash: `{tx.get('tx_hash') or '-'}`"
        )
    await query.edit_message_text(
        truncate("\n".join(lines), 3800),
        reply_markup=admin_pending_deposits_keyboard(items),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_deposit_view(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    tx_id = int(query.data.split(":", 1)[1])
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx:
        await query.answer("Transaction not found.", show_alert=True)
        return -1
    user = db.get_user(tx["user_id"])
    text = (
        f"💰 *Deposit `#{tx['id']}`*\n\n"
        f"User: {fmt_user(user) if user else tx['user_id']}\n"
        f"Amount: *${tx['amount']:.2f} {tx['currency']}*\n"
        f"Crypto: {tx.get('crypto_currency') or '-'} ({tx.get('network') or '-'})\n"
        f"Address: `{tx.get('wallet_address') or '-'}`\n"
        f"TX hash: `{tx.get('tx_hash') or '-'}`\n"
        f"Status: *{tx['status']}*\n"
        f"Created: {fmt_short_date(tx['created_at'])}\n"
        f"Note: {tx.get('note') or '-'}"
    )
    if tx.get("receipt_file_id"):
        try:
            await query.message.reply_photo(
                photo=tx["receipt_file_id"],
                caption=f"Receipt for #{tx['id']}",
            )
        except Exception:
            try:
                await query.message.reply_document(
                    document=tx["receipt_file_id"],
                    caption=f"Receipt for #{tx['id']}",
                )
            except Exception:
                pass
    await query.message.reply_text(
        text,
        reply_markup=admin_deposit_actions_keyboard(tx_id),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_deposit_decide(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    parts = query.data.split(":")
    action = parts[1]  # DA or DR
    tx_id = int(parts[2])
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx or tx["tx_type"] != "deposit":
        await query.answer("Not found / wrong type.", show_alert=True)
        return -1
    if tx["status"] != "pending":
        await query.answer(f"Already {tx['status']}.", show_alert=True)
        return -1

    user = db.get_user(tx["user_id"])
    if action == "DA":
        # Approve: credit user balance, total_deposited, mark tx approved+completed
        db.update_balance(tx["user_id"], float(tx["amount"]))
        db.execute(
            "UPDATE users SET total_deposited = total_deposited + ?, updated_at = ? "
            "WHERE user_id = ?",
            (float(tx["amount"]), int(time.time()), tx["user_id"]),
        )
        db.update_transaction(tx_id, "completed", admin_id=update.effective_user.id,
                              note="Approved by admin")
        await query.answer("Deposit approved.", show_alert=True)
        try:
            await context.bot.send_message(
                chat_id=tx["user_id"],
                text=(
                    f"✅ Your deposit `#{tx_id}` of *${tx['amount']:.2f}* "
                    f"has been approved. Funds are now in your wallet."
                ),
                parse_mode="Markdown",
            )
        except Exception:
            pass
    else:
        db.update_transaction(tx_id, "rejected", admin_id=update.effective_user.id,
                              note="Rejected by admin")
        await query.answer("Deposit rejected.", show_alert=True)
        try:
            await context.bot.send_message(
                chat_id=tx["user_id"],
                text=(
                    f"❌ Your deposit `#{tx_id}` of *${tx['amount']:.2f}* "
                    f"was rejected. Please contact support."
                ),
                parse_mode="Markdown",
            )
        except Exception:
            pass
    # Update the message that had the buttons
    try:
        await query.edit_message_reply_markup(reply_markup=None)
    except Exception:
        pass
    return await admin_deposits(update, context)


# ---------------------------------------------------------------------------
# Withdrawals
# ---------------------------------------------------------------------------


@admin_only
async def admin_withdrawals(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    db = get_db()
    items = db.list_transactions(tx_type="withdrawal", status="pending", limit=20)
    if not items:
        await query.edit_message_text(
            "💸 *Pending withdrawals*\n\nNothing pending ✅",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("⬅️ Admin Home", callback_data=CB["admin_home"])]
            ]),
            parse_mode="Markdown",
        )
        return -1
    lines = [f"💸 *Pending withdrawals* ({len(items)})\n"]
    for tx in items:
        u = db.get_user(tx["user_id"])
        note = tx.get("note") or ""
        if "GCash" in note:
            method = "📱 GCash"
        elif "Maya" in note:
            method = "💜 Maya"
        else:
            method = "₿ Crypto"
        lines.append(
            f"`#{tx['id']}` {fmt_user(u) if u else tx['user_id']}\n"
            f"  amount: *${tx['amount']:.2f}* · {method} → `{tx.get('wallet_address') or '-'}`"
        )
    await query.edit_message_text(
        truncate("\n".join(lines), 3800),
        reply_markup=admin_pending_withdrawals_keyboard(items),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_withdrawal_view(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    tx_id = int(query.data.split(":", 1)[1])
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx:
        await query.answer("Not found.", show_alert=True)
        return -1
    user = db.get_user(tx["user_id"])
    # Detect payment method from the note field
    note = tx.get("note") or ""
    if "GCash" in note:
        method_line = "Method: *GCash 📱*\n"
    elif "Maya" in note:
        method_line = "Method: *Maya 💜*\n"
    else:
        method_line = "Method: *Crypto ₿*\n"
    text = (
        f"💸 *Withdrawal `#{tx['id']}`*\n\n"
        f"User: {fmt_user(user) if user else tx['user_id']}\n"
        f"Amount: *${tx['amount']:.2f} {tx['currency']}*\n"
        f"{method_line}"
        f"Payout to: `{tx.get('wallet_address') or '-'}`\n"
        f"Status: *{tx['status']}*\n"
        f"Created: {fmt_short_date(tx['created_at'])}"
    )
    await query.message.reply_text(
        text,
        reply_markup=admin_withdrawal_actions_keyboard(tx_id),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_withdrawal_decide(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    parts = query.data.split(":")
    action = parts[1]
    tx_id = int(parts[2])
    db = get_db()
    tx = db.get_transaction(tx_id)
    if not tx or tx["tx_type"] != "withdrawal":
        await query.answer("Not found / wrong type.", show_alert=True)
        return -1
    if tx["status"] != "pending":
        await query.answer(f"Already {tx['status']}.", show_alert=True)
        return -1
    if action == "WA":
        # Mark paid
        db.execute(
            "UPDATE users SET total_withdrawn = total_withdrawn + ?, updated_at = ? "
            "WHERE user_id = ?",
            (abs(float(tx["amount"])), int(time.time()), tx["user_id"]),
        )
        db.update_transaction(tx_id, "completed", admin_id=update.effective_user.id,
                              note="Paid out by admin")
        await query.answer("Marked as paid.", show_alert=True)
        note = tx.get("note") or ""
        if "GCash" in note:
            payout_info = f"to your GCash number `{tx.get('wallet_address', '')}`"
        elif "Maya" in note:
            payout_info = f"to your Maya number `{tx.get('wallet_address', '')}`"
        else:
            payout_info = "to your crypto wallet"
        try:
            await context.bot.send_message(
                chat_id=tx["user_id"],
                text=(
                    f"✅ Your withdrawal `#{tx_id}` of *₱{abs(tx['amount']):.2f}* "
                    f"has been paid {payout_info}."
                ),
                parse_mode="Markdown",
            )
        except Exception:
            pass
    else:
        # Reject: refund the locked amount
        db.update_balance(tx["user_id"], abs(float(tx["amount"])))
        db.update_transaction(tx_id, "rejected", admin_id=update.effective_user.id,
                              note="Rejected by admin, funds returned")
        await query.answer("Withdrawal rejected, funds returned.", show_alert=True)
        try:
            await context.bot.send_message(
                chat_id=tx["user_id"],
                text=(
                    f"❌ Your withdrawal `#{tx_id}` was rejected. "
                    f"The funds have been returned to your wallet."
                ),
                parse_mode="Markdown",
            )
        except Exception:
            pass
    try:
        await query.edit_message_reply_markup(reply_markup=None)
    except Exception:
        pass
    return await admin_withdrawals(update, context)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@admin_only
async def admin_users(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    db = get_db()
    users = db.list_users(limit=20)
    text = (
        f"👥 *Users* (showing {len(users)} of {db.count_users()})\n"
        f"Send a user ID, username, or name to search."
    )
    await query.edit_message_text(
        text,
        reply_markup=admin_users_keyboard(users),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_user_search(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    term = (update.effective_message.text or "").strip()
    db = get_db()
    if not term:
        return await admin_users_list_message(update, context)
    users = db.search_users(term)
    if not users:
        await update.effective_message.reply_text("No matches.")
        return State.ADMIN_USER_LOOKUP
    text = f"🔎 *Search results for* `{term}`\n"
    await update.effective_message.reply_text(
        text,
        reply_markup=admin_users_keyboard(users),
        parse_mode="Markdown",
    )
    return State.ADMIN_USER_LOOKUP


@admin_only
async def admin_users_list_message(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    db = get_db()
    users = db.list_users(limit=20)
    await update.effective_message.reply_text(
        f"👥 *Users* (showing {len(users)} of {db.count_users()})",
        reply_markup=admin_users_keyboard(users),
        parse_mode="Markdown",
    )
    return State.ADMIN_USER_LOOKUP


@admin_only
async def admin_user_view(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    user_id = int(query.data.split(":", 2)[2])
    db = get_db()
    user = db.get_user(user_id)
    if not user:
        await query.answer("User not found.", show_alert=True)
        return -1
    inv = db.list_investments(user_id=user_id, limit=5)
    deposits = db.list_transactions(user_id=user_id, tx_type="deposit", limit=3)
    withdrawals = db.list_transactions(user_id=user_id, tx_type="withdrawal", limit=3)
    text = (
        f"👤 *{user.get('full_name') or user.get('username') or user_id}*\n"
        f"ID: `{user['user_id']}` · username: @{user.get('username') or '-'}\n"
        f"Joined: {fmt_short_date(user['created_at'])}\n"
        f"Banned: *{'yes' if user['is_banned'] else 'no'}* · Admin: *{'yes' if user['is_admin'] else 'no'}*\n\n"
        f"💰 Balance: *{fmt_money(user['balance'])}*\n"
        f"📥 Deposited: *{fmt_money(user['total_deposited'])}*\n"
        f"📤 Withdrawn: *{fmt_money(user['total_withdrawn'])}*\n"
        f"📈 Invested: *{fmt_money(user['total_invested'])}*\n"
        f"🪙 Earned: *{fmt_money(user['total_earned'])}*\n"
        f"Referral code: `{user['referral_code']}`\n"
    )
    if user.get("referred_by"):
        text += f"Referred by: `{user['referred_by']}`\n"
    if inv:
        text += "\n*Last investments*\n"
        for i in inv:
            text += f"`#{i['id']}` {i['plan_name']} — {fmt_money(i['principal'])} · {i['status']}\n"
    if deposits:
        text += "\n*Last deposits*\n"
        for d in deposits:
            text += f"`#{d['id']}` ${d['amount']:.2f} · {d['status']}\n"
    if withdrawals:
        text += "\n*Last withdrawals*\n"
        for w in withdrawals:
            text += f"`#{w['id']}` ${w['amount']:.2f} · {w['status']}\n"
    await query.edit_message_text(
        truncate(text, 3800),
        reply_markup=admin_user_view_keyboard(user),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_user_ban_toggle(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    parts = query.data.split(":")
    action = parts[1]  # UB or UU
    user_id = int(parts[2])
    db = get_db()
    if action == "UB":
        db.set_ban(user_id, True)
        await query.answer("User banned.", show_alert=True)
    else:
        db.set_ban(user_id, False)
        await query.answer("User unbanned.", show_alert=True)
    user = db.get_user(user_id)
    if not user:
        return -1
    await query.edit_message_text(
        f"User `{user_id}` updated. Banned: *{'yes' if user['is_banned'] else 'no'}*",
        reply_markup=admin_user_view_keyboard(user),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_user_adjust_start(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    user_id = int(query.data.split(":", 2)[2])
    context.user_data["adjust"] = {"user_id": user_id}
    await query.edit_message_text(
        f"💱 *Adjust balance* for user `{user_id}`\n\n"
        f"Send the *signed* amount to add or remove, e.g. `+50` or `-25`.",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Cancel", callback_data=f"{CB['admin_user_view']}{user_id}")]]
        ),
        parse_mode="Markdown",
    )
    return State.ADMIN_ADJUST_BALANCE


@admin_only
async def admin_user_adjust_amount(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    amount = parse_signed_amount(update.effective_message.text or "")
    if amount is None or amount == 0:
        await update.effective_message.reply_text("❌ Invalid amount. Try `+50` or `-25`.")
        return State.ADMIN_ADJUST_BALANCE
    context.user_data["adjust"]["amount"] = amount
    await update.effective_message.reply_text(
        "Add a *note* explaining the adjustment (or `-` to skip):",
        parse_mode="Markdown",
    )
    return State.ADMIN_ADJUST_NOTE


@admin_only
async def admin_user_adjust_commit(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    note = (update.effective_message.text or "").strip()
    adj = context.user_data.pop("adjust", None)
    if not adj:
        await update.effective_message.reply_text("Cancelled.", reply_markup=admin_home())
        return -1
    db = get_db()
    user = db.get_user(adj["user_id"])
    if not user:
        await update.effective_message.reply_text("User missing.", reply_markup=admin_home())
        return -1
    amount = float(adj["amount"])
    new_record = db.update_balance(user["user_id"], amount)
    if new_record is None:
        await update.effective_message.reply_text(
            "❌ Adjustment would produce a negative balance.",
            reply_markup=admin_user_view_keyboard(user),
        )
        return -1
    db.create_transaction(
        user_id=user["user_id"],
        tx_type="adjustment",
        amount=amount,
        status="completed",
        note=note if note != "-" else "Admin balance adjustment",
        admin_id=update.effective_user.id,
    )
    await update.effective_message.reply_text(
        f"✅ Balance adjusted by *{amount:+.2f}*. New balance: "
        f"*{fmt_money(new_record['balance'])}*.",
        reply_markup=admin_user_view_keyboard(new_record),
        parse_mode="Markdown",
    )
    return -1


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@admin_only
async def admin_settings(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    db = get_db()
    settings = db.all_settings()
    await query.edit_message_text(
        "⚙️ *Bot settings*\n\nTap a setting to change it.",
        reply_markup=admin_settings_keyboard(settings),
        parse_mode="Markdown",
    )
    return -1


@admin_only
async def admin_setting_edit(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    key = query.data.split(":", 2)[2]
    db = get_db()
    current = db.get_setting(key, "")
    context.user_data["edit_setting"] = key
    pretty = {
        "min_deposit_usd": "Minimum deposit in USD (e.g. `10`)",
        "min_withdrawal_usd": "Minimum withdrawal in USD (e.g. `5`)",
        "referral_bonus_percent": "Referral bonus percentage (e.g. `5`)",
        "deduct_referral_from_investor": "Deduct referral from investor? `true`/`false`",
        "support_handle": "Support contact (e.g. `@admin`)",
        "maintenance_mode": "Maintenance mode? `true`/`false`",
        "welcome_message": "Welcome message (plain text)",
    }
    await query.edit_message_text(
        f"⚙️ *Edit* `{key}`\n\nCurrent value:\n`{current}`\n\n{pretty.get(key, '')}\n\n"
        f"Send the new value:",
        parse_mode="Markdown",
    )
    return State.ADMIN_EDIT_SETTING


@admin_only
async def admin_setting_save(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    key = context.user_data.pop("edit_setting", None)
    if not key:
        await update.effective_message.reply_text("Cancelled.")
        return -1
    value_raw = (update.effective_message.text or "").strip()
    db = get_db()
    casters = {
        "min_deposit_usd": float,
        "min_withdrawal_usd": float,
        "referral_bonus_percent": float,
    }
    bool_keys = {"deduct_referral_from_investor", "maintenance_mode"}
    try:
        if key in casters:
            value: Any = casters[key](value_raw)
        elif key in bool_keys:
            value = value_raw.lower() in {"1", "true", "yes", "on"}
        else:
            value = value_raw
    except ValueError:
        await update.effective_message.reply_text("❌ Invalid value.")
        return State.ADMIN_EDIT_SETTING
    db.set_setting(key, value, admin_id=update.effective_user.id)
    await update.effective_message.reply_text(
        f"✅ Setting `{key}` saved.",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("⬅️ Settings", callback_data=CB["admin_settings"])]]
        ),
    )
    return -1


# ---------------------------------------------------------------------------
# Broadcast
# ---------------------------------------------------------------------------


@admin_only
async def admin_broadcast_start(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(
        "📣 *Broadcast*\n\nSend the message you want to deliver to *all users*. "
        "It supports Markdown. The bot will skip users that have blocked it.",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Cancel", callback_data=CB["admin_home"])]]
        ),
        parse_mode="Markdown",
    )
    return State.ADMIN_BROADCAST


@admin_only
async def admin_broadcast_send(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> int:
    text = update.effective_message.text or ""
    db = get_db()
    users = db.query_all("SELECT user_id FROM users WHERE is_banned = 0")
    sent = 0
    failed = 0
    for u in users:
        try:
            await context.bot.send_message(chat_id=u["user_id"], text=text)
            sent += 1
        except Exception:
            failed += 1
        await asyncio.sleep(0.05)  # be gentle with Telegram's flood limits
    await update.effective_message.reply_text(
        f"📣 Broadcast complete. Sent: *{sent}*, failed: *{failed}*.",
        reply_markup=admin_home(),
        parse_mode="Markdown",
    )
    return -1
