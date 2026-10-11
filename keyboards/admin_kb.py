"""Inline keyboards presented to admins."""
from __future__ import annotations

from typing import Any, Dict, List

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from utils.states import CB


def admin_home() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📊 Statistics", callback_data=CB["admin_stats"]),
         InlineKeyboardButton("📦 Investment Plans", callback_data=CB["admin_plans"])],
        [InlineKeyboardButton("💰 Pending Deposits", callback_data=CB["admin_deposits"]),
         InlineKeyboardButton("💸 Pending Withdrawals", callback_data=CB["admin_withdrawals"])],
        [InlineKeyboardButton("👥 Users", callback_data=CB["admin_users"]),
         InlineKeyboardButton("⚙️ Settings", callback_data=CB["admin_settings"])],
        [InlineKeyboardButton("📣 Broadcast", callback_data=CB["admin_broadcast"])],
        [InlineKeyboardButton("⬅️ Main Menu", callback_data=CB["main_menu"])],
    ])


def admin_plans_keyboard(plans: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = []
    for plan in plans:
        status = "🟢" if plan["is_active"] else "🔴"
        rows.append([InlineKeyboardButton(
            f"{status} {plan['name']} — {plan['daily_roi_percent']}% / {plan['duration_days']}d",
            callback_data=f"PLAN_VIEW:{plan['id']}",
        )])
    rows.append([InlineKeyboardButton("➕ New Plan", callback_data=CB["admin_plan_new"])])
    rows.append([InlineKeyboardButton("⬅️ Admin Home", callback_data=CB["admin_home"])])
    return InlineKeyboardMarkup(rows)


def admin_plan_view_keyboard(plan: Dict[str, Any]) -> InlineKeyboardMarkup:
    toggle_label = "🔴 Deactivate" if plan["is_active"] else "🟢 Activate"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(
            toggle_label,
            callback_data=f"{CB['admin_plan_toggle']}{plan['id']}",
        )],
        [InlineKeyboardButton(
            "🗑 Delete Plan",
            callback_data=f"{CB['admin_plan_delete']}{plan['id']}",
        )],
        [InlineKeyboardButton("⬅️ Back to Plans", callback_data=CB["admin_plans"])],
    ])


def admin_pending_deposits_keyboard(items: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = []
    for tx in items[:8]:  # cap visible rows
        user = tx.get("user_id")
        rows.append([InlineKeyboardButton(
            f"#{tx['id']} · user {user} · {tx['amount']:.2f} {tx.get('crypto_currency') or ''}",
            callback_data=f"DEP_VIEW:{tx['id']}",
        )])
    rows.append([InlineKeyboardButton("🔄 Refresh", callback_data=CB["admin_deposits"])])
    rows.append([InlineKeyboardButton("⬅️ Admin Home", callback_data=CB["admin_home"])])
    return InlineKeyboardMarkup(rows)


def admin_deposit_actions_keyboard(tx_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Approve", callback_data=f"{CB['admin_deposit_approve']}{tx_id}"),
         InlineKeyboardButton("❌ Reject", callback_data=f"{CB['admin_deposit_reject']}{tx_id}")],
        [InlineKeyboardButton("⬅️ Back", callback_data=CB["admin_deposits"])],
    ])


def admin_pending_withdrawals_keyboard(items: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = []
    for tx in items[:8]:
        rows.append([InlineKeyboardButton(
            f"#{tx['id']} · user {tx['user_id']} · {tx['amount']:.2f}",
            callback_data=f"WD_VIEW:{tx['id']}",
        )])
    rows.append([InlineKeyboardButton("🔄 Refresh", callback_data=CB["admin_withdrawals"])])
    rows.append([InlineKeyboardButton("⬅️ Admin Home", callback_data=CB["admin_home"])])
    return InlineKeyboardMarkup(rows)


def admin_withdrawal_actions_keyboard(tx_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Approve & Mark Paid", callback_data=f"{CB['admin_withdrawal_approve']}{tx_id}"),
         InlineKeyboardButton("❌ Reject", callback_data=f"{CB['admin_withdrawal_reject']}{tx_id}")],
        [InlineKeyboardButton("⬅️ Back", callback_data=CB["admin_withdrawals"])],
    ])


def admin_users_keyboard(users: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = []
    for u in users:
        banned = "🚫" if u.get("is_banned") else ""
        label = f"{banned}{u.get('full_name') or u.get('username') or u['user_id']} (`{u['user_id']}`)"
        rows.append([InlineKeyboardButton(
            label, callback_data=f"{CB['admin_user_view']}{u['user_id']}"
        )])
    rows.append([InlineKeyboardButton("🔄 Refresh", callback_data=CB["admin_users"])])
    rows.append([InlineKeyboardButton("⬅️ Admin Home", callback_data=CB["admin_home"])])
    return InlineKeyboardMarkup(rows)


def admin_user_view_keyboard(user: Dict[str, Any]) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("💱 Adjust Balance", callback_data=f"{CB['admin_user_adjust']}{user['user_id']}")],
    ]
    if user.get("is_banned"):
        rows.append([InlineKeyboardButton("✅ Unban User", callback_data=f"{CB['admin_user_unban']}{user['user_id']}")])
    else:
        rows.append([InlineKeyboardButton("🚫 Ban User", callback_data=f"{CB['admin_user_ban']}{user['user_id']}")])
    rows.append([InlineKeyboardButton("⬅️ Back", callback_data=CB["admin_users"])])
    return InlineKeyboardMarkup(rows)


def admin_settings_keyboard(settings: Dict[str, Any]) -> InlineKeyboardMarkup:
    pretty = {
        "min_deposit_usd": "💵 Min deposit (USD)",
        "min_withdrawal_usd": "💸 Min withdrawal (USD)",
        "referral_bonus_percent": "🎁 Referral bonus (%)",
        "deduct_referral_from_investor": "➖ Deduct referral from investor?",
        "support_handle": "📞 Support handle",
        "maintenance_mode": "🛠 Maintenance mode",
        "welcome_message": "👋 Welcome message",
    }
    rows = []
    for key, label in pretty.items():
        value = settings.get(key, "-")
        if isinstance(value, bool):
            value = "On" if value else "Off"
        rows.append([InlineKeyboardButton(
            f"{label}: {value}",
            callback_data=f"{CB['admin_setting_edit']}{key}",
        )])
    rows.append([InlineKeyboardButton("⬅️ Admin Home", callback_data=CB["admin_home"])])
    return InlineKeyboardMarkup(rows)
