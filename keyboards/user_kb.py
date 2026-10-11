"""Inline keyboards presented to investors."""
from __future__ import annotations

from typing import Any, Dict, List

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from utils.states import CB


def main_menu(is_admin: bool = False, web_url: str = "") -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("💼 Wallet", callback_data=CB["deposit"]),
         InlineKeyboardButton("📈 Invest", callback_data=CB["invest"])],
        [InlineKeyboardButton("💸 Withdraw", callback_data=CB["withdraw"]),
         InlineKeyboardButton("👥 Referral", callback_data=CB["referral"])],
        [InlineKeyboardButton("📊 My Investments", callback_data=CB["my_investments"]),
         InlineKeyboardButton("🧾 History", callback_data=CB["history"])],
    ]
    if web_url:
        rows.append([InlineKeyboardButton("🌐 Open Web Dashboard", url=web_url)])
    if is_admin:
        rows.append([InlineKeyboardButton("🛠 Admin Dashboard", callback_data=CB["admin_home"])])
    rows.append([InlineKeyboardButton("🔄 Refresh", callback_data=CB["main_menu"])])
    return InlineKeyboardMarkup(rows)


def back_to_main() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("⬅️ Back to Menu", callback_data=CB["main_menu"])]]
    )


def deposit_currency_keyboard(currencies: List[str]) -> InlineKeyboardMarkup:
    rows = []
    icons = {"BTC": "🟠", "ETH": "🔵", "USDT-TRC20": "🟢", "USDT-ERC20": "🟡", "LTC": "⚪"}
    for cur in currencies:
        icon = icons.get(cur, "💱")
        rows.append([InlineKeyboardButton(
            f"{icon} {cur}", callback_data=f"{CB['deposit_currency']}{cur}"
        )])
    rows.append([InlineKeyboardButton("⬅️ Back", callback_data=CB["main_menu"])])
    return InlineKeyboardMarkup(rows)


def plans_keyboard(plans: List[Dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = []
    for plan in plans:
        label = (
            f"📦 {plan['name']} — "
            f"{plan['daily_roi_percent']}% / {plan['duration_days']}d"
        )
        rows.append([InlineKeyboardButton(
            label, callback_data=f"{CB['invest_plan']}{plan['id']}"
        )])
    rows.append([InlineKeyboardButton("⬅️ Back", callback_data=CB["main_menu"])])
    return InlineKeyboardMarkup(rows)


def confirm_keyboard(yes_cb: str, no_cb: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Confirm", callback_data=yes_cb),
         InlineKeyboardButton("❌ Cancel", callback_data=no_cb)],
    ])


def cancel_keyboard(cancel_cb: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("❌ Cancel", callback_data=cancel_cb)],
    ])
