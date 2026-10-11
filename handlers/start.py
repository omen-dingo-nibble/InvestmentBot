"""``/start``, ``/weblogin`` and top-level navigation — sign-up bonus + craving withdrawal."""
from __future__ import annotations

import logging
import os
from typing import Optional

from telegram import Update
from telegram.ext import ContextTypes

from config import CONFIG, BRAND_NAME, BRAND_TAGLINE, BRAND_WEBSITE, BRAND_SUPPORT
from database import get_db
from keyboards.user_kb import main_menu
from utils.decorators import is_admin_user, not_banned
from utils.formatters import fmt_money, fmt_user
from utils.security import log_user_action
from utils.states import CB

log = logging.getLogger(__name__)


def _resolve_referrer(start_arg: str) -> Optional[int]:
    if not start_arg:
        return None
    arg = start_arg.strip()
    if arg.startswith("ref_"):
        arg = arg[4:]
    elif arg.startswith("ref"):
        arg = arg[3:]
    if not arg:
        return None
    db = get_db()
    if arg.isdigit():
        return int(arg)
    row = db.query_one(
        "SELECT user_id FROM users WHERE referral_code = ?", (arg,)
    )
    return row["user_id"] if row else None


@not_banned
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user = update.effective_user
    if not user:
        return -1

    db = get_db()
    is_new_user = db.get_user(user.id) is None
    db.get_or_create_user(user.id, user.username or "", user.full_name or "")
    log_user_action(update, "start")

    # Handle referral deep-link
    args = context.args or []
    if args:
        ref_id = _resolve_referrer(args[0])
        if ref_id and ref_id != user.id:
            if db.set_referrer(user.id, ref_id):
                log.info("User %s referred by %s", user.id, ref_id)
                try:
                    bonus_pct = db.get_setting(
                        "referral_bonus_percent", CONFIG.referral_bonus_percent
                    )
                    await context.bot.send_message(
                        chat_id=ref_id,
                        text=(
                            f"🎉 Someone joined using your referral link!\n\n"
                            f"*{fmt_user(db.get_user(user.id))}* just signed up.\n"
                            f"You'll earn *{bonus_pct:.2f}%* on every investment they make. 💰"
                        ),
                        parse_mode="Markdown",
                    )
                except Exception:
                    pass

    support = db.get_setting("support_handle", BRAND_SUPPORT)
    maintenance = bool(db.get_setting("maintenance_mode", False))
    if maintenance and not is_admin_user(user.id):
        await update.effective_message.reply_text(
            "🛠 Under maintenance. Please check back shortly.\n"
            f"Contact: {support}"
        )
        return -1

    # ── Grant sign-up bonus to brand-new users ──────────────────────
    signup_bonus = float(db.get_setting("signup_bonus_php", 50))
    bonus_granted = False
    if is_new_user and signup_bonus > 0:
        bonus_granted = db.grant_signup_bonus(user.id, signup_bonus)

    record = db.get_user(user.id)
    welcome = db.get_setting("welcome_message", f"Welcome to {BRAND_NAME}!")
    min_wd = float(db.get_setting("min_withdrawal_usd", CONFIG.min_withdrawal_usd))

    # ── New user — bonus announcement ───────────────────────────────
    if bonus_granted:
        await update.effective_message.reply_text(
            f"🎉 *Welcome to {BRAND_NAME}!*\n"
            f"_{BRAND_TAGLINE}_\n\n"
            f"👋 Hey *{user.first_name or 'there'}* — great to have you!\n\n"
            f"🎁 *We just dropped ₱{signup_bonus:.0f} into your wallet as a welcome gift!*\n\n"
            f"That's real money — and it starts growing the moment you put it to work.\n\n"
            f"💡 *Here's the thing:* you can't withdraw until you reach "
            f"*{fmt_money(min_wd)}*. The fastest way there? "
            f"*Invest your bonus* and let it compound. "
            f"Our Foundation plan pays *1.5% daily* — your ₱50 becomes ₱55.25 in just 7 days.\n\n"
            f"🚀 Hit *Invest* below and put your bonus to work right now.",
            reply_markup=main_menu(is_admin=is_admin_user(user.id)),
            parse_mode="Markdown",
        )
        return -1

    # ── Returning user — show balance with withdrawal teaser ────────
    balance = record["balance"]
    total_invested = record["total_invested"]
    total_earned = record["total_earned"]

    # How close are they to the withdrawal minimum?
    gap = max(0.0, min_wd - balance)
    if gap > 0 and balance > 0:
        pct = int((balance / min_wd) * 100)
        progress_bar = "🟩" * (pct // 10) + "⬜" * (10 - pct // 10)
        withdrawal_tease = (
            f"\n\n💸 *Withdrawal progress:* {progress_bar} {pct}%\n"
            f"You need *{fmt_money(gap)} more* to unlock withdrawals.\n"
            f"Invest now and you'll be there before you know it. 🔓"
        )
    elif balance >= min_wd:
        withdrawal_tease = (
            f"\n\n✅ *You're eligible to withdraw!*\n"
            f"Hit 💸 Withdraw below anytime."
        )
    else:
        withdrawal_tease = ""

    text = (
        f"👷 *{BRAND_NAME}*\n"
        f"_{BRAND_TAGLINE}_\n\n"
        f"👋 Welcome back, *{user.first_name or 'Investor'}*!\n\n"
        f"{welcome}\n\n"
        f"💰 Balance: *{fmt_money(balance)}*\n"
        f"📈 Total invested: *{fmt_money(total_invested)}*\n"
        f"🪙 Total earned: *{fmt_money(total_earned)}*"
        f"{withdrawal_tease}\n\n"
        f"📞 Support: {support}"
    )
    await update.effective_message.reply_text(
        text,
        reply_markup=main_menu(is_admin=is_admin_user(user.id)),
        parse_mode="Markdown",
    )
    return -1


@not_banned
async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    if query:
        await query.answer()
        user = update.effective_user
        db = get_db()
        record = db.get_user(user.id)
        balance = record["balance"]
        min_wd = float(db.get_setting("min_withdrawal_usd", CONFIG.min_withdrawal_usd))
        gap = max(0.0, min_wd - balance)

        if gap > 0 and balance > 0:
            pct = int((balance / min_wd) * 100)
            progress_bar = "🟩" * (pct // 10) + "⬜" * (10 - pct // 10)
            wd_line = (
                f"\n💸 Withdrawal: {progress_bar} {pct}% "
                f"(*{fmt_money(gap)} to go*)"
            )
        elif balance >= min_wd:
            wd_line = "\n✅ *Ready to withdraw!*"
        else:
            wd_line = ""

        text = (
            f"🏠 *Main Menu*\n\n"
            f"💰 Balance: *{fmt_money(balance)}*\n"
            f"📈 Invested: *{fmt_money(record['total_invested'])}*\n"
            f"🪙 Earned: *{fmt_money(record['total_earned'])}*"
            f"{wd_line}"
        )
        await query.edit_message_text(
            text,
            reply_markup=main_menu(is_admin=is_admin_user(user.id)),
            parse_mode="Markdown",
        )
        return -1

    return await start(update, context)


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    if query:
        await query.answer("Cancelled.")
        await show_main_menu(update, context)
        return -1
    if update.effective_message:
        await update.effective_message.reply_text(
            "Cancelled.", reply_markup=main_menu()
        )
    return -1


@not_banned
async def weblogin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Send a one-time login link to access the web investment dashboard."""
    user = update.effective_user
    if not user:
        return -1

    db = get_db()
    record = db.get_user(user.id)
    if not record:
        await update.effective_message.reply_text(
            "Please use /start first to create your account.",
        )
        return -1

    # Generate a one-time token (5 min TTL)
    token = db.create_web_login_token(user.id, ttl_seconds=300)

    # Build the web URL from environment or a sensible default
    web_host = os.environ.get("WEB_HOST_URL", "http://localhost:5000")
    login_url = f"{web_host}/app/auth?token={token}"

    await update.effective_message.reply_text(
        f"🌐 *Your Dashboard Login Link*\n\n"
        f"Tap the link below to open your Gyokuro investment dashboard:\n\n"
        f"{login_url}\n\n"
        f"⏱ *This link expires in 5 minutes* and can only be used once.\n\n"
        f"💡 If the link expires, just send /weblogin again.",
        parse_mode="Markdown",
        disable_web_page_preview=True,
    )
    return -1
