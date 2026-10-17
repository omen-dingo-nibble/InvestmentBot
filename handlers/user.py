"""Investor-facing conversation handlers — PHP (₱) only."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

from config import CONFIG, BRAND_NAME, BRAND_SUPPORT
from database import get_db
from keyboards.user_kb import (
    back_to_main,
    confirm_keyboard,
    cancel_keyboard,
    deposit_currency_keyboard,
    plans_keyboard,
    withdraw_method_keyboard,
)
from utils.decorators import not_banned
from utils.formatters import fmt_money, fmt_percent, fmt_short_date, fmt_user, truncate
from utils.helpers import looks_like_tx_hash, parse_amount
from utils.security import log_user_action
from utils.states import CB, State

log = logging.getLogger(__name__)

QR_DIR = Path(__file__).resolve().parent.parent / "web" / "static" / "qr"


# ---------------------------------------------------------------------------
# Wallet / history
# ---------------------------------------------------------------------------

@not_banned
async def wallet(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    user = update.effective_user
    db = get_db()
    record = db.get_user(user.id)
    recent = db.list_transactions(user_id=user.id, limit=5)

    lines = [
        "💼 *Your Wallet*",
        "",
        f"💰 Balance: *{fmt_money(record['balance'])}*",
        f"📥 Total deposited: *{fmt_money(record['total_deposited'])}*",
        f"📤 Total withdrawn: *{fmt_money(record['total_withdrawn'])}*",
        f"📈 Total invested: *{fmt_money(record['total_invested'])}*",
        f"🪙 Total earned: *{fmt_money(record['total_earned'])}*",
    ]

    # Withdrawal progress tease
    db2 = get_db()
    min_wd = float(db2.get_setting("min_withdrawal_usd", CONFIG.min_withdrawal_usd))
    balance = record["balance"]
    gap = max(0.0, min_wd - balance)
    if balance < min_wd and balance > 0:
        pct = int((balance / min_wd) * 100)
        progress_bar = "🟩" * (pct // 10) + "⬜" * (10 - pct // 10)
        lines += [
            "",
            f"🔒 *Withdrawal unlocks at {fmt_money(min_wd)}*",
            f"{progress_bar} {pct}% — only *{fmt_money(gap)} to go!*",
            f"💡 Invest and earn your way there faster.",
        ]
    elif balance >= min_wd:
        lines += ["", f"✅ *Withdrawal available!* Tap 💸 Withdraw below."]

    lines += ["", "*Recent activity*"]
    if not recent:
        lines.append("_No transactions yet._")
    else:
        for tx in recent:
            sign = "+" if tx["amount"] > 0 else ""
            lines.append(
                f"`#{tx['id']}` {tx['tx_type']:<11} "
                f"{sign}₱{abs(tx['amount']):,.2f} · "
                f"{tx['status']} · {fmt_short_date(tx['created_at'])}"
            )

    markup = InlineKeyboardMarkup([
        [InlineKeyboardButton("💳 Add Funds", callback_data=CB["deposit"])],
        [InlineKeyboardButton("📈 Invest", callback_data=CB["invest"]),
         InlineKeyboardButton("💸 Withdraw", callback_data=CB["withdraw"])],
        [InlineKeyboardButton("⬅️ Back to Menu", callback_data=CB["main_menu"])],
    ])
    await query.edit_message_text("\n".join(lines), reply_markup=markup, parse_mode="Markdown")
    return -1


@not_banned
async def history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    user = update.effective_user
    db = get_db()
    items = db.list_transactions(user_id=user.id, limit=20)
    if not items:
        await query.edit_message_text(
            "🧾 *Transaction history*\n\nNo transactions yet.",
            reply_markup=back_to_main(), parse_mode="Markdown",
        )
        return -1
    lines = ["🧾 *Last 20 transactions*", ""]
    for tx in items:
        sign = "+" if tx["amount"] > 0 else ""
        lines.append(
            f"`#{tx['id']}` *{tx['tx_type']}* — "
            f"{sign}₱{abs(tx['amount']):,.2f}\n"
            f"   status: {tx['status']} · {fmt_short_date(tx['created_at'])}"
        )
    await query.edit_message_text(
        truncate("\n".join(lines), 3800),
        reply_markup=back_to_main(), parse_mode="Markdown",
    )
    return -1


# ---------------------------------------------------------------------------
# Deposit flow
# ---------------------------------------------------------------------------

@not_banned
async def deposit_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    log_user_action(update, "deposit_start")
    context.user_data.pop("deposit", None)
    db = get_db()
    crypto_map = CONFIG.crypto.as_dict()
    # Key mapping from CONFIG symbol → settings key
    _enabled_key_map = {
        "BTC": "crypto_btc_enabled",
        "ETH": "crypto_eth_enabled",
        "USDT-TRC20": "crypto_usdt_trc20_enabled",
        "USDT-ERC20": "crypto_usdt_erc20_enabled",
        "LTC": "crypto_ltc_enabled",
    }
    # Only show currencies that have an address AND are enabled in admin settings
    available = [
        k for k, v in crypto_map.items()
        if v and str(db.get_setting(_enabled_key_map.get(k, ""), "1")).strip() not in ("0", "false", "False")
    ]
    if not available:
        await query.edit_message_text(
            "⚠️ No payment addresses configured yet. Please contact support.",
            reply_markup=back_to_main(),
        )
        return -1
    min_dep = float(db.get_setting("min_deposit_usd", CONFIG.min_deposit_usd))
    await query.edit_message_text(
        f"💳 *Add Funds*\n\n"
        f"Select the crypto you want to send.\n"
        f"Minimum deposit: *{fmt_money(min_dep)}*\n\n"
        f"After paying, upload your receipt screenshot or paste the TX hash.",
        reply_markup=deposit_currency_keyboard(available),
        parse_mode="Markdown",
    )
    return State.DEPOSIT_SELECT_CURRENCY


@not_banned
async def deposit_select_currency(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    currency = query.data.split(":", 2)[2]
    wallet_addr = CONFIG.crypto.as_dict().get(currency, "")
    if not wallet_addr:
        await query.edit_message_text(
            f"⚠️ Address for {currency} not configured. Contact support.",
            reply_markup=back_to_main(),
        )
        return -1
    context.user_data["deposit"] = {"currency": currency, "address": wallet_addr}
    db = get_db()
    min_dep = float(db.get_setting("min_deposit_usd", CONFIG.min_deposit_usd))

    network_note = ""
    if "TRC20" in currency:
        network_note = "\n\n⚠️ Send *USDT-TRC20 only*. Any other network = permanent loss."
    elif "ERC20" in currency:
        network_note = "\n\n⚠️ Send *USDT-ERC20 only* (Ethereum gas fees apply)."

    text = (
        f"💳 *Deposit via {currency}*\n\n"
        f"Send to this address:\n\n"
        f"`{wallet_addr}`{network_note}\n\n"
        f"Minimum: *{fmt_money(min_dep)}*\n\n"
        f"After paying, enter the *amount in ₱ PHP* you deposited."
    )

    # Send QR code if available
    qr_map = CONFIG.crypto.qr_dict()
    qr_file = qr_map.get(currency, "")
    qr_path = QR_DIR / qr_file if qr_file else None
    if qr_path and qr_path.exists():
        try:
            await query.message.reply_photo(
                photo=open(qr_path, "rb"),
                caption=f"📲 Scan to pay via {currency}",
            )
        except Exception as e:
            log.debug("Could not send QR for %s: %s", currency, e)

    await query.edit_message_text(
        text,
        reply_markup=cancel_keyboard(CB["main_menu"]),
        parse_mode="Markdown",
    )
    return State.DEPOSIT_ENTER_AMOUNT


@not_banned
async def deposit_enter_amount(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = (update.effective_message.text or "").strip()
    amount = parse_amount(text)
    db = get_db()
    min_dep = float(db.get_setting("min_deposit_usd", CONFIG.min_deposit_usd))
    if amount is None or amount <= 0:
        await update.effective_message.reply_text(
            "❌ Invalid amount. Enter a number e.g. `500` or `1000`.",
            reply_markup=cancel_keyboard(CB["main_menu"]),
            parse_mode="Markdown",
        )
        return State.DEPOSIT_ENTER_AMOUNT
    if amount < min_dep:
        await update.effective_message.reply_text(
            f"❌ Minimum deposit is *{fmt_money(min_dep)}*. Enter a larger amount.",
            reply_markup=cancel_keyboard(CB["main_menu"]),
            parse_mode="Markdown",
        )
        return State.DEPOSIT_ENTER_AMOUNT

    context.user_data["deposit"]["amount"] = amount
    dep = context.user_data["deposit"]
    await update.effective_message.reply_text(
        f"Got it — *{fmt_money(amount)}* via {dep['currency']}.\n\n"
        f"Now *upload a screenshot* of the transaction or paste the *TX hash*.",
        reply_markup=cancel_keyboard(CB["main_menu"]),
        parse_mode="Markdown",
    )
    return State.DEPOSIT_UPLOAD_RECEIPT


async def _finalise_deposit_request(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
    receipt_file_id: Optional[str], tx_hash: Optional[str],
) -> int:
    dep = context.user_data.get("deposit", {})
    user = update.effective_user
    db = get_db()
    if not dep:
        await update.effective_message.reply_text("Deposit cancelled.", reply_markup=back_to_main())
        return -1

    tx_id = db.create_transaction(
        user_id=user.id,
        tx_type="deposit",
        amount=float(dep["amount"]),
        status="pending",
        currency="PHP",
        crypto_currency=dep.get("currency"),
        network=(
            "TRC20" if "TRC20" in dep.get("currency", "")
            else "ERC20" if "ERC20" in dep.get("currency", "")
            else dep.get("currency")
        ),
        wallet_address=dep.get("address"),
        tx_hash=tx_hash,
        receipt_file_id=receipt_file_id,
        note=f"Deposit via {dep.get('currency')}",
    )
    context.user_data.pop("deposit", None)

    admin_text = (
        f"💰 *New deposit request* `#{tx_id}`\n\n"
        f"User: {fmt_user(db.get_user(user.id))}\n"
        f"Amount: *{fmt_money(dep['amount'])}*\n"
        f"Crypto: {dep.get('currency')}\n"
        f"TX hash: `{tx_hash or '-'}`\n"
    )
    from keyboards.admin_kb import admin_deposit_actions_keyboard
    for admin_id in CONFIG.admin_ids:
        try:
            await context.bot.send_message(chat_id=admin_id, text=admin_text, parse_mode="Markdown")
            if receipt_file_id:
                try:
                    await context.bot.send_photo(chat_id=admin_id, photo=receipt_file_id,
                                                  caption=f"Receipt for deposit #{tx_id}")
                except Exception:
                    await context.bot.send_document(chat_id=admin_id, document=receipt_file_id,
                                                     caption=f"Receipt for deposit #{tx_id}")
            await context.bot.send_message(
                chat_id=admin_id,
                text=f"Approve or reject deposit `#{tx_id}`:",
                reply_markup=admin_deposit_actions_keyboard(tx_id),
                parse_mode="Markdown",
            )
        except Exception as e:
            log.warning("Failed to notify admin %s: %s", admin_id, e)

    await update.effective_message.reply_text(
        f"✅ Deposit request *#{tx_id}* submitted!\n\n"
        f"Amount: *{fmt_money(dep['amount'])}*\n"
        f"The admin will review and credit your balance shortly.",
        reply_markup=back_to_main(),
        parse_mode="Markdown",
    )
    return -1


@not_banned
async def deposit_receive_receipt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    msg = update.effective_message
    receipt_file_id = None
    if msg.photo:
        receipt_file_id = msg.photo[-1].file_id
    elif msg.document:
        receipt_file_id = msg.document.file_id
    elif msg.text:
        if not looks_like_tx_hash(msg.text.strip()):
            await msg.reply_text(
                "❌ Doesn't look like a valid TX hash. Send a photo/doc or paste a hash (20+ chars).",
                reply_markup=cancel_keyboard(CB["main_menu"]),
            )
            return State.DEPOSIT_UPLOAD_RECEIPT
        return await _finalise_deposit_request(update, context, receipt_file_id=None, tx_hash=msg.text.strip())
    if not receipt_file_id:
        await msg.reply_text("Please upload a photo or document of the receipt.",
                              reply_markup=cancel_keyboard(CB["main_menu"]))
        return State.DEPOSIT_UPLOAD_RECEIPT
    return await _finalise_deposit_request(update, context, receipt_file_id=receipt_file_id, tx_hash=None)


# ---------------------------------------------------------------------------
# Investment flow
# ---------------------------------------------------------------------------

@not_banned
async def invest_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    log_user_action(update, "invest_start")
    db = get_db()
    plans = db.list_plans(active_only=True)
    if not plans:
        await query.edit_message_text("📦 No active plans right now. Check back later.", reply_markup=back_to_main())
        return -1
    lines = ["📦 *Gyokuro Investment Plans*\n"]
    for p in plans:
        lines.append(
            f"🔨 *{p['name']}* — {fmt_percent(p['daily_roi_percent'])} daily · {p['duration_days']}d\n"
            f"   Min: *{fmt_money(p['min_amount'])}*"
        )
    lines.append("\nPick a plan to continue.")
    await query.edit_message_text("\n".join(lines), reply_markup=plans_keyboard(plans), parse_mode="Markdown")
    return State.INVEST_SELECT_PLAN


@not_banned
async def invest_select_plan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    plan_id = int(query.data.split(":", 2)[2])
    db = get_db()
    plan = db.get_plan(plan_id)
    if not plan or not plan["is_active"]:
        await query.edit_message_text("That plan is no longer available.", reply_markup=back_to_main())
        return -1
    context.user_data["invest"] = {"plan_id": plan_id}
    user_record = db.get_user(update.effective_user.id)
    lines = [
        f"🔨 *{plan['name']}*",
        plan.get("description") or "",
        "",
        f"• Daily ROI: *{fmt_percent(plan['daily_roi_percent'])}*",
        f"• Duration: *{plan['duration_days']} days*",
        f"• Range: *{fmt_money(plan['min_amount'])} – {fmt_money(plan['max_amount'])}*",
        f"• Capital returned: *{'Yes' if plan['capital_return'] else 'No'}*",
        "",
        f"💰 Your balance: *{fmt_money(user_record['balance'])}*",
        "",
        f"Enter the amount in ₱ PHP to invest (min {fmt_money(plan['min_amount'])}).",
    ]
    await query.edit_message_text(
        "\n".join(lines), reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown"
    )
    return State.INVEST_ENTER_AMOUNT


@not_banned
async def invest_enter_amount(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = (update.effective_message.text or "").strip()
    amount = parse_amount(text)
    ctx = context.user_data.get("invest", {})
    if not ctx or "plan_id" not in ctx:
        await update.effective_message.reply_text("Session expired. Use /start.", reply_markup=back_to_main())
        return -1
    db = get_db()
    plan = db.get_plan(ctx["plan_id"])
    if not plan:
        await update.effective_message.reply_text("Plan not found.", reply_markup=back_to_main())
        return -1
    user_record = db.get_user(update.effective_user.id)
    if amount is None or amount <= 0:
        await update.effective_message.reply_text(
            "❌ Invalid amount. Enter e.g. `1000`.",
            reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown"
        )
        return State.INVEST_ENTER_AMOUNT
    if amount < plan["min_amount"]:
        await update.effective_message.reply_text(
            f"❌ Minimum is *{fmt_money(plan['min_amount'])}*.",
            reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown"
        )
        return State.INVEST_ENTER_AMOUNT
    if amount > plan["max_amount"]:
        await update.effective_message.reply_text(
            f"❌ Maximum is *{fmt_money(plan['max_amount'])}*.",
            reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown"
        )
        return State.INVEST_ENTER_AMOUNT
    if amount > user_record["balance"]:
        await update.effective_message.reply_text(
            f"❌ Insufficient balance. You have *{fmt_money(user_record['balance'])}*.",
            reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown"
        )
        return State.INVEST_ENTER_AMOUNT

    ctx["amount"] = amount
    expected_total = round(amount * (1 + plan["daily_roi_percent"] / 100.0 * plan["duration_days"]), 2)
    await update.effective_message.reply_text(
        f"📝 *Confirm Investment*\n\n"
        f"Plan: *{plan['name']}*\n"
        f"Principal: *{fmt_money(amount)}*\n"
        f"Daily ROI: *{fmt_percent(plan['daily_roi_percent'])}* × *{plan['duration_days']} days*\n"
        f"Expected total return: *{fmt_money(expected_total)}*\n"
        f"Capital returned: *{'Yes' if plan['capital_return'] else 'No'}*\n\n"
        f"Proceed?",
        reply_markup=confirm_keyboard("INVEST:YES", "INVEST:NO"),
        parse_mode="Markdown",
    )
    return State.INVEST_CONFIRM


async def invest_confirm_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    decision = query.data.split(":", 1)[1]
    user = update.effective_user
    db = get_db()
    ctx = context.user_data.get("invest", {})
    if decision == "NO" or not ctx:
        context.user_data.pop("invest", None)
        await query.edit_message_text("Investment cancelled.", reply_markup=back_to_main())
        return -1
    plan = db.get_plan(ctx["plan_id"])
    amount = float(ctx.get("amount", 0))
    if not plan or amount <= 0:
        await query.edit_message_text("Could not find plan. Cancelled.", reply_markup=back_to_main())
        return -1
    record = db.get_user(user.id)
    if record["balance"] < amount:
        await query.edit_message_text(
            f"❌ Insufficient balance ({fmt_money(record['balance'])}).", reply_markup=back_to_main()
        )
        return -1

    inv = db.create_investment(user.id, plan, amount)
    context.user_data.pop("invest", None)

    if record.get("referred_by"):
        bonus_pct = float(db.get_setting("referral_bonus_percent", CONFIG.referral_bonus_percent))
        bonus = round(amount * bonus_pct / 100.0, 2)
        if bonus > 0:
            try:
                await context.bot.send_message(
                    chat_id=record["referred_by"],
                    text=f"🎁 You earned *{fmt_money(bonus)}* referral bonus from {fmt_user(record)}'s investment!",
                    parse_mode="Markdown",
                )
            except Exception:
                pass

    await query.edit_message_text(
        f"✅ *Investment #{inv['id']} created!*\n\n"
        f"Plan: *{plan['name']}*\n"
        f"Principal: *{fmt_money(amount)}*\n"
        f"Daily ROI: *{fmt_percent(plan['daily_roi_percent'])}* for *{plan['duration_days']} days*\n\n"
        f"Use 'My Investments' to track progress.",
        reply_markup=back_to_main(), parse_mode="Markdown",
    )
    return -1


# ---------------------------------------------------------------------------
# My investments
# ---------------------------------------------------------------------------

@not_banned
async def my_investments(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    db = get_db()
    user = update.effective_user
    items = db.list_investments(user_id=user.id, limit=20)
    if not items:
        await query.edit_message_text(
            "📊 *My Investments*\n\nYou have no active investments yet.",
            reply_markup=back_to_main(), parse_mode="Markdown",
        )
        return -1
    lines = ["📊 *Your Investments*", ""]
    for inv in items:
        accrued = db.compute_investment_earnings_to_date(inv)
        total_due = accrued + (inv["principal"] if inv["capital_return"] else 0)
        lines.append(
            f"• `#{inv['id']}` *{inv['plan_name']}* — {inv['status']}\n"
            f"   Principal: {fmt_money(inv['principal'])} · "
            f"Earned: {fmt_money(accrued)} · "
            f"Payout: {fmt_money(total_due)}\n"
            f"   {fmt_short_date(inv['started_at'])} → {fmt_short_date(inv['expires_at'])}"
        )
    await query.edit_message_text(
        truncate("\n".join(lines), 3800),
        reply_markup=back_to_main(), parse_mode="Markdown",
    )
    return -1


# ---------------------------------------------------------------------------
# Withdraw
# ---------------------------------------------------------------------------

def _get_withdraw_methods(db) -> tuple[bool, bool, bool]:
    """Return (gcash_on, maya_on, crypto_on) based on admin settings.

    crypto_on is True if at least one crypto currency has both an address
    configured AND is not disabled in admin settings.
    """
    gcash_on = str(db.get_setting("gcash_enabled", "0")).strip() in ("1", "true", "True")
    maya_on  = str(db.get_setting("maya_enabled",  "0")).strip() in ("1", "true", "True")
    # Build the same key mapping used by the deposit flow
    _key_map = {
        "BTC": "crypto_btc_enabled",
        "ETH": "crypto_eth_enabled",
        "USDT-TRC20": "crypto_usdt_trc20_enabled",
        "USDT-ERC20": "crypto_usdt_erc20_enabled",
        "LTC": "crypto_ltc_enabled",
    }
    crypto_on = False
    for symbol, addr in CONFIG.crypto.as_dict().items():
        enabled_key = _key_map.get(symbol, "")
        is_enabled = str(db.get_setting(enabled_key, "1")).strip() not in ("0", "false", "False")
        if addr and is_enabled:
            crypto_on = True
            break
    return gcash_on, maya_on, crypto_on


@not_banned
async def withdraw_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    log_user_action(update, "withdraw_start")
    db = get_db()
    record = db.get_user(update.effective_user.id)
    min_wd = float(db.get_setting("min_withdrawal_usd", CONFIG.min_withdrawal_usd))
    balance = record["balance"]
    gap = max(0.0, min_wd - balance)

    # Not enough — show the progress tease instead of the form
    if balance < min_wd:
        pct = int((balance / min_wd) * 100) if balance > 0 else 0
        progress_bar = "🟩" * (pct // 10) + "⬜" * (10 - pct // 10)

        plans = db.list_plans(active_only=True)
        tease_plan = plans[0] if plans else None
        days_hint = ""
        if tease_plan and balance >= tease_plan["min_amount"]:
            daily_earn = balance * tease_plan["daily_roi_percent"] / 100
            if daily_earn > 0:
                days_needed = int(gap / daily_earn) + 1
                days_hint = (
                    f"\n\n⚡ *Quick math:* invest your *{fmt_money(balance)}* "
                    f"in the *{tease_plan['name']}* plan "
                    f"({tease_plan['daily_roi_percent']}%/day) and you'll hit "
                    f"the withdrawal limit in about *{days_needed} day{'s' if days_needed != 1 else ''}*."
                )

        await query.edit_message_text(
            f"💸 *Withdrawal*\n\n"
            f"Your balance: *{fmt_money(balance)}*\n"
            f"Minimum to withdraw: *{fmt_money(min_wd)}*\n\n"
            f"Progress: {progress_bar} *{pct}%*\n"
            f"You're *{fmt_money(gap)} away* from your first withdrawal. 🔒"
            f"{days_hint}\n\n"
            f"💡 Invest your balance and let it grow daily. "
            f"Every peso earns — tap *📈 Invest* to unlock withdrawals faster.",
            reply_markup=back_to_main(),
            parse_mode="Markdown",
        )
        return -1

    gcash_on, maya_on, crypto_on = _get_withdraw_methods(db)
    if not gcash_on and not maya_on and not crypto_on:
        await query.edit_message_text(
            "⚠️ No withdrawal methods are currently available. Please contact support.",
            reply_markup=back_to_main(),
        )
        return -1

    # Only one method available → skip the picker and go straight to amount
    total_methods = sum([gcash_on, maya_on, crypto_on])
    if total_methods == 1:
        single = "GCASH" if gcash_on else ("MAYA" if maya_on else "CRYPTO")
        context.user_data["withdraw"] = {"method": single}
        await query.edit_message_text(
            f"💸 *Withdraw Funds*\n\n"
            f"Balance: *{fmt_money(balance)}*\n"
            f"Minimum withdrawal: *{fmt_money(min_wd)}*\n\n"
            f"Enter the amount in ₱ PHP to withdraw.",
            reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown",
        )
        return State.WITHDRAW_ENTER_AMOUNT

    # Multiple methods → show the picker first
    context.user_data.pop("withdraw", None)
    await query.edit_message_text(
        f"💸 *Withdraw Funds*\n\n"
        f"Balance: *{fmt_money(balance)}*\n\n"
        f"Select your withdrawal method:",
        reply_markup=withdraw_method_keyboard(gcash_on, maya_on, crypto_on, CB["main_menu"]),
        parse_mode="Markdown",
    )
    return State.WITHDRAW_SELECT_METHOD


@not_banned
async def withdraw_select_method(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle the user tapping a withdrawal method button."""
    query = update.callback_query
    await query.answer()
    method = query.data.split(":", 2)[2].upper()  # GCASH | MAYA | CRYPTO
    db = get_db()
    record = db.get_user(update.effective_user.id)
    min_wd = float(db.get_setting("min_withdrawal_usd", CONFIG.min_withdrawal_usd))
    balance = record["balance"]

    # Security: verify the chosen method is still enabled
    gcash_on, maya_on, crypto_on = _get_withdraw_methods(db)
    method_ok = (
        (method == "GCASH" and gcash_on)
        or (method == "MAYA" and maya_on)
        or (method == "CRYPTO" and crypto_on)
    )
    if not method_ok:
        await query.edit_message_text(
            "⚠️ That withdrawal method is not available. Please try again.",
            reply_markup=back_to_main(),
        )
        return -1

    context.user_data["withdraw"] = {"method": method}
    await query.edit_message_text(
        f"💸 *Withdraw via {'GCash 📱' if method == 'GCASH' else 'Maya 💜' if method == 'MAYA' else 'Crypto ₿'}*\n\n"
        f"Balance: *{fmt_money(balance)}*\n"
        f"Minimum withdrawal: *{fmt_money(min_wd)}*\n\n"
        f"Enter the amount in ₱ PHP to withdraw.",
        reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown",
    )
    return State.WITHDRAW_ENTER_AMOUNT


@not_banned
async def withdraw_enter_amount(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    amount = parse_amount(update.effective_message.text or "")
    db = get_db()
    min_wd = float(db.get_setting("min_withdrawal_usd", CONFIG.min_withdrawal_usd))
    user_record = db.get_user(update.effective_user.id)
    if amount is None or amount <= 0:
        await update.effective_message.reply_text("❌ Invalid amount.", reply_markup=cancel_keyboard(CB["main_menu"]))
        return State.WITHDRAW_ENTER_AMOUNT
    if amount < min_wd:
        await update.effective_message.reply_text(
            f"❌ Minimum withdrawal is *{fmt_money(min_wd)}*.",
            reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown",
        )
        return State.WITHDRAW_ENTER_AMOUNT
    if amount > user_record["balance"]:
        await update.effective_message.reply_text(
            f"❌ Insufficient balance ({fmt_money(user_record['balance'])}).",
            reply_markup=cancel_keyboard(CB["main_menu"]),
        )
        return State.WITHDRAW_ENTER_AMOUNT
    context.user_data.setdefault("withdraw", {})["amount"] = amount
    method = context.user_data["withdraw"].get("method", "CRYPTO")

    if method in ("GCASH", "MAYA"):
        # Phone number is permanently bound to the account — use it directly
        phone = user_record.get("phone") or ""
        if not phone:
            await update.effective_message.reply_text(
                "⚠️ No phone number is linked to your account.\n\n"
                "Please contact support to bind your GCash / Maya number first.",
                reply_markup=cancel_keyboard(CB["main_menu"]),
            )
            return -1
        context.user_data["withdraw"]["address"] = phone
        label = "GCash 📱" if method == "GCASH" else "Maya 💜"
        await update.effective_message.reply_text(
            f"📝 *Confirm Withdrawal*\n\n"
            f"Method: *{label}*\n"
            f"Amount: *{fmt_money(amount)}*\n"
            f"Payout to: *{phone}* _(your registered number — cannot be changed)_\n\n"
            f"The admin will review and transfer the funds to your {label} account.",
            reply_markup=confirm_keyboard("WD:YES", "WD:NO"), parse_mode="Markdown",
        )
        return State.WITHDRAW_CONFIRM
    else:
        # Crypto — ask for wallet address
        await update.effective_message.reply_text(
            "Enter the *crypto wallet address* you want to receive payment on.",
            reply_markup=cancel_keyboard(CB["main_menu"]), parse_mode="Markdown",
        )
        return State.WITHDRAW_ENTER_ADDRESS


@not_banned
async def withdraw_enter_address(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    address = (update.effective_message.text or "").strip()
    if len(address) < 10 or len(address) > 200:
        await update.effective_message.reply_text(
            "❌ Doesn't look like a valid wallet address.", reply_markup=cancel_keyboard(CB["main_menu"])
        )
        return State.WITHDRAW_ENTER_ADDRESS
    context.user_data["withdraw"]["address"] = address
    wd = context.user_data["withdraw"]
    await update.effective_message.reply_text(
        f"📝 *Confirm Withdrawal*\n\n"
        f"Method: *Crypto ₿*\n"
        f"Amount: *{fmt_money(wd['amount'])}*\n"
        f"Address: `{address}`\n\n"
        f"The admin will review and process your payment manually.",
        reply_markup=confirm_keyboard("WD:YES", "WD:NO"), parse_mode="Markdown",
    )
    return State.WITHDRAW_CONFIRM


async def withdraw_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    decision = query.data.split(":", 1)[1]
    user = update.effective_user
    db = get_db()
    wd = context.user_data.get("withdraw", {})
    if decision == "NO" or not wd:
        context.user_data.pop("withdraw", None)
        await query.edit_message_text("Withdrawal cancelled.", reply_markup=back_to_main())
        return -1
    record = db.get_user(user.id)
    if record["balance"] < wd["amount"]:
        await query.edit_message_text("❌ Insufficient balance. Cancelled.", reply_markup=back_to_main())
        context.user_data.pop("withdraw", None)
        return -1

    method = wd.get("method", "CRYPTO")
    method_label = "GCash" if method == "GCASH" else ("Maya" if method == "MAYA" else "Crypto")

    db.update_balance(user.id, -float(wd["amount"]))
    tx_id = db.create_transaction(
        user_id=user.id,
        tx_type="withdrawal",
        amount=-float(wd["amount"]),
        status="pending",
        currency="PHP",
        wallet_address=wd.get("address", ""),
        note=f"User withdrawal via {method_label}",
    )
    admin_text = (
        f"💸 *New withdrawal request* `#{tx_id}`\n\n"
        f"User: {fmt_user(record)}\n"
        f"Amount: *{fmt_money(wd['amount'])}*\n"
        f"Method: *{method_label}*\n"
        f"Payout to: `{wd.get('address', '-')}`\n"
    )
    from keyboards.admin_kb import admin_withdrawal_actions_keyboard
    for admin_id in CONFIG.admin_ids:
        try:
            await context.bot.send_message(chat_id=admin_id, text=admin_text, parse_mode="Markdown")
            await context.bot.send_message(
                chat_id=admin_id,
                text=f"Approve or reject withdrawal `#{tx_id}`:",
                reply_markup=admin_withdrawal_actions_keyboard(tx_id),
                parse_mode="Markdown",
            )
        except Exception as e:
            log.warning("Failed to notify admin %s: %s", admin_id, e)
    context.user_data.pop("withdraw", None)
    await query.edit_message_text(
        f"✅ Withdrawal request *#{tx_id}* submitted!\n\n"
        f"*{fmt_money(wd['amount'])}* via {method_label} — admin will process shortly.",
        reply_markup=back_to_main(), parse_mode="Markdown",
    )
    return -1


# ---------------------------------------------------------------------------
# Referral
# ---------------------------------------------------------------------------

@not_banned
async def referral(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    user = update.effective_user
    db = get_db()
    record = db.get_user(user.id)
    stats = db.referral_stats(user.id)
    bot_username = (await context.bot.get_me()).username
    bonus_pct = float(db.get_setting("referral_bonus_percent", CONFIG.referral_bonus_percent))
    tg_link = f"https://t.me/{bot_username}?start=ref_{record['referral_code']}"

    lines = [
        "👥 *Referral Program*",
        "",
        f"🤖 *Telegram link:*\n`{tg_link}`",
        f"🆔 Or share code: `{record['referral_code']}`",
        "",
    ]

    # Add web mirror links if configured
    site_urls_raw = (db.get_setting("site_urls", "") or "").strip()
    if site_urls_raw:
        lines.append("🌐 *Web links (works on any mirror):*")
        for raw_url in site_urls_raw.replace("\n", ",").split(","):
            url = raw_url.strip().rstrip("/")
            if url:
                label = url.replace("https://", "").replace("http://", "")
                web_link = f"{url}/app/register?ref={record['referral_code']}"
                lines.append(f"`{web_link}` ({label})")
        lines.append("")

    lines += [
        f"👤 Referrals: *{stats['total']}*",
        f"💸 Total events: *{stats['events']}*",
        f"🪙 Total earned: *{fmt_money(stats['bonus'])}*",
        f"📊 Bonus rate: *{bonus_pct:.2f}%* of every investment your referrals make",
    ]
    if stats["referred_users"]:
        lines.append("\n*Your referred users*")
        for r in stats["referred_users"][:10]:
            lines.append(
                f"• {fmt_user(r)} — invested: {fmt_money(r['total_invested'])}, "
                f"bonus: {fmt_money(r['total_bonus'])}"
            )
    await query.edit_message_text(
        truncate("\n".join(lines), 3800),
        reply_markup=back_to_main(), parse_mode="Markdown",
    )
    return -1


