"""Entry point for the Telegram Investment Bot.

Run with::

    python bot.py

Reads ``BOT_TOKEN`` from the environment (or the ``.env`` file) and
starts polling.  All conversation handlers are wired in this module so
the routing is easy to read.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path

from telegram import Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    filters,
)

import config as cfg
from config import CONFIG
from database import get_db
from scheduler import register_scheduler
from web.app import create_app
from handlers.admin import (
    admin_broadcast_send,
    admin_broadcast_start,
    admin_dashboard,
    admin_deposit_decide,
    admin_deposit_view,
    admin_deposits,
    admin_plan_capital,
    admin_plan_daily_roi,
    admin_plan_delete,
    admin_plan_description,
    admin_plan_duration,
    admin_plan_max,
    admin_plan_min,
    admin_plan_name,
    admin_plan_new_start,
    admin_plan_toggle,
    admin_plan_view,
    admin_plans,
    admin_setting_edit,
    admin_setting_save,
    admin_settings,
    admin_stats,
    admin_user_adjust_amount,
    admin_user_adjust_commit,
    admin_user_adjust_start,
    admin_user_ban_toggle,
    admin_user_search,
    admin_user_view,
    admin_users,
    admin_users_list_message,
    admin_withdrawal_decide,
    admin_withdrawal_view,
    admin_withdrawals,
)
from handlers.start import cancel, show_main_menu, start, weblogin
from handlers.user import (
    deposit_enter_amount,
    deposit_receive_receipt,
    deposit_select_currency,
    deposit_start,
    history,
    invest_confirm_callback,
    invest_enter_amount,
    invest_select_plan,
    invest_start,
    my_investments,
    referral,
    wallet,
    withdraw_confirm,
    withdraw_enter_address,
    withdraw_enter_amount,
    withdraw_start,
)
from utils.states import CB, State

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _setup_logging() -> None:
    CONFIG.logs_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)
    fh = logging.handlers.RotatingFileHandler(
        CONFIG.logs_dir / "bot.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)


# ---------------------------------------------------------------------------
# Callback dispatcher
# ---------------------------------------------------------------------------


async def callback_router(update: Update, context):
    """Top-level callback dispatcher.

    All inline buttons use a ``prefix:value`` scheme; this function
    parses the prefix and delegates to the right handler.  Keeping it
    centralised avoids a giant ``add_handler`` block.
    """
    query = update.callback_query
    data = query.data or ""
    await query.answer()
    # No-op placeholder for visual separators
    if data == CB["noop"]:
        return -1
    # Main menu and global navigation
    if data == CB["main_menu"]:
        return await show_main_menu(update, context)
    if data == CB["deposit"]:
        return await deposit_start(update, context)
    if data.startswith(CB["deposit_currency"]):
        return await deposit_select_currency(update, context)
    if data == CB["invest"]:
        return await invest_start(update, context)
    if data.startswith(CB["invest_plan"]):
        return await invest_select_plan(update, context)
    if data == CB["withdraw"]:
        return await withdraw_start(update, context)
    if data == CB["referral"]:
        return await referral(update, context)
    if data == CB["history"]:
        return await history(update, context)
    if data == CB["my_investments"]:
        return await my_investments(update, context)
    if data.startswith("INVEST:"):
        return await invest_confirm_callback(update, context)
    if data.startswith("WD:"):
        return await withdraw_confirm(update, context)

    # Admin section
    if data == CB["admin_home"]:
        return await admin_dashboard(update, context)
    if data == CB["admin_stats"]:
        return await admin_stats(update, context)
    if data == CB["admin_plans"]:
        return await admin_plans(update, context)
    if data.startswith("PLAN_VIEW:"):
        return await admin_plan_view(update, context)
    if data.startswith(CB["admin_plan_toggle"]):
        return await admin_plan_toggle(update, context)
    if data.startswith(CB["admin_plan_delete"]):
        return await admin_plan_delete(update, context)
    if data == CB["admin_plan_new"]:
        return await admin_plan_new_start(update, context)
    if data == CB["admin_deposits"]:
        return await admin_deposits(update, context)
    if data.startswith("DEP_VIEW:"):
        return await admin_deposit_view(update, context)
    if data.startswith(CB["admin_deposit_approve"]) or data.startswith(CB["admin_deposit_reject"]):
        return await admin_deposit_decide(update, context)
    if data == CB["admin_withdrawals"]:
        return await admin_withdrawals(update, context)
    if data.startswith("WD_VIEW:"):
        return await admin_withdrawal_view(update, context)
    if data.startswith(CB["admin_withdrawal_approve"]) or data.startswith(CB["admin_withdrawal_reject"]):
        return await admin_withdrawal_decide(update, context)
    if data == CB["admin_users"]:
        return await admin_users(update, context)
    if data.startswith(CB["admin_user_view"]):
        return await admin_user_view(update, context)
    if data.startswith(CB["admin_user_ban"]) or data.startswith(CB["admin_user_unban"]):
        return await admin_user_ban_toggle(update, context)
    if data.startswith(CB["admin_user_adjust"]):
        return await admin_user_adjust_start(update, context)
    if data == CB["admin_settings"]:
        return await admin_settings(update, context)
    if data.startswith(CB["admin_setting_edit"]):
        return await admin_setting_edit(update, context)
    if data == CB["admin_broadcast"]:
        return await admin_broadcast_start(update, context)
    if data == CB["admin_cancel"]:
        return await cancel(update, context)

    log.warning("Unhandled callback data: %r", data)
    return -1


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def build_application() -> Application:
    if not CONFIG.bot_token or CONFIG.bot_token == "YOUR_BOT_TOKEN_HERE":
        raise SystemExit(
            "BOT_TOKEN is not set. Copy .env.example to .env and fill in your token."
        )
    app = ApplicationBuilder().token(CONFIG.bot_token).build()

    # ---- Investor deposit flow ----
    deposit_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(deposit_start, pattern=f"^{CB['deposit']}$")],
        states={
            State.DEPOSIT_SELECT_CURRENCY: [
                CallbackQueryHandler(deposit_select_currency, pattern=f"^{CB['deposit_currency']}"),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
            State.DEPOSIT_ENTER_AMOUNT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, deposit_enter_amount),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
            State.DEPOSIT_UPLOAD_RECEIPT: [
                MessageHandler(
                    (filters.PHOTO | filters.Document.ALL | filters.TEXT) & ~filters.COMMAND,
                    deposit_receive_receipt,
                ),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", cancel),
            CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
        ],
        per_user=True,
        per_chat=True,
    )

    # ---- Investor investment flow ----
    invest_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(invest_start, pattern=f"^{CB['invest']}$")],
        states={
            State.INVEST_SELECT_PLAN: [
                CallbackQueryHandler(invest_select_plan, pattern=f"^{CB['invest_plan']}"),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
            State.INVEST_ENTER_AMOUNT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, invest_enter_amount),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
            State.INVEST_CONFIRM: [
                CallbackQueryHandler(invest_confirm_callback, pattern=r"^INVEST:"),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", cancel),
            CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
        ],
    )

    # ---- Investor withdrawal flow ----
    withdraw_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(withdraw_start, pattern=f"^{CB['withdraw']}$")],
        states={
            State.WITHDRAW_ENTER_AMOUNT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, withdraw_enter_amount),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
            State.WITHDRAW_ENTER_ADDRESS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, withdraw_enter_address),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
            State.WITHDRAW_CONFIRM: [
                CallbackQueryHandler(withdraw_confirm, pattern=r"^WD:"),
                CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", cancel),
            CallbackQueryHandler(show_main_menu, pattern=f"^{CB['main_menu']}$"),
        ],
    )

    # ---- Admin plan creation ----
    plan_create_handler = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(admin_plan_new_start, pattern=f"^{CB['admin_plan_new']}$")
        ],
        states={
            State.ADMIN_PLAN_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_plan_name)],
            State.ADMIN_PLAN_DESCRIPTION: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_plan_description)],
            State.ADMIN_PLAN_MIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_plan_min)],
            State.ADMIN_PLAN_MAX: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_plan_max)],
            State.ADMIN_PLAN_DAILY_ROI: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_plan_daily_roi)],
            State.ADMIN_PLAN_DURATION: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_plan_duration)],
            State.ADMIN_PLAN_TOGGLE: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_plan_capital)],
        },
        fallbacks=[
            CallbackQueryHandler(admin_plans, pattern=f"^{CB['admin_plans']}$"),
            CommandHandler("cancel", cancel),
        ],
    )

    # ---- Admin settings editor ----
    settings_handler = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(admin_setting_edit, pattern=f"^{CB['admin_setting_edit']}")
        ],
        states={
            State.ADMIN_EDIT_SETTING: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_setting_save)],
        },
        fallbacks=[
            CallbackQueryHandler(admin_settings, pattern=f"^{CB['admin_settings']}$"),
            CommandHandler("cancel", cancel),
        ],
    )

    # ---- Admin balance adjust ----
    adjust_handler = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(admin_user_adjust_start, pattern=f"^{CB['admin_user_adjust']}")
        ],
        states={
            State.ADMIN_ADJUST_BALANCE: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_user_adjust_amount)],
            State.ADMIN_ADJUST_NOTE: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_user_adjust_commit)],
        },
        fallbacks=[
            CallbackQueryHandler(admin_users, pattern=f"^{CB['admin_users']}$"),
            CommandHandler("cancel", cancel),
        ],
    )

    # ---- Admin user search ----
    user_search_handler = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(admin_users, pattern=f"^{CB['admin_users']}$")
        ],
        states={
            State.ADMIN_USER_LOOKUP: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_user_search)],
        },
        fallbacks=[
            CallbackQueryHandler(admin_users, pattern=f"^{CB['admin_users']}$"),
            CommandHandler("cancel", cancel),
        ],
    )

    # ---- Admin broadcast ----
    broadcast_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(admin_broadcast_start, pattern=f"^{CB['admin_broadcast']}$")],
        states={
            State.ADMIN_BROADCAST: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_broadcast_send)],
        },
        fallbacks=[
            CallbackQueryHandler(admin_dashboard, pattern=f"^{CB['admin_home']}$"),
            CommandHandler("cancel", cancel),
        ],
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("weblogin", weblogin))
    app.add_handler(CommandHandler("admin", admin_dashboard))
    app.add_handler(deposit_handler)
    app.add_handler(invest_handler)
    add_handler = app.add_handler  # noqa: F841
    app.add_handler(withdraw_handler)
    app.add_handler(plan_create_handler)
    app.add_handler(settings_handler)
    app.add_handler(adjust_handler)
    app.add_handler(user_search_handler)
    app.add_handler(broadcast_handler)
    # Generic callback router for everything else
    app.add_handler(CallbackQueryHandler(callback_router))

    # Plain text outside any conversation: just nudge the user
    async def _text_fallback(update: Update, context):
        if update.effective_message and update.effective_chat.type == "private":
            await update.effective_message.reply_text(
                "Use /start to open the menu."
            )

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, _text_fallback))
    return app


def main() -> None:
    _setup_logging()
    log.info("Starting TGInvestmentBot…")
    # Eagerly initialise DB so seeding errors show up at startup
    get_db()

    web_host = os.environ.get("WEB_HOST", "0.0.0.0")
    # Railway injects PORT; fall back to WEB_PORT then 5000
    web_port = int(os.environ.get("PORT") or os.environ.get("WEB_PORT") or "5000")

    # ── Start Flask FIRST so Railway's health check gets a response ──
    # Railway sends an HTTP probe to $PORT almost immediately after the
    # process starts. If nothing is bound yet it returns 502. We start
    # the web server in a thread and give it a moment to bind before
    # we start the (blocking) Telegram bot.
    import threading, socket, time as _time

    web_app = create_app()

    def run_web():
        try:
            from werkzeug.serving import make_server
            srv = make_server(web_host, web_port, web_app, threaded=True)
            log.info("Web panel bound to %s:%d", web_host, web_port)
            srv.serve_forever()
        except Exception as exc:
            log.exception("Web server crashed: %s", exc)

    web_thread = threading.Thread(target=run_web, daemon=True, name="web-server")
    web_thread.start()

    # Wait until the port is actually open (max 10 s) before starting the bot.
    # This prevents the bot from consuming all startup time while Railway
    # probes the port and receives connection-refused.
    deadline = _time.time() + 10
    while _time.time() < deadline:
        try:
            with socket.create_connection((web_host if web_host != "0.0.0.0" else "127.0.0.1",
                                           web_port), timeout=0.5):
                log.info("Web server is ready on port %d", web_port)
                break
        except OSError:
            _time.sleep(0.1)
    else:
        log.warning("Web server did not become ready within 10 s — continuing anyway")

    # ── Now start the Telegram bot ────────────────────────────────────
    app = build_application()
    register_scheduler(app)
    log.info("Bot is up. Admin IDs: %s", CONFIG.admin_ids)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
