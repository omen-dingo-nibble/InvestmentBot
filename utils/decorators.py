"""Reusable decorators for command/handler authorisation."""
from __future__ import annotations

import functools
import logging
from typing import Callable

from telegram import Update
from telegram.ext import ContextTypes

from config import CONFIG
from database import get_db

log = logging.getLogger(__name__)


def is_admin_user(user_id: int) -> bool:
    if user_id in CONFIG.admin_ids:
        return True
    user = get_db().get_user(user_id)
    return bool(user and user.get("is_admin"))


def admin_only(func: Callable) -> Callable:
    """Reject any update whose sender is not an admin.

    Works for both message handlers and callback query handlers.
    """

    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if not user or not is_admin_user(user.id):
            log.warning("Blocked non-admin %s from %s", user.id if user else "?", func.__name__)
            if update.callback_query:
                await update.callback_query.answer("Admins only.", show_alert=True)
            elif update.effective_message:
                await update.effective_message.reply_text("This action is for admins only.")
            return None
        return await func(update, context, *args, **kwargs)

    return wrapper


def not_banned(func: Callable) -> Callable:
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if user:
            record = get_db().get_user(user.id)
            if record and record.get("is_banned"):
                if update.callback_query:
                    await update.callback_query.answer(
                        "Your account is suspended. Contact support.", show_alert=True
                    )
                elif update.effective_message:
                    await update.effective_message.reply_text(
                        "Your account is suspended. Please contact support."
                    )
                return None
        return await func(update, context, *args, **kwargs)

    return wrapper
