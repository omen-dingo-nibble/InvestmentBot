"""Background scheduler that auto-completes expired investments.

This module provides a repeating job that runs every hour (configurable),
checks for investments whose ``expires_at`` has passed and still have
``status = 'active'``, and completes them — crediting the user's balance
with accrued earnings (and principal if ``capital_return`` is set).

Integration with the bot is done via ``python-telegram-bot``'s built-in
``JobQueue``, so no extra process or cron is needed.
"""
from __future__ import annotations

import logging
from typing import Optional

from telegram.ext import Application, ContextTypes

from database import get_db

log = logging.getLogger(__name__)

# How often (in seconds) the scheduler checks for matured investments
CHECK_INTERVAL_SECONDS = 3600  # 1 hour


async def _complete_expired_investments(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Find and complete all investments that have passed their expiry."""
    db = get_db()
    import time

    now = int(time.time())
    expired = db.query_all(
        "SELECT id FROM investments WHERE status = 'active' AND expires_at <= ?",
        (now,),
    )
    if not expired:
        return

    log.info("Scheduler: found %d expired investments to complete.", len(expired))
    completed = 0
    errors = 0

    for row in expired:
        try:
            result = db.complete_investment(row["id"])
            if result and result["status"] == "completed":
                completed += 1
                # Notify the user
                inv = result
                try:
                    payout = float(inv.get("payout_amount") or 0)
                    await context.bot.send_message(
                        chat_id=inv["user_id"],
                        text=(
                            f"🎉 *Investment #{inv['id']} completed!*\n\n"
                            f"Plan: *{inv['plan_name']}*\n"
                            f"Principal: *${inv['principal']:.2f}*\n"
                            f"Total payout: *${payout:.2f}*\n\n"
                            f"Funds have been added to your wallet."
                        ),
                        parse_mode="Markdown",
                    )
                except Exception as e:
                    log.debug("Could not notify user %s: %s", inv["user_id"], e)
        except Exception as e:
            log.error("Failed to complete investment #%s: %s", row["id"], e)
            errors += 1

    log.info(
        "Scheduler: completed %d investments, %d errors.",
        completed, errors,
    )


def register_scheduler(app: Application) -> None:
    """Register the investment completion job with the bot's JobQueue.

    Call this after ``build_application()`` but before ``run_polling()``.
    """
    job_queue = app.job_queue
    if job_queue is None:
        log.warning(
            "JobQueue not available. Install python-telegram-bot[job-queue] "
            "to enable the investment scheduler."
        )
        return

    job_queue.run_repeating(
        _complete_expired_investments,
        interval=CHECK_INTERVAL_SECONDS,
        first=10,  # first run 10 seconds after startup
        name="complete_expired_investments",
    )
    log.info(
        "Investment scheduler registered (interval=%ds).",
        CHECK_INTERVAL_SECONDS,
    )
