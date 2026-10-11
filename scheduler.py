"""Background scheduler — auto-completes expired investments AND delivers
web-panel broadcast messages queued via the admin web panel.

Two repeating jobs:
  1. _complete_expired_investments  — runs every hour
  2. _deliver_pending_broadcast     — runs every 30 seconds (picks up queued broadcasts)
"""
from __future__ import annotations

import json
import logging
import time

from telegram.ext import Application, ContextTypes

from database import get_db
from config import BRAND_NAME

log = logging.getLogger(__name__)

CHECK_INTERVAL_SECONDS = 3600   # investment completion: every hour
BROADCAST_POLL_SECONDS = 30     # broadcast delivery: every 30 s


# ---------------------------------------------------------------------------
# Investment completion
# ---------------------------------------------------------------------------

async def _complete_expired_investments(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Find and complete all investments that have passed their expiry."""
    db = get_db()
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
                inv = result
                try:
                    payout = float(inv.get("payout_amount") or 0)
                    await context.bot.send_message(
                        chat_id=inv["user_id"],
                        text=(
                            f"🎉 *Investment #{inv['id']} completed!*\n\n"
                            f"Plan: *{inv['plan_name']}*\n"
                            f"Principal: *₱{inv['principal']:,.2f}*\n"
                            f"Total payout: *₱{payout:,.2f}*\n\n"
                            f"Funds have been added to your wallet. 💰"
                        ),
                        parse_mode="Markdown",
                    )
                except Exception as e:
                    log.debug("Could not notify user %s: %s", inv["user_id"], e)
        except Exception as e:
            log.error("Failed to complete investment #%s: %s", row["id"], e)
            errors += 1

    log.info("Scheduler: completed %d investments, %d errors.", completed, errors)


# ---------------------------------------------------------------------------
# Web-panel broadcast delivery
# ---------------------------------------------------------------------------

async def _deliver_pending_broadcast(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Pick up any broadcast queued via the web admin panel and send it."""
    db = get_db()
    raw = db.get_setting("_pending_broadcast")
    if not raw:
        return

    try:
        payload = raw if isinstance(raw, dict) else json.loads(raw)
    except (ValueError, TypeError):
        return

    message = payload.get("message", "").strip()
    if not message:
        return

    # Clear BEFORE sending so we don't re-send on crash/retry
    db.set_setting("_pending_broadcast", "")

    users = db.query_all("SELECT user_id FROM users WHERE is_banned = 0")
    log.info("Broadcast: sending to %d users.", len(users))

    sent = 0
    failed = 0
    for row in users:
        try:
            await context.bot.send_message(
                chat_id=row["user_id"],
                text=message,
                parse_mode="Markdown",
            )
            sent += 1
            # Throttle: Telegram allows ~30 msgs/sec to different chats
            import asyncio
            await asyncio.sleep(0.05)
        except Exception as e:
            log.debug("Broadcast failed for user %s: %s", row["user_id"], e)
            failed += 1

    log.info("Broadcast complete: %d sent, %d failed.", sent, failed)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_scheduler(app: Application) -> None:
    """Register all background jobs with the bot's JobQueue."""
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
        first=10,
        name="complete_expired_investments",
    )

    job_queue.run_repeating(
        _deliver_pending_broadcast,
        interval=BROADCAST_POLL_SECONDS,
        first=15,
        name="deliver_pending_broadcast",
    )

    log.info(
        "Scheduler registered: investments every %ds, broadcast poll every %ds.",
        CHECK_INTERVAL_SECONDS,
        BROADCAST_POLL_SECONDS,
    )
