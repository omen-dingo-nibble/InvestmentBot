"""Security and session tracking utilities.

Logs user actions with whatever device/platform information Telegram provides.
Telegram does not expose IP addresses, but we capture:
  - Telegram user language_code (locale)
  - Device info from the Telegram client (where available via API)
  - Platform hints from user language
  - All interaction timestamps for audit trail

For IP resolution, we log the IP when users interact through the web panel
or when they connect via webhook (if configured).
"""
from __future__ import annotations

import logging
from typing import Optional

from telegram import Update

from database import get_db

log = logging.getLogger(__name__)


def log_user_action(
    update: Update,
    action: str,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """Log a user's interaction for security tracking.

    Extracts available metadata from the Telegram Update object.
    """
    user = update.effective_user
    if not user:
        return

    # Extract what Telegram provides
    language = user.language_code or None
    platform = None
    device_info = None

    # Try to infer platform from the message source
    msg = update.effective_message
    if msg:
        # Telegram forwards include some metadata
        if hasattr(msg, "forward_origin"):
            pass
        # Web app data indicates web client
        if msg.web_app_data:
            platform = "web_app"

    # Build device string from available user info
    device_parts = []
    if user.is_bot:
        device_parts.append("bot")
    if user.is_premium:
        device_parts.append("premium")
    device_info = ", ".join(device_parts) if device_parts else None

    try:
        db = get_db()
        db.log_user_session(
            user_id=user.id,
            action=action,
            ip_address=ip_address,
            device_info=device_info,
            platform=platform,
            language=language,
            details=details,
        )
    except Exception as e:
        log.debug("Failed to log user session: %s", e)
