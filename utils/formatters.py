"""Display helpers — PHP (₱) only currency formatting."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def fmt_money(amount: float, currency: str = "PHP", decimals: int = 2) -> str:
    """Format a monetary value in Philippine Peso."""
    if amount is None:
        amount = 0
    sign = "-" if amount < 0 else ""
    return f"{sign}₱{abs(float(amount)):,.{decimals}f}"


def fmt_percent(value: float, decimals: int = 2) -> str:
    return f"{float(value):.{decimals}f}%"


def fmt_duration(seconds: int) -> str:
    if seconds <= 0:
        return "0s"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{int(days)}d")
    if hours:
        parts.append(f"{int(hours)}h")
    if minutes and not days:
        parts.append(f"{int(minutes)}m")
    return " ".join(parts) or "0m"


def fmt_datetime(ts: Optional[int]) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def fmt_short_date(ts: Optional[int]) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")


def fmt_user(user: Dict[str, Any]) -> str:
    if not user:
        return "?"
    name = user.get("full_name") or user.get("username") or str(user.get("user_id"))
    handle = f"@{user['username']}" if user.get("username") else ""
    return f"{name} {handle} (`{user['user_id']}`)".strip()


def truncate(text: str, limit: int = 4000) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def paginate(items: List[Any], page: int, per_page: int) -> tuple:
    total_pages = max(1, (len(items) + per_page - 1) // per_page)
    page = max(0, min(page, total_pages - 1))
    start = page * per_page
    return items[start : start + per_page], total_pages
