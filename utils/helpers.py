"""Helpers that don't fit anywhere else."""
from __future__ import annotations

import logging
import re
from decimal import Decimal, InvalidOperation
from typing import Optional, Tuple

log = logging.getLogger(__name__)


_TXN_RE = re.compile(r"^[A-Za-z0-9]{20,128}$")


def parse_amount(text: str) -> Optional[float]:
    """Parse a free-form number like ``"$1,234.50"`` or ``"1k"``."""
    if not text:
        return None
    cleaned = text.strip().replace(",", "").replace("$", "").replace(" ", "")
    if not cleaned:
        return None
    mult = 1.0
    if cleaned.lower().endswith("k"):
        mult = 1_000
        cleaned = cleaned[:-1]
    elif cleaned.lower().endswith("m"):
        mult = 1_000_000
        cleaned = cleaned[:-1]
    try:
        value = float(Decimal(cleaned) * Decimal(mult))
    except (InvalidOperation, ValueError):
        return None
    if value != value or value in (float("inf"), float("-inf")):
        return None
    return round(value, 4)


def parse_signed_amount(text: str) -> Optional[float]:
    """Parse a signed amount, e.g. ``+25`` or ``-50``."""
    if not text:
        return None
    raw = text.strip()
    sign = 1
    if raw.startswith("+"):
        raw = raw[1:]
    elif raw.startswith("-"):
        sign = -1
        raw = raw[1:]
    value = parse_amount(raw)
    if value is None:
        return None
    return sign * value


def looks_like_tx_hash(text: str) -> bool:
    if not text:
        return False
    return bool(_TXN_RE.match(text.strip()))


def detect_crypto_currency(text: str) -> Optional[str]:
    if not text:
        return None
    upper = text.upper().strip()
    if upper.startswith("BTC"):
        return "BTC"
    if upper.startswith("ETH"):
        return "ETH"
    if upper.startswith("LTC"):
        return "LTC"
    if "USDT" in upper or "TRC20" in upper or "ERC20" in upper:
        return "USDT"
    return None


def split_command_args(text: str) -> Tuple[Optional[str], str]:
    """Return (command, rest) e.g. ``/plan 2 daily`` -> (``plan``, ``2 daily``)."""
    if not text:
        return None, ""
    parts = text.split(maxsplit=1)
    cmd = parts[0].lstrip("/").split("@")[0].lower() if parts else None
    rest = parts[1] if len(parts) > 1 else ""
    return cmd, rest
