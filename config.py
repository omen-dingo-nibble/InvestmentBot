"""Centralized configuration for KKKPH Investment Bot.

Every runtime setting lives here so the rest of the codebase never touches
``os.environ`` directly.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------------------
# Branding constants for KKKPH
# ---------------------------------------------------------------------------
BRAND_NAME = "KKKPH"
BRAND_SHORT = "KKKPH"
BRAND_TAGLINE = "Grow Your Wealth. Sip the Returns."
BRAND_WEBSITE = "https://kkkph.site"
BRAND_SUPPORT = "@italiaelitetradingbot"

CREW = [
    {
        "name": "KKKPH Team",
        "title": "Investment Specialists",
        "bio": "A dedicated team committed to growing your wealth through smart, premium investment plans.",
    },
]

# ---------------------------------------------------------------------------
# KKKPH Investment Plans with product images
# ---------------------------------------------------------------------------
GYOKURO_PLANS = [
    {
        "name": "KKKPH Starter",
        "description": "Entry-level premium plan. Steady daily returns to begin your investment journey.",
        "min_amount": 99.0,
        "max_amount": 999.0,
        "daily_roi_percent": 2.0,
        "duration_days": 30,
        "capital_return": True,
        "sort_order": 0,
        "image": "gyokuro_1.jpg",
    },
    {
        "name": "KKKPH Silver",
        "description": "Mid-tier plan with enhanced returns for growing investors.",
        "min_amount": 1000.0,
        "max_amount": 4999.0,
        "daily_roi_percent": 2.5,
        "duration_days": 30,
        "capital_return": True,
        "sort_order": 1,
        "image": "gyokuro_2.jpg",
    },
    {
        "name": "KKKPH Gold",
        "description": "Premium plan with superior yields over 45 days.",
        "min_amount": 5000.0,
        "max_amount": 24999.0,
        "daily_roi_percent": 3.0,
        "duration_days": 45,
        "capital_return": True,
        "sort_order": 2,
        "image": "gyokuro_3.jpg",
    },
    {
        "name": "KKKPH Platinum",
        "description": "High-yield 60-day plan for serious investors seeking maximum growth.",
        "min_amount": 25000.0,
        "max_amount": 99999.0,
        "daily_roi_percent": 3.5,
        "duration_days": 60,
        "capital_return": True,
        "sort_order": 3,
        "image": "gyokuro_4.jpg",
    },
    {
        "name": "KKKPH Diamond",
        "description": "Elite 90-day plan with exceptional daily returns for top-tier investors.",
        "min_amount": 100000.0,
        "max_amount": 499999.0,
        "daily_roi_percent": 4.0,
        "duration_days": 90,
        "capital_return": True,
        "sort_order": 4,
        "image": "gyokuro_5.jpg",
    },
    {
        "name": "KKKPH Black",
        "description": "The pinnacle of investment — exclusive 90-day plan for premium members.",
        "min_amount": 500000.0,
        "max_amount": 5000000.0,
        "daily_roi_percent": 5.0,
        "duration_days": 90,
        "capital_return": True,
        "sort_order": 5,
        "image": "gyokuro_6.jpg",
    },
    {
        "name": "KKKPH Reserve",
        "description": "Special limited plan with flexible investment range.",
        "min_amount": 500.0,
        "max_amount": 2999.0,
        "daily_roi_percent": 2.2,
        "duration_days": 21,
        "capital_return": True,
        "sort_order": 6,
        "image": "gyokuro_7.jpg",
    },
]

# Supported currencies with symbols
CURRENCIES = {
    "USD": {"symbol": "$", "name": "US Dollar", "php_rate_key": "usd_to_php_rate"},
    "PHP": {"symbol": "₱", "name": "Philippine Peso", "usd_rate_key": "php_to_usd_rate"},
}


def _int_list(raw: str) -> List[int]:
    if not raw:
        return []
    out: List[int] = []
    for chunk in raw.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            out.append(int(chunk))
        except ValueError:
            logging.warning("Ignoring non-integer admin id: %r", chunk)
    return out


def _bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class CryptoConfig:
    btc: str = ""
    eth: str = ""
    usdt_trc20: str = ""
    usdt_erc20: str = ""
    ltc: str = ""
    # QR code image file paths (relative to web/static/qr/)
    btc_qr: str = ""
    eth_qr: str = ""
    usdt_trc20_qr: str = ""
    usdt_erc20_qr: str = ""
    ltc_qr: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {
            "BTC": self.btc,
            "ETH": self.eth,
            "USDT-TRC20": self.usdt_trc20,
            "USDT-ERC20": self.usdt_erc20,
            "LTC": self.ltc,
        }

    def qr_dict(self) -> Dict[str, str]:
        """Map of crypto key → QR filename (relative to web/static/qr/)."""
        return {
            "BTC": self.btc_qr,
            "ETH": self.eth_qr,
            "USDT-TRC20": self.usdt_trc20_qr,
            "USDT-ERC20": self.usdt_erc20_qr,
            "LTC": self.ltc_qr,
        }


@dataclass
class Config:
    bot_token: str = ""
    bot_username: str = "italiaelitetradingbot"
    admin_ids: List[int] = field(default_factory=list)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    min_deposit_usd: float = 10.0
    min_withdrawal_usd: float = 5.0
    referral_bonus_percent: float = 5.0
    deduct_referral_from_investor: bool = False
    auto_verify_tx: bool = False
    blockchain_api_key: str = ""
    blockchain_api_url: str = "https://api.blockchain.info/v2"
    db_path: Path = BASE_DIR / "data" / "bot.db"
    logs_dir: Path = BASE_DIR / "logs"
    # Default PHP/USD exchange rate (admin can override in settings)
    default_php_rate: float = 56.0  # 1 USD = 56 PHP (approximate)

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        cfg.bot_token = os.getenv("BOT_TOKEN", "").strip()
        cfg.bot_username = os.getenv("BOT_USERNAME", "italiaelitetradingbot").strip()
        cfg.admin_ids = _int_list(os.getenv("ADMIN_IDS", ""))

        cfg.crypto = CryptoConfig(
            btc=os.getenv("CRYPTO_BTC_ADDRESS", "").strip(),
            eth=os.getenv("CRYPTO_ETH_ADDRESS", "").strip(),
            usdt_trc20=os.getenv("CRYPTO_USDT_TRC20_ADDRESS", "").strip(),
            usdt_erc20=os.getenv("CRYPTO_USDT_ERC20_ADDRESS", "").strip(),
            ltc=os.getenv("CRYPTO_LTC_ADDRESS", "").strip(),
            btc_qr=os.getenv("QR_BTC", "btc_qr.png").strip(),
            eth_qr=os.getenv("QR_ETH", "eth_qr.png").strip(),
            usdt_trc20_qr=os.getenv("QR_USDT_TRC20", "usdt_trc20_qr.png").strip(),
            usdt_erc20_qr=os.getenv("QR_USDT_ERC20", "usdt_erc20_qr.png").strip(),
            ltc_qr=os.getenv("QR_LTC", "ltc_qr.png").strip(),
        )

        cfg.min_deposit_usd = float(os.getenv("MIN_DEPOSIT_USD", "10") or 10)
        cfg.min_withdrawal_usd = float(os.getenv("MIN_WITHDRAWAL_USD", "5") or 5)
        cfg.referral_bonus_percent = float(
            os.getenv("REFERRAL_BONUS_PERCENT", "5") or 5
        )
        cfg.deduct_referral_from_investor = _bool(
            os.getenv("DEDUCT_REFERRAL_FROM_INVESTOR", "false")
        )
        cfg.auto_verify_tx = _bool(os.getenv("AUTO_VERIFY_TX", "false"))
        cfg.blockchain_api_key = os.getenv("BLOCKCHAIN_API_KEY", "").strip()
        cfg.blockchain_api_url = os.getenv(
            "BLOCKCHAIN_API_URL", "https://api.blockchain.info/v2"
        ).strip()
        cfg.default_php_rate = float(os.getenv("DEFAULT_PHP_RATE", "56.0") or 56.0)

        db_path = os.getenv("DB_PATH", "data/bot.db").strip() or "data/bot.db"
        cfg.db_path = (BASE_DIR / db_path) if not Path(db_path).is_absolute() else Path(db_path)
        cfg.logs_dir = BASE_DIR / os.getenv("LOGS_DIR", "logs")

        cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
        cfg.logs_dir.mkdir(parents=True, exist_ok=True)
        return cfg


CONFIG = Config.load()
