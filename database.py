"""SQLite persistence layer.

The bot uses a small set of tables that cover every business concept:
users, deposit/withdrawal transactions, investment plans, the user's
investments, the referral link between users, and a key/value table for
admin-tunable settings (e.g. global referral percentage, daily ROI).

The code is deliberately written in raw SQL with a thin repository wrapper
so a template user can read every query and tweak it without learning an
ORM.  Every public method commits its own transaction to keep reasoning
simple.
"""
from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from config import CONFIG, BRAND_NAME, BRAND_SUPPORT

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id            INTEGER PRIMARY KEY,
    username           TEXT,
    full_name          TEXT,
    referral_code      TEXT UNIQUE NOT NULL,
    referred_by        INTEGER,
    balance            REAL NOT NULL DEFAULT 0,
    pending_balance    REAL NOT NULL DEFAULT 0,
    total_deposited    REAL NOT NULL DEFAULT 0,
    total_withdrawn    REAL NOT NULL DEFAULT 0,
    total_invested     REAL NOT NULL DEFAULT 0,
    total_earned       REAL NOT NULL DEFAULT 0,
    is_banned          INTEGER NOT NULL DEFAULT 0,
    is_admin           INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    FOREIGN KEY (referred_by) REFERENCES users(user_id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by);
CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);

CREATE TABLE IF NOT EXISTS plans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    description       TEXT,
    min_amount        REAL NOT NULL,
    max_amount        REAL NOT NULL,
    daily_roi_percent REAL NOT NULL,
    duration_days     INTEGER NOT NULL,
    capital_return    INTEGER NOT NULL DEFAULT 1,
    is_active         INTEGER NOT NULL DEFAULT 1,
    sort_order        INTEGER NOT NULL DEFAULT 0,
    image             TEXT,
    created_at        INTEGER NOT NULL
);
-- Add image column to existing tables (idempotent)
CREATE TABLE IF NOT EXISTS _plans_image_migration (done INTEGER PRIMARY KEY);

CREATE TABLE IF NOT EXISTS transactions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    tx_type         TEXT NOT NULL,            -- deposit|withdrawal|investment|earning|referral|adjustment
    amount          REAL NOT NULL,            -- signed; positive credits, negative debits
    currency        TEXT NOT NULL DEFAULT 'USD',
    crypto_currency TEXT,
    network         TEXT,
    wallet_address  TEXT,
    tx_hash         TEXT,
    receipt_file_id TEXT,
    status          TEXT NOT NULL,            -- pending|approved|rejected|completed|failed
    note            TEXT,
    admin_id        INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_tx_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_tx_type ON transactions(tx_type);

CREATE TABLE IF NOT EXISTS investments (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL,
    plan_id           INTEGER NOT NULL,
    plan_name         TEXT NOT NULL,
    principal         REAL NOT NULL,
    daily_roi_percent REAL NOT NULL,
    duration_days     INTEGER NOT NULL,
    capital_return    INTEGER NOT NULL DEFAULT 1,
    accrued_earnings  REAL NOT NULL DEFAULT 0,
    payout_amount     REAL NOT NULL DEFAULT 0,  -- total amount already paid out
    status            TEXT NOT NULL,            -- active|completed|cancelled
    started_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    completed_at      INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_inv_user ON investments(user_id);
CREATE INDEX IF NOT EXISTS idx_inv_status ON investments(status);

CREATE TABLE IF NOT EXISTS referrals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id   INTEGER NOT NULL,
    referred_id   INTEGER NOT NULL UNIQUE,
    total_bonus   REAL NOT NULL DEFAULT 0,
    total_events  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    FOREIGN KEY (referrer_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (referred_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  INTEGER NOT NULL,
    updated_by  INTEGER
);

CREATE TABLE IF NOT EXISTS web_admins (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,
    password     TEXT NOT NULL,
    display_name TEXT,
    role         TEXT NOT NULL DEFAULT 'admin',
    is_active    INTEGER NOT NULL DEFAULT 1,
    last_login   INTEGER,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id    INTEGER,
    admin_name  TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    details     TEXT,
    ip_address  TEXT,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_admin ON audit_logs(admin_id);

CREATE TABLE IF NOT EXISTS user_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    ip_address  TEXT,
    device_info TEXT,
    platform    TEXT,
    language    TEXT,
    action      TEXT NOT NULL,
    details     TEXT,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_usessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_usessions_created ON user_sessions(created_at);

CREATE TABLE IF NOT EXISTS web_login_tokens (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_wlt_user ON web_login_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_wlt_expires ON web_login_tokens(expires_at);
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> int:
    return int(time.time())


def _new_referral_code() -> str:
    return secrets.token_urlsafe(6).replace("=", "").replace("+", "").replace("/", "")[:10]


def _row_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


# ---------------------------------------------------------------------------
# Database wrapper
# ---------------------------------------------------------------------------


class Database:
    """Thread-safe SQLite wrapper with a tiny repository API.

    ``python-telegram-bot`` runs handlers on a thread pool, so all access
    goes through a single shared connection guarded by a lock.  SQLite
    with WAL mode easily handles the volume a Telegram bot produces.
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path), check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = _row_factory
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(SCHEMA)
        self._seed_defaults()

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------
    @contextmanager
    def cursor(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
            finally:
                cur.close()

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self.cursor() as cur:
            return cur.execute(sql, params)

    def executemany(self, sql: str, seq: Iterable[Sequence[Any]]) -> sqlite3.Cursor:
        with self.cursor() as cur:
            return cur.executemany(sql, seq)

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        with self.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()

    def query_all(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        with self.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    # ------------------------------------------------------------------
    # Seeding
    # ------------------------------------------------------------------
    def _seed_defaults(self) -> None:
        with self._lock:
            # Migrate: add image column to plans if missing
            try:
                self._conn.execute("ALTER TABLE plans ADD COLUMN image TEXT")
            except Exception:
                pass  # column already exists

            self._conn.execute("BEGIN")
            try:
                # Default plans if none exist — use Gyokuro plans
                count = self.query_one("SELECT COUNT(*) AS c FROM plans")
                if not count or count["c"] == 0:
                    from config import GYOKURO_PLANS
                    for p in GYOKURO_PLANS:
                        self._conn.execute(
                            """INSERT INTO plans
                               (name, description, min_amount, max_amount,
                                daily_roi_percent, duration_days,
                                capital_return, is_active, sort_order, image, created_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                            (
                                p["name"], p["description"],
                                p["min_amount"], p["max_amount"],
                                p["daily_roi_percent"], p["duration_days"],
                                1 if p["capital_return"] else 0,
                                p["sort_order"], p.get("image", ""),
                                _now(),
                            ),
                        )
                # Default settings
                defaults = {
                    "min_deposit_usd": str(CONFIG.min_deposit_usd),
                    "min_withdrawal_usd": str(CONFIG.min_withdrawal_usd),
                    "referral_bonus_percent": str(CONFIG.referral_bonus_percent),
                    "deduct_referral_from_investor": json.dumps(
                        CONFIG.deduct_referral_from_investor
                    ),
                    "support_handle": BRAND_SUPPORT,
                    "maintenance_mode": json.dumps(False),
                    "usd_to_php_rate": str(CONFIG.default_php_rate),
                    "signup_bonus_php": "50",
                    "welcome_message": (
                        f"Welcome to {BRAND_NAME}!\n\n"
                        "Gyokuro is your gateway to smart daily earnings. "
                        "Invest in our premium tea-inspired plans and watch your money grow every day.\n\n"
                        "Use the buttons below to get started."
                    ),
                }
                for k, v in defaults.items():
                    self._conn.execute(
                        """INSERT OR IGNORE INTO settings (key, value, updated_at)
                           VALUES (?, ?, ?)""",
                        (k, v, _now()),
                    )
                # Default web admin account (admin/gyokuroadmin)
                admin_exists = self.query_one("SELECT COUNT(*) AS c FROM web_admins")
                if not admin_exists or admin_exists["c"] == 0:
                    import hashlib
                    pw_hash = hashlib.pbkdf2_hmac(
                        "sha256", b"gyokuroadmin", b"tginvestbot_salt_v1", 100000
                    ).hex()
                    self._conn.execute(
                        """INSERT INTO web_admins
                           (username, password, display_name, role, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        ("admin", pw_hash, "Gyokuro Administrator", "superadmin", _now(), _now()),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------
    def grant_signup_bonus(self, user_id: int, amount: float) -> bool:
        """Credit a one-time signup bonus. Returns True if newly granted, False if already received."""
        with self._lock:
            already = self.query_one(
                "SELECT id FROM transactions WHERE user_id = ? AND tx_type = 'signup_bonus' LIMIT 1",
                (user_id,),
            )
            if already:
                return False
            self._conn.execute("BEGIN")
            try:
                self.execute(
                    "UPDATE users SET balance = balance + ?, updated_at = ? WHERE user_id = ?",
                    (amount, _now(), user_id),
                )
                self.execute(
                    """INSERT INTO transactions
                       (user_id, tx_type, amount, currency, status, note, created_at, updated_at)
                       VALUES (?, 'signup_bonus', ?, 'PHP', 'completed', ?, ?, ?)""",
                    (user_id, amount, f"Welcome bonus — ₱{amount:.0f} on sign up!", _now(), _now()),
                )
                self._conn.execute("COMMIT")
                return True
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def get_or_create_user(
        self, user_id: int, username: str = "", full_name: str = ""
    ) -> Dict[str, Any]:
        with self._lock:
            row = self.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
            if row:
                updates = []
                params: List[Any] = []
                if username and row["username"] != username:
                    updates.append("username = ?")
                    params.append(username)
                if full_name and row["full_name"] != full_name:
                    updates.append("full_name = ?")
                    params.append(full_name)
                if updates:
                    updates.append("updated_at = ?")
                    params.append(_now())
                    params.append(user_id)
                    self.execute(
                        f"UPDATE users SET {', '.join(updates)} WHERE user_id = ?",
                        params,
                    )
                return self.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
            # New user
            code = _new_referral_code()
            while self.query_one("SELECT 1 FROM users WHERE referral_code = ?", (code,)):
                code = _new_referral_code()
            self.execute(
                """INSERT INTO users
                   (user_id, username, full_name, referral_code, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, username, full_name, code, _now(), _now()),
            )
            return self.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))

    def set_referrer(self, user_id: int, referrer_id: int) -> bool:
        if user_id == referrer_id:
            return False
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                user = self.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
                if not user or user["referred_by"]:
                    self._conn.execute("ROLLBACK")
                    return False
                referrer = self.query_one(
                    "SELECT 1 FROM users WHERE user_id = ?", (referrer_id,)
                )
                if not referrer:
                    self._conn.execute("ROLLBACK")
                    return False
                self.execute(
                    "UPDATE users SET referred_by = ?, updated_at = ? WHERE user_id = ?",
                    (referrer_id, _now(), user_id),
                )
                self.execute(
                    """INSERT OR IGNORE INTO referrals
                       (referrer_id, referred_id, created_at) VALUES (?, ?, ?)""",
                    (referrer_id, user_id, _now()),
                )
                self._conn.execute("COMMIT")
                return True
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def update_balance(self, user_id: int, delta: float) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                row = self.query_one("SELECT balance FROM users WHERE user_id = ?", (user_id,))
                if not row:
                    self._conn.execute("ROLLBACK")
                    return None
                new_balance = round((row["balance"] or 0) + delta, 8)
                if new_balance < 0:
                    self._conn.execute("ROLLBACK")
                    return None
                self.execute(
                    "UPDATE users SET balance = ?, updated_at = ? WHERE user_id = ?",
                    (new_balance, _now(), user_id),
                )
                self._conn.execute("COMMIT")
                return self.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def set_ban(self, user_id: int, banned: bool) -> None:
        self.execute(
            "UPDATE users SET is_banned = ?, updated_at = ? WHERE user_id = ?",
            (1 if banned else 0, _now(), user_id),
        )

    def set_admin(self, user_id: int, admin: bool) -> None:
        self.execute(
            "UPDATE users SET is_admin = ?, updated_at = ? WHERE user_id = ?",
            (1 if admin else 0, _now(), user_id),
        )

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        return self.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))

    def list_users(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        return self.query_all(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    def count_users(self) -> int:
        row = self.query_one("SELECT COUNT(*) AS c FROM users")
        return row["c"] if row else 0

    def search_users(self, term: str) -> List[Dict[str, Any]]:
        like = f"%{term}%"
        return self.query_all(
            """SELECT * FROM users
               WHERE CAST(user_id AS TEXT) LIKE ?
                  OR IFNULL(username,'') LIKE ?
                  OR IFNULL(full_name,'') LIKE ?
               ORDER BY created_at DESC LIMIT 50""",
            (like, like, like),
        )

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        if not row:
            return default
        raw = row["value"]
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return raw

    def set_setting(self, key: str, value: Any, admin_id: Optional[int] = None) -> None:
        if not isinstance(value, str):
            value = json.dumps(value)
        self.execute(
            """INSERT INTO settings (key, value, updated_at, updated_by)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   updated_at = excluded.updated_at,
                   updated_by = excluded.updated_by""",
            (key, value, _now(), admin_id),
        )

    def all_settings(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for row in self.query_all("SELECT key, value FROM settings"):
            try:
                out[row["key"]] = json.loads(row["value"])
            except (ValueError, TypeError):
                out[row["key"]] = row["value"]
        return out

    # ------------------------------------------------------------------
    # Plans
    # ------------------------------------------------------------------
    def list_plans(self, active_only: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM plans"
        if active_only:
            sql += " WHERE is_active = 1"
        sql += " ORDER BY sort_order ASC, id ASC"
        return self.query_all(sql)

    def get_plan(self, plan_id: int) -> Optional[Dict[str, Any]]:
        return self.query_one("SELECT * FROM plans WHERE id = ?", (plan_id,))

    def create_plan(
        self,
        name: str,
        description: str,
        min_amount: float,
        max_amount: float,
        daily_roi_percent: float,
        duration_days: int,
        capital_return: bool = True,
        is_active: bool = True,
        sort_order: int = 0,
    ) -> int:
        cur = self.execute(
            """INSERT INTO plans
               (name, description, min_amount, max_amount, daily_roi_percent,
                duration_days, capital_return, is_active, sort_order, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, min_amount, max_amount, daily_roi_percent,
             duration_days, 1 if capital_return else 0,
             1 if is_active else 0, sort_order, _now()),
        )
        return cur.lastrowid

    def update_plan(self, plan_id: int, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        params: List[Any] = list(fields.values()) + [plan_id]
        self.execute(f"UPDATE plans SET {cols} WHERE id = ?", params)

    def delete_plan(self, plan_id: int) -> None:
        self.execute("DELETE FROM plans WHERE id = ?", (plan_id,))

    # ------------------------------------------------------------------
    # Transactions (deposits / withdrawals / adjustments)
    # ------------------------------------------------------------------
    def create_transaction(
        self,
        user_id: int,
        tx_type: str,
        amount: float,
        status: str = "pending",
        currency: str = "USD",
        crypto_currency: Optional[str] = None,
        network: Optional[str] = None,
        wallet_address: Optional[str] = None,
        tx_hash: Optional[str] = None,
        receipt_file_id: Optional[str] = None,
        note: Optional[str] = None,
    ) -> int:
        cur = self.execute(
            """INSERT INTO transactions
               (user_id, tx_type, amount, currency, crypto_currency, network,
                wallet_address, tx_hash, receipt_file_id, status, note,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, tx_type, amount, currency, crypto_currency, network,
             wallet_address, tx_hash, receipt_file_id, status, note,
             _now(), _now()),
        )
        return cur.lastrowid

    def update_transaction(
        self, tx_id: int, status: str, admin_id: Optional[int] = None, note: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        self.execute(
            """UPDATE transactions
               SET status = ?, admin_id = ?, note = COALESCE(?, note), updated_at = ?
               WHERE id = ?""",
            (status, admin_id, note, _now(), tx_id),
        )
        return self.get_transaction(tx_id)

    def get_transaction(self, tx_id: int) -> Optional[Dict[str, Any]]:
        return self.query_one("SELECT * FROM transactions WHERE id = ?", (tx_id,))

    def list_transactions(
        self,
        tx_type: Optional[str] = None,
        status: Optional[str] = None,
        user_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM transactions WHERE 1=1"
        params: List[Any] = []
        if tx_type:
            sql += " AND tx_type = ?"
            params.append(tx_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return self.query_all(sql, params)

    def count_transactions(
        self, tx_type: Optional[str] = None, status: Optional[str] = None
    ) -> int:
        sql = "SELECT COUNT(*) AS c FROM transactions WHERE 1=1"
        params: List[Any] = []
        if tx_type:
            sql += " AND tx_type = ?"
            params.append(tx_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        row = self.query_one(sql, params)
        return row["c"] if row else 0

    # ------------------------------------------------------------------
    # Investments
    # ------------------------------------------------------------------
    def create_investment(
        self, user_id: int, plan: Dict[str, Any], amount: float
    ) -> Dict[str, Any]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                now = _now()
                duration = int(plan["duration_days"])
                expires = now + duration * 86400
                cur = self.execute(
                    """INSERT INTO investments
                       (user_id, plan_id, plan_name, principal,
                        daily_roi_percent, duration_days, capital_return,
                        accrued_earnings, payout_amount, status,
                        started_at, expires_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 'active', ?, ?)""",
                    (user_id, plan["id"], plan["name"], amount,
                     plan["daily_roi_percent"], duration,
                     plan["capital_return"], now, expires),
                )
                investment_id = cur.lastrowid
                # Lock the funds: deduct from balance, add to invested total
                self.execute(
                    """UPDATE users
                       SET balance = balance - ?,
                           total_invested = total_invested + ?,
                           updated_at = ?
                       WHERE user_id = ? AND balance >= ?""",
                    (amount, amount, _now(), user_id, amount),
                )
                # Automatic referral bonus
                user = self.query_one(
                    "SELECT referred_by FROM users WHERE user_id = ?", (user_id,)
                )
                if user and user.get("referred_by"):
                    bonus_pct = float(self.get_setting("referral_bonus_percent", 5.0))
                    bonus = round(amount * bonus_pct / 100.0, 8)
                    if bonus > 0:
                        referrer_id = user["referred_by"]
                        self.execute(
                            """UPDATE referrals
                               SET total_bonus = total_bonus + ?,
                                   total_events = total_events + 1
                               WHERE referrer_id = ? AND referred_id = ?""",
                            (bonus, referrer_id, user_id),
                        )
                        self.execute(
                            """UPDATE users
                               SET balance = balance + ?, updated_at = ?
                               WHERE user_id = ?""",
                            (bonus, _now(), referrer_id),
                        )
                        self.execute(
                            """INSERT INTO transactions
                               (user_id, tx_type, amount, currency, status, note,
                                created_at, updated_at)
                               VALUES (?, 'referral', ?, 'USD', 'completed', ?, ?, ?)""",
                            (referrer_id, bonus,
                             f"Referral bonus from user {user_id}",
                             _now(), _now()),
                        )
                self._conn.execute("COMMIT")
                return self.get_investment(investment_id)  # type: ignore[return-value]
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def get_investment(self, investment_id: int) -> Optional[Dict[str, Any]]:
        return self.query_one("SELECT * FROM investments WHERE id = ?", (investment_id,))

    def list_investments(
        self,
        user_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM investments WHERE 1=1"
        params: List[Any] = []
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return self.query_all(sql, params)

    def count_investments(self, status: Optional[str] = None) -> int:
        sql = "SELECT COUNT(*) AS c FROM investments WHERE 1=1"
        params: List[Any] = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        row = self.query_one(sql, params)
        return row["c"] if row else 0

    def complete_investment(self, investment_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                inv = self.get_investment(investment_id)
                if not inv or inv["status"] != "active":
                    self._conn.execute("ROLLBACK")
                    return inv
                principal = float(inv["principal"])
                capital_return = bool(inv["capital_return"])
                already_paid = float(inv["payout_amount"] or 0)
                total_earnings = self.compute_investment_total_earnings(inv)
                # Pay out remaining earnings + principal if capital_return
                pending_earnings = max(total_earnings - already_paid, 0.0)
                credit = pending_earnings + (principal if capital_return else 0.0)
                self.execute(
                    """UPDATE investments
                       SET status = 'completed',
                           accrued_earnings = ?,
                           payout_amount = ?,
                           completed_at = ?
                       WHERE id = ?""",
                    (total_earnings, total_earnings + (principal if capital_return else 0.0),
                     _now(), investment_id),
                )
                if credit > 0:
                    self.execute(
                        """UPDATE users
                           SET balance = balance + ?,
                               total_earned = total_earned + ?,
                               updated_at = ?
                           WHERE user_id = ?""",
                        (credit, pending_earnings, _now(), inv["user_id"]),
                    )
                    self.create_transaction(
                        user_id=inv["user_id"],
                        tx_type="earning",
                        amount=credit,
                        status="completed",
                        note=f"Investment #{investment_id} completed",
                    )
                self._conn.execute("COMMIT")
                return self.get_investment(investment_id)
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def cancel_investment(self, investment_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                inv = self.get_investment(investment_id)
                if not inv or inv["status"] != "active":
                    self._conn.execute("ROLLBACK")
                    return inv
                # Refund principal to balance, drop any accrued earnings
                self.execute(
                    """UPDATE investments
                       SET status = 'cancelled', completed_at = ?
                       WHERE id = ?""",
                    (_now(), investment_id),
                )
                self.execute(
                    """UPDATE users
                       SET balance = balance + ?,
                           total_invested = total_invested - ?,
                           updated_at = ?
                       WHERE user_id = ?""",
                    (inv["principal"], inv["principal"], _now(), inv["user_id"]),
                )
                self.create_transaction(
                    user_id=inv["user_id"],
                    tx_type="adjustment",
                    amount=float(inv["principal"]),
                    status="completed",
                    note=f"Investment #{investment_id} cancelled, principal refunded",
                )
                self._conn.execute("COMMIT")
                return self.get_investment(investment_id)
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    @staticmethod
    def compute_investment_total_earnings(inv: Dict[str, Any]) -> float:
        """Linear time-based earnings, capped at duration.

        Earnings accrue continuously from ``started_at`` to ``expires_at``;
        we expose the total that *should* have been earned by the current
        wall-clock time so callers can compare it to ``payout_amount``.
        """
        principal = float(inv["principal"])
        daily_roi = float(inv["daily_roi_percent"])
        duration = int(inv["duration_days"])
        if duration <= 0 or principal <= 0 or daily_roi <= 0:
            return 0.0
        total = principal * (daily_roi / 100.0) * duration
        return round(total, 8)

    @staticmethod
    def compute_investment_earnings_to_date(inv: Dict[str, Any], now: Optional[int] = None) -> float:
        """Earnings that have accrued up to ``now`` (capped at duration)."""
        principal = float(inv["principal"])
        daily_roi = float(inv["daily_roi_percent"])
        duration = int(inv["duration_days"])
        if duration <= 0 or principal <= 0 or daily_roi <= 0:
            return 0.0
        now = now or _now()
        elapsed_days = max(0, min(duration, (now - int(inv["started_at"])) / 86400.0))
        return round(principal * (daily_roi / 100.0) * elapsed_days, 8)

    # ------------------------------------------------------------------
    # Referrals
    # ------------------------------------------------------------------
    def referral_stats(self, user_id: int) -> Dict[str, Any]:
        row = self.query_one(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(total_bonus), 0) AS bonus,
                      COALESCE(SUM(total_events), 0) AS events
               FROM referrals WHERE referrer_id = ?""",
            (user_id,),
        ) or {"total": 0, "bonus": 0.0, "events": 0}
        referred_users = self.query_all(
            """SELECT u.user_id, u.username, u.full_name, u.total_invested,
                      r.total_bonus, r.created_at
               FROM referrals r JOIN users u ON u.user_id = r.referred_id
               WHERE r.referrer_id = ? ORDER BY r.created_at DESC""",
            (user_id,),
        )
        return {
            "total": row["total"],
            "bonus": row["bonus"],
            "events": row["events"],
            "referred_users": referred_users,
        }

    def record_referral_bonus(
        self, referrer_id: int, referred_id: int, bonus: float
    ) -> None:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self.execute(
                    """UPDATE referrals
                       SET total_bonus = total_bonus + ?,
                           total_events = total_events + 1
                       WHERE referrer_id = ? AND referred_id = ?""",
                    (bonus, referrer_id, referred_id),
                )
                self.execute(
                    """UPDATE users
                       SET balance = balance + ?, updated_at = ?
                       WHERE user_id = ?""",
                    (bonus, _now(), referrer_id),
                )
                self.create_transaction(
                    user_id=referrer_id,
                    tx_type="referral",
                    amount=bonus,
                    status="completed",
                    note=f"Referral bonus from user {referred_id}",
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------
    # Aggregate stats (for admin dashboard)
    # ------------------------------------------------------------------
    def admin_stats(self) -> Dict[str, Any]:
        def _scalar(sql, default=0):
            row = self.query_one(sql)
            return row["v"] if row else default

        totals = {
            "users": _scalar("SELECT COUNT(*) AS v FROM users"),
            "banned": _scalar("SELECT COUNT(*) AS v FROM users WHERE is_banned = 1"),
            "active_investments": _scalar(
                "SELECT COUNT(*) AS v FROM investments WHERE status = 'active'"
            ),
            "pending_deposits": _scalar(
                "SELECT COUNT(*) AS v FROM transactions WHERE tx_type = 'deposit' AND status = 'pending'"
            ),
            "pending_withdrawals": _scalar(
                "SELECT COUNT(*) AS v FROM transactions WHERE tx_type = 'withdrawal' AND status = 'pending'"
            ),
            "total_invested": _scalar(
                "SELECT COALESCE(SUM(principal), 0) AS v FROM investments WHERE status IN ('active','completed')"
            ),
            "total_principal_active": _scalar(
                "SELECT COALESCE(SUM(principal), 0) AS v FROM investments WHERE status = 'active'"
            ),
            "total_earnings_paid": _scalar(
                "SELECT COALESCE(SUM(amount), 0) AS v FROM transactions WHERE tx_type = 'earning' AND status = 'completed'"
            ),
            "total_deposits_approved": _scalar(
                "SELECT COALESCE(SUM(amount), 0) AS v FROM transactions WHERE tx_type = 'deposit' AND status = 'completed'"
            ),
            "total_withdrawals_completed": _scalar(
                "SELECT COALESCE(SUM(amount), 0) AS v FROM transactions WHERE tx_type = 'withdrawal' AND status = 'completed'"
            ),
            "total_referral_bonus": _scalar(
                "SELECT COALESCE(SUM(amount), 0) AS v FROM transactions WHERE tx_type = 'referral' AND status = 'completed'"
            ),
        }
        return totals

    # ------------------------------------------------------------------
    # Web Admins
    # ------------------------------------------------------------------
    def get_web_admin(self, username: str) -> Optional[Dict[str, Any]]:
        return self.query_one(
            "SELECT * FROM web_admins WHERE username = ? AND is_active = 1",
            (username,),
        )

    def get_web_admin_by_id(self, admin_id: int) -> Optional[Dict[str, Any]]:
        return self.query_one("SELECT * FROM web_admins WHERE id = ?", (admin_id,))

    def create_web_admin(
        self, username: str, password_hash: str, display_name: str = "", role: str = "admin"
    ) -> int:
        cur = self.execute(
            """INSERT INTO web_admins (username, password, display_name, role, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (username, password_hash, display_name or username, role, _now(), _now()),
        )
        return cur.lastrowid

    def update_web_admin_login(self, admin_id: int) -> None:
        self.execute(
            "UPDATE web_admins SET last_login = ?, updated_at = ? WHERE id = ?",
            (_now(), _now(), admin_id),
        )

    def update_web_admin_password(self, admin_id: int, password_hash: str) -> None:
        self.execute(
            "UPDATE web_admins SET password = ?, updated_at = ? WHERE id = ?",
            (password_hash, _now(), admin_id),
        )

    def list_web_admins(self) -> List[Dict[str, Any]]:
        return self.query_all("SELECT * FROM web_admins ORDER BY created_at ASC")

    # ------------------------------------------------------------------
    # Audit Logs
    # ------------------------------------------------------------------
    def log_audit(
        self,
        action: str,
        admin_id: Optional[int] = None,
        admin_name: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> int:
        cur = self.execute(
            """INSERT INTO audit_logs
               (admin_id, admin_name, action, target_type, target_id, details, ip_address, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (admin_id, admin_name, action, target_type, target_id, details, ip_address, _now()),
        )
        return cur.lastrowid

    def list_audit_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        return self.query_all(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    def count_audit_logs(self) -> int:
        row = self.query_one("SELECT COUNT(*) AS c FROM audit_logs")
        return row["c"] if row else 0

    # ------------------------------------------------------------------
    # User Sessions (security tracking)
    # ------------------------------------------------------------------
    def log_user_session(
        self,
        user_id: int,
        action: str,
        ip_address: Optional[str] = None,
        device_info: Optional[str] = None,
        platform: Optional[str] = None,
        language: Optional[str] = None,
        details: Optional[str] = None,
    ) -> int:
        cur = self.execute(
            """INSERT INTO user_sessions
               (user_id, ip_address, device_info, platform, language, action, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, ip_address, device_info, platform, language, action, details, _now()),
        )
        return cur.lastrowid

    def list_user_sessions(
        self, user_id: Optional[int] = None, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM user_sessions WHERE 1=1"
        params: List[Any] = []
        if user_id:
            sql += " AND user_id = ?"
            params.append(user_id)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return self.query_all(sql, params)

    def get_user_last_session(self, user_id: int) -> Optional[Dict[str, Any]]:
        return self.query_one(
            "SELECT * FROM user_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        )

    def count_user_sessions(self, user_id: Optional[int] = None) -> int:
        if user_id:
            row = self.query_one(
                "SELECT COUNT(*) AS c FROM user_sessions WHERE user_id = ?", (user_id,)
            )
        else:
            row = self.query_one("SELECT COUNT(*) AS c FROM user_sessions")
        return row["c"] if row else 0

    # ------------------------------------------------------------------
    # Web login tokens (one-time URL tokens for user portal access)
    # ------------------------------------------------------------------
    def create_web_login_token(self, user_id: int, ttl_seconds: int = 300) -> str:
        """Generate a one-time login token. Expires after ttl_seconds (default 5 min)."""
        token = secrets.token_urlsafe(32)
        now = _now()
        self.execute(
            """INSERT INTO web_login_tokens (token, user_id, created_at, expires_at)
               VALUES (?, ?, ?, ?)""",
            (token, user_id, now, now + ttl_seconds),
        )
        return token

    def consume_web_login_token(self, token: str) -> Optional[int]:
        """Validate and consume a token. Returns user_id on success, None otherwise."""
        now = _now()
        row = self.query_one(
            """SELECT * FROM web_login_tokens
               WHERE token = ? AND expires_at > ? AND used_at IS NULL""",
            (token, now),
        )
        if not row:
            return None
        self.execute(
            "UPDATE web_login_tokens SET used_at = ? WHERE token = ?",
            (now, token),
        )
        return row["user_id"]

    def cleanup_web_login_tokens(self) -> None:
        """Remove expired tokens older than 1 hour."""
        cutoff = _now() - 3600
        self.execute("DELETE FROM web_login_tokens WHERE expires_at < ?", (cutoff,))

    # ------------------------------------------------------------------
    # Per-user investment count helper
    # ------------------------------------------------------------------
    def count_investments_for_user(self, user_id: int, status: Optional[str] = None) -> int:
        if status:
            row = self.query_one(
                "SELECT COUNT(*) AS c FROM investments WHERE user_id = ? AND status = ?",
                (user_id, status),
            )
        else:
            row = self.query_one(
                "SELECT COUNT(*) AS c FROM investments WHERE user_id = ?",
                (user_id,),
            )
        return row["c"] if row else 0


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_DB: Optional[Database] = None


def get_db() -> Database:
    global _DB
    if _DB is None:
        _DB = Database(CONFIG.db_path)
    return _DB
