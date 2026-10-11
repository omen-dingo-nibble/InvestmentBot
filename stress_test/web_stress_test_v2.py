"""HTTP-layer stress & security test v2 for Gyokuro InvestmentBot.

Extends the original web_stress_test.py with additional coverage of:

  * Admin login CSRF (now enforced)
  * Double-approve race for deposits (should be atomic)
  * Double-reject race for withdrawals (should not double-refund)
  * Double-approve race for withdrawals
  * Maintenance mode — portal routes return 503 when flag is set
  * Plan creation input validation (invalid ROI, swapped min/max, etc.)
  * Broadcast sanitization / length cap
  * Concurrent withdrawal rejection (race-condition hardening)
  * All original test suites re-run to confirm no regressions

Run with:
    python -m stress_test.web_stress_test_v2
"""
from __future__ import annotations

import concurrent.futures
import os
import sys
import time
import traceback
from pathlib import Path

# ── Project root on sys.path ──────────────────────────────────────────────
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

# ── Isolated test DB ──────────────────────────────────────────────────────
TEST_DB = ROOT / "data" / "web_test_v2.db"
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DB_PATH"] = "data/web_test_v2.db"
os.environ["FLASK_SECRET_KEY"] = "web-stress-v2-secret-key-32chars!!"
os.environ["ADMIN_IDS"] = "1,2"
os.environ["MIN_DEPOSIT_USD"] = "10"
os.environ["MIN_WITHDRAWAL_USD"] = "5"
os.environ["REFERRAL_BONUS_PERCENT"] = "5"

import database as _db_mod
_db_mod._DB = None

from config import CONFIG
CONFIG.db_path = TEST_DB
TEST_DB.parent.mkdir(parents=True, exist_ok=True)

from web.app import create_app
from database import get_db

# ── Colour helpers ────────────────────────────────────────────────────────
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
B = "\033[96m"
W = "\033[0m"
BOLD = "\033[1m"


def section(title: str):
    print(f"\n{BOLD}{B}{'─'*60}{W}")
    print(f"{BOLD}{B}  {title}{W}")
    print(f"{BOLD}{B}{'─'*60}{W}")


# ── Stats tracker ─────────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.failures: list[tuple[str, str]] = []

    def expect(self, label: str, condition: bool, detail: str = ""):
        if condition:
            print(f"  {G}✓{W} {label}")
            self.passed += 1
        else:
            msg = f" — {detail}" if detail else ""
            print(f"  {R}✗{W} {label}{msg}")
            self.failed += 1
            self.failures.append((label, detail))

    def warn(self, label: str, detail: str = ""):
        print(f"  {Y}⚠{W} {label}{(' — ' + detail) if detail else ''}")
        self.warnings += 1


S = Stats()

# ── Test helpers ──────────────────────────────────────────────────────────

ADMIN_USER = "admin"
ADMIN_PASS = "gyokuroadmin"
_phone_counter = 70_000_000  # separate range from v1 test


def next_phone() -> str:
    global _phone_counter
    _phone_counter += 1
    return f"+639{_phone_counter}"


def _get_csrf(client) -> str:
    """Return the current session CSRF token; hit login page if needed."""
    with client.session_transaction() as sess:
        if "_csrf" in sess:
            return sess["_csrf"]
    client.get("/admin/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf", "")


def _get_csrf_portal(client) -> str:
    client.get("/app/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf", "")


def admin_session(client) -> bool:
    """Log the test client in as admin."""
    csrf = _get_csrf(client)
    r = client.post("/admin/login", data={
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
        "_csrf_token": csrf,
    }, follow_redirects=True)
    return r.status_code == 200


def portal_register_and_login(client, phone: str, password: str = "pass1234",
                               name: str = "Test User") -> bool:
    csrf = _get_csrf_portal(client)
    r = client.post("/app/register", data={
        "phone": phone,
        "full_name": name,
        "password": password,
        "confirm_password": password,
        "_csrf_token": csrf,
    }, follow_redirects=False)
    return r.status_code == 302


def portal_login(client, phone: str, password: str = "pass1234") -> bool:
    csrf = _get_csrf_portal(client)
    r = client.post("/app/login", data={
        "phone": phone,
        "password": password,
        "_csrf_token": csrf,
    }, follow_redirects=False)
    return r.status_code == 302


def check_security_headers(response, label: str):
    required = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": None,
    }
    for header, expected_val in required.items():
        present = header in response.headers
        S.expect(f"{label}: has {header}", present)
        if present and expected_val:
            S.expect(
                f"{label}: {header} = {expected_val}",
                response.headers[header] == expected_val,
                f"got: {response.headers.get(header)}",
            )


# ════════════════════════════════════════════════════════════════════════════
# NEW TEST SECTIONS
# ════════════════════════════════════════════════════════════════════════════

def test_admin_login_csrf_now_enforced(app):
    """Admin login POST without CSRF token must now return 403."""
    section("Admin login CSRF — now enforced on login POST")
    with app.test_client() as c:
        # No CSRF token at all
        r = c.post("/admin/login", data={
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
            # deliberately omitting _csrf_token
        }, follow_redirects=False)
        S.expect(
            "Admin login POST without CSRF → 403",
            r.status_code == 403,
            f"got {r.status_code}",
        )

    with app.test_client() as c:
        # Wrong CSRF token
        r = c.post("/admin/login", data={
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
            "_csrf_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }, follow_redirects=False)
        S.expect(
            "Admin login POST with wrong CSRF → 403",
            r.status_code == 403,
            f"got {r.status_code}",
        )

    with app.test_client() as c:
        # Correct CSRF token → should succeed
        csrf = _get_csrf(c)
        r = c.post("/admin/login", data={
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect(
            "Admin login with correct CSRF → 302",
            r.status_code == 302,
            f"got {r.status_code}",
        )


def test_deposit_double_approve_race(app):
    """Two concurrent admin requests to approve the same deposit must result
    in exactly one credit — not two."""
    section("Deposit double-approve race — atomic claim prevents double credit")
    db = get_db()
    db.set_setting("crypto_usdt_trc20_address", "TFakeWalletAddr_v2")

    phone = next_phone()
    with app.test_client() as c:
        portal_register_and_login(c, phone)
        csrf = _get_csrf_portal(c)
        c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20",
            "amount_php": "5000",
            "tx_hash": "race_deposit_hash_v2",
            "_csrf_token": csrf,
        })

    user = db.get_user_by_phone(phone)
    txs = db.list_transactions(user_id=user["user_id"], tx_type="deposit", status="pending")
    if not txs:
        S.warn("No pending deposit found — skipping double-approve test")
        return
    tx_id = txs[0]["id"]
    initial_balance = float(db.get_user(user["user_id"])["balance"])

    approve_results = []

    def do_approve():
        with app.test_client() as c:
            admin_session(c)
            csrf = _get_csrf(c)
            r = c.post(f"/deposits/{tx_id}/approve", data={"_csrf_token": csrf},
                       follow_redirects=False)
            return r.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(do_approve) for _ in range(4)]
        approve_results = [f.result() for f in concurrent.futures.as_completed(futures)]

    final_balance = float(db.get_user(user["user_id"])["balance"])
    credited = round(final_balance - initial_balance, 2)

    S.expect(
        "Balance credited exactly once (not 2× or 4×)",
        abs(credited - 5000.0) < 0.01,
        f"credited ₱{credited:.2f} on ₱5000 deposit",
    )
    final_tx = db.get_transaction(tx_id)
    S.expect(
        "Transaction status is completed (not still pending or duplicated)",
        final_tx["status"] in ("completed", "processing"),
        f"status = {final_tx['status']}",
    )


def test_withdrawal_double_reject_no_double_refund(app):
    """Two concurrent admins rejecting the same withdrawal must refund only once."""
    section("Withdrawal double-reject — atomic claim prevents double-refund")
    db = get_db()
    phone = next_phone()

    with app.test_client() as c:
        portal_register_and_login(c, phone)

    user = db.get_user_by_phone(phone)
    db.update_balance(user["user_id"], 3000)

    # User submits a withdrawal
    with app.test_client() as c:
        portal_login(c, phone)
        csrf = _get_csrf_portal(c)
        c.post("/app/withdraw", data={
            "amount": "1000",
            "crypto_currency": "USDT-TRC20",
            "wallet_address": "TRejectTestAddress123456",
            "_csrf_token": csrf,
        })

    txs = db.list_transactions(user_id=user["user_id"], tx_type="withdrawal", status="pending")
    if not txs:
        S.warn("No pending withdrawal — skipping double-reject test")
        return
    tx_id = txs[0]["id"]

    # Balance should now be 3000 - 1000 = 2000
    balance_after_lock = float(db.get_user(user["user_id"])["balance"])
    S.expect(
        "Balance locked: 3000 - 1000 = 2000",
        abs(balance_after_lock - 2000.0) < 0.01,
        f"got ₱{balance_after_lock:.2f}",
    )

    reject_results = []

    def do_reject():
        with app.test_client() as c:
            admin_session(c)
            csrf = _get_csrf(c)
            r = c.post(f"/withdrawals/{tx_id}/reject", data={"_csrf_token": csrf},
                       follow_redirects=False)
            return r.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = [ex.submit(do_reject) for _ in range(3)]
        reject_results = [f.result() for f in concurrent.futures.as_completed(futures)]

    final_balance = float(db.get_user(user["user_id"])["balance"])
    S.expect(
        "Balance restored to exactly 3000 (single refund, not 2× or 3×)",
        abs(final_balance - 3000.0) < 0.01,
        f"got ₱{final_balance:.2f}",
    )
    tx_after = db.get_transaction(tx_id)
    S.expect(
        "Withdrawal status is rejected",
        tx_after["status"] == "rejected",
        f"status = {tx_after['status']}",
    )


def test_withdrawal_double_approve_no_double_total_withdrawn(app):
    """Concurrent approve calls on the same withdrawal must only increment
    total_withdrawn once."""
    section("Withdrawal double-approve — total_withdrawn incremented exactly once")
    db = get_db()
    phone = next_phone()

    with app.test_client() as c:
        portal_register_and_login(c, phone)

    user = db.get_user_by_phone(phone)
    db.update_balance(user["user_id"], 5000)

    with app.test_client() as c:
        portal_login(c, phone)
        csrf = _get_csrf_portal(c)
        c.post("/app/withdraw", data={
            "amount": "2000",
            "crypto_currency": "BTC",
            "wallet_address": "bc1qDoubleApproveTestAddr",
            "_csrf_token": csrf,
        })

    txs = db.list_transactions(user_id=user["user_id"], tx_type="withdrawal", status="pending")
    if not txs:
        S.warn("No pending withdrawal — skipping double-approve test")
        return
    tx_id = txs[0]["id"]
    total_wd_before = float(db.get_user(user["user_id"])["total_withdrawn"])

    def do_approve():
        with app.test_client() as c:
            admin_session(c)
            csrf = _get_csrf(c)
            r = c.post(f"/withdrawals/{tx_id}/approve", data={"_csrf_token": csrf},
                       follow_redirects=False)
            return r.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = [ex.submit(do_approve) for _ in range(3)]
        [f.result() for f in concurrent.futures.as_completed(futures)]

    total_wd_after = float(db.get_user(user["user_id"])["total_withdrawn"])
    delta = round(total_wd_after - total_wd_before, 2)
    S.expect(
        "total_withdrawn incremented by exactly 2000 (not 2× or 3×)",
        abs(delta - 2000.0) < 0.01,
        f"delta = ₱{delta:.2f}",
    )


def test_maintenance_mode_blocks_portal(app):
    """When maintenance_mode is True, authenticated portal routes should
    return 503 (not 200), while the login page itself stays accessible."""
    section("Maintenance mode — portal routes blocked, login page still reachable")
    db = get_db()
    phone = next_phone()

    with app.test_client() as c:
        portal_register_and_login(c, phone)

    # Enable maintenance mode
    db.set_setting("maintenance_mode", True)

    with app.test_client() as c:
        portal_login(c, phone)

        protected_portal_routes = [
            "/app/",
            "/app/me",
            "/app/plans",
            "/app/rewards",
            "/app/invite",
            "/app/deposit",
            "/app/withdraw",
            "/app/api/balance",
            "/app/api/investments",
        ]
        for path in protected_portal_routes:
            r = c.get(path)
            S.expect(
                f"Maintenance mode: {path} → 503",
                r.status_code == 503,
                f"got {r.status_code}",
            )

    # Login page should still render (not blocked)
    with app.test_client() as c:
        r = c.get("/app/login")
        S.expect(
            "Maintenance mode: login page still accessible (200)",
            r.status_code == 200,
            f"got {r.status_code}",
        )

    # Restore
    db.set_setting("maintenance_mode", False)

    # Verify portal works again after maintenance mode is lifted
    with app.test_client() as c:
        portal_login(c, phone)
        r = c.get("/app/")
        S.expect(
            "After maintenance lifted: home accessible (200)",
            r.status_code == 200,
            f"got {r.status_code}",
        )


def test_plan_create_input_validation(app):
    """Plan creation should reject invalid ROI %, swapped min/max, and
    extreme duration values."""
    section("Plan create — server-side input validation on numeric fields")
    with app.test_client() as c:
        admin_session(c)

        # ROI > 100%
        csrf = _get_csrf(c)
        r = c.post("/plans/create", data={
            "name": "BadROI Plan",
            "description": "test",
            "min_amount": "100",
            "max_amount": "1000",
            "daily_roi": "150",        # 150% daily — invalid
            "duration": "30",
            "is_active": "on",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect(
            "ROI > 100% rejected (400 or re-render 200, not redirect)",
            r.status_code in (200, 400),
            f"got {r.status_code} — plan should not have been created",
        )
        db = get_db()
        bad = [p for p in db.list_plans() if p["name"] == "BadROI Plan"]
        S.expect("BadROI Plan not persisted", len(bad) == 0, f"found {len(bad)} rows")

        # min_amount > max_amount
        csrf2 = _get_csrf(c)
        r = c.post("/plans/create", data={
            "name": "SwappedRange Plan",
            "description": "test",
            "min_amount": "9999",
            "max_amount": "100",       # min > max
            "daily_roi": "2",
            "duration": "30",
            "is_active": "on",
            "_csrf_token": csrf2,
        }, follow_redirects=False)
        S.expect(
            "min_amount > max_amount rejected",
            r.status_code in (200, 400),
            f"got {r.status_code}",
        )
        swapped = [p for p in db.list_plans() if p["name"] == "SwappedRange Plan"]
        S.expect("SwappedRange Plan not persisted", len(swapped) == 0)

        # Negative min_amount
        csrf3 = _get_csrf(c)
        r = c.post("/plans/create", data={
            "name": "NegAmount Plan",
            "description": "test",
            "min_amount": "-500",
            "max_amount": "1000",
            "daily_roi": "2",
            "duration": "30",
            "is_active": "on",
            "_csrf_token": csrf3,
        }, follow_redirects=False)
        S.expect(
            "Negative min_amount rejected",
            r.status_code in (200, 400),
            f"got {r.status_code}",
        )
        neg = [p for p in db.list_plans() if p["name"] == "NegAmount Plan"]
        S.expect("NegAmount Plan not persisted", len(neg) == 0)

        # Zero duration
        csrf4 = _get_csrf(c)
        r = c.post("/plans/create", data={
            "name": "ZeroDuration Plan",
            "description": "test",
            "min_amount": "100",
            "max_amount": "1000",
            "daily_roi": "2",
            "duration": "0",           # 0 days — invalid
            "is_active": "on",
            "_csrf_token": csrf4,
        }, follow_redirects=False)
        S.expect(
            "Zero duration rejected",
            r.status_code in (200, 400),
            f"got {r.status_code}",
        )

        # Valid plan — should create fine
        csrf5 = _get_csrf(c)
        r = c.post("/plans/create", data={
            "name": "ValidStressTestPlan",
            "description": "Created by stress test v2",
            "min_amount": "100",
            "max_amount": "5000",
            "daily_roi": "2.5",
            "duration": "30",
            "is_active": "on",
            "_csrf_token": csrf5,
        }, follow_redirects=False)
        S.expect("Valid plan → redirect (302)", r.status_code == 302, f"got {r.status_code}")
        valid = [p for p in db.list_plans() if p["name"] == "ValidStressTestPlan"]
        S.expect("Valid plan persisted in DB", len(valid) == 1)


def test_broadcast_sanitization(app):
    """Broadcast message should be stored and capped; oversized messages
    should not cause a 500."""
    section("Broadcast — oversized and empty message handling")
    with app.test_client() as c:
        admin_session(c)

        # Empty message
        csrf = _get_csrf(c)
        r = c.post("/broadcast", data={
            "message": "",
            "_csrf_token": csrf,
        }, follow_redirects=True)
        S.expect(
            "Empty broadcast → 200 with error (not 500)",
            r.status_code == 200,
            f"got {r.status_code}",
        )
        S.expect(
            "Error shown for empty broadcast",
            b"empty" in r.data.lower() or b"cannot" in r.data.lower(),
        )

        # Oversized message (10 000 chars > 4000 char cap)
        csrf2 = _get_csrf(c)
        big_msg = "X" * 10_000
        r = c.post("/broadcast", data={
            "message": big_msg,
            "_csrf_token": csrf2,
        }, follow_redirects=True)
        S.expect(
            "Oversized broadcast handled (no 500)",
            r.status_code in (200, 302, 400),
            f"got {r.status_code}",
        )

        # Check that if it was stored, it was truncated to ≤ 4000 chars
        db = get_db()
        import json as _json
        stored_raw = db.get_setting("_pending_broadcast")
        if stored_raw:
            try:
                stored = _json.loads(stored_raw) if isinstance(stored_raw, str) else stored_raw
                msg_len = len(stored.get("message", ""))
                S.expect(
                    f"Stored broadcast message truncated to ≤ 4000 chars (got {msg_len})",
                    msg_len <= 4000,
                )
            except Exception:
                S.warn("Could not parse stored broadcast setting")
        else:
            S.warn("No broadcast was stored (might have been rejected — OK)")

        # Valid short broadcast
        csrf3 = _get_csrf(c)
        r = c.post("/broadcast", data={
            "message": "Hello investors! Stress test broadcast.",
            "_csrf_token": csrf3,
        }, follow_redirects=True)
        S.expect(
            "Valid broadcast queued → 200 with success message",
            r.status_code == 200,
            f"got {r.status_code}",
        )
        S.expect(
            "Success message shown",
            b"queued" in r.data.lower() or b"broadcast" in r.data.lower(),
        )


def test_settings_input_sanitization(app):
    """Settings form should not 500 on oversized or malformed inputs."""
    section("Settings — oversized / malformed inputs don't crash the server")
    with app.test_client() as c:
        admin_session(c)
        csrf = _get_csrf(c)
        r = c.post("/settings", data={
            "bot_token": "x" * 2000,                   # too long
            "bot_username": "<script>alert(1)</script>",  # XSS attempt
            "admin_ids": "1, not_a_number, 2",         # mixed IDs
            "min_deposit_usd": "not_a_float",           # invalid float
            "min_withdrawal_usd": "-100",               # negative
            "referral_bonus_percent": "999",            # extreme
            "usd_to_php_rate": "abc",                   # invalid
            "signup_bonus_php": "",                     # empty float
            "support_handle": "@" + "A" * 600,          # oversized handle
            "welcome_message": "Hello" * 500,           # oversized message
            "_csrf_token": csrf,
        }, follow_redirects=True)
        S.expect(
            "Settings POST with bad data handled (no 500)",
            r.status_code in (200, 302, 400),
            f"got {r.status_code}",
        )

        # Verify bot_token was sanitized (truncated, not full 2000 chars)
        db = get_db()
        stored_token = db.get_setting("bot_token", "")
        S.expect(
            "bot_token stored at ≤ 500 chars (sanitized)",
            len(str(stored_token)) <= 500,
            f"len = {len(str(stored_token))}",
        )

        # XSS payload in bot_username must be escaped in rendered output
        r2 = c.get("/settings")
        S.expect(
            "XSS payload in bot_username HTML-escaped in output",
            b"<script>alert(1)</script>" not in r2.data,
            "raw <script> found in response!",
        )


# ════════════════════════════════════════════════════════════════════════════
# REGRESSION TESTS  (ported from web_stress_test.py so this suite is
# self-contained — runs everything in one go)
# ════════════════════════════════════════════════════════════════════════════

def test_security_headers(app):
    section("Security headers present on all response types")
    with app.test_client() as c:
        for path in ("/admin/login", "/app/login", "/app/register"):
            r = c.get(path)
            check_security_headers(r, path)

        admin_session(c)
        r = c.get("/admin")
        check_security_headers(r, "/admin (auth)")
        S.expect(
            "X-Frame-Options prevents embedding",
            r.headers.get("X-Frame-Options") == "DENY",
        )
        S.expect(
            "Server header removed",
            "Server" not in r.headers or "werkzeug" not in r.headers.get("Server", "").lower(),
        )
        S.expect(
            "CSP blocks frame-ancestors",
            "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", ""),
        )


def test_auth_protection(app):
    section("All protected endpoints reject unauthenticated requests")
    with app.test_client() as c:
        for path in ("/admin", "/users", "/deposits", "/withdrawals",
                     "/plans", "/settings", "/broadcast", "/audit", "/account"):
            r = c.get(path)
            S.expect(
                f"GET {path} redirects when not logged in",
                r.status_code in (301, 302),
                f"got {r.status_code}",
            )
    with app.test_client() as c:
        for path in ("/app/", "/app/me", "/app/plans", "/app/deposit", "/app/withdraw"):
            r = c.get(path)
            S.expect(
                f"Portal GET {path} redirects when not logged in",
                r.status_code in (301, 302),
                f"got {r.status_code}",
            )


def test_csrf_protection(app):
    section("CSRF — forged POST requests blocked on protected routes")
    db = get_db()
    with app.test_client() as c:
        admin_session(c)
        users = db.list_users(limit=1)
        if not users:
            S.warn("No users — skipping CSRF tests")
            return
        uid = users[0]["user_id"]

        # No token → 403
        r = c.post(f"/users/{uid}/adjust", data={"amount": "999999", "note": "hack"})
        S.expect("Balance adjust without CSRF → 403", r.status_code == 403, f"got {r.status_code}")

        # Wrong token → 403
        r = c.post(f"/users/{uid}/adjust", data={
            "amount": "999999", "note": "hack",
            "_csrf_token": "a" * 64,
        })
        S.expect("Balance adjust wrong CSRF → 403", r.status_code == 403, f"got {r.status_code}")

        # Correct token → success
        r = c.post(f"/users/{uid}/adjust", data={
            "amount": "0", "note": "noop",
            "_csrf_token": _get_csrf(c),
        }, follow_redirects=False)
        S.expect("Correct CSRF → 302", r.status_code in (302, 200), f"got {r.status_code}")

    # Portal CSRF check
    phone = next_phone()
    with app.test_client() as c:
        portal_register_and_login(c, phone)
        db.update_balance(db.get_user_by_phone(phone)["user_id"], 5000)
        r = c.post("/app/withdraw", data={
            "amount": "100",
            "crypto_currency": "USDT-TRC20",
            "wallet_address": "TFakeWallet123456",
        })
        S.expect("Portal withdraw without CSRF → 403", r.status_code == 403, f"got {r.status_code}")


def test_portal_registration(app):
    section("Portal registration — valid, duplicate, weak password, oversized")
    phone = next_phone()
    with app.test_client() as c:
        csrf = _get_csrf_portal(c)
        r = c.post("/app/register", data={
            "phone": phone, "full_name": "Valid User",
            "password": "secure123", "confirm_password": "secure123",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Valid registration → 302", r.status_code == 302)

    with app.test_client() as c:
        csrf = _get_csrf_portal(c)
        r = c.post("/app/register", data={
            "phone": phone, "full_name": "Dup",
            "password": "secure123", "confirm_password": "secure123",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Duplicate phone → 200 with error", r.status_code == 200)
        S.expect("Error mentions 'already registered'",
                 b"already registered" in r.data or b"error" in r.data.lower())

    with app.test_client() as c:
        csrf = _get_csrf_portal(c)
        r = c.post("/app/register", data={
            "phone": next_phone(), "password": "abc", "confirm_password": "abc",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Short password → 200 or redirect", r.status_code in (200, 302))

    with app.test_client() as c:
        csrf = _get_csrf_portal(c)
        r = c.post("/app/register", data={
            "phone": next_phone(), "full_name": "A" * 1000,
            "password": "validpass123", "confirm_password": "validpass123",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Oversized name → no 500", r.status_code in (200, 302, 400))

    with app.test_client() as c:
        csrf = _get_csrf_portal(c)
        r = c.post("/app/register", data={
            "phone": next_phone(), "password": "pass1234", "confirm_password": "pass5678",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Password mismatch → 200", r.status_code == 200)


def test_withdrawal_race_condition(app):
    section("Withdrawal race condition — 5 concurrent ₱600 requests on ₱1000 balance")
    phone = next_phone()
    db = get_db()
    with app.test_client() as c:
        portal_register_and_login(c, phone)
    user = db.get_user_by_phone(phone)
    db.update_balance(user["user_id"], 1000)

    def do_withdraw(amount: int):
        with app.test_client() as c:
            portal_login(c, phone)
            csrf = _get_csrf_portal(c)
            r = c.post("/app/withdraw", data={
                "amount": str(amount),
                "crypto_currency": "BTC",
                "wallet_address": "bc1qFakeAddrForTest123",
                "_csrf_token": csrf,
            })
            return r.status_code, b"success" in r.data.lower() or b"submitted" in r.data.lower()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(do_withdraw, 600) for _ in range(5)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    successes = sum(1 for _, ok in results if ok)
    final_balance = float(db.get_user(user["user_id"])["balance"])
    S.expect(
        f"At most 1 of 5 concurrent ₱600 withdrawals succeeded (got {successes})",
        successes <= 1,
        f"{successes} went through on ₱1000 balance",
    )
    S.expect(
        f"Balance never goes negative (got ₱{final_balance:.2f})",
        final_balance >= -0.01,
        f"balance = {final_balance}",
    )


def test_concurrent_investor_sessions(app, n: int = 50):
    section(f"Concurrent load — {n} investors: register → home → deposit → balance")
    db = get_db()
    db.set_setting("crypto_usdt_trc20_address", "TFakeWalletAddrV2Stress")

    def investor_flow(idx: int) -> str:
        phone = next_phone()
        try:
            with app.test_client() as c:
                csrf = _get_csrf_portal(c)
                r = c.post("/app/register", data={
                    "phone": phone, "full_name": f"Investor {idx}",
                    "password": "invest1234", "confirm_password": "invest1234",
                    "_csrf_token": csrf,
                }, follow_redirects=False)
                if r.status_code != 302:
                    return f"reg_fail:{r.status_code}"

                r = c.get("/app/")
                if r.status_code != 200:
                    return f"home_fail:{r.status_code}"

                r = c.get("/app/plans")
                if r.status_code != 200:
                    return f"plans_fail:{r.status_code}"

                csrf2 = _get_csrf_portal(c)
                r = c.post("/app/deposit", data={
                    "crypto_currency": "USDT-TRC20",
                    "amount_php": "1000",
                    "tx_hash": f"v2hash{idx}abc",
                    "_csrf_token": csrf2,
                })
                if r.status_code != 200:
                    return f"deposit_fail:{r.status_code}"

                r = c.get("/app/api/balance")
                if r.status_code != 200:
                    return f"api_fail:{r.status_code}"

                r = c.get("/app/me")
                if r.status_code != 200:
                    return f"me_fail:{r.status_code}"

                return "ok"
        except Exception as e:
            return f"exception:{type(e).__name__}:{e}"

    t_start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(investor_flow, range(n)))
    elapsed = time.time() - t_start

    ok_count = sum(1 for r in results if r == "ok")
    errors = [r for r in results if r != "ok"]
    S.expect(
        f"{ok_count}/{n} concurrent investor flows succeeded",
        ok_count >= int(n * 0.95),
        f"failures: {errors[:5]}",
    )
    S.warn(f"Throughput: {n / elapsed:.1f} flow/sec ({elapsed:.2f}s total)")

    # DB consistency
    total_users = db.count_users()
    S.expect(f"DB has ≥ {n} registered users", total_users >= n, f"got {total_users}")
    pending = len(db.list_transactions(tx_type="deposit", status="pending", limit=1000))
    S.expect("Pending deposits ≥ successful flows", pending >= ok_count,
             f"pending={pending} ok={ok_count}")


def test_concurrent_admin_reads(app, n: int = 30):
    section(f"Concurrent admin reads — {n} parallel requests")
    paths = ["/admin", "/users", "/audit", "/deposits", "/withdrawals", "/plans"]

    def admin_read_flow(idx: int) -> str:
        try:
            with app.test_client() as c:
                admin_session(c)
                r = c.get(paths[idx % len(paths)])
                return f"ok:{r.status_code}"
        except Exception as e:
            return f"err:{e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        results = list(ex.map(admin_read_flow, range(n)))

    ok = sum(1 for r in results if r.startswith("ok:200"))
    S.expect(
        f"{ok}/{n} concurrent admin reads returned 200",
        ok >= int(n * 0.95),
        f"non-200: {[r for r in results if not r.startswith('ok:200')][:5]}",
    )


def test_path_traversal_and_idor(app):
    section("Path traversal & IDOR — portal users can't access admin or other user data")
    phone_a = next_phone()
    phone_b = next_phone()
    with app.test_client() as c:
        portal_register_and_login(c, phone_a)
    with app.test_client() as c:
        portal_register_and_login(c, phone_b)

    db = get_db()
    user_b = db.get_user_by_phone(phone_b)

    with app.test_client() as c:
        portal_login(c, phone_a)

        r = c.get("/app/api/balance")
        S.expect("API balance returns 200 for own user", r.status_code == 200)
        data = r.get_json()
        S.expect("API response has 'balance' key", "balance" in (data or {}))

        r = c.get("/admin")
        S.expect("Portal user → /admin redirected", r.status_code in (302, 401, 403))

        r = c.get(f"/users/{user_b['user_id']}")
        S.expect("Portal user → /users/<id> redirected", r.status_code in (302, 401, 403))


def test_input_boundary_conditions(app):
    section("Input boundary — negative amounts, XSS payloads, huge search, bad page")
    db = get_db()
    users = db.list_users(limit=1)
    if not users:
        S.warn("No users — skipping boundary tests")
        return
    uid = users[0]["user_id"]

    with app.test_client() as c:
        admin_session(c)
        csrf = _get_csrf(c)

        # Very large negative inject
        r = c.post(f"/users/{uid}/transactions/create", data={
            "tx_type": "adjustment", "amount": "-999999999",
            "status": "completed", "currency": "PHP",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Huge negative amount handled (no 500)", r.status_code in (200, 302, 400))

        # XSS in note
        csrf2 = _get_csrf(c)
        xss = "<script>alert('XSS')</script>"
        r = c.post(f"/users/{uid}/transactions/create", data={
            "tx_type": "adjustment", "amount": "0",
            "status": "completed", "currency": "PHP", "note": xss,
            "_csrf_token": csrf2,
        }, follow_redirects=True)
        S.expect("XSS payload in note → no 500", r.status_code == 200)
        S.expect("XSS payload HTML-escaped in output", b"<script>alert" not in r.data)

        # Oversized search
        r = c.get(f"/users?q={'A' * 2000}")
        S.expect("Oversized search → no 500", r.status_code in (200, 400))

        r = c.get("/users?page=-99")
        S.expect("Negative page handled", r.status_code == 200)

        r = c.get("/users?page=abc")
        S.expect("Non-numeric page handled", r.status_code == 200)

        r = c.get("/users/9999999999")
        S.expect("Non-existent user → redirect/404", r.status_code in (302, 404))


# ════════════════════════════════════════════════════════════════════════════
# Main runner
# ════════════════════════════════════════════════════════════════════════════

def main() -> int:
    print(f"\n{BOLD}{'═'*60}")
    print(" Gyokuro — HTTP Stress & Security Test Suite v2")
    print(f"{'═'*60}{W}")
    print(f" Test DB: {TEST_DB}")

    app = create_app()

    # Disable rate limiting for most tests (tested selectively)
    app.config["RATELIMIT_ENABLED"] = False

    try:
        # ── New hardening tests ────────────────────────────────────
        test_admin_login_csrf_now_enforced(app)
        test_deposit_double_approve_race(app)
        test_withdrawal_double_reject_no_double_refund(app)
        test_withdrawal_double_approve_no_double_total_withdrawn(app)
        test_maintenance_mode_blocks_portal(app)
        test_plan_create_input_validation(app)
        test_broadcast_sanitization(app)
        test_settings_input_sanitization(app)

        # ── Regression / baseline tests ────────────────────────────
        test_security_headers(app)
        test_auth_protection(app)
        test_csrf_protection(app)
        test_portal_registration(app)
        test_input_boundary_conditions(app)
        test_path_traversal_and_idor(app)

        # ── Concurrency tests (rate-limiting re-enabled) ───────────
        app.config["RATELIMIT_ENABLED"] = True
        test_withdrawal_race_condition(app)
        test_concurrent_investor_sessions(app, n=50)
        test_concurrent_admin_reads(app, n=30)

    except Exception:
        print(f"\n{R}Uncaught exception:{W}")
        traceback.print_exc()
        return 2

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'═'*60}{W}")
    print(f"  {G}Passed{W}:   {S.passed}")
    print(f"  {R}Failed{W}:   {S.failed}")
    print(f"  {Y}Warnings{W}: {S.warnings}")

    if S.failures:
        print(f"\n{BOLD}{R}Failures:{W}")
        for label, detail in S.failures:
            print(f"  {R}•{W} {label}")
            if detail:
                print(f"      {Y}{detail}{W}")

    print(f"\n{'═'*60}")
    if S.failed == 0:
        print(f"{BOLD}{G}All tests passed.{W} 🎉")
    else:
        print(f"{BOLD}{R}{S.failed} test(s) failed.{W}")

    db = get_db()
    final = db.admin_stats()
    print(f"\n{BOLD}Final DB state:{W}")
    for k, v in final.items():
        print(f"  {k}: {v:.2f}" if isinstance(v, float) else f"  {k}: {v}")

    return 0 if S.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
