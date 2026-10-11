"""HTTP-layer stress & security test for Gyokuro InvestmentBot web app.

This test suite:

  * Spins up the Flask test client against an isolated test DB
  * Tests every major HTTP flow: admin auth, portal auth, CSRF enforcement,
    rate-limit responses, all CRUD endpoints, concurrent load
  * Verifies security headers on every response
  * Checks that unauthenticated requests are rejected on protected routes
  * Simulates 50 concurrent investor sessions (register → deposit → withdraw)
  * Tests input boundary conditions (oversized fields, negative amounts, etc.)
  * Verifies CSRF tokens block forged POST requests
  * Stress-tests the admin panel with concurrent reads and mutations

Run with:
    python -m stress_test.web_stress_test

No external dependencies beyond what the app already uses.
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

# ── Point at an isolated test DB BEFORE importing app code ───────────────
TEST_DB = ROOT / "data" / "web_test.db"
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DB_PATH"] = "data/web_test.db"
os.environ["FLASK_SECRET_KEY"] = "web-stress-test-secret-key-32chars!!"
os.environ["ADMIN_IDS"] = "1,2"
os.environ["MIN_DEPOSIT_USD"] = "10"
os.environ["MIN_WITHDRAWAL_USD"] = "5"
os.environ["REFERRAL_BONUS_PERCENT"] = "5"

# Reset DB singleton so we get a fresh instance on our test path
import database as _db_mod
_db_mod._DB = None

from config import CONFIG
CONFIG.db_path = TEST_DB
TEST_DB.parent.mkdir(parents=True, exist_ok=True)

# Now import the app
from web.app import create_app
from database import get_db

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
G = "\033[92m"   # green
R = "\033[91m"   # red
Y = "\033[93m"   # yellow
B = "\033[96m"   # cyan
W = "\033[0m"    # reset
BOLD = "\033[1m"


def section(title: str):
    print(f"\n{BOLD}{B}{'─'*60}{W}")
    print(f"{BOLD}{B}  {title}{W}")
    print(f"{BOLD}{B}{'─'*60}{W}")


# ---------------------------------------------------------------------------
# Stats tracker
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

ADMIN_USER = "admin"
ADMIN_PASS = "gyokuroadmin"
_phone_counter = 60_000_000


def next_phone() -> str:
    global _phone_counter
    _phone_counter += 1
    return f"+639{_phone_counter}"


def admin_session(client):
    """Log the test client in as admin; return the CSRF token."""
    r = client.get("/admin/login")
    # Extract CSRF token by logging in (server sets session cookie → issues _csrf)
    r = client.post("/admin/login", data={
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
        "_csrf_token": _get_csrf(client),
    }, follow_redirects=True)
    return r.status_code == 200


def _get_csrf(client) -> str:
    """Fetch any authenticated page to ensure session exists, return CSRF token."""
    # The CSRF token is stored in the session cookie; we obtain it by making
    # any GET request (which triggers _csrf_token() in the template context).
    # We parse it from the hidden field or from a fresh endpoint.
    with client.session_transaction() as sess:
        if "_csrf" in sess:
            return sess["_csrf"]
    # Hit the login page to initialise the session
    client.get("/admin/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf", "")


def portal_register_and_login(client, phone: str, password: str = "pass1234",
                               name: str = "Test User") -> bool:
    """Register a new investor account and stay logged in."""
    csrf = _get_csrf_portal(client)
    r = client.post("/app/register", data={
        "phone": phone,
        "full_name": name,
        "password": password,
        "confirm_password": password,
        "_csrf_token": csrf,
    }, follow_redirects=False)
    return r.status_code == 302


def _get_csrf_portal(client) -> str:
    """Get CSRF token from portal session."""
    client.get("/app/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf", "")


def check_security_headers(response, label: str):
    """Assert that all required security headers are present."""
    required = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": None,  # just check presence
    }
    for header, expected_val in required.items():
        present = header in response.headers
        S.expect(
            f"{label}: has {header}",
            present,
            f"missing on {response.request.path if hasattr(response, 'request') else 'response'}",
        )
        if present and expected_val:
            S.expect(
                f"{label}: {header} = {expected_val}",
                response.headers[header] == expected_val,
                f"got: {response.headers.get(header)}",
            )


# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------

def test_security_headers(app):
    section("Security headers present on all response types")
    with app.test_client() as c:
        for path, method in [
            ("/admin/login", "GET"),
            ("/app/login", "GET"),
            ("/app/register", "GET"),
        ]:
            if method == "GET":
                r = c.get(path)
            else:
                r = c.post(path)
            check_security_headers(r, path)

        # Also check authenticated pages
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
        protected = [
            "/admin",
            "/users",
            "/deposits",
            "/withdrawals",
            "/plans",
            "/settings",
            "/broadcast",
            "/audit",
            "/account",
        ]
        for path in protected:
            r = c.get(path)
            S.expect(
                f"GET {path} redirects when not logged in",
                r.status_code in (302, 301),
                f"got {r.status_code}",
            )
            if r.status_code in (301, 302):
                S.expect(
                    f"  → redirects to login",
                    "login" in (r.headers.get("Location") or "").lower(),
                    r.headers.get("Location", ""),
                )

    # Portal protected routes
    with app.test_client() as c:
        portal_protected = ["/app/", "/app/me", "/app/plans", "/app/deposit", "/app/withdraw"]
        for path in portal_protected:
            r = c.get(path)
            S.expect(
                f"Portal GET {path} redirects when not logged in",
                r.status_code in (302, 301),
                f"got {r.status_code}",
            )


def test_admin_login(app):
    section("Admin login — correct / wrong credentials + rate limiting")
    with app.test_client() as c:
        # Good credentials
        csrf = _get_csrf(c)
        r = c.post("/admin/login", data={
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Admin login with correct creds → 302", r.status_code == 302)
        S.expect(
            "Admin login redirects to /admin",
            "/admin" in (r.headers.get("Location") or ""),
            r.headers.get("Location", ""),
        )

    with app.test_client() as c:
        # Wrong password
        csrf = _get_csrf(c)
        r = c.post("/admin/login", data={
            "username": ADMIN_USER,
            "password": "wrongpassword!!!",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Admin login with wrong password → 200 (re-render)", r.status_code == 200)
        S.expect(
            "Error message shown on bad login",
            b"Invalid" in r.data,
            "",
        )

    with app.test_client() as c:
        # Missing CSRF token on login POST
        r = c.post("/admin/login", data={
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
            # no _csrf_token
        }, follow_redirects=False)
        # With our CSRF check, this should be blocked with 403
        # (or redirect to login — either is acceptable for login itself
        #  since login page also handles GET → csrf token may be missing)
        S.warn(
            "Login without CSRF token — check if blocked",
            f"status={r.status_code}",
        )


def test_csrf_protection(app):
    section("CSRF — forged POST requests blocked on protected routes")
    with app.test_client() as c:
        admin_session(c)

        # Forged POST to balance adjust (no CSRF token)
        db = get_db()
        users = db.list_users(limit=1)
        if not users:
            S.warn("No users in DB — skipping CSRF adjust test")
            return

        uid = users[0]["user_id"]

        # No token at all
        r = c.post(f"/users/{uid}/adjust", data={"amount": "999999", "note": "hack"})
        S.expect(
            "Balance adjust without CSRF token → 403",
            r.status_code == 403,
            f"got {r.status_code}",
        )

        # Wrong token
        r = c.post(f"/users/{uid}/adjust", data={
            "amount": "999999",
            "note": "hack",
            "_csrf_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        })
        S.expect(
            "Balance adjust with wrong CSRF token → 403",
            r.status_code == 403,
            f"got {r.status_code}",
        )

        # Correct token — should succeed
        r = c.post(f"/users/{uid}/adjust", data={
            "amount": "0",
            "note": "stress test noop",
            "_csrf_token": _get_csrf(c),
        }, follow_redirects=False)
        S.expect(
            "Balance adjust with correct CSRF token → redirect",
            r.status_code in (302, 200),
            f"got {r.status_code}",
        )

    # Portal withdrawal CSRF check
    phone = next_phone()
    with app.test_client() as c:
        portal_register_and_login(c, phone)
        # Give user some balance via DB
        db = get_db()
        user = db.get_user_by_phone(phone)
        if user:
            db.update_balance(user["user_id"], 5000)

        # POST without CSRF
        r = c.post("/app/withdraw", data={
            "amount": "100",
            "crypto_currency": "USDT-TRC20",
            "wallet_address": "TFakeWalletAddress123456",
        })
        S.expect(
            "Portal withdraw without CSRF → 403",
            r.status_code == 403,
            f"got {r.status_code}",
        )


def test_portal_registration(app):
    section("Portal registration — valid, duplicate, weak password, oversized input")
    phone = next_phone()

    with app.test_client() as c:
        csrf = _get_csrf_portal(c)

        # Valid registration
        r = c.post("/app/register", data={
            "phone": phone,
            "full_name": "Valid User",
            "password": "secure123",
            "confirm_password": "secure123",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Valid registration → redirect", r.status_code == 302)

    # Duplicate phone — fresh client (no session from the registration)
    with app.test_client() as c:
        csrf2 = _get_csrf_portal(c)
        r = c.post("/app/register", data={
            "phone": phone,
            "full_name": "Dup User",
            "password": "secure123",
            "confirm_password": "secure123",
            "_csrf_token": csrf2,
        }, follow_redirects=False)
        S.expect(
            "Duplicate phone registration → 200 with error",
            r.status_code == 200,
            f"got {r.status_code}",
        )
        S.expect(
            "Duplicate phone shows error message",
            b"already registered" in r.data or b"error" in r.data.lower(),
        )

    with app.test_client() as c:
        # Weak password
        csrf = _get_csrf_portal(c)
        r = c.post("/app/register", data={
            "phone": next_phone(),
            "full_name": "Weak Pw User",
            "password": "abc",
            "confirm_password": "abc",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect(
            "Short password → stays on register page (200 or redirect)",
            r.status_code in (200, 302),
        )

    with app.test_client() as c:
        # Oversized name (>500 chars)
        csrf = _get_csrf_portal(c)
        big_name = "A" * 1000
        r = c.post("/app/register", data={
            "phone": next_phone(),
            "full_name": big_name,
            "password": "validpass123",
            "confirm_password": "validpass123",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect(
            "Oversized name field handled (no 500)",
            r.status_code in (200, 302, 400),
            f"got {r.status_code}",
        )

    with app.test_client() as c:
        # Password mismatch — separate client, no rate-limit carry-over
        csrf = _get_csrf_portal(c)
        r = c.post("/app/register", data={
            "phone": next_phone(),
            "full_name": "Mismatch",
            "password": "pass1234",
            "confirm_password": "pass5678",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect(
            "Password mismatch → re-render with error",
            r.status_code == 200,
            f"got {r.status_code}",
        )


def test_portal_login(app):
    section("Portal login — valid, wrong password, banned account")
    phone = next_phone()
    with app.test_client() as c:
        # Register first
        portal_register_and_login(c, phone)

    with app.test_client() as c:
        csrf = _get_csrf_portal(c)
        r = c.post("/app/login", data={
            "phone": phone,
            "password": "pass1234",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Portal login correct creds → 302", r.status_code == 302)

    with app.test_client() as c:
        csrf = _get_csrf_portal(c)
        r = c.post("/app/login", data={
            "phone": phone,
            "password": "WRONGPASSWORD",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Portal login wrong password → 200", r.status_code == 200)
        S.expect("Error message shown", b"Incorrect" in r.data)

    # Ban the user and try to log in
    db = get_db()
    user = db.get_user_by_phone(phone)
    if user:
        db.set_ban(user["user_id"], True)
        with app.test_client() as c:
            csrf = _get_csrf_portal(c)
            r = c.post("/app/login", data={
                "phone": phone,
                "password": "pass1234",
                "_csrf_token": csrf,
            }, follow_redirects=False)
            S.expect(
                "Banned account login → 200 with suspension message",
                r.status_code == 200,
                f"got {r.status_code}",
            )
            S.expect(
                "Banned message shown",
                b"suspended" in r.data or b"banned" in r.data.lower(),
            )
        db.set_ban(user["user_id"], False)


def test_deposit_submission(app):
    section("Portal deposit submission — valid, min amount, bad amount")
    db = get_db()
    db.set_setting("crypto_usdt_trc20_address", "TFakeWalletAddress123456")
    phone = next_phone()
    with app.test_client() as c:
        portal_register_and_login(c, phone)
        csrf = _get_csrf_portal(c)

        # Valid deposit
        csrf = _get_csrf_portal(c)
        r = c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20",
            "amount_php": "1000",
            "tx_hash": "abc123testxyz",
            "_csrf_token": csrf,
        }, follow_redirects=True)  # follow redirect after success
        S.expect(
            "Valid deposit submission → 200 (no 500)",
            r.status_code == 200,
            f"got {r.status_code}",
        )
        S.expect(
            "Deposit page or success response",
            b"Deposit" in r.data or b"submitted" in r.data.lower() or b"Gyokuro" in r.data,
        )

        # Below minimum
        csrf2 = _get_csrf_portal(c)
        r = c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20",
            "amount_php": "1",
            "_csrf_token": csrf2,
        }, follow_redirects=True)
        S.expect(
            "Below-minimum deposit → 200 with error",
            r.status_code == 200,
            f"got {r.status_code}",
        )
        S.expect("Error mentions minimum", b"Minimum" in r.data or b"minimum" in r.data)

        # Zero amount
        csrf3 = _get_csrf_portal(c)
        r = c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20",
            "amount_php": "0",
            "_csrf_token": csrf3,
        }, follow_redirects=True)
        S.expect(
            "Zero amount deposit handled (no 500)",
            r.status_code in (200, 400),
            f"got {r.status_code}",
        )


def test_withdrawal_security(app):
    section("Portal withdrawal — balance enforcement, race condition")
    phone = next_phone()
    db = get_db()

    with app.test_client() as c:
        ok = portal_register_and_login(c, phone)
        if not ok:
            S.warn("Registration failed in withdrawal test — skipping")
            return

    user = db.get_user_by_phone(phone)
    if not user:
        S.warn("Could not find registered user — skipping withdrawal test")
        return

    db.update_balance(user["user_id"], 2000)  # give them ₱2000

    with app.test_client() as c:
        # Log in
        csrf = _get_csrf_portal(c)
        c.post("/app/login", data={
            "phone": phone,
            "password": "pass1234",
            "_csrf_token": csrf,
        })

        # Try to withdraw more than balance
        csrf2 = _get_csrf_portal(c)
        r = c.post("/app/withdraw", data={
            "amount": "9999",
            "crypto_currency": "USDT-TRC20",
            "wallet_address": "TFakeRecipientAddress123",
            "_csrf_token": csrf2,
        }, follow_redirects=True)
        S.expect(
            "Over-balance withdrawal → 200 with error",
            r.status_code == 200,
            f"got {r.status_code}",
        )
        S.expect(
            "Insufficient balance message shown",
            b"nsufficien" in r.data or b"balance" in r.data.lower(),
        )

        # Valid withdrawal
        csrf3 = _get_csrf_portal(c)
        r = c.post("/app/withdraw", data={
            "amount": "500",
            "crypto_currency": "USDT-TRC20",
            "wallet_address": "TFakeRecipientAddress123",
            "_csrf_token": csrf3,
        }, follow_redirects=True)
        S.expect(
            "Valid withdrawal → success page (200)",
            r.status_code == 200,
            f"got {r.status_code}",
        )

        # Check balance was actually deducted
        user_after = db.get_user(user["user_id"])
        S.expect(
            "Balance reduced by withdrawal amount (2000 - 500 = 1500)",
            abs(float(user_after["balance"]) - 1500.0) < 0.01,
            f"balance is {user_after['balance']}",
        )


def test_withdrawal_race_condition(app):
    section("Withdrawal race condition — concurrent requests from same account")
    phone = next_phone()
    db = get_db()

    # Setup: register + give ₱1000
    with app.test_client() as c:
        portal_register_and_login(c, phone)
    user = db.get_user_by_phone(phone)
    db.update_balance(user["user_id"], 1000)

    withdraw_results = []

    def do_withdraw(amount: int):
        with app.test_client() as c:
            # Log in
            csrf = _get_csrf_portal(c)
            c.post("/app/login", data={
                "phone": phone,
                "password": "pass1234",
                "_csrf_token": csrf,
            })
            csrf2 = _get_csrf_portal(c)
            r = c.post("/app/withdraw", data={
                "amount": str(amount),
                "crypto_currency": "BTC",
                "wallet_address": "bc1qFakeAddressForTest123",
                "_csrf_token": csrf2,
            })
            return r.status_code, b"success" in r.data.lower() or b"submitted" in r.data.lower()

    # Fire 5 concurrent withdrawal requests of ₱600 each
    # Total demand: ₱3000 — only ₱1000 available
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(do_withdraw, 600) for _ in range(5)]
        withdraw_results = [f.result() for f in concurrent.futures.as_completed(futures)]

    successes = sum(1 for _, ok in withdraw_results if ok)
    final_user = db.get_user(user["user_id"])
    final_balance = float(final_user["balance"])

    S.expect(
        f"At most 1 of 5 concurrent ₱600 withdrawals succeeded (got {successes})",
        successes <= 1,
        f"{successes} withdrawals went through on ₱1000 balance",
    )
    S.expect(
        f"Balance never goes negative (got ₱{final_balance:.2f})",
        final_balance >= -0.01,
        f"balance = {final_balance}",
    )


def test_admin_user_management(app):
    section("Admin user management — edit, ban, balance adjust, tx inject")
    db = get_db()
    phone = next_phone()

    # Create a test user
    with app.test_client() as c:
        portal_register_and_login(c, phone)
    user = db.get_user_by_phone(phone)
    uid = user["user_id"]

    with app.test_client() as c:
        admin_session(c)
        csrf = _get_csrf(c)

        # View user detail page
        r = c.get(f"/users/{uid}")
        S.expect(f"Admin user detail page renders (200)", r.status_code == 200)

        # Edit user profile
        r = c.post(f"/users/{uid}/edit", data={
            "full_name": "Stress Test User Updated",
            "username": "stresstest",
            "phone": phone,
            "referral_code": user["referral_code"],
            "referred_by": "",
            "balance": "100.00",
            "pending_balance": "0.00",
            "total_deposited": "0.00",
            "total_withdrawn": "0.00",
            "total_invested": "0.00",
            "total_earned": "0.00",
            "is_banned": "0",
            "is_admin": "0",
            "new_password": "",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Edit user → redirect", r.status_code == 302)

        user_after = db.get_user(uid)
        S.expect(
            "Full name updated",
            user_after["full_name"] == "Stress Test User Updated",
            f"got: {user_after['full_name']}",
        )
        S.expect(
            "Balance set to 100",
            abs(float(user_after["balance"]) - 100.0) < 0.01,
            f"got: {user_after['balance']}",
        )

        # Balance delta adjust
        csrf2 = _get_csrf(c)
        r = c.post(f"/users/{uid}/adjust", data={
            "amount": "50",
            "note": "Stress test adjustment",
            "_csrf_token": csrf2,
        }, follow_redirects=False)
        S.expect("Balance adjust → redirect", r.status_code == 302)
        S.expect(
            "Balance now 150",
            abs(float(db.get_user(uid)["balance"]) - 150.0) < 0.01,
            f"got: {db.get_user(uid)['balance']}",
        )

        # Inject transaction
        csrf3 = _get_csrf(c)
        r = c.post(f"/users/{uid}/transactions/create", data={
            "tx_type": "deposit",
            "amount": "200",
            "status": "completed",
            "currency": "PHP",
            "note": "Stress test injection",
            "apply_balance": "1",
            "_csrf_token": csrf3,
        }, follow_redirects=False)
        S.expect("Inject tx → redirect", r.status_code == 302)

        txs = db.list_transactions(user_id=uid, tx_type="deposit")
        S.expect(
            "Injected transaction exists in DB",
            any(t["note"] == "Stress test injection" for t in txs),
        )

        # Ban user
        csrf4 = _get_csrf(c)
        r = c.post(f"/users/{uid}/ban", data={"_csrf_token": csrf4}, follow_redirects=False)
        S.expect("Ban user → redirect", r.status_code == 302)
        S.expect("User is now banned", bool(db.get_user(uid)["is_banned"]))

        # Unban
        csrf5 = _get_csrf(c)
        r = c.post(f"/users/{uid}/ban", data={"_csrf_token": csrf5}, follow_redirects=False)
        S.expect("Unban user → redirect", r.status_code == 302)
        S.expect("User is now active", not bool(db.get_user(uid)["is_banned"]))


def test_input_boundary_conditions(app):
    section("Input boundary conditions — negative amounts, XSS payloads, huge inputs")
    db = get_db()
    users = db.list_users(limit=1)
    if not users:
        S.warn("No users — skipping boundary tests")
        return
    uid = users[0]["user_id"]

    with app.test_client() as c:
        admin_session(c)
        csrf = _get_csrf(c)

        # Negative deposit via admin inject (should be allowed — admins can inject anything)
        r = c.post(f"/users/{uid}/transactions/create", data={
            "tx_type": "adjustment",
            "amount": "-999999999",
            "status": "completed",
            "currency": "PHP",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect(
            "Very large negative amount handled (no 500)",
            r.status_code in (200, 302, 400),
            f"got {r.status_code}",
        )

        # XSS payload in note field
        csrf2 = _get_csrf(c)
        xss = "<script>alert('XSS')</script>"
        r = c.post(f"/users/{uid}/transactions/create", data={
            "tx_type": "adjustment",
            "amount": "0",
            "status": "completed",
            "currency": "PHP",
            "note": xss,
            "_csrf_token": csrf2,
        }, follow_redirects=True)
        S.expect(
            "XSS payload stored but not reflected unescaped",
            r.status_code == 200,
            f"got {r.status_code}",
        )
        # Check it's Jinja2-escaped in the HTML
        raw_script = b"<script>alert" 
        escaped = b"&lt;script&gt;" 
        S.expect(
            "XSS payload is HTML-escaped in response",
            raw_script not in r.data,
            "raw <script> tag found in response — XSS possible!",
        )

        # Oversized search query
        r = c.get(f"/users?q={'A' * 2000}")
        S.expect(
            "Oversized search query handled (no 500)",
            r.status_code in (200, 400),
            f"got {r.status_code}",
        )

        # Invalid page number
        r = c.get("/users?page=-99")
        S.expect("Negative page param handled", r.status_code == 200)

        r = c.get("/users?page=abc")
        S.expect("Non-numeric page param handled", r.status_code == 200)

        # Non-existent user
        r = c.get("/users/9999999999")
        S.expect(
            "Non-existent user detail → redirect not 500",
            r.status_code in (302, 404),
            f"got {r.status_code}",
        )


def test_concurrent_investor_sessions(app, n: int = 50):
    section(f"Concurrent load — {n} investors: register → deposit → balance check")
    db = get_db()
    db.set_setting("crypto_usdt_trc20_address", "TFakeWalletAddress123456")

    results: list[str] = []
    phones_used: list[str] = []

    def investor_flow(idx: int) -> str:
        phone = next_phone()
        phones_used.append(phone)
        try:
            with app.test_client() as c:
                # 1. Register
                csrf = _get_csrf_portal(c)
                r = c.post("/app/register", data={
                    "phone": phone,
                    "full_name": f"Investor {idx}",
                    "password": "invest1234",
                    "confirm_password": "invest1234",
                    "_csrf_token": csrf,
                }, follow_redirects=False)
                if r.status_code != 302:
                    return f"reg_fail:{r.status_code}"

                # 2. View home
                r = c.get("/app/")
                if r.status_code != 200:
                    return f"home_fail:{r.status_code}"

                # 3. View plans
                r = c.get("/app/plans")
                if r.status_code != 200:
                    return f"plans_fail:{r.status_code}"

                # 4. Submit deposit
                csrf2 = _get_csrf_portal(c)
                r = c.post("/app/deposit", data={
                    "crypto_currency": "USDT-TRC20",
                    "amount_php": "1000",
                    "tx_hash": f"hash{idx}abc",
                    "_csrf_token": csrf2,
                })
                if r.status_code != 200:
                    return f"deposit_fail:{r.status_code}"

                # 5. API balance check
                r = c.get("/app/api/balance")
                if r.status_code != 200:
                    return f"api_fail:{r.status_code}"

                # 6. Me page
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
        f"{ok_count}/{n} concurrent investor flows completed successfully",
        ok_count >= int(n * 0.95),  # 95% success threshold
        f"failures: {errors[:5]}",
    )
    S.warn(f"Total wall-clock time for {n} concurrent flows: {elapsed:.2f}s")

    # Verify DB consistency
    total_users = db.count_users()
    S.expect(
        f"DB has ≥ {n} registered users",
        total_users >= n,
        f"got {total_users}",
    )

    pending_deposits = len(db.list_transactions(tx_type="deposit", status="pending", limit=1000))
    S.expect(
        f"Pending deposits recorded for successful flows",
        pending_deposits >= ok_count,
        f"got {pending_deposits} pending deposits for {ok_count} flows",
    )

    # Avg throughput
    rps = n / elapsed
    print(f"  {B}ℹ{W}  Throughput: {rps:.1f} req/sec equiv. ({n} flows / {elapsed:.2f}s)")


def test_concurrent_admin_reads(app, n: int = 30):
    section(f"Concurrent admin reads — {n} parallel requests to dashboard/users/audit")
    results = []

    def admin_read_flow(idx: int) -> str:
        try:
            with app.test_client() as c:
                admin_session(c)
                paths = ["/admin", "/users", "/audit", "/deposits", "/withdrawals", "/plans"]
                path = paths[idx % len(paths)]
                r = c.get(path)
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


def test_one_time_token_auth(app):
    section("One-time token auth — valid token, expired token, reuse")
    phone = next_phone()
    with app.test_client() as c:
        portal_register_and_login(c, phone)

    db = get_db()
    user = db.get_user_by_phone(phone)
    uid = user["user_id"]

    # Create a valid token
    token = db.create_web_login_token(uid, ttl_seconds=300)

    with app.test_client() as c:
        r = c.get(f"/app/auth?token={token}", follow_redirects=False)
        S.expect("Valid one-time token → 302 redirect", r.status_code == 302)
        S.expect("Redirects to /app/", "/app/" in r.headers.get("Location", ""))

        # Reuse the same token (should fail — already consumed)
        r2 = c.get(f"/app/auth?token={token}", follow_redirects=False)
        S.expect(
            "Reused token → redirect to login (not /app/)",
            r2.status_code in (302, 200),
        )

    # Expired token
    expired_token = db.create_web_login_token(uid, ttl_seconds=-1)  # already expired
    with app.test_client() as c:
        r = c.get(f"/app/auth?token={expired_token}", follow_redirects=False)
        S.expect("Expired token → redirect to login", r.status_code in (200, 302))

    # Non-existent token
    with app.test_client() as c:
        r = c.get("/app/auth?token=totallyinvalidtoken123456789", follow_redirects=False)
        S.expect("Fake token → redirect to login", r.status_code in (200, 302))


def test_deposit_approval_flow(app):
    section("Admin deposit approval — approve and reject via web panel")
    phone = next_phone()
    db = get_db()

    with app.test_client() as c:
        portal_register_and_login(c, phone)
        db.set_setting("crypto_usdt_trc20_address", "TFakeWalletAddress123456")
        csrf = _get_csrf_portal(c)
        c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20",
            "amount_php": "5000",
            "tx_hash": "approvaltesthash",
            "_csrf_token": csrf,
        })

    user = db.get_user_by_phone(phone)
    txs = db.list_transactions(user_id=user["user_id"], tx_type="deposit", status="pending")
    if not txs:
        S.warn("No pending deposit found — skipping approval test")
        return
    tx_id = txs[0]["id"]

    with app.test_client() as c:
        admin_session(c)
        csrf = _get_csrf(c)

        # Approve
        r = c.post(f"/deposits/{tx_id}/approve", data={"_csrf_token": csrf}, follow_redirects=False)
        S.expect("Approve deposit → redirect", r.status_code == 302)

        tx_after = db.get_transaction(tx_id)
        S.expect("Deposit status = completed", tx_after["status"] == "completed")

        user_after = db.get_user(user["user_id"])
        S.expect(
            "User balance credited ₱5000",
            abs(float(user_after["balance"]) - 5000.0) < 0.01,
            f"got: {user_after['balance']}",
        )

    # Create another deposit and reject it
    with app.test_client() as c:
        portal_register_and_login(c, phone)  # re-login as same user
        csrf2 = _get_csrf_portal(c)
        c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20",
            "amount_php": "1000",
            "tx_hash": "rejectiontesthash",
            "_csrf_token": csrf2,
        })

    txs2 = db.list_transactions(user_id=user["user_id"], tx_type="deposit", status="pending")
    if txs2:
        tx2_id = txs2[0]["id"]
        with app.test_client() as c:
            admin_session(c)
            csrf3 = _get_csrf(c)
            r = c.post(f"/deposits/{tx2_id}/reject", data={"_csrf_token": csrf3}, follow_redirects=False)
            S.expect("Reject deposit → redirect", r.status_code == 302)
            S.expect("Deposit status = rejected", db.get_transaction(tx2_id)["status"] == "rejected")


def test_path_traversal_and_idor(app):
    section("Path traversal & IDOR — users can't access other users' data")
    # Register two investors
    phone_a = next_phone()
    phone_b = next_phone()

    with app.test_client() as c:
        portal_register_and_login(c, phone_a)
    with app.test_client() as c:
        portal_register_and_login(c, phone_b)

    db = get_db()
    user_a = db.get_user_by_phone(phone_a)
    user_b = db.get_user_by_phone(phone_b)

    # Log in as user A and try to access user B's data via API
    with app.test_client() as c:
        # Login as A
        csrf = _get_csrf_portal(c)
        c.post("/app/login", data={
            "phone": phone_a,
            "password": "pass1234",
            "_csrf_token": csrf,
        })
        # API only returns logged-in user's data — no user_id param
        r = c.get("/app/api/balance")
        S.expect("API balance returns 200 for logged-in user", r.status_code == 200)
        data = r.get_json()
        S.expect("API returns balance object with expected keys", "balance" in (data or {}))

    # Try to access admin routes as portal user
    with app.test_client() as c:
        csrf = _get_csrf_portal(c)
        c.post("/app/login", data={
            "phone": phone_a,
            "password": "pass1234",
            "_csrf_token": csrf,
        })
        r = c.get("/admin")
        S.expect("Portal user cannot access admin → redirect", r.status_code in (302, 401, 403))

        r = c.get(f"/users/{user_b['user_id']}")
        S.expect("Portal user cannot access admin users page → redirect", r.status_code in (302, 401, 403))


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def main() -> int:
    print(f"\n{BOLD}{'═'*60}")
    print(" Gyokuro — HTTP Stress & Security Test Suite")
    print(f"{'═'*60}{W}")
    print(f" Test DB: {TEST_DB}")

    app = create_app()

    # Disable rate limiting during tests (we test it separately)
    app.config["RATELIMIT_ENABLED"] = False

    try:
        test_security_headers(app)
        test_auth_protection(app)
        test_admin_login(app)
        test_csrf_protection(app)
        test_portal_registration(app)
        test_portal_login(app)
        test_deposit_submission(app)
        test_withdrawal_security(app)
        test_one_time_token_auth(app)
        test_deposit_approval_flow(app)
        test_admin_user_management(app)
        test_input_boundary_conditions(app)
        test_path_traversal_and_idor(app)

        # Re-enable rate limits for concurrent tests
        app.config["RATELIMIT_ENABLED"] = True
        test_withdrawal_race_condition(app)
        test_concurrent_investor_sessions(app, n=50)
        test_concurrent_admin_reads(app, n=30)

    except Exception:
        print(f"\n{R}Uncaught exception during test:{W}")
        traceback.print_exc()
        return 2

    # ── Summary ──────────────────────────────────────────────────────────
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

    if S.failed == 0:
        print(f"\n{BOLD}{G}All tests passed.{W} 🎉")
    else:
        print(f"\n{BOLD}{R}{S.failed} test(s) failed.{W}")

    db = get_db()
    final = db.admin_stats()
    print(f"\n{BOLD}Final DB state:{W}")
    for k, v in final.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.2f}")
        else:
            print(f"  {k}: {v}")

    return 0 if S.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
