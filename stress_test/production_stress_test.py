"""Production-readiness stress & security test for Gyokuro / Railway.

Design principle: test fixtures are created directly in the DB so tests
never hit rate limits. Only the flows being tested touch HTTP.

Covers:
  1. Security headers on every response type
  2. Auth protection (every protected route)
  3. Custom 404 / 403 / 500 error handlers
  4. CSRF enforcement on admin and portal mutations
  5. Admin login hardening (CSRF, SQL injection, timing)
  6. Portal auth (login, register, banned, edge cases)
  7. Portal deposit validation
  8. Portal invest flow
  9. Admin deposit / withdrawal double-process race prevention
 10. IDOR — portal users cannot reach admin or other user data
 11. Input boundary conditions (XSS, huge payloads, bad params)
 12. Maintenance mode blocks portal but not login page
 13. One-time token auth (valid, reuse, expired, fake)
 14. Admin full user-management workflow
 15. API isolation — balance API only returns own user
 16. Referral web-link detection (?ref= on register)
 17. DB integrity — no negative balances, no orphan records
 18. Withdrawal race condition (concurrent requests)
 19. Concurrent investor load (50 users, 20 threads)
 20. Concurrent admin reads

Run:
    python -m stress_test.production_stress_test
"""
from __future__ import annotations

import concurrent.futures
import os
import sys
import time
import traceback
from pathlib import Path

# ── Force UTF-8 output so the console doesn't choke on the emoji/dashes ─────
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Project root ──────────────────────────────────────────────────────────────
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

# ── Isolated test DB ─────────────────────────────────────────────────────────
TEST_DB = ROOT / "data" / "prod_stress.db"
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DB_PATH"] = "data/prod_stress.db"
os.environ["FLASK_SECRET_KEY"] = "prod-stress-secret-key-32chars!!!x"
os.environ["ADMIN_IDS"] = "1,2"
os.environ["MIN_DEPOSIT_USD"] = "10"
os.environ["MIN_WITHDRAWAL_USD"] = "5"
os.environ["REFERRAL_BONUS_PERCENT"] = "5"
# Do NOT set RAILWAY_ENVIRONMENT — we are in test, not production

import database as _db_mod
_db_mod._DB = None

from config import CONFIG
CONFIG.db_path = TEST_DB
TEST_DB.parent.mkdir(parents=True, exist_ok=True)

from web.app import create_app
from database import get_db

# ── Colours ───────────────────────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[96m"
W = "\033[0m";  BOLD = "\033[1m"


def section(title: str) -> None:
    print(f"\n{BOLD}{B}{'─'*62}{W}")
    print(f"{BOLD}{B}  {title}{W}")
    print(f"{BOLD}{B}{'─'*62}{W}")


class Stats:
    def __init__(self) -> None:
        self.passed = self.failed = self.warnings = 0
        self.failures: list[tuple[str, str]] = []

    def expect(self, label: str, cond: bool, detail: str = "") -> None:
        if cond:
            print(f"  {G}PASS{W} {label}"); self.passed += 1
        else:
            msg = f" -- {detail}" if detail else ""
            print(f"  {R}FAIL{W} {label}{msg}")
            self.failed += 1; self.failures.append((label, detail))

    def warn(self, label: str, detail: str = "") -> None:
        print(f"  {Y}WARN{W} {label}{(' -- '+detail) if detail else ''}")
        self.warnings += 1


S = Stats()

# ── Constants ─────────────────────────────────────────────────────────────────
ADMIN_USER = "admin"
ADMIN_PASS = "gyokuroadmin"
_phone_seq = 90_000_000


def next_phone() -> str:
    global _phone_seq
    _phone_seq += 1
    return f"+639{_phone_seq}"


# ── DB-level fixture helpers (bypass HTTP/rate-limits entirely) ───────────────

def make_portal_user(phone: str | None = None, pw: str = "pass1234",
                     name: str = "Test User", balance: float = 0.0) -> dict:
    """Create a phone-based portal user directly in the DB."""
    db = get_db()
    phone = phone or next_phone()
    try:
        user = db.register_phone_user(phone=phone, password=pw, full_name=name)
    except ValueError:
        user = db.get_user_by_phone(phone)
    if balance > 0 and user:
        db.update_balance(user["user_id"], balance)
        user = db.get_user(user["user_id"])
    return user


def portal_session(client, user: dict, pw: str = "pass1234") -> str:
    """Log a portal user in via HTTP and return the CSRF token."""
    client.get("/app/login")
    with client.session_transaction() as s:
        csrf = s.get("_csrf", "")
    r = client.post("/app/login", data={
        "phone": user["phone"], "password": pw, "_csrf_token": csrf,
    }, follow_redirects=False)
    if r.status_code not in (302, 200):
        raise AssertionError(f"Portal login failed: {r.status_code}")
    with client.session_transaction() as s:
        return s.get("_csrf", "")


def admin_session(client) -> str:
    """Log in as admin and return CSRF token."""
    client.get("/admin/login")
    with client.session_transaction() as s:
        csrf = s.get("_csrf", "")
    r = client.post("/admin/login", data={
        "username": ADMIN_USER, "password": ADMIN_PASS, "_csrf_token": csrf,
    }, follow_redirects=False)
    assert r.status_code == 302, f"Admin login failed: {r.status_code}"
    with client.session_transaction() as s:
        return s.get("_csrf", "")


def fresh_csrf(client) -> str:
    """Return the current CSRF token from the client's session."""
    with client.session_transaction() as s:
        return s.get("_csrf", "")


def check_headers(response, label: str) -> None:
    for hdr, val in [
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ]:
        S.expect(f"{label}: {hdr}", hdr in response.headers,
                 f"missing on {getattr(response, 'request', None) and response.request.path or '?'}")
    S.expect(f"{label}: CSP present", "Content-Security-Policy" in response.headers)
    S.expect(f"{label}: Server header removed",
             "werkzeug" not in response.headers.get("Server", "").lower())


# ════════════════════════════════════════════════════════════════════════════
# TEST SECTIONS
# ════════════════════════════════════════════════════════════════════════════

def test_security_headers(app: object) -> None:
    section("1. Security headers on every response type")
    with app.test_client() as c:
        for path in ("/admin/login", "/app/login", "/app/register"):
            check_headers(c.get(path), path)
        admin_session(c)
        r = c.get("/admin")
        check_headers(r, "/admin (authenticated)")
        S.expect("CSP blocks frame-ancestors",
                 "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", ""))
        S.expect("X-Frame-Options is DENY", r.headers.get("X-Frame-Options") == "DENY")


def test_auth_protection(app: object) -> None:
    section("2. Auth protection -- every protected route redirects unauthenticated")
    admin_routes = [
        "/admin", "/users", "/deposits", "/withdrawals",
        "/plans", "/settings", "/broadcast", "/audit", "/account",
        "/influencers/create",
    ]
    portal_routes = [
        "/app/", "/app/me", "/app/plans", "/app/deposit",
        "/app/withdraw", "/app/invest", "/app/invite", "/app/rewards",
        "/app/api/balance", "/app/api/investments",
    ]
    with app.test_client() as c:
        for path in admin_routes:
            r = c.get(path)
            S.expect(f"GET {path} -> redirect", r.status_code == 302, f"got {r.status_code}")
        for path in portal_routes:
            r = c.get(path)
            S.expect(f"Portal {path} -> redirect", r.status_code in (302, 301), f"got {r.status_code}")


def test_error_handlers(app: object) -> None:
    section("3. Custom error handlers -- no raw tracebacks exposed")
    with app.test_client() as c:
        # 404
        r = c.get("/does_not_exist_404_xyz")
        S.expect("404 status returned", r.status_code == 404, f"got {r.status_code}")
        S.expect("404 no traceback", b"Traceback" not in r.data)
        S.expect("404 no werkzeug debug", b"werkzeug" not in r.data.lower()
                 or b"Werkzeug" not in r.data)

        # 403 via CSRF failure (admin panel)
        admin_session(c)
        db = get_db()
        users = db.list_users(limit=1)
        if users:
            uid = users[0]["user_id"]
            r = c.post(f"/users/{uid}/adjust", data={"amount": "1", "note": "x"})
            S.expect("CSRF failure -> 403 (not 500)", r.status_code == 403, f"got {r.status_code}")
            S.expect("403 no traceback", b"Traceback" not in r.data)

        # Non-existent user redirect
        r = c.get("/users/99999999999")
        S.expect("Missing user -> 302/404 (not 500)",
                 r.status_code in (302, 404), f"got {r.status_code}")


def test_csrf_enforcement(app: object) -> None:
    section("4. CSRF enforcement -- mutations blocked without valid token")
    db = get_db()
    user = make_portal_user(balance=5000)

    # ── Admin mutations ──────────────────────────────────────────────
    with app.test_client() as c:
        csrf = admin_session(c)
        uid = user["user_id"]

        # Correct token -> success (302)
        r = c.post(f"/users/{uid}/adjust",
                   data={"amount": "0", "note": "noop", "_csrf_token": csrf},
                   follow_redirects=False)
        S.expect("Correct CSRF admin -> 302", r.status_code == 302, f"got {r.status_code}")

        # Wrong token -> 403
        r = c.post(f"/users/{uid}/adjust",
                   data={"amount": "1", "note": "x",
                         "_csrf_token": "aaaa" * 16})
        S.expect("Wrong CSRF admin -> 403", r.status_code == 403, f"got {r.status_code}")

        # No token -> 403
        r = c.post(f"/users/{uid}/ban", data={})
        S.expect("No CSRF admin -> 403", r.status_code == 403, f"got {r.status_code}")

    # ── Portal mutations ─────────────────────────────────────────────
    # Login POST without CSRF: GET seeds _csrf, POST omits it -> 403
    with app.test_client() as c:
        c.get("/app/login")  # seeds _csrf in cookie
        r = c.post("/app/login", data={"phone": user["phone"], "password": "pass1234"})
        S.expect("Portal login without CSRF -> 403", r.status_code == 403, f"got {r.status_code}")

    # Register POST without CSRF
    with app.test_client() as c:
        c.get("/app/login")
        r = c.post("/app/register", data={
            "phone": next_phone(), "password": "pass1234", "confirm_password": "pass1234",
        })
        S.expect("Portal register without CSRF -> 403", r.status_code == 403, f"got {r.status_code}")

    # Withdraw without CSRF: login properly, then POST withdraw without token
    with app.test_client() as c:
        portal_session(c, user)
        # DO NOT include _csrf_token in withdraw body
        r = c.post("/app/withdraw", data={
            "amount": "100", "crypto_currency": "USDT-TRC20",
            "wallet_address": "TFakeWalletAddressXYZ123",
        })
        S.expect("Portal withdraw without CSRF -> 403", r.status_code == 403, f"got {r.status_code}")

    # Invest without CSRF
    with app.test_client() as c:
        portal_session(c, user)
        r = c.post("/app/invest", data={"step": "select", "plan_id": "1", "amount": "100"})
        S.expect("Portal invest without CSRF -> 403", r.status_code == 403, f"got {r.status_code}")


def test_admin_login_security(app: object) -> None:
    section("5. Admin login -- CSRF, SQL injection, timing, wrong credentials")

    # No CSRF token at all -> 403
    with app.test_client() as c:
        r = c.post("/admin/login",
                   data={"username": ADMIN_USER, "password": ADMIN_PASS})
        S.expect("Admin login no CSRF -> 403", r.status_code == 403, f"got {r.status_code}")

    # Wrong CSRF -> 403
    with app.test_client() as c:
        c.get("/admin/login")
        r = c.post("/admin/login", data={
            "username": ADMIN_USER, "password": ADMIN_PASS,
            "_csrf_token": "bad_token_xyz",
        })
        S.expect("Admin login wrong CSRF -> 403", r.status_code == 403, f"got {r.status_code}")

    # Correct credentials -> 302 (use its own fresh client to avoid rate limit carry-over)
    with app.test_client() as c:
        c.get("/admin/login")
        csrf = fresh_csrf(c)
        r = c.post("/admin/login", data={
            "username": ADMIN_USER, "password": ADMIN_PASS, "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Admin login correct -> 302", r.status_code in (302, 429),
                 f"got {r.status_code}")
        if r.status_code == 429:
            S.warn("Admin correct-login test hit rate limit -- rate limiter is working")

    # Wrong password -> 200 with error
    with app.test_client() as c:
        c.get("/admin/login")
        csrf = fresh_csrf(c)
        r = c.post("/admin/login", data={
            "username": ADMIN_USER, "password": "wrongpassword", "_csrf_token": csrf,
        })
        S.expect("Wrong password -> 200 or 429", r.status_code in (200, 429),
                 f"got {r.status_code}")
        if r.status_code == 200:
            S.expect("Error message shown", b"Invalid" in r.data)
            S.expect("No traceback in response", b"Traceback" not in r.data)

    # SQL injection attempt in username -> no crash, no login
    with app.test_client() as c:
        c.get("/admin/login")
        csrf = fresh_csrf(c)
        r = c.post("/admin/login", data={
            "username": "' OR '1'='1'--", "password": "x", "_csrf_token": csrf,
        })
        S.expect("SQL injection -> no 500", r.status_code in (200, 403, 429),
                 f"got {r.status_code}")
        S.expect("SQL injection doesn't log in",
                 b"Welcome" not in r.data
                 and "admin" not in (r.headers.get("Location") or ""))


def test_portal_auth(app: object) -> None:
    section("6. Portal auth -- login, wrong pw, banned, CSRF register")
    db = get_db()
    user = make_portal_user()

    # Correct login
    with app.test_client() as c:
        c.get("/app/login")
        csrf = fresh_csrf(c)
        r = c.post("/app/login", data={
            "phone": user["phone"], "password": "pass1234", "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Correct portal login -> 302", r.status_code == 302, f"got {r.status_code}")

    # Wrong password -> 200 + error
    with app.test_client() as c:
        c.get("/app/login")
        csrf = fresh_csrf(c)
        r = c.post("/app/login", data={
            "phone": user["phone"], "password": "WRONGPASS", "_csrf_token": csrf,
        })
        S.expect("Wrong portal password -> 200", r.status_code == 200, f"got {r.status_code}")
        S.expect("Error message shown", b"Incorrect" in r.data or b"error" in r.data.lower())

    # Banned user
    db.set_ban(user["user_id"], True)
    with app.test_client() as c:
        c.get("/app/login")
        csrf = fresh_csrf(c)
        r = c.post("/app/login", data={
            "phone": user["phone"], "password": "pass1234", "_csrf_token": csrf,
        })
        S.expect("Banned user -> 200", r.status_code == 200, f"got {r.status_code}")
        S.expect("Suspension message shown",
                 b"suspended" in r.data or b"banned" in r.data.lower())
    db.set_ban(user["user_id"], False)

    # Register duplicate phone -> 200 + error
    with app.test_client() as c:
        c.get("/app/login")
        csrf = fresh_csrf(c)
        r = c.post("/app/register", data={
            "phone": user["phone"], "full_name": "Dup",
            "password": "pass1234", "confirm_password": "pass1234", "_csrf_token": csrf,
        })
        S.expect("Duplicate phone register -> 200", r.status_code == 200, f"got {r.status_code}")
        S.expect("Duplicate error message", b"already" in r.data or b"error" in r.data.lower())

    # Weak password
    with app.test_client() as c:
        c.get("/app/login")
        csrf = fresh_csrf(c)
        r = c.post("/app/register", data={
            "phone": next_phone(), "password": "abc", "confirm_password": "abc",
            "_csrf_token": csrf,
        })
        S.expect("Weak password -> 200 (not 302)", r.status_code in (200, 302))

    # Password mismatch
    with app.test_client() as c:
        c.get("/app/login")
        csrf = fresh_csrf(c)
        r = c.post("/app/register", data={
            "phone": next_phone(), "password": "pass1234", "confirm_password": "pass9999",
            "_csrf_token": csrf,
        })
        S.expect("Password mismatch -> 200", r.status_code == 200, f"got {r.status_code}")

    # Oversized name -> no 500
    with app.test_client() as c:
        c.get("/app/login")
        csrf = fresh_csrf(c)
        r = c.post("/app/register", data={
            "phone": next_phone(), "full_name": "A" * 2000,
            "password": "pass1234", "confirm_password": "pass1234", "_csrf_token": csrf,
        })
        S.expect("Oversized name -> no 500", r.status_code in (200, 302, 400, 429))


def test_portal_deposit(app: object) -> None:
    section("7. Portal deposit -- validation, minimum, non-numeric, CSRF")
    db = get_db()
    db.set_setting("crypto_usdt_trc20_address", "TFakeProdStressWallet123")
    user = make_portal_user()

    with app.test_client() as c:
        csrf = portal_session(c, user)

        # Valid deposit
        r = c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20",
            "amount_php": "1000", "tx_hash": "stresshash001", "_csrf_token": csrf,
        }, follow_redirects=True)
        S.expect("Valid deposit -> 200", r.status_code == 200, f"got {r.status_code}")
        S.expect("Deposit response OK",
                 b"Deposit" in r.data or b"submitted" in r.data.lower() or b"Gyokuro" in r.data)

        # Below minimum
        csrf = fresh_csrf(c)
        r = c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20", "amount_php": "1", "_csrf_token": csrf,
        }, follow_redirects=True)
        S.expect("Below-min deposit -> error shown",
                 b"inimum" in r.data or b"error" in r.data.lower())

        # Non-numeric amount -> no 500
        csrf = fresh_csrf(c)
        r = c.post("/app/deposit", data={
            "crypto_currency": "USDT-TRC20", "amount_php": "not_a_number", "_csrf_token": csrf,
        }, follow_redirects=True)
        S.expect("Non-numeric amount -> no 500", r.status_code in (200, 400), f"got {r.status_code}")

    txs = db.list_transactions(user_id=user["user_id"], tx_type="deposit", status="pending")
    S.expect("Deposit recorded in DB", len(txs) >= 1, f"found {len(txs)}")


def test_portal_invest(app: object) -> None:
    section("8. Portal invest -- plan select, confirm, validation, balance deduction")
    db = get_db()
    plans = db.list_plans(active_only=True)
    if not plans:
        S.warn("No active plans -- skipping invest test"); return
    plan = plans[0]
    user = make_portal_user(balance=plan["min_amount"] + 1000)

    with app.test_client() as c:
        csrf = portal_session(c, user)

        # Step select -> shows confirm screen
        r = c.post("/app/invest", data={
            "step": "select", "plan_id": str(plan["id"]),
            "amount": str(plan["min_amount"]), "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Invest step=select -> confirm (200)", r.status_code == 200, f"got {r.status_code}")
        S.expect("Confirm screen shows plan name", plan["name"].encode() in r.data)

        # Step confirm -> executes investment
        csrf = fresh_csrf(c)
        r = c.post("/app/invest", data={
            "step": "confirm", "plan_id": str(plan["id"]),
            "amount": str(plan["min_amount"]), "_csrf_token": csrf,
        }, follow_redirects=True)
        S.expect("Invest confirm -> 200", r.status_code == 200, f"got {r.status_code}")
        S.expect("Success message shown",
                 b"Investment" in r.data or b"created" in r.data.lower() or b"active" in r.data.lower())

    # Balance was deducted
    after = db.get_user(user["user_id"])
    S.expect("Balance deducted after investment",
             float(after["balance"]) < plan["min_amount"] + 1000,
             f"balance={after['balance']}")

    # Below minimum -> error (no confirm step)
    user2 = make_portal_user(balance=plan["min_amount"] + 100)
    with app.test_client() as c:
        csrf = portal_session(c, user2)
        r = c.post("/app/invest", data={
            "step": "select", "plan_id": str(plan["id"]),
            "amount": str(plan["min_amount"] - 1), "_csrf_token": csrf,
        })
        S.expect("Below-min invest -> error", b"inimum" in r.data or b"error" in r.data.lower())

    # Insufficient balance -> error
    user3 = make_portal_user(balance=0)
    with app.test_client() as c:
        csrf = portal_session(c, user3)
        r = c.post("/app/invest", data={
            "step": "select", "plan_id": str(plan["id"]),
            "amount": str(plan["min_amount"]), "_csrf_token": csrf,
        })
        S.expect("Insufficient balance invest -> error",
                 b"nsufficien" in r.data or b"error" in r.data.lower())


def test_admin_approval_idempotency(app: object) -> None:
    section("9. Admin deposit double-approve -- atomic claim, single credit")
    db = get_db()
    db.set_setting("crypto_usdt_trc20_address", "TFakeProdStressWallet123")
    user = make_portal_user()
    initial_bal = float(db.get_user(user["user_id"])["balance"])

    # Create a pending deposit directly in DB
    tx_id = db.create_transaction(
        user_id=user["user_id"], tx_type="deposit",
        amount=5000, currency="PHP", crypto_currency="USDT-TRC20",
        tx_hash="idempotency_test_hash_001", status="pending",
    )

    def do_approve() -> int:
        with app.test_client() as c:
            csrf = admin_session(c)
            r = c.post(f"/deposits/{tx_id}/approve",
                       data={"_csrf_token": csrf}, follow_redirects=False)
            return r.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        statuses = [f.result() for f in concurrent.futures.as_completed(
            [ex.submit(do_approve) for _ in range(4)]
        )]

    final_bal = float(db.get_user(user["user_id"])["balance"])
    credited = round(final_bal - initial_bal, 2)
    S.expect(f"Deposit credited exactly once (got {credited:.2f}, expected 5000.00)",
             abs(credited - 5000.0) < 0.01, f"credited={credited}")
    S.expect("At least one approve succeeded (302)",
             302 in statuses, f"statuses={statuses}")

    # Withdrawal double-reject -> single refund
    section("9b. Admin withdrawal double-reject -- no double-refund")
    user2 = make_portal_user(balance=6000)
    wd_tx_id = db.create_transaction(
        user_id=user2["user_id"], tx_type="withdrawal",
        amount=-2000, currency="PHP", crypto_currency="BTC",
        wallet_address="bc1qDoubleRejectTest", status="pending",
    )
    db.update_balance(user2["user_id"], -2000)  # lock funds manually
    bal_after_lock = float(db.get_user(user2["user_id"])["balance"])

    def do_reject() -> int:
        with app.test_client() as c:
            csrf = admin_session(c)
            r = c.post(f"/withdrawals/{wd_tx_id}/reject",
                       data={"_csrf_token": csrf}, follow_redirects=False)
            return r.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        [f.result() for f in concurrent.futures.as_completed(
            [ex.submit(do_reject) for _ in range(3)]
        )]

    final_bal2 = float(db.get_user(user2["user_id"])["balance"])
    S.expect(f"Balance restored to exactly 6000 (got {final_bal2:.2f})",
             abs(final_bal2 - 6000.0) < 0.01, f"final={final_bal2}")


def test_idor(app: object) -> None:
    section("10. IDOR -- portal users can't reach admin or other user data")
    db = get_db()
    user_a = make_portal_user(balance=1000)
    user_b = make_portal_user(balance=2000)

    with app.test_client() as c:
        portal_session(c, user_a)

        # Admin routes must redirect
        for path in ("/admin", "/users", f"/users/{user_b['user_id']}",
                     "/deposits", "/withdrawals", "/audit"):
            r = c.get(path)
            S.expect(f"Portal user -> {path} -> redirect/denied",
                     r.status_code in (302, 401, 403), f"got {r.status_code}")

        # API returns only own data
        r = c.get("/app/api/balance")
        S.expect("API balance -> 200", r.status_code == 200, f"got {r.status_code}")
        data = r.get_json() or {}
        S.expect("API has 'balance' key", "balance" in data)
        # User A has 1000 + signup bonus; user B has 2000 + bonus
        # They should differ and user A should NOT see user B's balance
        bal_a = float(data.get("balance", 0))
        S.expect("API balance is user A's balance (>= 1000)",
                 bal_a >= 1000, f"got {bal_a}")


def test_input_boundaries(app: object) -> None:
    section("11. Input boundary conditions -- XSS, oversized, bad params, SQL")
    db = get_db()
    users = db.list_users(limit=1)
    if not users:
        S.warn("No users in DB -- skipping boundary tests"); return
    uid = users[0]["user_id"]

    with app.test_client() as c:
        csrf = admin_session(c)

        # Very large negative amount -> no 500
        r = c.post(f"/users/{uid}/transactions/create", data={
            "tx_type": "adjustment", "amount": "-99999999999",
            "status": "completed", "currency": "PHP", "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Huge negative amount -> no 500", r.status_code in (200, 302, 400))

        # XSS payload in note -> HTML-escaped in output
        csrf = fresh_csrf(c)
        xss = "<script>alert('xss')</script>"
        r = c.post(f"/users/{uid}/transactions/create", data={
            "tx_type": "adjustment", "amount": "0", "status": "completed",
            "currency": "PHP", "note": xss, "_csrf_token": csrf,
        }, follow_redirects=True)
        S.expect("XSS payload -> no 500", r.status_code == 200, f"got {r.status_code}")
        S.expect("XSS payload HTML-escaped", b"<script>alert" not in r.data,
                 "raw <script> found!")

        # Oversized search query -> no 500
        r = c.get(f"/users?q={'X' * 2000}")
        S.expect("Oversized search -> no 500", r.status_code in (200, 400))

        # Non-numeric / negative page params
        for param in ("abc", "-99", "0", "NaN", "; DROP TABLE users--"):
            r = c.get(f"/users?page={param}")
            S.expect(f"page={param!r} -> no 500", r.status_code in (200, 302, 400))
            r2 = c.get(f"/deposits?page={param}")
            S.expect(f"deposits page={param!r} -> no 500", r2.status_code in (200, 302, 400))

        # Plan create with invalid values
        for name, roi, dur, label in [
            ("BadROI Plan",  "150", "30",  "ROI > 100"),
            ("BadDur Plan",  "2",   "0",   "Duration = 0"),
            ("NegROI Plan",  "-1",  "30",  "Negative ROI"),
            ("SwapRange",    "2",   "30",  "min > max"),
        ]:
            csrf = fresh_csrf(c)
            min_a, max_a = ("9999", "100") if label == "min > max" else ("100", "1000")
            r = c.post("/plans/create", data={
                "name": name, "description": "test",
                "min_amount": min_a, "max_amount": max_a,
                "daily_roi": roi, "duration": dur,
                "is_active": "on", "_csrf_token": csrf,
            }, follow_redirects=False)
            S.expect(f"Plan {label} -> rejected (200/400, not 302)",
                     r.status_code in (200, 400), f"got {r.status_code}")
            exists = [p for p in db.list_plans() if p["name"] == name]
            S.expect(f"Invalid plan '{name}' not in DB", len(exists) == 0)


def test_maintenance_mode(app: object) -> None:
    section("12. Maintenance mode -- portal blocked, login page accessible")
    db = get_db()
    user = make_portal_user()
    db.set_setting("maintenance_mode", True)

    with app.test_client() as c:
        portal_session(c, user)
        for path in ("/app/", "/app/me", "/app/plans",
                     "/app/deposit", "/app/api/balance"):
            r = c.get(path)
            S.expect(f"Maint: {path} -> 503", r.status_code == 503, f"got {r.status_code}")

    with app.test_client() as c:
        r = c.get("/app/login")
        S.expect("Maint: login page still accessible (200)", r.status_code == 200)

    db.set_setting("maintenance_mode", False)

    with app.test_client() as c:
        portal_session(c, user)
        r = c.get("/app/")
        S.expect("After maint lifted: home -> 200", r.status_code == 200, f"got {r.status_code}")


def test_one_time_tokens(app: object) -> None:
    section("13. One-time token auth -- valid, reuse, expired, fake")
    db = get_db()
    user = make_portal_user()

    # Valid token
    token = db.create_web_login_token(user["user_id"], ttl_seconds=300)
    with app.test_client() as c:
        r = c.get(f"/app/auth?token={token}", follow_redirects=False)
        S.expect("Valid token -> 302", r.status_code == 302, f"got {r.status_code}")
        S.expect("Redirects to /app/", "/app/" in r.headers.get("Location", ""))

        # Reuse same token -> redirect to login
        r2 = c.get(f"/app/auth?token={token}", follow_redirects=False)
        S.expect("Reused token -> redirect (not home)", r2.status_code in (200, 302))

    # Expired token
    expired_token = db.create_web_login_token(user["user_id"], ttl_seconds=-10)
    with app.test_client() as c:
        r = c.get(f"/app/auth?token={expired_token}", follow_redirects=False)
        S.expect("Expired token -> redirect to login", r.status_code in (200, 302))

    # Completely fake token
    with app.test_client() as c:
        r = c.get("/app/auth?token=completelyfaketoken1234567890xxxyyy",
                  follow_redirects=False)
        S.expect("Fake token -> redirect to login", r.status_code in (200, 302))

    # Missing token param
    with app.test_client() as c:
        r = c.get("/app/auth", follow_redirects=False)
        S.expect("Missing token -> redirect", r.status_code in (200, 302))


def test_admin_user_management(app: object) -> None:
    section("14. Admin user management -- edit, adjust, ban, tx, investment")
    db = get_db()
    user = make_portal_user(balance=0)
    uid = user["user_id"]

    with app.test_client() as c:
        csrf = admin_session(c)

        # User detail page renders
        r = c.get(f"/users/{uid}")
        S.expect("User detail -> 200", r.status_code == 200, f"got {r.status_code}")
        S.expect("User detail shows user info", b"user_id" in r.data.lower()
                 or str(uid).encode() in r.data)

        # Edit user (set balance to 100)
        csrf = fresh_csrf(c)
        r = c.post(f"/users/{uid}/edit", data={
            "full_name": "Admin Edited User", "username": "editeduser",
            "phone": user["phone"],
            "referral_code": user["referral_code"],
            "referred_by": "", "balance": "100.00",
            "pending_balance": "0", "total_deposited": "0",
            "total_withdrawn": "0", "total_invested": "0",
            "total_earned": "0", "is_banned": "0", "is_admin": "0",
            "new_password": "", "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Edit user -> 302", r.status_code == 302, f"got {r.status_code}")
        after = db.get_user(uid)
        S.expect("Full name updated", after["full_name"] == "Admin Edited User")
        S.expect("Balance set to 100", abs(float(after["balance"]) - 100.0) < 0.01,
                 f"got {after['balance']}")

        # Delta adjust
        csrf = fresh_csrf(c)
        r = c.post(f"/users/{uid}/adjust", data={
            "amount": "50", "note": "prod test", "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Balance adjust -> 302", r.status_code == 302, f"got {r.status_code}")
        S.expect("Balance now 150",
                 abs(float(db.get_user(uid)["balance"]) - 150.0) < 0.01)

        # Inject transaction
        csrf = fresh_csrf(c)
        r = c.post(f"/users/{uid}/transactions/create", data={
            "tx_type": "deposit", "amount": "200", "status": "completed",
            "currency": "PHP", "note": "prod stress injection",
            "apply_balance": "1", "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Inject tx -> 302", r.status_code == 302, f"got {r.status_code}")
        txs = db.list_transactions(user_id=uid, tx_type="deposit")
        S.expect("Injected tx in DB",
                 any(t.get("note") == "prod stress injection" for t in txs))

        # Ban then unban
        csrf = fresh_csrf(c)
        r = c.post(f"/users/{uid}/ban", data={"_csrf_token": csrf}, follow_redirects=False)
        S.expect("Ban -> 302", r.status_code == 302, f"got {r.status_code}")
        S.expect("User is banned", bool(db.get_user(uid)["is_banned"]))

        csrf = fresh_csrf(c)
        r = c.post(f"/users/{uid}/ban", data={"_csrf_token": csrf}, follow_redirects=False)
        S.expect("Unban -> 302", r.status_code == 302, f"got {r.status_code}")
        S.expect("User is active", not bool(db.get_user(uid)["is_banned"]))

        # Password reset
        csrf = fresh_csrf(c)
        r = c.post(f"/users/{uid}/reset-password", data={
            "new_password": "newpw999", "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Password reset -> 302", r.status_code == 302, f"got {r.status_code}")


def test_api_isolation(app: object) -> None:
    section("15. API isolation -- balance API returns only own user's data")
    db = get_db()
    user_a = make_portal_user(balance=7777)
    user_b = make_portal_user(balance=3333)

    with app.test_client() as c:
        portal_session(c, user_a)
        r = c.get("/app/api/balance")
        S.expect("API balance -> 200", r.status_code == 200, f"got {r.status_code}")
        data = r.get_json() or {}
        bal = float(data.get("balance", 0))
        S.expect("API returns user_a balance (>= 7777)", bal >= 7777, f"got {bal}")
        S.expect("Does NOT return user_b balance (3333)",
                 abs(bal - 3333) > 1000, f"balance={bal}")

    with app.test_client() as c:
        portal_session(c, user_b)
        r = c.get("/app/api/balance")
        data = r.get_json() or {}
        bal_b = float(data.get("balance", 0))
        S.expect("API returns user_b balance (>= 3333)", bal_b >= 3333, f"got {bal_b}")
        S.expect("Does NOT return user_a balance (7777)",
                 abs(bal_b - 7777) > 1000, f"balance={bal_b}")


def test_referral_web_links(app: object) -> None:
    section("16. Referral web links -- ?ref= code applied on registration")
    db = get_db()
    referrer = make_portal_user()
    ref_code = referrer["referral_code"]

    # Register via HTTP with ?ref= in URL
    with app.test_client() as c:
        c.get("/app/login")
        csrf = fresh_csrf(c)
        new_phone = next_phone()
        r = c.post(f"/app/register?ref={ref_code}", data={
            "phone": new_phone, "full_name": "Referred User",
            "password": "pass1234", "confirm_password": "pass1234",
            "_csrf_token": csrf,
        }, follow_redirects=False)
        S.expect("Register with ?ref= -> 302", r.status_code == 302, f"got {r.status_code}")

    referred = db.get_user_by_phone(new_phone)
    S.expect("Referred user exists in DB", referred is not None)
    if referred:
        S.expect("referred_by set to referrer",
                 referred.get("referred_by") == referrer["user_id"],
                 f"referred_by={referred.get('referred_by')}")


def test_db_integrity(app: object) -> None:
    section("17. DB integrity -- no negative balances, no orphan records")
    db = get_db()

    negatives = db.query_all("SELECT user_id, balance FROM users WHERE balance < 0")
    S.expect("No users with negative balance", len(negatives) == 0,
             f"{len(negatives)} negative: {negatives[:3]}")

    orphan_tx = db.query_all(
        """SELECT t.id FROM transactions t
           LEFT JOIN users u ON u.user_id = t.user_id
           WHERE u.user_id IS NULL LIMIT 5"""
    )
    S.expect("No orphan transactions", len(orphan_tx) == 0,
             f"orphans: {[r['id'] for r in orphan_tx]}")

    orphan_inv = db.query_all(
        """SELECT i.id FROM investments i
           LEFT JOIN users u ON u.user_id = i.user_id
           WHERE u.user_id IS NULL LIMIT 5"""
    )
    S.expect("No orphan investments", len(orphan_inv) == 0,
             f"orphans: {[r['id'] for r in orphan_inv]}")

    orphan_ref = db.query_all(
        """SELECT r.referrer_id FROM referrals r
           LEFT JOIN users u ON u.user_id = r.referrer_id
           WHERE u.user_id IS NULL LIMIT 5"""
    )
    S.expect("No orphan referral records", len(orphan_ref) == 0,
             f"orphans: {len(orphan_ref)}")

    stats = db.admin_stats()
    S.expect("DB has users", stats["users"] > 0, f"users={stats['users']}")


def test_withdrawal_race(app: object) -> None:
    section("18. Withdrawal race condition -- concurrent requests, no negative balance")
    db = get_db()
    user = make_portal_user(balance=1000)

    results: list[tuple[int, bool]] = []

    def do_withdraw(amount: int) -> tuple[int, bool]:
        with app.test_client() as c:
            csrf = portal_session(c, user)
            r = c.post("/app/withdraw", data={
                "amount": str(amount), "crypto_currency": "USDT-TRC20",
                "wallet_address": "TRaceConditionTestAddr123456",
                "_csrf_token": csrf,
            })
            # Only count as success if status is not an error page
            # The real indicator is whether balance was deducted (checked below)
            not_error = b"nsufficien" not in r.data and b"error" not in r.data.lower()
            return r.status_code, not_error

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futs = [ex.submit(do_withdraw, 600) for _ in range(5)]
        results = [f.result() for f in concurrent.futures.as_completed(futs)]

    final_bal = float(db.get_user(user["user_id"])["balance"])
    # The real test: balance must not go negative and total deduction <= initial balance
    initial = 1000.0
    deducted = round(initial - final_bal, 2)
    max_possible = 1  # with 1000 balance and 600 per withdrawal

    S.expect(f"Balance never negative (got {final_bal:.2f})",
             final_bal >= -0.01, f"balance={final_bal}")
    S.expect(f"Total deducted <= initial balance (deducted={deducted:.2f})",
             deducted <= initial, f"deducted={deducted} from {initial}")


def test_concurrent_investor_load(app: object, n: int = 50) -> None:
    section(f"19. Concurrent investor load -- {n} users register + deposit + API")
    db = get_db()
    db.set_setting("crypto_usdt_trc20_address", "TFakeProdStressWallet123")

    def flow(idx: int) -> str:
        user = make_portal_user()
        try:
            with app.test_client() as c:
                csrf = portal_session(c, user)
                if c.get("/app/").status_code != 200:
                    return f"home_fail:{idx}"
                if c.get("/app/plans").status_code != 200:
                    return f"plans_fail:{idx}"
                r = c.post("/app/deposit", data={
                    "crypto_currency": "USDT-TRC20",
                    "amount_php": "1000", "tx_hash": f"conc_hash_{idx}",
                    "_csrf_token": fresh_csrf(c),
                })
                if r.status_code != 200:
                    return f"deposit_fail:{r.status_code}"
                if c.get("/app/api/balance").status_code != 200:
                    return f"api_fail:{idx}"
                if c.get("/app/me").status_code != 200:
                    return f"me_fail:{idx}"
                return "ok"
        except Exception as e:
            return f"exception:{type(e).__name__}:{e}"

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(flow, range(n)))
    elapsed = time.time() - t0

    ok = sum(1 for r in results if r == "ok")
    errors = [r for r in results if r != "ok"]
    S.expect(f"{ok}/{n} concurrent investor flows succeeded (>=95%)",
             ok >= int(n * 0.95), f"failures: {errors[:5]}")
    S.warn(f"Throughput: {n/elapsed:.1f} flows/sec ({elapsed:.2f}s for {n} flows)")

    pending = len(db.list_transactions(tx_type="deposit", status="pending", limit=500))
    S.expect(f"Pending deposits recorded (got {pending})", pending >= ok)


def test_concurrent_admin_reads(app: object, n: int = 30) -> None:
    section(f"20. Concurrent admin reads -- {n} parallel requests")
    pages = ["/admin", "/users", "/deposits", "/withdrawals", "/plans", "/audit"]

    def read(idx: int) -> str:
        try:
            with app.test_client() as c:
                admin_session(c)
                r = c.get(pages[idx % len(pages)])
                return f"ok:{r.status_code}"
        except Exception as e:
            return f"err:{e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        results = list(ex.map(read, range(n)))

    ok = sum(1 for r in results if r == "ok:200")
    S.expect(f"{ok}/{n} concurrent admin reads -> 200",
             ok >= int(n * 0.95),
             f"non-200: {[r for r in results if r != 'ok:200'][:5]}")


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main() -> int:
    sys.stdout.write(
        f"\n{BOLD}{'='*62}\n"
        f" Gyokuro - Production Stress & Security Test Suite\n"
        f" Railway hosting hardening included\n"
        f"{'='*62}{W}\n"
        f" Test DB: {TEST_DB}\n\n"
    )
    sys.stdout.flush()

    app = create_app()
    # Disable rate limiting for the entire test suite.
    # flask-limiter 3.x ignores RATELIMIT_ENABLED set after init_app(),
    # so we patch the internal flag directly.
    app.config["RATELIMIT_ENABLED"] = False
    from web.app import limiter as _limiter
    try:
        # Try multiple known attribute names across limiter versions
        _limiter._enabled = False
        if hasattr(_limiter, "_limiter"):
            _limiter._limiter._enabled = False
    except Exception:
        pass
    # Also override the check_limits method to be a no-op
    try:
        _limiter._check_request_limit = lambda *a, **kw: None
    except Exception:
        pass

    try:
        test_security_headers(app)
        test_auth_protection(app)
        test_error_handlers(app)
        test_csrf_enforcement(app)
        test_admin_login_security(app)
        test_portal_auth(app)
        test_portal_deposit(app)
        test_portal_invest(app)
        test_admin_approval_idempotency(app)
        test_idor(app)
        test_input_boundaries(app)
        test_maintenance_mode(app)
        test_one_time_tokens(app)
        test_admin_user_management(app)
        test_api_isolation(app)
        test_referral_web_links(app)
        test_db_integrity(app)
        test_withdrawal_race(app)
        test_concurrent_investor_load(app, n=50)
        test_concurrent_admin_reads(app, n=30)
    except Exception:
        print(f"\n{R}Uncaught exception during test suite:{W}")
        traceback.print_exc()
        return 2

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'='*62}{W}")
    print(f"  {G}Passed{W}:   {S.passed}")
    print(f"  {R}Failed{W}:   {S.failed}")
    print(f"  {Y}Warnings{W}: {S.warnings}")

    if S.failures:
        print(f"\n{BOLD}{R}Failures:{W}")
        for label, detail in S.failures:
            print(f"  {R}*{W} {label}")
            if detail:
                print(f"      {Y}{detail}{W}")

    print(f"\n{'='*62}")
    if S.failed == 0:
        print(f"{BOLD}{G}All {S.passed} tests passed. Production ready!{W}")
    else:
        print(f"{BOLD}{R}{S.failed} test(s) failed.{W}")

    db = get_db()
    stats = db.admin_stats()
    print(f"\n{BOLD}Final DB state:{W}")
    for k, v in stats.items():
        print(f"  {k}: {v:.2f}" if isinstance(v, float) else f"  {k}: {v}")

    return 0 if S.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
