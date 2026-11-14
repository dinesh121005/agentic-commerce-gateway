"""
PostgreSQL 16 Milestone P1.1.1-G Adversarial Security Test Suite.
Validates Buyer-Level Isolation, Control-Plane Protection, and Active RLS on Disposable DB.
Target: Local PostgreSQL 16 instance on 127.0.0.1:5433 (database: agentic_disposable_test)

CRITICAL INVARIANTS:
1. Target is strictly the disposable database (agentic_disposable_test) on port 5433.
2. The primary database (agentic_commerce) is NEVER accessed by this suite.
3. Tests all 12 adversarial scenarios mandated by Milestone P1.1.1-G:
   1. Buyer A cannot read Buyer B's wallet.
   2. Buyer A cannot modify Buyer B's signing keys.
   3. Buyer A cannot retrieve Buyer B's mandates.
   4. Buyer A cannot consume Buyer B's purchase approvals.
   5. Missing customer context fails closed across all 8 buyer tables.
   6. Customer context cannot leak across pooled physical transactions.
   7. Merchant A cannot access Merchant B's control-plane records.
   8. Tenant runtime (app_user) cannot modify or read merchant_users.
   9. Tenant runtime (app_user) cannot insert or modify processed_webhook_events.
   10. Existing merchant isolation RLS continues passing on migrated database.
   11. System audit writes remain restricted to system_audit_writer role.
   12. Existing audit hashes and signed mandates remain verifiable.
"""
import hashlib
import json
import os
import time
import pytest
from dotenv import load_dotenv

load_dotenv("d:/agentic-commerce-gateway/.env", override=False)

try:
    import psycopg2
    from psycopg2 import sql
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

from app.audit.store import compute_event_hash
from app.signing.crypto import (
    DOMAIN_MANDATE,
    verify_payload_signature,
)
from app.signing.canonical import rfc8785_canonicalize

DISPOSABLE_DB = "agentic_disposable_test"


def get_disposable_pg_url(role="app") -> str:
    """Resolve local PostgreSQL URL for disposable database testing."""
    if role == "admin":
        raw = os.environ.get("LOCAL_PG_ADMIN_URL")
    elif role == "auth":
        raw = os.environ.get("LOCAL_PG_AUTH_URL")
    elif role == "audit":
        raw = os.environ.get("LOCAL_PG_AUDIT_URL")
    else:
        raw = os.environ.get("LOCAL_PG_APP_URL") or os.environ.get("LOCAL_DATABASE_URL")

    if not raw:
        pytest.fail(f"FATAL: Database URL for role '{role}' not configured in .env.")
    if "127.0.0.1:5433" not in raw and "localhost:5433" not in raw:
        pytest.fail(f"FATAL: Safety violation: Non-local host in URL: {raw}")
    
    # Replace database name with DISPOSABLE_DB
    base_url = raw.rsplit("/", 1)[0]
    return f"{base_url}/{DISPOSABLE_DB}"


@pytest.fixture(scope="module")
def app_conn():
    """Provides connection as app_user to disposable database."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_disposable_pg_url("app")
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def auth_conn():
    """Provides connection as gateway_auth to disposable database."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_disposable_pg_url("auth")
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def audit_conn():
    """Provides connection as system_audit_writer to disposable database."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_disposable_pg_url("audit")
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def admin_conn():
    """Provides connection as gateway_admin to disposable database."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_disposable_pg_url("admin")
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Buyer A cannot read Buyer B's wallet
# ══════════════════════════════════════════════════════════════════════════════

def test_buyer_cannot_read_other_buyer_wallet(app_conn):
    """
    Verifies that Buyer A (CUST_DISP_1) cannot select or update Buyer B's (CUST_DISP_2) wallet.
    """
    with app_conn.cursor() as cur:
        # Establish Buyer 1 context
        cur.execute("SET LOCAL app.current_customer_id = 'CUST_DISP_1';")
        
        # 1. Direct targeted query on Buyer 2's wallet returns 0 rows
        cur.execute("SELECT * FROM customer_wallets WHERE customer_id = 'CUST_DISP_2';")
        rows = cur.fetchall()
        assert len(rows) == 0, f"RLS Leak: Buyer 1 was able to read Buyer 2's wallet: {rows}"

        # 2. Blanket SELECT returns only Buyer 1's wallet
        cur.execute("SELECT customer_id, balance_paise FROM customer_wallets;")
        wallets = cur.fetchall()
        assert len(wallets) == 1, f"Expected exactly 1 wallet row for Buyer 1, got {len(wallets)}"
        assert wallets[0][0] == "CUST_DISP_1"
        assert wallets[0][1] == 50000

        # 3. Targeted UPDATE on Buyer 2's wallet affects 0 rows
        cur.execute("UPDATE customer_wallets SET balance_paise = 999999 WHERE customer_id = 'CUST_DISP_2';")
        assert cur.rowcount == 0, f"RLS Leak: Buyer 1 was able to update Buyer 2's wallet (rowcount={cur.rowcount})"

    app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Buyer A cannot modify Buyer B's signing keys
# ══════════════════════════════════════════════════════════════════════════════

def test_buyer_cannot_modify_other_buyer_signing_keys(app_conn):
    """
    Verifies Buyer A cannot update, delete, or inject signing keys for Buyer B.
    """
    with app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_customer_id = 'CUST_DISP_1';")

        # 1. Cross-buyer SELECT returns 0 rows
        cur.execute("SELECT * FROM customer_signing_keys WHERE customer_id = 'CUST_DISP_2';")
        assert len(cur.fetchall()) == 0

        # 2. Cross-buyer UPDATE affects 0 rows
        cur.execute("UPDATE customer_signing_keys SET status = 'REVOKED' WHERE customer_id = 'CUST_DISP_2';")
        assert cur.rowcount == 0

        # 3. Cross-buyer DELETE affects 0 rows
        cur.execute("DELETE FROM customer_signing_keys WHERE customer_id = 'CUST_DISP_2';")
        assert cur.rowcount == 0

        # 4. Attempting to inject a key under Buyer 2's customer_id triggers RLS WITH CHECK violation
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute(
                """
                INSERT INTO customer_signing_keys (key_id, customer_id, public_key, device_name, storage_type, status, created_at, expires_at)
                VALUES ('KEY_FORGED', 'CUST_DISP_2', 'fake_key', 'Attacker', 'software', 'ACTIVE', %s, %s);
                """,
                (time.time(), time.time() + 86400)
            )
        assert "row-level security policy" in str(exc_info.value).lower()

    app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Buyer A cannot retrieve Buyer B's mandates
# ══════════════════════════════════════════════════════════════════════════════

def test_buyer_cannot_retrieve_other_buyer_mandates(app_conn):
    """
    Verifies Buyer A cannot read or modify customer_mandates or signed_mandates of Buyer B.
    """
    with app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_customer_id = 'CUST_DISP_1';")

        # 1. Customer Mandates isolation
        cur.execute("SELECT * FROM customer_mandates WHERE customer_id = 'CUST_DISP_2';")
        assert len(cur.fetchall()) == 0

        cur.execute("SELECT customer_id FROM customer_mandates;")
        mandates = cur.fetchall()
        assert len(mandates) == 1
        assert mandates[0][0] == "CUST_DISP_1"

        # 2. Signed Mandates isolation
        cur.execute("SELECT * FROM signed_mandates WHERE customer_id = 'CUST_DISP_2';")
        assert len(cur.fetchall()) == 0

        cur.execute("SELECT customer_id FROM signed_mandates;")
        signed = cur.fetchall()
        assert len(signed) == 1
        assert signed[0][0] == "CUST_DISP_1"

        # 3. Cross-buyer UPDATE on signed mandates affects 0 rows
        cur.execute("UPDATE signed_mandates SET status = 'REVOKED' WHERE customer_id = 'CUST_DISP_2';")
        assert cur.rowcount == 0

    app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Buyer A cannot consume Buyer B's purchase approvals
# ══════════════════════════════════════════════════════════════════════════════

def test_buyer_cannot_consume_other_buyer_purchase_approvals(app_conn):
    """
    Verifies Buyer A cannot view or consume Buyer B's pending purchase approvals.
    """
    with app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_customer_id = 'CUST_DISP_1';")

        # 1. Cross-buyer SELECT returns 0 rows
        cur.execute("SELECT * FROM purchase_approvals WHERE customer_id = 'CUST_DISP_2';")
        assert len(cur.fetchall()) == 0

        # 2. Cross-buyer UPDATE affects 0 rows
        cur.execute("UPDATE purchase_approvals SET status = 'CONSUMED' WHERE customer_id = 'CUST_DISP_2';")
        assert cur.rowcount == 0

        # 3. Cross-buyer approval injection fails RLS WITH CHECK
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute(
                """
                INSERT INTO purchase_approvals (
                    approval_id, purchase_id, customer_id, mandate_id, mandate_version, key_id, total_payable_paise, canonical_payload, payload_hash, signature, status, expires_at, created_at
                ) VALUES (
                    'APP_FORGE', 'PURCH_FORGE', 'CUST_DISP_2', 'MAND_DISP_2', 1, 'KEY_DISP_2', 1000, '{}', 'hash', 'sig', 'CONSUMED', %s, %s
                );
                """,
                (time.time() + 3600, time.time())
            )
        assert "row-level security policy" in str(exc_info.value).lower()

    app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Missing customer context fails closed across all 8 buyer tables
# ══════════════════════════════════════════════════════════════════════════════

def test_missing_customer_context_fails_closed(app_conn):
    """
    Verifies that when app.current_customer_id is missing or set to empty string,
    all 8 buyer tables return zero rows and block all inserts.
    """
    buyer_tables = [
        "customer_wallets",
        "customer_signing_keys",
        "customer_mandates",
        "signed_mandates",
        "purchase_approvals",
        "signing_challenges",
        "refresh_tokens",
        "customer_credentials",
    ]

    with app_conn.cursor() as cur:
        # Explicitly set empty customer context
        cur.execute("SET LOCAL app.current_customer_id = '';")

        # 1. Assert SELECT on every buyer table returns exactly 0 rows
        for tbl in buyer_tables:
            cur.execute(sql.SQL("SELECT COUNT(*) FROM public.{};").format(sql.Identifier(tbl)))
            count = cur.fetchone()[0]
            assert count == 0, f"Fail-Closed Violation: Table '{tbl}' returned {count} rows with empty customer context!"

        # 2. Assert INSERT into customer_wallets without customer context fails closed
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute(
                """
                INSERT INTO customer_wallets (customer_id, balance, currency, balance_paise, created_at, updated_at)
                VALUES ('CUST_NEW', 100.0, 'INR', 10000, %s, %s);
                """,
                (time.time(), time.time())
            )
        assert "row-level security policy" in str(exc_info.value).lower()

    app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 6. Customer context cannot leak across pooled physical transactions
# ══════════════════════════════════════════════════════════════════════════════

def test_customer_context_cannot_leak_across_pooled_transactions(app_conn):
    """
    Verifies that SET LOCAL app.current_customer_id resets cleanly upon COMMIT or ROLLBACK,
    preventing context bleed across shared connections in a connection pool.
    """
    # Transaction 1: Active context for Buyer 1
    with app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_customer_id = 'CUST_DISP_1';")
        cur.execute("SELECT customer_id FROM customer_wallets;")
        rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "CUST_DISP_1"
    app_conn.commit()

    # Transaction 2 (Same connection, NO context set): Must fail closed immediately
    with app_conn.cursor() as cur:
        cur.execute("SELECT current_setting('app.current_customer_id', true);")
        ctx = cur.fetchone()[0]
        assert ctx in ("", None), f"Leaked customer context: expected '' or None, got '{ctx}'"
        cur.execute("SELECT COUNT(*) FROM customer_wallets;")
        count = cur.fetchone()[0]
        assert count == 0, f"Pool Leak: Transaction 2 saw {count} wallets without setting customer context!"
    app_conn.rollback()

    # Transaction 3: Active context for Buyer 2
    with app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_customer_id = 'CUST_DISP_2';")
        cur.execute("SELECT customer_id FROM customer_wallets;")
        rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "CUST_DISP_2"
    app_conn.commit()

    # Transaction 4 (Same connection, NO context set): Must fail closed again
    with app_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM customer_wallets;")
        assert cur.fetchone()[0] == 0
    app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 7. Merchant A cannot access Merchant B's control-plane records
# ══════════════════════════════════════════════════════════════════════════════

def test_merchant_cannot_access_other_merchant_control_plane(app_conn):
    """
    Verifies that Merchant Alpha cannot view Merchant Beta's metadata, memberships, or invitations.
    """
    with app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_DISP_A';")

        # 1. Merchants table: Can only see own tenant record
        cur.execute("SELECT * FROM merchants WHERE id = 'MERCH_DISP_B';")
        assert len(cur.fetchall()) == 0

        cur.execute("SELECT id FROM merchants;")
        merchants = cur.fetchall()
        assert len(merchants) == 1
        assert merchants[0][0] == "MERCH_DISP_A"

        # 2. Merchant Memberships table: Can only see own memberships
        cur.execute("SELECT * FROM merchant_memberships WHERE merchant_id = 'MERCH_DISP_B';")
        assert len(cur.fetchall()) == 0

        cur.execute("SELECT merchant_id FROM merchant_memberships;")
        memberships = cur.fetchall()
        assert len(memberships) == 1
        assert memberships[0][0] == "MERCH_DISP_A"

        # 3. Merchant Invitations table: Can only see own invitations
        cur.execute("SELECT * FROM merchant_invitations WHERE merchant_id = 'MERCH_DISP_B';")
        assert len(cur.fetchall()) == 0

        cur.execute("SELECT merchant_id FROM merchant_invitations;")
        invitations = cur.fetchall()
        assert len(invitations) == 1
        assert invitations[0][0] == "MERCH_DISP_A"

    app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 8. Tenant runtime cannot modify or read merchant_users
# ══════════════════════════════════════════════════════════════════════════════

def test_tenant_runtime_cannot_modify_or_read_merchant_users(app_conn, auth_conn):
    """
    Verifies that app_user has zero permissions on merchant_users (fail closed on table DML),
    while gateway_auth retains authorized control-plane access.
    """
    # 1. app_user SELECT must raise InsufficientPrivilege
    with app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("SELECT * FROM merchant_users;")
        assert "permission denied for table merchant_users" in str(exc_info.value).lower()
    app_conn.rollback()

    # 2. app_user INSERT must raise InsufficientPrivilege
    with app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute(
                """
                INSERT INTO merchant_users (id, email, password_hash, status, created_at, updated_at)
                VALUES ('USER_ROGUE', 'rogue@attack.example', 'hash', 'ACTIVE', %s, %s);
                """,
                (time.time(), time.time())
            )
        assert "permission denied for table merchant_users" in str(exc_info.value).lower()
    app_conn.rollback()

    # 3. gateway_auth CAN read merchant_users
    with auth_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM merchant_users;")
        count = cur.fetchone()[0]
        assert count >= 2, f"gateway_auth should have read access to merchant_users, got count={count}"
    auth_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 9. Tenant runtime cannot insert or modify processed_webhook_events
# ══════════════════════════════════════════════════════════════════════════════

def test_tenant_runtime_cannot_insert_or_modify_processed_webhooks(app_conn, audit_conn):
    """
    Verifies that app_user has zero permissions on processed_webhook_events,
    while system_audit_writer retains authorized webhook idempotency access.
    """
    # 1. app_user SELECT must raise InsufficientPrivilege
    with app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("SELECT * FROM processed_webhook_events;")
        assert "permission denied for table processed_webhook_events" in str(exc_info.value).lower()
    app_conn.rollback()

    # 2. app_user INSERT must raise InsufficientPrivilege
    with app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("INSERT INTO processed_webhook_events (event_id, received_at) VALUES ('evt_hack', %s);", (time.time(),))
        assert "permission denied for table processed_webhook_events" in str(exc_info.value).lower()
    app_conn.rollback()

    # 3. system_audit_writer CAN insert and select processed_webhook_events
    with audit_conn.cursor() as cur:
        test_evt_id = f"evt_webhook_auth_test_{int(time.time())}"
        cur.execute("INSERT INTO processed_webhook_events (event_id, received_at) VALUES (%s, %s);", (test_evt_id, time.time()))
        cur.execute("SELECT event_id FROM processed_webhook_events WHERE event_id = %s;", (test_evt_id,))
        row = cur.fetchone()
        assert row is not None
        assert row[0] == test_evt_id
    audit_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 10. Existing merchant-isolation RLS passes on migrated database
# ══════════════════════════════════════════════════════════════════════════════

def test_existing_merchant_isolation_rls_passes_on_migrated_db(app_conn):
    """
    Verifies catalog_products, audit_records, and audit_events continue enforcing
    merchant isolation correctly under active RLS.
    """
    with app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_DISP_A';")

        # 1. Catalog Products: Merchant Alpha can see its own product, but NOT Merchant Beta's
        cur.execute("SELECT id, merchant_id FROM catalog_products;")
        products = cur.fetchall()
        assert len(products) == 1
        assert products[0][0] == "PROD_A1"
        assert products[0][1] == "MERCH_DISP_A"

        # 2. Catalog Products: Cross-merchant insert is blocked by WITH CHECK
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute(
                """
                INSERT INTO catalog_products (id, merchant_id, name, description, price, stock, category, created_at, updated_at)
                VALUES ('PROD_SNEAK', 'MERCH_DISP_B', 'Sneak Prod', 'Desc', 10.0, 5, 'electronics', %s, %s);
                """,
                (time.time(), time.time())
            )
        assert "row-level security policy" in str(exc_info.value).lower()
    app_conn.rollback()

    with app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_DISP_A';")
        # 3. Audit Records: Merchant Alpha sees only own records
        cur.execute("SELECT transaction_id, merchant_id FROM audit_records;")
        records = cur.fetchall()
        for r in records:
            assert r[1] == "MERCH_DISP_A"

        # 4. Audit Events: Merchant Alpha sees only own events
        cur.execute("SELECT event_id, merchant_id FROM audit_events;")
        events = cur.fetchall()
        for ev in events:
            assert ev[1] == "MERCH_DISP_A"
    app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 11. System audit writes remain restricted to system_audit_writer role
# ══════════════════════════════════════════════════════════════════════════════

def test_system_audit_writes_remain_restricted(app_conn, audit_conn, admin_conn):
    """
    Verifies that app_user is blocked from append_system_audit_event(),
    while system_audit_writer can append events, and the event strictly forces merchant_id IS NULL.
    """
    # 1. app_user execution must raise InsufficientPrivilege
    with app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute(
                """
                SELECT append_system_audit_event(
                    'ev_probe', 'tx_probe', 'POLICY_UPDATED', '1700000000', '{}', 'GENESIS', 'fake_hash'
                );
                """
            )
        assert "permission denied for function append_system_audit_event" in str(exc_info.value).lower()
    app_conn.rollback()

    # 2. system_audit_writer appends a valid system event with verified hash and advisory lock
    now_str = str(time.time())
    ev_id = f"ev_sys_test_{int(time.time())}"
    tx_id = f"tx_sys_test_{int(time.time())}"
    ev_type = "SYSTEM_CONFIG_UPDATED"
    payload = json.dumps({"config_key": "disposable_security_audit", "value": "enabled"}, sort_keys=True)

    with audit_conn.cursor() as cur:
        cur.execute("SELECT get_latest_audit_event_hash();")
        head_hash = cur.fetchone()[0]

        calc_hash = compute_event_hash(
            prev_hash=head_hash,
            event_id=ev_id,
            transaction_id=tx_id,
            event_type=ev_type,
            timestamp=now_str,
            payload_json=payload,
        )

        cur.execute(
            """
            SELECT append_system_audit_event(%s, %s, %s, %s, %s, %s, %s);
            """,
            (ev_id, tx_id, ev_type, now_str, payload, head_hash, calc_hash)
        )
    audit_conn.commit()

    # 3. Verify event was persisted with merchant_id IS NULL (system event, cannot be tenant-owned)
    with admin_conn.cursor() as cur:
        cur.execute(
            """
            SELECT event_id, event_type, merchant_id, prev_hash, event_hash
            FROM audit_events
            WHERE event_id = %s;
            """,
            (ev_id,)
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0] == ev_id
        assert row[1] == "SYSTEM_CONFIG_UPDATED"
        assert row[2] is None, f"System audit event must have merchant_id IS NULL, got '{row[2]}'"
        assert row[3] == head_hash
        assert row[4] == calc_hash


# ══════════════════════════════════════════════════════════════════════════════
# 12. Existing audit hashes and signed mandates remain verifiable
# ══════════════════════════════════════════════════════════════════════════════

def test_audit_hash_compatibility_and_signed_mandates_verifiable(admin_conn):
    """
    Verifies that:
    1. Seeded signed mandate for Buyer 1 is cryptographically verifiable via Ed25519 public key.
    2. Seeded audit events match exact hash calculation in both Python and PostgreSQL SHA-256.
    """
    with admin_conn.cursor() as cur:
        # 1. Cryptographic Mandate Signature Verification
        cur.execute(
            """
            SELECT m.mandate_id, m.canonical_payload, m.signature, m.domain_separator, k.public_key
            FROM signed_mandates m
            JOIN customer_signing_keys k ON m.customer_id = k.customer_id AND m.key_id = k.key_id
            WHERE m.mandate_id = 'MAND_DISP_1';
            """
        )
        mandate_row = cur.fetchone()
        assert mandate_row is not None, "Seeded signed mandate MAND_DISP_1 not found!"
        mand_id, canon_payload_str, sig_b64url, domain_sep, pub_key_b64url = mandate_row

        mandate_obj = json.loads(canon_payload_str)
        # Verify Ed25519 signature
        is_valid = verify_payload_signature(
            public_key_b64url=pub_key_b64url,
            signature_b64url=sig_b64url,
            domain_separator=domain_sep,
            payload=mandate_obj,
        )
        assert is_valid is True, "Ed25519 signature verification failed for signed mandate!"

        # 2. Audit Event Hash Integrity Verification
        cur.execute(
            """
            SELECT event_id, transaction_id, event_type, timestamp, payload_json, prev_hash, event_hash
            FROM audit_events
            ORDER BY id ASC;
            """
        )
        audit_rows = cur.fetchall()
        assert len(audit_rows) >= 1, "No audit events found in disposable database!"

        for r in audit_rows:
            ev_id, tx_id, ev_type, ts, payload_str, prev_h, stored_hash = r
            
            # Python recomputation
            py_hash = compute_event_hash(
                prev_hash=prev_h or "GENESIS",
                event_id=ev_id,
                transaction_id=tx_id,
                event_type=ev_type,
                timestamp=ts,
                payload_json=payload_str,
            )

            # PostgreSQL SHA-256 recomputation
            raw_str = f"{prev_h or 'GENESIS'}|{ev_id}|{tx_id}|{ev_type}|{ts}|{payload_str}"
            cur.execute("SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(%s, 'UTF8')), 'hex');", (raw_str,))
            pg_hash = cur.fetchone()[0]

            assert py_hash == pg_hash, f"Hash mismatch between Python ({py_hash}) and PostgreSQL ({pg_hash})"
            assert py_hash == stored_hash, f"Computed hash ({py_hash}) does not match stored hash ({stored_hash})"

    print("\n[OK] 100% cryptographic verifiability confirmed for Ed25519 mandates and SHA-256 audit ledger!")
