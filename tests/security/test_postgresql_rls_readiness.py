"""
PostgreSQL 16 Row-Level Security (RLS) Integration Readiness Test Suite.
Milestone: P1.1.1-B — Gate A5 / Task 7
Target: Local PostgreSQL 16 instance on 127.0.0.1:5433 (agentic-postgres16)

CRITICAL INVARIANTS:
1. Strictly isolated to local port 5433 (NEVER connects to Render production).
2. Connects using application runtime identity 'app_user'.
3. Does NOT execute 001_postgresql_rls_hardening.sql.
4. Validates transaction lifecycle, SET LOCAL scope, connection reuse, authentication bootstrap,
   audit ownership derivation, and system-event separation.
"""
import os
import uuid
import pytest
from dotenv import load_dotenv

load_dotenv(override=False)

try:
    import psycopg2
    from psycopg2 import sql
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False


def get_live_postgres_url() -> str:
    """Resolve and validate the local PostgreSQL live test URL."""
    url = os.environ.get("LOCAL_PG_APP_URL") or os.environ.get("LOCAL_DATABASE_URL")
    if not url:
        pytest.fail(
            "FATAL: LOCAL_PG_APP_URL or LOCAL_DATABASE_URL is not set in environment or .env. "
            "PostgreSQL live tests MUST NOT fall back to SQLite."
        )
    if "127.0.0.1:5433" not in url and "localhost:5433" not in url:
        pytest.fail(
            f"FATAL: Safety violation! Attempted to connect to non-local database: {url}. "
            "Tests must strictly run against local Docker port 5433."
        )
    return url


@pytest.fixture(scope="module")
def pg_app_conn():
    """Provides a connection to local PostgreSQL as app_user."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required for live PostgreSQL tests.")
    url = get_live_postgres_url()
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Transaction Lifecycle & SET LOCAL Scope Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_missing_tenant_context_evaluates_to_null_and_fails_closed(pg_app_conn):
    """
    Test 1: When no tenant GUC is set, NULLIF(current_setting(..., true), '') evaluates to NULL.
    In SQL, 'merchant_id = NULL' evaluates to UNKNOWN (falsy), ensuring fail-closed behavior.
    """
    with pg_app_conn.cursor() as cur:
        # Transaction begins automatically in psycopg2 (autocommit=False)
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        val = cur.fetchone()[0]
        # In a fresh transaction, the custom parameter is None (NULL) or empty string
        assert val is None or val == "", f"Expected unset GUC to be None or empty, got: {val}"

        # Test the exact RLS policy predicate expression
        cur.execute("SELECT NULLIF(current_setting('app.current_merchant_id', true), '') IS NULL;")
        is_null = cur.fetchone()[0]
        assert is_null is True, "Missing tenant context MUST evaluate to NULL"

        # Verify that predicate 'merchant_id = NULLIF(...)' evaluates to UNKNOWN (never matches rows)
        cur.execute("SELECT 'MERCH_ELEC' = NULLIF(current_setting('app.current_merchant_id', true), '');")
        matches = cur.fetchone()[0]
        assert matches is None, "Equality against NULL must evaluate to NULL (falsy in RLS)"
    pg_app_conn.rollback()


def test_rollback_cleans_up_set_local_tenant_context(pg_app_conn):
    """
    Test 2: SET LOCAL app.current_merchant_id is strictly wiped when the transaction rolls back.
    """
    with pg_app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_TEST_ROLLBACK';")
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        assert cur.fetchone()[0] == "MERCH_TEST_ROLLBACK"

    # Roll back transaction
    pg_app_conn.rollback()

    # Next transaction must have zero residual context
    with pg_app_conn.cursor() as cur:
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        val = cur.fetchone()[0]
        assert val is None or val == "", f"Leaked tenant context after ROLLBACK: {val}"
    pg_app_conn.rollback()


def test_commit_cleans_up_set_local_tenant_context(pg_app_conn):
    """
    Test 3: SET LOCAL app.current_merchant_id is strictly wiped when the transaction commits.
    """
    with pg_app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_TEST_COMMIT';")
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        assert cur.fetchone()[0] == "MERCH_TEST_COMMIT"

    # Commit transaction
    pg_app_conn.commit()

    # Next transaction on the same connection must have zero residual context
    with pg_app_conn.cursor() as cur:
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        val = cur.fetchone()[0]
        assert val is None or val == "", f"Leaked tenant context after COMMIT: {val}"
    pg_app_conn.rollback()


def test_connection_reuse_and_tenant_switching_isolation(pg_app_conn):
    """
    Test 4: Simulates connection pooling checkout/checkin.
    Transaction 1 sets Tenant A -> commits.
    Transaction 2 on the SAME physical connection sets Tenant B -> verifies no Tenant A leakage.
    """
    backend_pid_1 = pg_app_conn.get_backend_pid()

    # Step 1: Request 1 checkout on pooled connection
    with pg_app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_TENANT_A';")
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        assert cur.fetchone()[0] == 'MERCH_TENANT_A'
    pg_app_conn.commit()

    # Step 2: Connection returned to pool and checked out for Request 2
    backend_pid_2 = pg_app_conn.get_backend_pid()
    assert backend_pid_1 == backend_pid_2, "Must be the exact same physical PostgreSQL process"

    # Verify connection was sanitized upon transaction boundary
    with pg_app_conn.cursor() as cur:
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        val = cur.fetchone()[0]
        assert val is None or val == "", f"Tenant A context leaked into pool: {val}"

        # Request 2 sets Tenant B
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_TENANT_B';")
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        assert cur.fetchone()[0] == 'MERCH_TENANT_B'
    pg_app_conn.commit()

    # Final verify
    with pg_app_conn.cursor() as cur:
        cur.execute("SELECT current_setting('app.current_merchant_id', true);")
        assert cur.fetchone()[0] in (None, "")
    pg_app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Authentication Bootstrap & Membership Lookup Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_authentication_bootstrap_queries_execute_safely(pg_app_conn):
    """
    Test 5: Verifies that queries required during merchant login, membership lookup,
    and merchant switching execute cleanly within their authorized trust boundary.
    - app_user is denied direct access to merchant_users (P1.1.1-G control plane hardening).
    - gateway_auth performs employee credential lookup safely.
    - Membership query uses SET LOCAL app.current_user_id.
    """
    # 1. Login query: app_user is denied direct access to merchant_users (P1.1.1-G)
    with pg_app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute(
                """
                SELECT id, email, password_hash, status, token_version
                FROM merchant_users
                WHERE email = %s;
                """,
                ("demo_owner@example.com",)
            )
    pg_app_conn.rollback()

    # 2. Login query via authorized gateway_auth role
    auth_url = os.environ.get("LOCAL_PG_AUTH_URL")
    if auth_url:
        with psycopg2.connect(auth_url) as auth_conn:
            with auth_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, email, password_hash, status, token_version
                    FROM merchant_users
                    WHERE email = %s;
                    """,
                    ("demo_owner@example.com",)
                )
                user_row = cur.fetchone()

    # 3. Bootstrap membership query: user lists their memberships before selecting an org
    with pg_app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_user_id = 'USER_BOOTSTRAP_TEST';")
        cur.execute(
            """
            SELECT id, merchant_id, role, status
            FROM merchant_memberships
            WHERE user_id = %s;
            """,
            ("USER_BOOTSTRAP_TEST",)
        )
        memberships = cur.fetchall()
        assert isinstance(memberships, list)
    pg_app_conn.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Audit Event Architecture, Ownership & Cryptographic Integrity Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_conflicting_payload_merchant_id_is_overridden_by_tenant_context():
    """
    Test 6: When an authoritative TenantContext is active, callers CANNOT inject
    a different merchant_id into payload_dict to spoof ownership.
    """
    from app.core.context import TenantContext, set_current_tenant_context
    from app.audit.store import AuditStore

    pg_url = get_live_postgres_url()
    store = AuditStore(db_path=pg_url)

    # Establish authentic TenantContext for MERCH_AUTHENTIC
    ctx = TenantContext(
        user_id="USER_LEGIT",
        merchant_id="MERCH_AUTHENTIC",
        membership_id="MEM_001",
        role="STAFF",
        permissions={"catalog:read"},
    )
    token = set_current_tenant_context(ctx)

    try:
        tx_id = f"TX_CONFLICT_{uuid.uuid4().hex[:8]}"
        # Adversary attempts to pass payload with 'MERCH_SPOOFED'
        ev_hash, _ = store.append_event(
            transaction_id=tx_id,
            event_type="PROPOSAL_EVALUATED",
            payload_dict={"merchant_id": "MERCH_SPOOFED", "amount": 50.0, "decision": "APPROVED"}
        )

        # Inspect database: ownership column MUST be MERCH_AUTHENTIC, not MERCH_SPOOFED
        conn = psycopg2.connect(pg_url)
        with conn.cursor() as cur:
            cur.execute("SELECT merchant_id FROM audit_events WHERE transaction_id = %s;", (tx_id,))
            saved_merchant = cur.fetchone()[0]
            assert saved_merchant == "MERCH_AUTHENTIC", (
                f"SECURITY VIOLATION: Expected 'MERCH_AUTHENTIC', found injected '{saved_merchant}'"
            )
        conn.close()
    finally:
        set_current_tenant_context(None)


def test_audit_ownership_resolution_fallback_to_audit_records():
    """
    Test 7: During async callbacks or compensations where TenantContext is not active,
    ownership is derived from the verified audit_records transaction.
    """
    from app.core.context import set_current_tenant_context
    from app.audit.store import AuditStore

    pg_url = get_live_postgres_url()
    store = AuditStore(db_path=pg_url)

    # Ensure no TenantContext
    set_current_tenant_context(None)

    tx_id = f"TX_ASYNC_{uuid.uuid4().hex[:8]}"

    # Step 1: Write proposal (establishes audit_records with merchant_id = 'MERCH_ELEC')
    store.write_proposal(
        transaction_id=tx_id,
        customer_id="CUST001",
        product_id="PROD_HEADPHONES",
        merchant_id="MERCH_ELEC",
        quantity=1,
        amount=1499.0,
        decision="APPROVED",
        decision_reason="Policy passed",
    )

    # Step 2: Async webhook arrives (e.g. PAYMENT_CAPTURED) without TenantContext or merchant_id in payload
    # update_payment_outcome calls _append_event internally and reconciles audit_records.record_hash
    store.update_payment_outcome(
        transaction_id=tx_id,
        payment_status="captured",
        razorpay_payment_id="pay_test_123",
    )

    # Step 3: Verify the payment event was automatically bound to 'MERCH_ELEC' via audit_records
    conn = psycopg2.connect(pg_url)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT merchant_id FROM audit_events WHERE transaction_id = %s AND event_type = 'PAYMENT_CAPTURED';",
            (tx_id,)
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "MERCH_ELEC", f"Expected ownership inherited from audit_records: got {row[0]}"
    conn.close()


def test_system_event_merchant_id_is_strictly_null():
    """
    Test 8: System-level events (e.g. key registration, customer auth tokens)
    without merchant association are recorded with merchant_id = NULL.
    """
    from app.core.context import set_current_tenant_context
    from app.audit.store import AuditStore

    set_current_tenant_context(None)
    pg_url = get_live_postgres_url()
    store = AuditStore(db_path=pg_url)

    tx_id = f"TX_SYSTEM_KEY_{uuid.uuid4().hex[:8]}"
    ev_hash, _ = store.append_event(
        transaction_id=tx_id,
        event_type="KEY_REGISTERED",
        payload_dict={"customer_id": "CUST_SYS_TEST", "key_id": "KEY_PUB_01"}
    )

    conn = psycopg2.connect(pg_url)
    with conn.cursor() as cur:
        cur.execute("SELECT merchant_id FROM audit_events WHERE transaction_id = %s;", (tx_id,))
        saved_merchant = cur.fetchone()[0]
        assert saved_merchant is None, f"System event must have merchant_id = NULL, got '{saved_merchant}'"
    conn.close()


def test_global_audit_chain_integrity_remains_unbroken():
    """
    Test 9: Verifies that consecutive events (across different merchants and system events)
    maintain an unbroken, mathematically continuous SHA-256 hash chain verified by verify_integrity().
    """
    from app.audit.store import AuditStore
    pg_url = get_live_postgres_url()
    store = AuditStore(db_path=pg_url)

    # Run integrity verification across the entire PostgreSQL ledger
    res = store.verify_integrity()
    assert res["valid"] is True, f"Cryptographic audit chain broken: {res}"
    assert res["status"] == "VERIFIED_IMMUTABLE"
    assert res["total_records"] > 0
    assert len(res["chain_head"]) == 64  # Valid SHA-256 hex string


# ══════════════════════════════════════════════════════════════════════════════
# 4. System-Event Access Boundary Test
# ══════════════════════════════════════════════════════════════════════════════

def test_merchant_context_predicate_blocks_system_events(pg_app_conn):
    """
    Test 10: Validates that under the proposed RLS policy:
      USING (merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '') AND merchant_id IS NOT NULL)
    a query executed with an active merchant context CANNOT match system events (merchant_id IS NULL).
    """
    with pg_app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_ELEC';")

        # Test predicate against a system-level event row where merchant_id IS NULL:
        # (merchant_id = 'MERCH_ELEC' AND merchant_id IS NOT NULL)
        cur.execute(
            """
            SELECT (
                (merchant_id = NULLIF(current_setting('app.current_merchant_id', true), ''))
                AND merchant_id IS NOT NULL
            ) AS is_visible
            FROM (SELECT NULL::text AS merchant_id) AS system_event;
            """
        )
        is_visible = cur.fetchone()[0]
        assert is_visible is False or is_visible is None, (
            "SECURITY FAILURE: System event (merchant_id IS NULL) must NEVER be visible under merchant context!"
        )
    pg_app_conn.rollback()
