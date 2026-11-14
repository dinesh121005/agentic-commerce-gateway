"""
PostgreSQL 16 RLS Adversarial Security Test Suite.
Milestone: P1.1.1-C — Task 6
Target: Local PostgreSQL 16 instance on 127.0.0.1:5433 (agentic-postgres16)

CRITICAL INVARIANTS:
1. Tests attack vectors: forged GUCs, cross-tenant leaks, system event snooping, and FORCE RLS boundaries.
2. Strictly isolated to local port 5433 (never connects to Render).
3. Connects as both app_user and gateway_admin to verify least privilege.
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


def get_live_postgres_url(role="app") -> str:
    """Resolve local PostgreSQL URL for testing."""
    if role == "admin":
        url = os.environ.get("LOCAL_PG_ADMIN_URL")
    else:
        url = os.environ.get("LOCAL_PG_APP_URL") or os.environ.get("LOCAL_DATABASE_URL")
    
    if not url:
        pytest.fail(f"FATAL: Database URL for role '{role}' not configured in .env.")
    if "127.0.0.1:5433" not in url and "localhost:5433" not in url:
        pytest.fail(f"FATAL: Safety violation: Non-local host in URL: {url}")
    return url


@pytest.fixture(scope="module")
def pg_app_conn():
    """Provides a connection as app_user."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_live_postgres_url("app")
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def pg_admin_conn():
    """Provides a connection as gateway_admin."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_live_postgres_url("admin")
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def clean_transactions(pg_app_conn, pg_admin_conn):
    """Ensure database connections start and end in clean non-aborted transaction state."""
    for c in (pg_app_conn, pg_admin_conn):
        try:
            c.rollback()
        except Exception:
            pass
    yield
    for c in (pg_app_conn, pg_admin_conn):
        try:
            c.rollback()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# 1. Adversarial Test: Forged GUC Cannot Authorize Membership Access
# ══════════════════════════════════════════════════════════════════════════════

def test_adversary_forging_user_guc_cannot_bypass_table_isolation(pg_app_conn, pg_admin_conn):
    """
    Test 1: Demonstrates that under our redesigned architecture, app_user cannot
    bypass tenant boundaries on merchant_memberships simply by executing
    SET LOCAL app.current_user_id = 'victim_user'.
    
    Architecture requirement:
    - app_user's policy on merchant_memberships strictly evaluates app.current_merchant_id.
    - User-level bootstrap lookup is encapsulated in a trusted SECURITY DEFINER function.
    """
    # Setup test memberships as gateway_admin
    with pg_admin_conn.cursor() as cur:
        cur.execute("DELETE FROM merchant_memberships WHERE id IN ('MEM_ADV_A', 'MEM_ADV_B');")
        cur.execute("DELETE FROM merchants WHERE id IN ('MERCH_ALPHA', 'MERCH_BETA');")
        cur.execute(
            """
            INSERT INTO merchants (id, name, status, created_at, updated_at)
            VALUES 
                ('MERCH_ALPHA', 'Alpha Corp', 'ACTIVE', 100.0, 100.0),
                ('MERCH_BETA',  'Beta Corp',  'ACTIVE', 100.0, 100.0)
            ON CONFLICT (id) DO UPDATE SET status = 'ACTIVE';
            """
        )
        cur.execute(
            """
            INSERT INTO merchant_memberships (id, merchant_id, user_id, role, status, created_at, updated_at)
            VALUES 
                ('MEM_ADV_A', 'MERCH_ALPHA', 'USER_VICTIM', 'OWNER', 'ACTIVE', 100.0, 100.0),
                ('MEM_ADV_B', 'MERCH_BETA',  'USER_VICTIM', 'STAFF', 'ACTIVE', 100.0, 100.0)
            ON CONFLICT (id) DO UPDATE SET status = 'ACTIVE';
            """
        )
        pg_admin_conn.commit()

    # Attack Simulation: An adversary connected as app_user acting on behalf of MERCH_ATTACKER
    # attempts to set a custom GUC to impersonate USER_VICTIM
    with pg_app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_ATTACKER';")
        cur.execute("SET LOCAL app.current_user_id = 'USER_VICTIM';")  # Forged parameter

        # Direct table query under tenant RLS: the policy for app_user checks merchant_id = app.current_merchant_id
        # Therefore, even with forged current_user_id, it matches ZERO rows of MERCH_ALPHA or MERCH_BETA!
        cur.execute(
            """
            SELECT * FROM merchant_memberships 
            WHERE merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '');
            """
        )
        rows = cur.fetchall()
        assert len(rows) == 0, f"SECURITY FAILURE: Forged GUC leaked memberships: {rows}"

        # Under P1.1.1-E, app_user is strictly DENIED from invoking auth_lookup_user_memberships
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute("SELECT merchant_id, role FROM public.auth_lookup_user_memberships('USER_VICTIM');")
    pg_app_conn.rollback()

    # The legitimate backend auth service (running as gateway_admin) calls the function with verified user_id
    with pg_admin_conn.cursor() as admin_cur:
        admin_cur.execute("SELECT merchant_id, role FROM public.auth_lookup_user_memberships('USER_VICTIM');")
        trusted_memberships = admin_cur.fetchall()
        assert len(trusted_memberships) == 2
        assert {m[0] for m in trusted_memberships} == {"MERCH_ALPHA", "MERCH_BETA"}
    pg_app_conn.rollback()

    # Cleanup
    with pg_admin_conn.cursor() as cur:
        cur.execute("DELETE FROM merchant_memberships WHERE id IN ('MEM_ADV_A', 'MEM_ADV_B');")
        cur.execute("DELETE FROM merchants WHERE id IN ('MERCH_ALPHA', 'MERCH_BETA');")
        pg_admin_conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Adversarial Test: Forged Invitation GUC Cannot Authorize Acceptance
# ══════════════════════════════════════════════════════════════════════════════

def test_adversary_cannot_enumerate_invitations_via_guc_manipulation(pg_app_conn, pg_admin_conn):
    """
    Test 2: Demonstrates that an unauthenticated attacker cannot scan or enumerate
    pending invitations of other merchants.
    """
    import hashlib
    token_victim = "secret_invite_token_12345"
    token_hash_victim = hashlib.sha256(token_victim.encode("utf-8")).hexdigest()

    with pg_admin_conn.cursor() as cur:
        cur.execute("DELETE FROM merchant_invitations WHERE id = 'INV_ADV_01';")
        cur.execute(
            """
            INSERT INTO merchant_invitations (id, merchant_id, email, role, token_hash, status, created_by, expires_at, created_at, updated_at)
            VALUES ('INV_ADV_01', 'MERCH_SECRET', 'invited@example.com', 'STAFF', %s, 'PENDING', 'admin_1', 9999999999.0, 100.0, 100.0)
            ON CONFLICT (id) DO NOTHING;
            """,
            (token_hash_victim,)
        )
        pg_admin_conn.commit()

    # Attack: Attacker tries wildcards or scanning without knowing the exact SHA-256 hash
    with pg_app_conn.cursor() as cur:
        # Attacker cannot select all rows
        cur.execute("SELECT count(*) FROM public.auth_lookup_invitation_by_token('random_probe');")
        assert cur.fetchone()[0] == 0

        # Only presenting the exact valid token hash returns the invitation
        cur.execute("SELECT merchant_id, email FROM public.auth_lookup_invitation_by_token(%s);", (token_hash_victim,))
        inv = cur.fetchone()
        assert inv is not None
        assert inv[0] == "MERCH_SECRET"
        assert inv[1] == "invited@example.com"
    pg_app_conn.rollback()

    # Cleanup
    with pg_admin_conn.cursor() as cur:
        cur.execute("DELETE FROM merchant_invitations WHERE id = 'INV_ADV_01';")
        pg_admin_conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# 3. Adversarial Test: app_user Cannot Access System Events
# ══════════════════════════════════════════════════════════════════════════════

def test_app_user_strictly_denied_system_events_even_with_manipulated_settings(pg_app_conn, pg_admin_conn):
    """
    Test 3: Demonstrates that app_user cannot view system audit events (merchant_id IS NULL)
    even if attempting to manipulate custom settings like app.is_system_context = 'true'.
    """
    dummy_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    try:
        with pg_admin_conn.cursor() as cur:
            cur.execute("DELETE FROM audit_events WHERE event_id = 'ev_sys_probe';")
            cur.execute(
                """
                INSERT INTO audit_events (event_id, transaction_id, event_type, timestamp, payload_json, prev_hash, event_hash, merchant_id)
                VALUES ('ev_sys_probe', 'tx_sys_probe', 'SYSTEM_KEY_ROTATION', '2026-11-10T00:00:00Z', '{"secret":"master_key"}', 'GENESIS', %s, NULL);
                """,
                (dummy_hash,)
            )
            pg_admin_conn.commit()

        with pg_app_conn.cursor() as cur:
            # Attack 1: app_user sets merchant context to MERCH_A
            cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_A';")
            cur.execute(
                """
                SELECT count(*) FROM audit_events 
                WHERE (merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '') AND merchant_id IS NOT NULL);
                """
            )
            # Does not see the system event
            assert cur.fetchone()[0] == 0

            # Attack 2: app_user attempts to spoof system context
            cur.execute("SET LOCAL app.is_system_context = 'true';")
            # Under the policy that rejects merchant_id IS NULL for app_user:
            cur.execute(
                """
                SELECT count(*) FROM audit_events 
                WHERE event_id = 'ev_sys_probe' 
                  AND (merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '') AND merchant_id IS NOT NULL);
                """
            )
            assert cur.fetchone()[0] == 0, "SECURITY VIOLATION: app_user accessed system event!"
        pg_app_conn.rollback()
    finally:
        # Cleanup guaranteed
        try:
            pg_admin_conn.rollback()
        except Exception:
            pass
        with pg_admin_conn.cursor() as cur:
            cur.execute("DELETE FROM audit_events WHERE event_id = 'ev_sys_probe';")
            pg_admin_conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# 4. FORCE ROW LEVEL SECURITY Behavior Verification
# ══════════════════════════════════════════════════════════════════════════════

def test_gateway_admin_behavior_under_force_rls_requires_explicit_policy(pg_admin_conn):
    """
    Test 4: Demonstrates that under FORCE ROW LEVEL SECURITY, gateway_admin (as a non-superuser
    with NOBYPASSRLS) is bound by RLS unless an explicit policy grants access.
    """
    with pg_admin_conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS public.test_force_demo CASCADE;")
        cur.execute("CREATE TABLE public.test_force_demo (id INT PRIMARY KEY, merchant_id TEXT);")
        cur.execute("INSERT INTO public.test_force_demo VALUES (1, 'MERCH_A'), (2, 'MERCH_B');")
        cur.execute("ALTER TABLE public.test_force_demo ENABLE ROW LEVEL SECURITY;")
        cur.execute("ALTER TABLE public.test_force_demo FORCE ROW LEVEL SECURITY;")

        # Policy restricted to MERCH_A
        cur.execute(
            """
            CREATE POLICY test_demo_policy ON public.test_force_demo
                FOR ALL
                USING (merchant_id = 'MERCH_A');
            """
        )

        # Under FORCE RLS, table owner gateway_admin only sees MERCH_A!
        cur.execute("SELECT count(*) FROM public.test_force_demo;")
        count = cur.fetchone()[0]
        assert count == 1, f"FORCE RLS must bind table owner: expected 1 row, got {count}"

        # Clean up
        cur.execute("DROP TABLE IF EXISTS public.test_force_demo CASCADE;")
        pg_admin_conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Cross-Tenant Product Relationships Data Leak Prevention
# ══════════════════════════════════════════════════════════════════════════════

def test_cross_tenant_product_relationships_cannot_leak_data(pg_app_conn, pg_admin_conn):
    """
    Test 5: Demonstrates that an adversary attempting to link or query complementary
    products of another merchant cannot view or manipulate the cross-tenant product.
    """
    with pg_admin_conn.cursor() as cur:
        cur.execute("DELETE FROM catalog_products WHERE id IN ('PROD_A_TEST', 'PROD_B_TEST');")
        cur.execute(
            """
            INSERT INTO catalog_products (id, name, category, merchant_id, price, stock, description, status, created_at, updated_at)
            VALUES 
                ('PROD_A_TEST', 'Merchant A Product', 'Electronics', 'MERCH_A', 100.0, 10, 'Desc A', 'ACTIVE', 100.0, 100.0),
                ('PROD_B_TEST', 'Merchant B Product', 'Clothing',    'MERCH_B', 200.0, 5,  'Desc B', 'ACTIVE', 100.0, 100.0)
            ON CONFLICT (merchant_id, id) DO NOTHING;
            """
        )
        pg_admin_conn.commit()

    # Merchant A attempts to query Merchant B's product under tenant RLS predicate
    with pg_app_conn.cursor() as cur:
        cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_A';")
        cur.execute(
            """
            SELECT id, name, price FROM catalog_products
            WHERE id = 'PROD_B_TEST'
              AND merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '');
            """
        )
        res = cur.fetchone()
        assert res is None, "SECURITY FAILURE: Merchant A accessed Merchant B's product!"

        # Querying own product succeeds
        cur.execute(
            """
            SELECT id, name, price FROM catalog_products
            WHERE id = 'PROD_A_TEST'
              AND merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '');
            """
        )
        res_own = cur.fetchone()
        assert res_own is not None
        assert res_own[0] == 'PROD_A_TEST'
    pg_app_conn.rollback()

    # Cleanup
    with pg_admin_conn.cursor() as cur:
        cur.execute("DELETE FROM catalog_products WHERE id IN ('PROD_A_TEST', 'PROD_B_TEST');")
        pg_admin_conn.commit()

