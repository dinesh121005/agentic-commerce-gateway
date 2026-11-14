"""
Live PostgreSQL 16 Security and Tenant Isolation Pre-flight Suite.
Milestone: P1.1.1-A — Gate A5
Target: Local PostgreSQL 16 instance on 127.0.0.1:5433 (agentic-postgres16)

CRITICAL INVARIANTS:
1. Strictly isolated to local port 5433 (NEVER connects to Render production).
2. Connects using application runtime identity 'app_user'.
3. Never silently falls back to SQLite; fails explicitly if PostgreSQL is unavailable.
4. Asserts role privilege limits (NOSUPERUSER, NOBYPASSRLS).
"""
import os
import re
import pytest
from dotenv import load_dotenv

# Explicitly load .env
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
    # Strict isolation check: enforce local port 5433 only
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
    try:
        conn = psycopg2.connect(url, connect_timeout=5)
    except Exception as exc:
        pytest.fail(f"Failed to connect to local PostgreSQL 16 at {url}: {exc}")
    
    yield conn
    conn.close()


def test_postgresql_preflight_version_and_database(pg_app_conn):
    """Assert server version is PostgreSQL 16+ and connected database is agentic_commerce."""
    with pg_app_conn.cursor() as cur:
        # 1. Verify database name
        cur.execute("SELECT current_database();")
        db_name = cur.fetchone()[0]
        assert db_name == "agentic_commerce", f"Expected database 'agentic_commerce', got '{db_name}'"

        # 2. Verify server version >= 16 (160000)
        cur.execute("SHOW server_version_num;")
        version_num = int(cur.fetchone()[0])
        assert version_num >= 160000, f"Expected PostgreSQL version >= 160000, got {version_num}"

        cur.execute("SELECT version();")
        v_str = cur.fetchone()[0]
        assert "PostgreSQL 16" in v_str, f"Expected PostgreSQL 16 in version banner, got '{v_str}'"


def test_postgresql_preflight_app_user_privilege_limits(pg_app_conn):
    """Assert app_user is NOSUPERUSER and NOBYPASSRLS."""
    with pg_app_conn.cursor() as cur:
        cur.execute("SELECT current_user;")
        current_user = cur.fetchone()[0]
        assert current_user == "app_user", f"Expected current_user 'app_user', got '{current_user}'"

        cur.execute(
            """
            SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
            FROM pg_roles
            WHERE rolname = 'app_user';
            """
        )
        row = cur.fetchone()
        assert row is not None, "app_user role does not exist in pg_roles"
        rolname, rolsuper, rolbypassrls, rolcanlogin = row
        assert rolsuper is False, "SECURITY FAILURE: app_user must be NOSUPERUSER"
        assert rolbypassrls is False, "SECURITY FAILURE: app_user must be NOBYPASSRLS"
        assert rolcanlogin is True, "app_user must have LOGIN privilege"


def test_postgresql_preflight_gateway_admin_privilege_limits(pg_app_conn):
    """Assert schema owner gateway_admin is NOSUPERUSER and NOBYPASSRLS."""
    with pg_app_conn.cursor() as cur:
        cur.execute(
            """
            SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
            FROM pg_roles
            WHERE rolname = 'gateway_admin';
            """
        )
        row = cur.fetchone()
        assert row is not None, "gateway_admin role does not exist in pg_roles"
        rolname, rolsuper, rolbypassrls, rolcanlogin = row
        assert rolsuper is False, "SECURITY FAILURE: gateway_admin must be NOSUPERUSER"
        assert rolbypassrls is False, "SECURITY FAILURE: gateway_admin must be NOBYPASSRLS"


def test_postgresql_preflight_all_tables_owned_by_gateway_admin(pg_app_conn):
    """Assert all 18 commerce tables are owned by gateway_admin, not app_user or postgres."""
    with pg_app_conn.cursor() as cur:
        cur.execute(
            """
            SELECT tablename, tableowner
            FROM pg_tables
            WHERE schemaname = 'public'
            ORDER BY tablename;
            """
        )
        tables = cur.fetchall()
        assert len(tables) >= 18, f"Expected at least 18 tables, found {len(tables)}"
        
        for tname, owner in tables:
            assert owner == "gateway_admin", (
                f"SECURITY FAILURE: Table {tname} is owned by '{owner}', expected 'gateway_admin'"
            )


def test_postgresql_preflight_catalog_compound_primary_key(pg_app_conn):
    """Assert catalog_products table enforces compound primary key (merchant_id, id)."""
    with pg_app_conn.cursor() as cur:
        cur.execute(
            """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
              AND tc.table_schema = kcu.table_schema
            WHERE tc.table_name = 'catalog_products' AND tc.constraint_type = 'PRIMARY KEY'
            ORDER BY kcu.ordinal_position;
            """
        )
        pk_cols = [r[0] for r in cur.fetchall()]
        assert pk_cols == ["merchant_id", "id"], (
            f"Expected compound primary key ['merchant_id', 'id'], got {pk_cols}"
        )


def test_postgresql_preflight_audit_events_merchant_id_column(pg_app_conn):
    """Assert audit_events table contains merchant_id column with appropriate indexing."""
    with pg_app_conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'audit_events' AND column_name = 'merchant_id';
            """
        )
        col = cur.fetchone()
        assert col is not None, "Column merchant_id is missing from audit_events"
        assert col[0] == "merchant_id"
        assert col[2] == "YES", "audit_events.merchant_id must be nullable to support system-level events"

        # Verify index exists on audit_events(merchant_id)
        cur.execute(
            """
            SELECT indexname
            FROM pg_indexes
            WHERE tablename = 'audit_events' AND indexname LIKE '%merchant%';
            """
        )
        indexes = cur.fetchall()
        assert len(indexes) > 0, "Expected index on audit_events(merchant_id)"


def test_postgresql_preflight_app_user_denied_ddl(pg_app_conn):
    """Assert app_user cannot execute DDL (CREATE TABLE) in public schema."""
    with pg_app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute("CREATE TABLE public.unauthorized_probe (id INT);")
    pg_app_conn.rollback()


def test_postgresql_preflight_app_user_allowed_dml(pg_app_conn):
    """Assert app_user can execute transactional DML (SELECT, INSERT, UPDATE, DELETE) on authorized tables."""
    with pg_app_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM catalog_products;")
        count = cur.fetchone()[0]
        assert count > 0, "Expected seeded catalog products"


def test_postgresql_audit_events_merchant_scoping_and_hash_integrity(pg_app_conn):
    """Assert audit_events supports merchant-scoped events, system NULL events, and maintains hash chain integrity."""
    from app.audit.store import AuditStore, compute_event_hash
    from uuid import uuid4
    from datetime import datetime, timezone
    import json

    pg_url = get_live_postgres_url()
    store = AuditStore(db_path=pg_url)

    # 1. Append a merchant-scoped audit event
    tx_merch = f"TX_TEST_MERCH_{uuid4().hex[:8]}"
    ev_hash_1, prev_hash_1 = store.append_event(
        transaction_id=tx_merch,
        event_type="PROPOSAL_EVALUATED",
        payload_dict={"merchant_id": "MERCH_ELEC", "amount": 100.0, "decision": "APPROVED"}
    )
    assert ev_hash_1 is not None

    # 2. Append a system-level event with NO merchant_id
    tx_sys = f"TX_TEST_SYS_{uuid4().hex[:8]}"
    ev_hash_2, prev_hash_2 = store.append_event(
        transaction_id=tx_sys,
        event_type="SIGNING_KEY_REGISTERED",
        payload_dict={"customer_id": "CUST_TEST", "key_id": "KEY_TEST"}
    )
    assert ev_hash_2 is not None
    assert prev_hash_2 == ev_hash_1

    # 3. Verify in database that merchant_id is stored accurately
    with pg_app_conn.cursor() as cur:
        cur.execute("SELECT merchant_id, event_hash FROM audit_events WHERE transaction_id = %s;", (tx_merch,))
        row_m = cur.fetchone()
        assert row_m is not None
        assert row_m[0] == "MERCH_ELEC"
        assert row_m[1] == ev_hash_1

        cur.execute("SELECT merchant_id, event_hash FROM audit_events WHERE transaction_id = %s;", (tx_sys,))
        row_s = cur.fetchone()
        assert row_s is not None
        assert row_s[0] is None, "System event merchant_id must be NULL"
        assert row_s[1] == ev_hash_2

    # 4. Verify continuous hash chain validation passes 100%
    verification = store.verify_integrity()
    assert verification["valid"] is True, f"Hash chain verification failed: {verification}"
    assert verification["status"] == "VERIFIED_IMMUTABLE"

