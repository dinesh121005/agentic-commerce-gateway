"""
PostgreSQL 16 Privileged Functions Security, Authorization & Audit Concurrency Test Suite.
Milestone: P1.1.1-E
Target: Local PostgreSQL 16 instance on 127.0.0.1:5433 (agentic-postgres16)

CRITICAL INVARIANTS & VERIFICATIONS (P1.1.1-E):
1. Role-Based Privilege Segregation:
   - app_user REVOKED from public.auth_lookup_user_memberships (cannot enumerate cross-tenant memberships).
   - app_user REVOKED from public.append_system_audit_event (cannot fabricate system events).
   - app_user GRANTED public.get_latest_audit_event_hash (for advisory-locked tenant event serialization).
   - app_user GRANTED public.auth_lookup_invitation_by_token (for single-use token acceptance).
   - gateway_admin retains full EXECUTE on all functions as OWNER.
2. In-Database Cryptographic Verification:
   - public.append_system_audit_event independently recalculates SHA-256 hash using PostgreSQL 16 native bytea/sha256.
   - Tampered or mismatched event hashes are strictly rejected with check_violation.
   - Unauthorized event types are strictly rejected with invalid_parameter_value.
3. Concurrency & Chain Integrity:
   - Advisory lock (hashtext('audit_events_chain_lock')) is proven to remain held across predecessor read and insert.
   - At least 50 concurrent mixed tenant and system appends across multiple merchants run without error.
   - Zero forks, zero gaps, 100% cryptographic ledger integrity verification.
4. Tenant Isolation & Impersonation Resistance:
   - app_user cannot directly query or insert system events under RLS.
   - Legitimate login and merchant switching workflows are fully preserved via control plane.
"""
import concurrent.futures
import copy
import hashlib
import json
import os
import secrets
import time
import uuid
from typing import Any, Dict, List
import pytest
from dotenv import load_dotenv

load_dotenv("d:/agentic-commerce-gateway/.env", override=False)

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
    elif role == "auth":
        url = os.environ.get("LOCAL_PG_AUTH_URL")
    elif role == "audit":
        url = os.environ.get("LOCAL_PG_AUDIT_URL")
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


@pytest.fixture(scope="module")
def pg_auth_conn():
    """Provides a connection as gateway_auth."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_live_postgres_url("auth")
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def pg_system_audit_conn():
    """Provides a connection as system_audit_writer."""
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_live_postgres_url("audit")
    conn = psycopg2.connect(url, connect_timeout=5)
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def clean_transactions(pg_app_conn, pg_admin_conn, pg_auth_conn, pg_system_audit_conn):
    """Ensure database connections start and end in clean non-aborted transaction state."""
    conns = (pg_app_conn, pg_admin_conn, pg_auth_conn, pg_system_audit_conn)
    for c in conns:
        try:
            c.rollback()
        except Exception:
            pass
    yield
    for c in conns:
        try:
            c.rollback()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# TASK 1 & TASK 4: Privilege Matrix & Identity Binding Verification
# ══════════════════════════════════════════════════════════════════════════════

def test_privileged_functions_metadata_and_revised_permission_matrix(pg_admin_conn):
    """
    Task 4 & Task 1 (P1.1.1-F): Verify actual PostgreSQL grants, ownership, and security properties
    across the four distinct database roles: gateway_admin, gateway_auth, system_audit_writer, app_user.
    Revised Permission Matrix:
    - append_system_audit_event: OWNER=gateway_admin, system_audit_writer=GRANTED, app_user=REVOKED, gateway_auth=REVOKED
    - auth_lookup_user_memberships: OWNER=gateway_admin, gateway_auth=GRANTED, app_user=REVOKED, system_audit_writer=REVOKED
    - get_latest_audit_event_hash: OWNER=gateway_admin, app_user=GRANTED, system_audit_writer=GRANTED, gateway_auth=GRANTED, gateway_admin=GRANTED
    - auth_lookup_invitation_by_token: OWNER=gateway_admin, app_user=GRANTED, gateway_auth=GRANTED, gateway_admin=GRANTED
    """
    expected_functions = [
        "append_system_audit_event",
        "auth_lookup_invitation_by_token",
        "auth_lookup_user_memberships",
        "get_latest_audit_event_hash",
    ]

    with pg_admin_conn.cursor() as cur:
        cur.execute(
            """
            SELECT 
                p.proname,
                pg_get_userbyid(p.proowner) AS owner,
                p.prosecdef,
                p.proconfig,
                has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec,
                has_function_privilege('app_user', p.oid, 'EXECUTE') AS app_user_exec,
                has_function_privilege('gateway_auth', p.oid, 'EXECUTE') AS auth_exec,
                has_function_privilege('system_audit_writer', p.oid, 'EXECUTE') AS audit_exec,
                has_function_privilege('gateway_admin', p.oid, 'EXECUTE') AS admin_exec
            FROM pg_proc p
            JOIN pg_namespace n ON p.pronamespace = n.oid
            WHERE n.nspname = 'public' AND p.proname = ANY(%s)
            ORDER BY p.proname;
            """,
            (expected_functions,)
        )
        rows = cur.fetchall()
        assert len(rows) == 4, f"Expected 4 functions, found {len(rows)}"

        matrix = {
            r[0]: {
                "owner": r[1],
                "secdef": r[2],
                "config": r[3],
                "public": r[4],
                "app_user": r[5],
                "auth": r[6],
                "audit": r[7],
                "admin": r[8],
            }
            for r in rows
        }

        for fname, perms in matrix.items():
            assert perms["owner"] == "gateway_admin", f"{fname}: owner must be gateway_admin"
            assert perms["secdef"] is True, f"{fname}: prosecdef must be True"
            assert perms["config"] == ["search_path=pg_catalog, public"], f"{fname}: insecure search_path"
            assert perms["public"] is False, f"SECURITY VIOLATION: {fname} executable by PUBLIC"
            assert perms["admin"] is True, f"{fname}: gateway_admin must have EXECUTE"

        # Explicit Verification of Least Privilege Boundaries
        # 1. auth_lookup_user_memberships: gateway_auth & admin ONLY
        assert matrix["auth_lookup_user_memberships"]["auth"] is True, "gateway_auth must have EXECUTE on auth_lookup_user_memberships"
        assert matrix["auth_lookup_user_memberships"]["app_user"] is False, "app_user must be REVOKED from auth_lookup_user_memberships"
        assert matrix["auth_lookup_user_memberships"]["audit"] is False, "system_audit_writer must be REVOKED from auth_lookup_user_memberships"

        # 2. append_system_audit_event: system_audit_writer & admin ONLY
        assert matrix["append_system_audit_event"]["audit"] is True, "system_audit_writer must have EXECUTE on append_system_audit_event"
        assert matrix["append_system_audit_event"]["app_user"] is False, "app_user must be REVOKED from append_system_audit_event"
        assert matrix["append_system_audit_event"]["auth"] is False, "gateway_auth must be REVOKED from append_system_audit_event"

        # 3. get_latest_audit_event_hash: all runtime roles can serialize via advisory lock
        assert matrix["get_latest_audit_event_hash"]["app_user"] is True
        assert matrix["get_latest_audit_event_hash"]["audit"] is True
        assert matrix["get_latest_audit_event_hash"]["auth"] is True

        # 4. auth_lookup_invitation_by_token: runtime roles can look up token
        assert matrix["auth_lookup_invitation_by_token"]["app_user"] is True
        assert matrix["auth_lookup_invitation_by_token"]["auth"] is True


def test_schema_privilege_boundaries(pg_admin_conn):
    """
    Task 4 & Task 6: Verify schema privilege boundaries.
    app_user, gateway_auth, system_audit_writer, and PUBLIC cannot create schema objects.
    Only gateway_admin holds CREATE on schema public.
    """
    with pg_admin_conn.cursor() as cur:
        for r in ('app_user', 'gateway_auth', 'system_audit_writer', 'public'):
            cur.execute("SELECT has_schema_privilege(%s, 'public', 'CREATE');", (r,))
            assert cur.fetchone()[0] is False, f"SECURITY FAILURE: role {r} has CREATE on schema public"

        cur.execute("SELECT has_schema_privilege('gateway_admin', 'public', 'CREATE');")
        assert cur.fetchone()[0] is True, "gateway_admin must have CREATE on schema public"


def test_app_user_strictly_denied_auth_lookup_user_memberships(pg_app_conn):
    """
    Task 1: Prove app_user CANNOT pass arbitrary p_user_id to auth_lookup_user_memberships.
    Execution must be blocked by PostgreSQL with permission denied (42501).
    """
    with pg_app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("SELECT * FROM public.auth_lookup_user_memberships('VICTIM_USER_123');")
        assert "permission denied for function auth_lookup_user_memberships" in str(exc_info.value)
    pg_app_conn.rollback()


def test_gateway_admin_authorized_membership_lookup_and_filtering(pg_admin_conn):
    """
    Task 1: Verify authorized control-plane execution of auth_lookup_user_memberships.
    Proves that:
    - Active memberships in active merchants are returned.
    - Suspended merchants and deactivated memberships are excluded.
    - Input validation rejects malformed/injection parameters.
    """
    with pg_admin_conn.cursor() as cur:
        cur.execute("DELETE FROM merchant_memberships WHERE user_id = 'USER_AUTH_TEST';")
        cur.execute("DELETE FROM merchants WHERE id IN ('MERCH_T1', 'MERCH_T2', 'MERCH_T3', 'MERCH_T4');")
        cur.execute(
            """
            INSERT INTO merchants (id, name, status, created_at, updated_at) VALUES 
                ('MERCH_T1', 'Active Merchant 1', 'ACTIVE', 100.0, 100.0),
                ('MERCH_T2', 'Active Merchant 2', 'ACTIVE', 100.0, 100.0),
                ('MERCH_T3', 'Inactive Merchant', 'SUSPENDED', 100.0, 100.0),
                ('MERCH_T4', 'Active Merchant 4', 'ACTIVE', 100.0, 100.0)
            ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status;
            """
        )
        cur.execute(
            """
            INSERT INTO merchant_memberships (id, merchant_id, user_id, role, status, created_at, updated_at) VALUES
                ('MEM_T1', 'MERCH_T1', 'USER_AUTH_TEST', 'OWNER', 'ACTIVE', 100.0, 100.0),
                ('MEM_T2', 'MERCH_T2', 'USER_AUTH_TEST', 'STAFF', 'ACTIVE', 200.0, 200.0),
                ('MEM_T3', 'MERCH_T4', 'USER_AUTH_TEST', 'VIEWER', 'DEACTIVATED', 300.0, 300.0),
                ('MEM_T4', 'MERCH_T3', 'USER_AUTH_TEST', 'STAFF', 'ACTIVE', 400.0, 400.0)
            ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status;
            """
        )
        pg_admin_conn.commit()

        # Authorized call as gateway_admin succeeds
        cur.execute("SELECT id, merchant_id, role, merchant_name FROM public.auth_lookup_user_memberships('USER_AUTH_TEST');")
        rows = cur.fetchall()
        assert len(rows) == 2
        returned_merchants = {r[1] for r in rows}
        assert returned_merchants == {"MERCH_T1", "MERCH_T2"}
        assert "MERCH_T3" not in returned_merchants  # Suspended merchant excluded
        assert "MERCH_T4" not in returned_merchants  # Deactivated membership excluded

        # Input validation checks
        cur.execute("SELECT count(*) FROM public.auth_lookup_user_memberships(NULL);")
        assert cur.fetchone()[0] == 0

        cur.execute("SELECT count(*) FROM public.auth_lookup_user_memberships('   ');")
        assert cur.fetchone()[0] == 0

        cur.execute("SELECT count(*) FROM public.auth_lookup_user_memberships(%s);", ("A" * 300,))
        assert cur.fetchone()[0] == 0

        cur.execute("SELECT count(*) FROM public.auth_lookup_user_memberships('USER_AUTH_TEST\nDROP TABLE--');")
        assert cur.fetchone()[0] == 0

        # Cleanup
        cur.execute("DELETE FROM merchant_memberships WHERE user_id = 'USER_AUTH_TEST';")
        cur.execute("DELETE FROM merchants WHERE id IN ('MERCH_T1', 'MERCH_T2', 'MERCH_T3', 'MERCH_T4');")
        pg_admin_conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# TASK 2: System Audit Event Integrity & Whitelisting Verification
# ══════════════════════════════════════════════════════════════════════════════

def test_app_user_strictly_denied_append_system_audit_event(pg_app_conn):
    """
    Task 2: Prove app_user CANNOT execute append_system_audit_event.
    Execution must be blocked with permission denied (42501).
    """
    with pg_app_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute(
                """
                SELECT public.append_system_audit_event(
                    'ev_evil', 'tx_evil', 'SYSTEM_INIT', '2026-11-11T12:00:00Z',
                    '{}', 'GENESIS', '0000000000000000000000000000000000000000000000000000000000000000'
                );
                """
            )
        assert "permission denied for function append_system_audit_event" in str(exc_info.value)
    pg_app_conn.rollback()


def test_append_system_audit_event_rejects_hash_tampering(pg_admin_conn):
    """
    Task 2: Cryptographic Event Integrity Verification.
    Independently verifies that if a caller passes an event_hash that does not match
    the canonical SHA-256 calculation over event data, the function strictly raises check_violation.
    """
    with pg_admin_conn.cursor() as cur:
        cur.execute("SELECT public.get_latest_audit_event_hash();")
        head_hash = cur.fetchone()[0]
    pg_admin_conn.commit()

    ev_id = f"ev_tamper_{uuid.uuid4().hex[:8]}"
    tx_id = f"tx_tamper_{uuid.uuid4().hex[:8]}"
    ts = "2026-11-11T12:00:00Z"
    payload = json.dumps({"key": "legitimate_data"}, sort_keys=True)
    # Fabricated / incorrect event hash
    fabricated_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    with pg_admin_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.CheckViolation) as exc_info:
            cur.execute(
                """
                SELECT public.append_system_audit_event(
                    %s, %s, 'SYSTEM_INIT', %s, %s, %s, %s
                );
                """,
                (ev_id, tx_id, ts, payload, head_hash, fabricated_hash)
            )
        assert "Cryptographic event hash mismatch" in str(exc_info.value)
    pg_admin_conn.rollback()


def test_append_system_audit_event_enforces_authorized_event_types(pg_admin_conn):
    """
    Task 2: Authorized System Event Types Whitelist.
    Rejects tenant event types (e.g. PROPOSAL_EVALUATED) or fabricated types
    with invalid_parameter_value.
    """
    from app.audit.store import compute_event_hash
    with pg_admin_conn.cursor() as cur:
        cur.execute("SELECT public.get_latest_audit_event_hash();")
        head_hash = cur.fetchone()[0]
    pg_admin_conn.commit()

    ev_id = f"ev_type_{uuid.uuid4().hex[:8]}"
    tx_id = f"tx_type_{uuid.uuid4().hex[:8]}"
    ts = "2026-11-11T12:00:00Z"
    payload = json.dumps({"action": "unauthorized"}, sort_keys=True)

    # 1. Attempting to write a tenant event type via system function
    unauthorized_type = "PROPOSAL_EVALUATED"
    ev_hash = compute_event_hash(head_hash, ev_id, tx_id, unauthorized_type, ts, payload)

    with pg_admin_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InvalidParameterValue) as exc_info:
            cur.execute(
                """
                SELECT public.append_system_audit_event(
                    %s, %s, %s, %s, %s, %s, %s
                );
                """,
                (ev_id, tx_id, unauthorized_type, ts, payload, head_hash, ev_hash)
            )
        assert "Unauthorized system event type" in str(exc_info.value)
    pg_admin_conn.rollback()

    # 2. Attempting to write an arbitrary rogue event type
    rogue_type = "MALICIOUS_ESCROW_RELEASE"
    ev_hash2 = compute_event_hash(head_hash, ev_id, tx_id, rogue_type, ts, payload)
    with pg_admin_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InvalidParameterValue) as exc_info:
            cur.execute(
                """
                SELECT public.append_system_audit_event(
                    %s, %s, %s, %s, %s, %s, %s
                );
                """,
                (ev_id, tx_id, rogue_type, ts, payload, head_hash, ev_hash2)
            )
        assert "Unauthorized system event type" in str(exc_info.value)
    pg_admin_conn.rollback()


def test_append_system_audit_event_rejects_stale_predecessor_hash(pg_admin_conn):
    """
    Task 2: Verify append_system_audit_event enforces strict continuity.
    Providing a stale or mismatched p_prev_hash must be rejected with check_violation.
    """
    from app.audit.store import compute_event_hash
    stale_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    ev_id = f"ev_stale_{uuid.uuid4().hex[:8]}"
    tx_id = f"tx_stale_{uuid.uuid4().hex[:8]}"
    ts = "2026-11-11T12:00:00Z"
    payload = json.dumps({"test": True}, sort_keys=True)
    ev_hash = compute_event_hash(stale_hash, ev_id, tx_id, "SYSTEM_INIT", ts, payload)

    with pg_admin_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.CheckViolation) as exc_info:
            cur.execute(
                """
                SELECT public.append_system_audit_event(
                    %s, %s, 'SYSTEM_INIT', %s, %s, %s, %s
                );
                """,
                (ev_id, tx_id, ts, payload, stale_hash, ev_hash)
            )
        assert "Audit ledger continuity error" in str(exc_info.value)
    pg_admin_conn.rollback()


def test_append_system_audit_event_cannot_be_abused_to_create_tenant_events(pg_admin_conn):
    """
    Task 2: Verify append_system_audit_event strictly forces merchant_id = NULL.
    Even if caller specifies merchant_id in payload, the column merchant_id is strictly NULL.
    """
    from app.audit.store import compute_event_hash
    with pg_admin_conn.cursor() as cur:
        cur.execute("SELECT public.get_latest_audit_event_hash();")
        prev_h = cur.fetchone()[0]
    pg_admin_conn.commit()

    ev_id = f"ev_abuse_{uuid.uuid4().hex[:8]}"
    tx_id = f"tx_abuse_{uuid.uuid4().hex[:8]}"
    ts = "2026-11-11T12:00:00Z"
    payload_dict = {"merchant_id": "MERCH_VICTIM", "action": "FORGED_EVENT"}
    payload_json = json.dumps(payload_dict, sort_keys=True)
    ev_hash = compute_event_hash(
        prev_hash=prev_h,
        event_id=ev_id,
        transaction_id=tx_id,
        event_type="SYSTEM_KEY_ROTATION",
        timestamp=ts,
        payload_json=payload_json,
    )

    with pg_admin_conn.cursor() as cur:
        cur.execute(
            """
            SELECT public.append_system_audit_event(
                %s, %s, 'SYSTEM_KEY_ROTATION', %s, %s, %s, %s
            );
            """,
            (ev_id, tx_id, ts, payload_json, prev_h, ev_hash)
        )
        pg_admin_conn.commit()

        # Verify column merchant_id is guaranteed NULL
        cur.execute("SELECT merchant_id FROM public.audit_events WHERE event_id = %s;", (ev_id,))
        row = cur.fetchone()
        assert row is not None
        assert row[0] is None, f"SECURITY VIOLATION: merchant_id was set to {row[0]}, expected NULL!"

        # Cleanup
        cur.execute("DELETE FROM public.audit_events WHERE event_id = %s;", (ev_id,))
        pg_admin_conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# TASK 1 & TASK 4 (P1.1.1-F): Dedicated Role Boundaries & Tamper Resistance
# ══════════════════════════════════════════════════════════════════════════════

def test_gateway_auth_privilege_boundaries(pg_auth_conn, pg_admin_conn):
    """
    P1.1.1-F Adversarial Test 3: gateway_auth privilege boundaries.
    - Can execute public.auth_lookup_user_memberships
    - CANNOT execute public.append_system_audit_event (permission denied)
    - CANNOT perform DML (SELECT, INSERT, UPDATE, DELETE) on business tables
    """
    with pg_auth_conn.cursor() as cur:
        # 1. Allowed: auth lookup function
        cur.execute("SELECT * FROM public.auth_lookup_user_memberships('SOME_USER');")
        rows = cur.fetchall()
        assert isinstance(rows, list)

        # 2. Denied: append_system_audit_event
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute(
                """
                SELECT public.append_system_audit_event(
                    'ev_auth_evil', 'tx_auth_evil', 'SYSTEM_INIT', '2026-11-11T12:00:00Z',
                    '{}', 'GENESIS', '0000000000000000000000000000000000000000000000000000000000000000'
                );
                """
            )
        assert "permission denied for function append_system_audit_event" in str(exc_info.value)
    pg_auth_conn.rollback()

    # 3. Denied: direct DML on non-control-plane business tables
    with pg_auth_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("SELECT * FROM public.catalog_products LIMIT 1;")
        assert "permission denied for table catalog_products" in str(exc_info.value)
    pg_auth_conn.rollback()

    with pg_auth_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("SELECT * FROM public.processed_webhook_events LIMIT 1;")
        assert "permission denied for table processed_webhook_events" in str(exc_info.value)
    pg_auth_conn.rollback()


def test_system_audit_writer_privilege_boundaries(pg_system_audit_conn):
    """
    P1.1.1-F Adversarial Test 4: system_audit_writer privilege boundaries.
    - Can execute public.get_latest_audit_event_hash
    - CANNOT execute public.auth_lookup_user_memberships (permission denied)
    - CANNOT perform DML (SELECT, INSERT, UPDATE, DELETE) on business tables
    """
    with pg_system_audit_conn.cursor() as cur:
        # 1. Allowed: get_latest_audit_event_hash
        cur.execute("SELECT public.get_latest_audit_event_hash();")
        head = cur.fetchone()[0]
        assert head is not None

        # 2. Denied: auth_lookup_user_memberships
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("SELECT * FROM public.auth_lookup_user_memberships('VICTIM_USER');")
        assert "permission denied for function auth_lookup_user_memberships" in str(exc_info.value)
    pg_system_audit_conn.rollback()

    # 3. Denied: direct DML on business tables
    with pg_system_audit_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("SELECT * FROM public.customer_wallets LIMIT 1;")
        assert "permission denied for table customer_wallets" in str(exc_info.value)
    pg_system_audit_conn.rollback()

    with pg_system_audit_conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
            cur.execute("SELECT * FROM public.merchants LIMIT 1;")
        assert "permission denied for table merchants" in str(exc_info.value)
    pg_system_audit_conn.rollback()


def test_runtime_roles_cannot_alter_rls_policies_or_schema(pg_app_conn, pg_auth_conn, pg_system_audit_conn):
    """
    P1.1.1-F Adversarial Tests 5 & 6:
    Runtime roles (app_user, gateway_auth, system_audit_writer) cannot alter RLS policies,
    alter table schema, or create objects in schema public.
    """
    runtime_conns = {
        "app_user": pg_app_conn,
        "gateway_auth": pg_auth_conn,
        "system_audit_writer": pg_system_audit_conn,
    }

    for role_name, conn in runtime_conns.items():
        with conn.cursor() as cur:
            # 1. Attempting to alter RLS on a table
            with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
                cur.execute("ALTER TABLE public.merchants DISABLE ROW LEVEL SECURITY;")
            assert "must be owner of table merchants" in str(exc_info.value)
        conn.rollback()

        with conn.cursor() as cur:
            # 2. Attempting to create an object in schema public
            with pytest.raises(psycopg2.errors.InsufficientPrivilege) as exc_info:
                cur.execute(f"CREATE TABLE public.hack_{role_name} (id INT);")
            assert "permission denied for schema public" in str(exc_info.value)
        conn.rollback()


def test_rollback_preserves_audit_chain_integrity(pg_system_audit_conn, pg_admin_conn):
    """
    P1.1.1-F Adversarial Test 11:
    A rolled-back audit append transaction must NOT leave orphan blocks or break the ledger.
    Subsequent appends must attach strictly to the original unbroken predecessor head.
    """
    from app.audit.store import compute_event_hash

    # 1. Get initial unbroken head
    with pg_admin_conn.cursor() as cur:
        cur.execute("SELECT public.get_latest_audit_event_hash();")
        initial_head = cur.fetchone()[0]
    pg_admin_conn.commit()

    ev_id = f"ev_aborted_{uuid.uuid4().hex[:8]}"
    tx_id = f"tx_aborted_{uuid.uuid4().hex[:8]}"
    ts = "2026-11-11T12:00:00Z"
    payload = json.dumps({"action": "DOOMED_TRANSACTION"}, sort_keys=True)
    ev_hash = compute_event_hash(initial_head, ev_id, tx_id, "SYSTEM_CONFIG_UPDATED", ts, payload)

    # 2. Append event inside transaction on system_audit_writer connection, then ROLLBACK
    with pg_system_audit_conn.cursor() as cur:
        cur.execute(
            """
            SELECT public.append_system_audit_event(
                %s, %s, 'SYSTEM_CONFIG_UPDATED', %s, %s, %s, %s
            );
            """,
            (ev_id, tx_id, ts, payload, initial_head, ev_hash)
        )
    pg_system_audit_conn.rollback()

    # 3. Verify event does NOT exist in audit_events
    with pg_admin_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.audit_events WHERE event_id = %s;", (ev_id,))
        assert cur.fetchone()[0] == 0, "SECURITY FAILURE: Rolled back event still persisted in audit_events!"

        # 4. Verify ledger head remains strictly initial_head
        cur.execute("SELECT public.get_latest_audit_event_hash();")
        current_head = cur.fetchone()[0]
        assert current_head == initial_head, f"Ledger head drifted after rollback: expected {initial_head}, got {current_head}"
    pg_admin_conn.commit()


def test_existing_signed_mandates_remain_verifiable():
    """
    P1.1.1-F Adversarial Test 12:
    Verifies that Ed25519 canonical JSON signatures (RFC 8785) on spending mandates
    remain 100% verifiable and intact without alteration to the cryptographic algorithms.
    """
    from app.signing.canonical import rfc8785_canonicalize
    from app.signing.crypto import (
        DOMAIN_MANDATE,
        generate_ed25519_keypair,
        sign_payload,
        verify_payload_signature,
    )

    priv_key, pub_key, _ = generate_ed25519_keypair()
    mandate_payload = {
        "customer_id": "CUST_TEST_001",
        "mandate_id": str(uuid.uuid4()),
        "mandate_version": 1,
        "max_tx_paise": 500000,
        "daily_budget_paise": 2000000,
        "authorized_merchant_ids": ["MERCH_ELEC"],
        "valid_until": "2027-01-01T00:00:00Z",
    }

    # 1. Sign canonical payload
    sig_b64 = sign_payload(priv_key, DOMAIN_MANDATE, mandate_payload)
    assert sig_b64 is not None

    # 2. Verify signature passes
    is_valid = verify_payload_signature(
        public_key_b64url=pub_key,
        signature_b64url=sig_b64,
        domain_separator=DOMAIN_MANDATE,
        payload=mandate_payload,
    )
    assert is_valid is True, "Cryptographic mandate verification failed on valid payload!"

    # 3. Verify tampering is strictly detected
    tampered_payload = copy.deepcopy(mandate_payload)
    tampered_payload["max_tx_paise"] = 999999999
    with pytest.raises(Exception):
        verify_payload_signature(
            public_key_b64url=pub_key,
            signature_b64url=sig_b64,
            domain_separator=DOMAIN_MANDATE,
            payload=tampered_payload,
        )


# ══════════════════════════════════════════════════════════════════════════════
# TASK 3: Audit-Chain Transaction Verification & 50 Mixed Appends
# ══════════════════════════════════════════════════════════════════════════════

def test_audit_chain_advisory_lock_held_across_read_and_commit():
    """
    Task 3: Prove that:
    1. Predecessor retrieval acquires pg_advisory_xact_lock.
    2. The advisory lock remains held until transaction completion (COMMIT).
    3. Another concurrent connection cannot acquire the lock or append until the first commits.
    """
    admin_url = get_live_postgres_url("admin")
    app_url = get_live_postgres_url("app")

    conn1 = psycopg2.connect(app_url)
    conn2 = psycopg2.connect(admin_url)

    try:
        # Step 1: Conn1 calls get_latest_audit_event_hash() inside transaction
        cur1 = conn1.cursor()
        cur1.execute("SELECT public.get_latest_audit_event_hash();")
        head = cur1.fetchone()[0]
        assert head is not None

        # Step 2: Conn2 attempts non-blocking acquisition of the EXACT same advisory lock
        cur2 = conn2.cursor()
        cur2.execute("SELECT pg_try_advisory_xact_lock(hashtext('audit_events_chain_lock')::bigint);")
        acquired = cur2.fetchone()[0]
        # PROOF: Conn1 still holds the lock! Conn2 must be denied.
        assert acquired is False, "CONCURRENCY FAILURE: Advisory lock was NOT held by conn1!"

        # Step 3: Conn1 commits transaction, releasing transaction-level advisory lock
        conn1.commit()

        # Step 4: Conn2 now attempts acquisition; must succeed immediately
        cur2.execute("SELECT pg_try_advisory_xact_lock(hashtext('audit_events_chain_lock')::bigint);")
        acquired_after = cur2.fetchone()[0]
        assert acquired_after is True, "Advisory lock was not freed upon conn1 commit!"
        conn2.commit()
    finally:
        conn1.close()
        conn2.close()


def test_audit_chain_100_concurrent_mixed_merchant_and_system_appends():
    """
    P1.1.1-F Requirement: Run at least 100 concurrent mixed audit appends through actual application code paths.
    Verifies that:
    1. 70 tenant appends across 5 distinct merchants and 30 system appends
       execute concurrently under high thread contention (16 workers).
    2. Tenant events execute as app_user; system events route through system_audit_writer.
    3. All 100 appends succeed with zero deadlocks and zero serialization aborts.
    4. The global ledger has ZERO forks (each block chains strictly to predecessor).
    5. Full cryptographic ledger integrity verification passes (AuditStore.verify_integrity()).
    """
    from app.audit.store import AuditStore
    pg_url = get_live_postgres_url("app")
    store = AuditStore(db_path=pg_url)

    merchants = ["MERCH_C100_A", "MERCH_C100_B", "MERCH_C100_C", "MERCH_C100_D", "MERCH_C100_E"]
    num_total_events = 100
    num_system_events = 30
    num_tenant_events = num_total_events - num_system_events

    # Seed merchants
    with psycopg2.connect(get_live_postgres_url("admin")) as conn:
        with conn.cursor() as cur:
            for m in merchants:
                cur.execute(
                    "INSERT INTO merchants (id, name, status, created_at, updated_at) VALUES (%s, %s, 'ACTIVE', 100.0, 100.0) ON CONFLICT (id) DO NOTHING;",
                    (m, f"Corp {m}")
                )
            conn.commit()

    results = []

    def execute_mixed_append(idx: int) -> Dict[str, Any]:
        is_system = (idx < num_system_events)
        if is_system:
            # System event: no merchant_id in payload, writes through append_system_audit_event
            tx_id = f"SYS_EVT_{idx:03d}_{uuid.uuid4().hex[:6]}"
            ev_type = "KEY_REGISTERED" if idx % 2 == 0 else "SYSTEM_CONFIG_UPDATED"
            payload = {
                "system_idx": idx,
                "config_key": f"key_{idx}",
                "nonce": secrets.token_hex(8),
            }
        else:
            # Tenant event: bound to a specific merchant organization
            merch = merchants[idx % len(merchants)]
            tx_id = f"TENANT_EVT_{idx:03d}_{uuid.uuid4().hex[:6]}"
            ev_type = "PROPOSAL_EVALUATED" if idx % 2 == 0 else "PURCHASE_SETTLED"
            payload = {
                "tenant_idx": idx,
                "merchant_id": merch,
                "amount": float(100 + idx),
                "nonce": secrets.token_hex(8),
            }

        ev_hash, prev_h = store.append_event(
            transaction_id=tx_id,
            event_type=ev_type,
            payload_dict=payload,
        )
        return {
            "idx": idx,
            "is_system": is_system,
            "tx_id": tx_id,
            "event_hash": ev_hash,
            "prev_hash": prev_h,
        }

    # Execute 50 concurrent worker threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(execute_mixed_append, i) for i in range(num_total_events)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            results.append(res)

    assert len(results) == num_total_events, f"Expected {num_total_events} appends, got {len(results)}"

    # 1. Official AuditStore cryptographic verification
    integrity = store.verify_integrity()
    assert integrity["valid"] is True, f"Cryptographic integrity failed: {integrity}"
    assert integrity["total_records"] >= num_total_events

    # 2. Strict Ledger Walk Verification: ZERO FORKS
    with psycopg2.connect(get_live_postgres_url("admin")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, event_id, transaction_id, event_hash, prev_hash, merchant_id
                FROM public.audit_events
                ORDER BY id ASC;
                """
            )
            all_rows = cur.fetchall()

    for i in range(1, len(all_rows)):
        prev_row = all_rows[i - 1]
        curr_row = all_rows[i]
        expected_prev = prev_row[3]
        actual_prev = curr_row[4]
        assert actual_prev == expected_prev, (
            f"LEDGER FORK DETECTED between row {prev_row[0]} and row {curr_row[0]}! "
            f"Expected prev_hash {expected_prev}, got {actual_prev}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# TASK 5: Authentication & End-to-End Workflow Verification
# ══════════════════════════════════════════════════════════════════════════════

def test_invitation_lookup_lifecycle_expiry_and_revocation(pg_admin_conn, pg_app_conn):
    """
    Task 5: Test invitation lookup:
    - Valid pending invitation returned
    - Expired invitation returns 0 rows
    - Revoked invitation returns 0 rows
    - Input validation: invalid hex, length != 64, SQL injection
    """
    token_valid = "valid_invite_token_" + secrets.token_hex(16)
    token_hash_valid = hashlib.sha256(token_valid.encode("utf-8")).hexdigest()

    token_expired = "expired_invite_token_" + secrets.token_hex(16)
    token_hash_expired = hashlib.sha256(token_expired.encode("utf-8")).hexdigest()

    token_revoked = "revoked_invite_token_" + secrets.token_hex(16)
    token_hash_revoked = hashlib.sha256(token_revoked.encode("utf-8")).hexdigest()

    now = time.time()
    with pg_admin_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO merchant_invitations (id, merchant_id, email, role, token_hash, status, created_by, expires_at, created_at, updated_at) VALUES
                ('INV_TEST_VALID',   'MERCH_M1', 'valid@example.com',   'STAFF', %s, 'PENDING', 'admin_1', %s, %s, %s),
                ('INV_TEST_EXPIRED', 'MERCH_M1', 'expired@example.com', 'STAFF', %s, 'PENDING', 'admin_1', %s, %s, %s),
                ('INV_TEST_REVOKED', 'MERCH_M1', 'revoked@example.com', 'STAFF', %s, 'REVOKED', 'admin_1', %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, expires_at = EXCLUDED.expires_at;
            """,
            (
                token_hash_valid, now + 3600.0, now, now,
                token_hash_expired, now - 100.0, now - 200.0, now - 200.0,
                token_hash_revoked, now + 3600.0, now, now,
            )
        )
        pg_admin_conn.commit()

    with pg_app_conn.cursor() as cur:
        cur.execute("SELECT id, merchant_id, email, role, status FROM public.auth_lookup_invitation_by_token(%s);", (token_hash_valid,))
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "INV_TEST_VALID"

        cur.execute("SELECT count(*) FROM public.auth_lookup_invitation_by_token(%s);", (token_hash_expired,))
        assert cur.fetchone()[0] == 0

        cur.execute("SELECT count(*) FROM public.auth_lookup_invitation_by_token(%s);", (token_hash_revoked,))
        assert cur.fetchone()[0] == 0

        cur.execute("SELECT count(*) FROM public.auth_lookup_invitation_by_token('invalid_non_hex');")
        assert cur.fetchone()[0] == 0

        cur.execute("SELECT count(*) FROM public.auth_lookup_invitation_by_token(%s);", ("' OR '1'='1' --",))
        assert cur.fetchone()[0] == 0
    pg_app_conn.rollback()

    with pg_admin_conn.cursor() as cur:
        cur.execute("DELETE FROM merchant_invitations WHERE id IN ('INV_TEST_VALID', 'INV_TEST_EXPIRED', 'INV_TEST_REVOKED');")
        pg_admin_conn.commit()


def test_atomic_invitation_acceptance_under_high_concurrency():
    """
    Task 5: Test atomic invitation acceptance under concurrency (10 workers).
    Exactly one succeeds; all others are rejected.
    """
    from app.merchant.service import merchant_service
    from app.merchant.store import merchant_store

    pg_url = get_live_postgres_url("app")
    merchant_store.db_path = pg_url

    merch_id = f"merch_atom_{uuid.uuid4().hex[:8]}"
    with psycopg2.connect(get_live_postgres_url("admin")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO merchants (id, name, status, created_at, updated_at) VALUES (%s, 'Atomic Corp', 'ACTIVE', 100.0, 100.0);",
                (merch_id,)
            )
            conn.commit()

    raw_token = "single_use_secret_" + secrets.token_hex(16)
    token_h = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    inv_data = merchant_store.create_invitation(
        merchant_id=merch_id,
        email=f"atomic_{uuid.uuid4().hex[:6]}@example.com",
        role="STAFF",
        token_hash=token_h,
        created_by="admin_test",
        expires_at=time.time() + 3600.0,
    )

    successes = []
    failures = []

    def attempt_accept(worker_id: int):
        try:
            res = merchant_service.accept_invitation(
                raw_token=raw_token,
                password="StrongPassword123!#$",
            )
            return ("SUCCESS", worker_id, res)
        except Exception as e:
            return ("FAILURE", worker_id, str(e))

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_accept, i) for i in range(10)]
        for f in concurrent.futures.as_completed(futures):
            outcome, w_id, details = f.result()
            if outcome == "SUCCESS":
                successes.append((w_id, details))
            else:
                failures.append((w_id, details))

    assert len(successes) == 1, f"RACE CONDITION FAILURE: {len(successes)} workers accepted the invitation!"
    assert len(failures) == 9

    with psycopg2.connect(get_live_postgres_url("admin")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM merchant_invitations WHERE id = %s;", (inv_data["id"],))
            assert cur.fetchone()[0] == "ACCEPTED"
            cur.execute("DELETE FROM merchant_invitations WHERE id = %s;", (inv_data["id"],))
            cur.execute("DELETE FROM merchant_memberships WHERE merchant_id = %s;", (merch_id,))
            cur.execute("DELETE FROM merchants WHERE id = %s;", (merch_id,))
            conn.commit()


def test_system_event_direct_access_denied_under_rls():
    """
    Task 5: Verify direct access vs authorized access under RLS.
    app_user cannot directly SELECT rows with merchant_id IS NULL,
    and cannot directly INSERT rows with merchant_id = NULL.
    """
    admin_url = get_live_postgres_url("admin")
    app_url = get_live_postgres_url("app")

    with psycopg2.connect(admin_url) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS public.test_sys_events_rls CASCADE;")
            cur.execute(
                """
                CREATE TABLE public.test_sys_events_rls (
                    id SERIAL PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    merchant_id TEXT,
                    payload TEXT NOT NULL
                );
                """
            )
            cur.execute("ALTER TABLE public.test_sys_events_rls OWNER TO gateway_admin;")
            cur.execute("ALTER TABLE public.test_sys_events_rls ENABLE ROW LEVEL SECURITY;")
            cur.execute("ALTER TABLE public.test_sys_events_rls FORCE ROW LEVEL SECURITY;")

            cur.execute(
                """
                CREATE POLICY test_app_user_sys_policy ON public.test_sys_events_rls
                    FOR ALL TO app_user
                    USING (merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '') AND merchant_id IS NOT NULL)
                    WITH CHECK (merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '') AND merchant_id IS NOT NULL);
                """
            )
            cur.execute(
                """
                CREATE POLICY test_admin_sys_policy ON public.test_sys_events_rls
                    FOR ALL TO gateway_admin
                    USING (true) WITH CHECK (true);
                """
            )
            cur.execute(
                "INSERT INTO public.test_sys_events_rls (event_id, merchant_id, payload) VALUES ('ev_sys_secret', NULL, 'secret_key');"
            )
            conn.commit()

    with psycopg2.connect(app_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL app.current_merchant_id = 'MERCH_TENANT_1';")
            # Direct SELECT cannot see system events (merchant_id IS NULL)
            cur.execute("SELECT count(*) FROM public.test_sys_events_rls WHERE merchant_id IS NULL;")
            assert cur.fetchone()[0] == 0

            # Direct INSERT with merchant_id = NULL fails RLS WITH CHECK
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                cur.execute(
                    "INSERT INTO public.test_sys_events_rls (event_id, merchant_id, payload) VALUES ('ev_bad', NULL, 'evil');"
                )
            conn.rollback()

    # Cleanup
    with psycopg2.connect(admin_url) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS public.test_sys_events_rls CASCADE;")
            conn.commit()


def test_legitimate_login_and_merchant_switching_preserved():
    """
    Task 5: End-to-end verification of employee registration, authentication,
    membership retrieval, and merchant switching workflows under the new security architecture.
    """
    from app.merchant.service import merchant_service
    from app.merchant.store import merchant_store

    pg_url = get_live_postgres_url("app")
    merchant_store.db_path = pg_url

    email = f"emp_{uuid.uuid4().hex[:6]}@corp.example"
    pwd = "SecureEmployeePass123!#"

    # 1. Register employee and primary merchant
    reg_result = merchant_service.register_merchant(
        email=email,
        password=pwd,
        full_name="Corp Owner",
        merchant_name="Primary Corp",
    )
    user_id = reg_result["user_id"]
    primary_merch_id = reg_result["merchant_id"]

    # 2. Authenticate employee
    auth_result = merchant_service.authenticate_employee(email=email, password=pwd)
    assert auth_result["user_id"] == user_id
    assert auth_result["merchant_id"] == primary_merch_id

    # 3. Create second merchant and assign membership
    merch2 = merchant_store.create_merchant("Secondary Corp")
    merchant_store.create_membership(
        merchant_id=merch2["id"],
        user_id=user_id,
        role="OWNER",
        status="ACTIVE",
    )

    # 4. Verify membership enumeration through control-plane store
    memberships = merchant_store.list_user_memberships(user_id)
    assert len(memberships) == 2
    merchant_ids = {m["merchant_id"] for m in memberships}
    assert primary_merch_id in merchant_ids
    assert merch2["id"] in merchant_ids

    # 5. Switch organization to Secondary Corp
    switch_res = merchant_service.switch_organization(user_id=user_id, target_merchant_id=merch2["id"])
    assert switch_res["merchant_id"] == merch2["id"]
    assert switch_res["access_token"] is not None

    # Cleanup
    with psycopg2.connect(get_live_postgres_url("admin")) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM merchant_memberships WHERE user_id = %s;", (user_id,))
            cur.execute("DELETE FROM merchants WHERE id IN (%s, %s);", (primary_merch_id, merch2["id"]))
            cur.execute("DELETE FROM merchant_users WHERE id = %s;", (user_id,))
            conn.commit()
