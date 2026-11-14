"""
Deploy Hardened PostgreSQL 16 SECURITY DEFINER Functions.
Milestone: P1.1.1-E
Target: 127.0.0.1:5433 / agentic_commerce

Deploys and hardens:
1. public.auth_lookup_user_memberships(p_user_id TEXT)
2. public.auth_lookup_invitation_by_token(p_token_hash TEXT)
3. public.get_latest_audit_event_hash()
4. public.append_system_audit_event(...)
"""
import os
import sys
import psycopg2
from dotenv import load_dotenv

load_dotenv(override=False)

admin_url = os.environ.get("LOCAL_PG_ADMIN_URL")
if not admin_url:
    print("FATAL: LOCAL_PG_ADMIN_URL not configured.")
    sys.exit(1)

if "127.0.0.1:5433" not in admin_url and "localhost:5433" not in admin_url:
    print(f"FATAL: Safety violation: Attempted to run against non-local host: {admin_url}")
    sys.exit(1)

DEPLOY_SQL = r"""
-- 1. auth_lookup_user_memberships
CREATE OR REPLACE FUNCTION public.auth_lookup_user_memberships(p_user_id TEXT)
RETURNS TABLE (
    id TEXT,
    merchant_id TEXT,
    role TEXT,
    status TEXT,
    merchant_name TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- 1. Trustworthy Caller Identity Verification:
    -- Only authorized authentication/control-plane roles may invoke this cross-tenant enumeration function.
    -- app_user (the tenant runtime role) is strictly prohibited.
    IF SESSION_USER = 'app_user' OR SESSION_USER NOT IN ('gateway_auth', 'gateway_admin', 'postgres') THEN
        RAISE EXCEPTION 'Access denied: role % is not authorized to execute auth_lookup_user_memberships', SESSION_USER
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- 2. Strict input validation
    IF p_user_id IS NULL 
       OR pg_catalog.length(pg_catalog.btrim(p_user_id)) = 0 
       OR pg_catalog.length(p_user_id) > 255 
       OR p_user_id ~ '[\r\n\x00]' THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT 
        m.id, 
        m.merchant_id, 
        m.role, 
        m.status, 
        o.name AS merchant_name
    FROM public.merchant_memberships m
    JOIN public.merchants o ON m.merchant_id = o.id
    WHERE m.user_id = pg_catalog.btrim(p_user_id) 
      AND m.status = 'ACTIVE' 
      AND o.status = 'ACTIVE'
    ORDER BY m.created_at ASC;
END;
$$;

-- 2. auth_lookup_invitation_by_token
CREATE OR REPLACE FUNCTION public.auth_lookup_invitation_by_token(p_token_hash TEXT)
RETURNS TABLE (
    id TEXT,
    merchant_id TEXT,
    email TEXT,
    role TEXT,
    status TEXT,
    created_by TEXT,
    expires_at DOUBLE PRECISION
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- Strict input validation: SHA-256 hex string must be exactly 64 lower/upper hex characters
    IF p_token_hash IS NULL OR p_token_hash !~ '^[a-fA-F0-9]{64}$' THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT 
        i.id, 
        i.merchant_id, 
        i.email, 
        i.role, 
        i.status, 
        i.created_by, 
        i.expires_at::double precision AS expires_at
    FROM public.merchant_invitations i
    WHERE i.token_hash = pg_catalog.lower(p_token_hash)
      AND i.status = 'PENDING'
      AND i.expires_at > EXTRACT(EPOCH FROM pg_catalog.clock_timestamp());
END;
$$;

-- 3. get_latest_audit_event_hash
CREATE OR REPLACE FUNCTION public.get_latest_audit_event_hash()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_latest_hash TEXT;
BEGIN
    -- Acquire exclusive transaction-level advisory lock to serialize ledger appends across all merchants
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('audit_events_chain_lock')::bigint);

    SELECT event_hash INTO v_latest_hash
    FROM public.audit_events
    ORDER BY id DESC
    LIMIT 1;

    -- Defensive sanity check on ledger head format
    IF v_latest_hash IS NOT NULL AND v_latest_hash !~ '^[a-fA-F0-9]{64}$' THEN
        RAISE EXCEPTION 'Corrupted audit ledger head detected: %', v_latest_hash
            USING ERRCODE = 'data_corrupted';
    END IF;

    RETURN COALESCE(v_latest_hash, 'GENESIS');
END;
$$;

-- 4. append_system_audit_event
CREATE OR REPLACE FUNCTION public.append_system_audit_event(
    p_event_id TEXT,
    p_transaction_id TEXT,
    p_event_type TEXT,
    p_timestamp TEXT,
    p_payload_json TEXT,
    p_prev_hash TEXT,
    p_event_hash TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_current_head TEXT;
    v_raw_payload TEXT;
    v_expected_hash TEXT;
BEGIN
    -- 0. Caller Authorization Check (defense-in-depth)
    IF SESSION_USER = 'app_user' OR SESSION_USER NOT IN ('system_audit_writer', 'gateway_admin', 'postgres') THEN
        RAISE EXCEPTION 'Access denied: role % is not authorized to execute append_system_audit_event', SESSION_USER
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- 1. Strict input validation
    IF p_event_id IS NULL OR pg_catalog.length(pg_catalog.btrim(p_event_id)) = 0 OR pg_catalog.length(p_event_id) > 255 OR p_event_id ~ '[\r\n\x00]' THEN
        RAISE EXCEPTION 'p_event_id cannot be null, empty, or contain control characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_transaction_id IS NULL OR pg_catalog.length(pg_catalog.btrim(p_transaction_id)) = 0 OR pg_catalog.length(p_transaction_id) > 255 OR p_transaction_id ~ '[\r\n\x00]' THEN
        RAISE EXCEPTION 'p_transaction_id cannot be null, empty, or contain control characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_event_type IS NULL OR pg_catalog.length(pg_catalog.btrim(p_event_type)) = 0 OR pg_catalog.length(p_event_type) > 100 OR p_event_type !~ '^[A-Z0-9_]+$' THEN
        RAISE EXCEPTION 'p_event_type must be uppercase alphanumeric and underscores, max 100 characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_timestamp IS NULL OR pg_catalog.length(pg_catalog.btrim(p_timestamp)) = 0 OR pg_catalog.length(p_timestamp) > 64 OR p_timestamp ~ '[\r\n\x00]' THEN
        RAISE EXCEPTION 'p_timestamp cannot be null or empty' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_payload_json IS NULL OR pg_catalog.length(pg_catalog.btrim(p_payload_json)) = 0 THEN
        RAISE EXCEPTION 'p_payload_json cannot be null or empty' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_prev_hash IS NULL OR (p_prev_hash != 'GENESIS' AND p_prev_hash !~ '^[a-fA-F0-9]{64}$') THEN
        RAISE EXCEPTION 'p_prev_hash must be GENESIS or 64 hex characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_event_hash IS NULL OR p_event_hash !~ '^[a-fA-F0-9]{64}$' THEN
        RAISE EXCEPTION 'p_event_hash must be 64 hex characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- 2. Enforce authorized system event types whitelist
    IF p_event_type NOT IN (
        'KEY_CHALLENGE_ISSUED', 'KEY_REGISTERED', 'KEY_REVOKED',
        'SIGNING_KEY_REGISTERED', 'SIGNING_KEY_REVOKED',
        'MANDATE_REGISTERED', 'MANDATE_SUPERSEDED', 'MANDATE_REVOKED',
        'PURCHASE_APPROVAL_CREATED', 'PURCHASE_APPROVAL_CONSUMED',
        'SYSTEM_KEY_ROTATION', 'SYSTEM_INIT', 'SYSTEM_CONFIG_UPDATED',
        'SYSTEM_AUDIT_VERIFIED'
    ) THEN
        RAISE EXCEPTION 'Unauthorized system event type: %', p_event_type
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- 3. Validate well-formed JSON
    BEGIN
        PERFORM p_payload_json::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'p_payload_json is not valid JSON: %', SQLERRM USING ERRCODE = 'invalid_parameter_value';
    END;

    -- 4. Independent Cryptographic Event Hash Integrity Verification
    -- Recomputes SHA-256 hash according to canonical formula: prev_hash|event_id|transaction_id|event_type|timestamp|payload_json
    v_raw_payload := p_prev_hash || '|' || pg_catalog.btrim(p_event_id) || '|' || pg_catalog.btrim(p_transaction_id) || '|' || pg_catalog.btrim(p_event_type) || '|' || pg_catalog.btrim(p_timestamp) || '|' || p_payload_json;
    v_expected_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_raw_payload, 'UTF8')), 'hex');

    IF pg_catalog.lower(p_event_hash) != v_expected_hash THEN
        RAISE EXCEPTION 'Cryptographic event hash mismatch: calculated %, received %', v_expected_hash, p_event_hash
            USING ERRCODE = 'check_violation';
    END IF;

    -- 5. Concurrency Lock: acquire exclusive transaction advisory lock
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('audit_events_chain_lock')::bigint);

    -- 6. Verify ledger head continuity: p_prev_hash must strictly match current ledger head
    SELECT COALESCE(event_hash, 'GENESIS') INTO v_current_head
    FROM public.audit_events
    ORDER BY id DESC
    LIMIT 1;

    IF v_current_head IS NULL THEN
        v_current_head := 'GENESIS';
    END IF;

    IF p_prev_hash != v_current_head THEN
        RAISE EXCEPTION 'Audit ledger continuity error: expected prev_hash %, but current ledger head is %',
            p_prev_hash, v_current_head
            USING ERRCODE = 'check_violation';
    END IF;

    -- 7. Insert strictly with merchant_id = NULL (system event, cannot be tenant-owned)
    INSERT INTO public.audit_events (
        event_id, transaction_id, event_type, timestamp, payload_json, prev_hash, event_hash, merchant_id
    ) VALUES (
        pg_catalog.btrim(p_event_id),
        pg_catalog.btrim(p_transaction_id),
        pg_catalog.btrim(p_event_type),
        pg_catalog.btrim(p_timestamp),
        p_payload_json,
        p_prev_hash,
        p_event_hash,
        NULL
    );
END;
$$;

-- Function Ownership and Access Control Hardening
ALTER FUNCTION public.auth_lookup_user_memberships(TEXT) OWNER TO gateway_admin;
ALTER FUNCTION public.auth_lookup_invitation_by_token(TEXT) OWNER TO gateway_admin;
ALTER FUNCTION public.get_latest_audit_event_hash() OWNER TO gateway_admin;
ALTER FUNCTION public.append_system_audit_event(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) OWNER TO gateway_admin;

REVOKE ALL ON FUNCTION public.auth_lookup_user_memberships(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_lookup_invitation_by_token(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_latest_audit_event_hash() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.append_system_audit_event(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.auth_lookup_user_memberships(TEXT) FROM app_user, system_audit_writer;
REVOKE ALL ON FUNCTION public.append_system_audit_event(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) FROM app_user, gateway_auth;

GRANT EXECUTE ON FUNCTION public.get_latest_audit_event_hash() TO app_user, system_audit_writer, gateway_auth, gateway_admin;
GRANT EXECUTE ON FUNCTION public.auth_lookup_invitation_by_token(TEXT) TO app_user, gateway_auth, gateway_admin;
GRANT EXECUTE ON FUNCTION public.auth_lookup_user_memberships(TEXT) TO gateway_auth, gateway_admin;
GRANT EXECUTE ON FUNCTION public.append_system_audit_event(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) TO system_audit_writer, gateway_admin;

-- Schema Privilege Boundary: runtime roles must not have schema modification rights
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM app_user, gateway_auth, system_audit_writer;
GRANT USAGE ON SCHEMA public TO app_user, gateway_auth, system_audit_writer;
"""

def deploy():
    print(f"Connecting as gateway_admin to: {admin_url.split('@')[1]}")
    conn = psycopg2.connect(admin_url)
    conn.autocommit = True
    with conn.cursor() as cur:
        print("Deploying hardened PostgreSQL functions...")
        cur.execute(DEPLOY_SQL)
        print("Hardened functions successfully deployed!")
        
        cur.execute("""
            SELECT routine_name, routine_type, security_type 
            FROM information_schema.routines 
            WHERE routine_schema = 'public'
            ORDER BY routine_name;
        """)
        routines = cur.fetchall()
        print("\nVerified routines in schema 'public':")
        for r in routines:
            print(f"  {r[0]:<35} type: {r[1]:<10} security: {r[2]}")
    conn.close()

if __name__ == "__main__":
    deploy()
