-- ==============================================================================
-- Migration 001: PostgreSQL Row-Level Security (RLS) Tenant & Buyer Isolation Hardening
-- Milestone: P1.1.1 — Tenant, Buyer & Control-Plane Hardening (P1.1.1-G Comprehensive Revision)
-- Author: Principal Backend & Database Security Architect
-- Target Database: PostgreSQL 16+
-- ==============================================================================
--
-- ARCHITECTURAL RATIONALE & THREAT MODEL SPECIFICATIONS:
-- 1. Dual-Axis Context Lifecycle (Tenant & Buyer Isolation):
--    - Merchant Data is isolated via transaction-scoped `SET LOCAL app.current_merchant_id = 'MERCH_...'`.
--    - Buyer Data is isolated via transaction-scoped `SET LOCAL app.current_customer_id = 'CUST_...'`.
--    - Session-level `SET` MUST NEVER be used because pooled physical connections are reused.
--    - `SET LOCAL` guarantees context parameters automatically revert upon COMMIT or ROLLBACK.
--
-- 2. FORCE ROW LEVEL SECURITY & Role Boundaries:
--    - FORCE ROW LEVEL SECURITY guarantees that table owners (gateway_admin) are bound
--      by RLS policies during application queries.
--    - All roles (`gateway_admin`, `gateway_auth`, `system_audit_writer`, `app_user`) retain NOBYPASSRLS.
--    - Dedicated control-plane roles (gateway_auth, system_audit_writer) are explicitly granted
--      least-privilege operations on their respective domains.
--
-- 3. Policy Semantics (PERMISSIVE with Strict Fail-Closed Predicates):
--    - All isolation policies are defined AS PERMISSIVE.
--    - When `app.current_merchant_id` or `app.current_customer_id` is missing or empty,
--      `NULLIF(..., '')` evaluates to NULL.
--    - In SQL, `column = NULL` evaluates to UNKNOWN (falsy in RLS), failing closed.
--
-- 4. Buyer vs Merchant Resource Boundaries:
--    - Buyer tables (wallets, keys, mandates, approvals, challenges, tokens, credentials)
--      are strictly bound to customer_id, NEVER merchant_id.
--    - Buyers can seamlessly authorize transactions across multiple merchants without mandate splitting.
-- ==============================================================================

BEGIN;

-- 1. Ensure commerce and buyer tables have compound indexes for tenant & customer lookup
CREATE INDEX IF NOT EXISTS idx_cat_prod_tenant ON catalog_products (merchant_id, id);
CREATE INDEX IF NOT EXISTS idx_audit_records_tenant ON audit_records (merchant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events (merchant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_memberships_tenant ON merchant_memberships (merchant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_invitations_tenant ON merchant_invitations (merchant_id, token_hash);

-- Buyer indexes
CREATE INDEX IF NOT EXISTS idx_wallets_cust ON customer_wallets (customer_id);
CREATE INDEX IF NOT EXISTS idx_keys_cust ON customer_signing_keys (customer_id, key_id);
CREATE INDEX IF NOT EXISTS idx_mandates_cust ON customer_mandates (customer_id);
CREATE INDEX IF NOT EXISTS idx_signed_mandates_cust ON signed_mandates (customer_id, mandate_id);
CREATE INDEX IF NOT EXISTS idx_approvals_cust ON purchase_approvals (customer_id, approval_id);
CREATE INDEX IF NOT EXISTS idx_challenges_cust ON signing_challenges (customer_id, challenge_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_cust ON refresh_tokens (customer_id, token_hash);
CREATE INDEX IF NOT EXISTS idx_credentials_cust ON customer_credentials (customer_id);

-- ==============================================================================
-- 2. Merchant Tables RLS (Merchant Tenant Scoping)
-- ==============================================================================

-- 2.1 Catalog Products Table RLS
ALTER TABLE catalog_products ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalog_products FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_catalog ON catalog_products;
CREATE POLICY tenant_isolation_catalog ON catalog_products
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    )
    WITH CHECK (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_catalog_policy ON catalog_products;
CREATE POLICY admin_catalog_policy ON catalog_products
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 2.2 Audit Records Table RLS
ALTER TABLE audit_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_audit_records ON audit_records;
CREATE POLICY tenant_isolation_audit_records ON audit_records
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    )
    WITH CHECK (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_audit_records_policy ON audit_records;
CREATE POLICY admin_audit_records_policy ON audit_records
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 2.3 Audit Events Table RLS
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_audit_events_app_user ON audit_events;
CREATE POLICY tenant_isolation_audit_events_app_user ON audit_events
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    )
    WITH CHECK (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_audit_events_policy ON audit_events;
CREATE POLICY admin_audit_events_policy ON audit_events
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 2.4 Merchant Memberships Table RLS
ALTER TABLE merchant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_memberships FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_memberships ON merchant_memberships;
CREATE POLICY tenant_isolation_memberships ON merchant_memberships
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    )
    WITH CHECK (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_memberships_policy ON merchant_memberships;
CREATE POLICY admin_memberships_policy ON merchant_memberships
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin, gateway_auth
    USING (true)
    WITH CHECK (true);

-- 2.5 Merchant Invitations Table RLS
ALTER TABLE merchant_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_invitations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_invitations ON merchant_invitations;
CREATE POLICY tenant_isolation_invitations ON merchant_invitations
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    )
    WITH CHECK (
        merchant_id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND merchant_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_invitations_policy ON merchant_invitations;
CREATE POLICY admin_invitations_policy ON merchant_invitations
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin, gateway_auth
    USING (true)
    WITH CHECK (true);

-- ==============================================================================
-- 3. Control-Plane Protection & Table Restrictions
-- ==============================================================================

-- 3.1 Merchants Root Organization Table RLS & Permissions
ALTER TABLE merchants ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchants FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_merchants ON merchants;
CREATE POLICY tenant_isolation_merchants ON merchants
    AS PERMISSIVE
    FOR SELECT
    TO app_user
    USING (
        id = NULLIF(current_setting('app.current_merchant_id', true), '')
        AND id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_merchants_policy ON merchants;
CREATE POLICY admin_merchants_policy ON merchants
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin, gateway_auth
    USING (true)
    WITH CHECK (true);

-- app_user must never insert, update, or delete root merchants
REVOKE INSERT, UPDATE, DELETE ON merchants FROM app_user;

-- 3.2 Merchant Users Table (Global Employee Credentials) RLS & Permissions
ALTER TABLE merchant_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE merchant_users FORCE ROW LEVEL SECURITY;

REVOKE ALL ON merchant_users FROM app_user;
GRANT SELECT, INSERT, UPDATE ON merchant_users TO gateway_auth, gateway_admin;

DROP POLICY IF EXISTS admin_merchant_users_policy ON merchant_users;
CREATE POLICY admin_merchant_users_policy ON merchant_users
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin, gateway_auth
    USING (true)
    WITH CHECK (true);

-- 3.3 Processed Webhook Events (Idempotency Ledger) RLS & Permissions
ALTER TABLE processed_webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE processed_webhook_events FORCE ROW LEVEL SECURITY;

REVOKE UPDATE, DELETE ON processed_webhook_events FROM app_user;
GRANT SELECT, INSERT ON processed_webhook_events TO system_audit_writer, gateway_admin;

DROP POLICY IF EXISTS webhook_processing_policy ON processed_webhook_events;
CREATE POLICY webhook_processing_policy ON processed_webhook_events
    AS PERMISSIVE
    FOR ALL
    TO system_audit_writer, gateway_admin
    USING (true)
    WITH CHECK (true);

-- ==============================================================================
-- 4. Buyer-Level Isolation Policies (Customer-Scoped)
-- ==============================================================================

-- 4.1 Customer Wallets Table RLS
ALTER TABLE customer_wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_wallets FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS buyer_isolation_wallets ON customer_wallets;
CREATE POLICY buyer_isolation_wallets ON customer_wallets
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    )
    WITH CHECK (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_wallets_policy ON customer_wallets;
CREATE POLICY admin_wallets_policy ON customer_wallets
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 4.2 Customer Signing Keys Table RLS
ALTER TABLE customer_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_signing_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS buyer_isolation_signing_keys ON customer_signing_keys;
CREATE POLICY buyer_isolation_signing_keys ON customer_signing_keys
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    )
    WITH CHECK (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_signing_keys_policy ON customer_signing_keys;
CREATE POLICY admin_signing_keys_policy ON customer_signing_keys
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 4.3 Customer Credentials Table RLS
ALTER TABLE customer_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_credentials FORCE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON customer_credentials TO gateway_auth;

DROP POLICY IF EXISTS buyer_isolation_credentials ON customer_credentials;
CREATE POLICY buyer_isolation_credentials ON customer_credentials
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    )
    WITH CHECK (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_credentials_policy ON customer_credentials;
CREATE POLICY admin_credentials_policy ON customer_credentials
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin, gateway_auth
    USING (true)
    WITH CHECK (true);

-- 4.4 Customer Mandates Table RLS
ALTER TABLE customer_mandates ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_mandates FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS buyer_isolation_mandates ON customer_mandates;
CREATE POLICY buyer_isolation_mandates ON customer_mandates
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    )
    WITH CHECK (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_mandates_policy ON customer_mandates;
CREATE POLICY admin_mandates_policy ON customer_mandates
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 4.5 Signed Mandates Table RLS
ALTER TABLE signed_mandates ENABLE ROW LEVEL SECURITY;
ALTER TABLE signed_mandates FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS buyer_isolation_signed_mandates ON signed_mandates;
CREATE POLICY buyer_isolation_signed_mandates ON signed_mandates
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    )
    WITH CHECK (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_signed_mandates_policy ON signed_mandates;
CREATE POLICY admin_signed_mandates_policy ON signed_mandates
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 4.6 Purchase Approvals Table RLS
ALTER TABLE purchase_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE purchase_approvals FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS buyer_isolation_purchase_approvals ON purchase_approvals;
CREATE POLICY buyer_isolation_purchase_approvals ON purchase_approvals
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    )
    WITH CHECK (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_purchase_approvals_policy ON purchase_approvals;
CREATE POLICY admin_purchase_approvals_policy ON purchase_approvals
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 4.7 Signing Challenges Table RLS
ALTER TABLE signing_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_challenges FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS buyer_isolation_signing_challenges ON signing_challenges;
CREATE POLICY buyer_isolation_signing_challenges ON signing_challenges
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    )
    WITH CHECK (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_signing_challenges_policy ON signing_challenges;
CREATE POLICY admin_signing_challenges_policy ON signing_challenges
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- 4.8 Refresh Tokens Table RLS
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS buyer_isolation_refresh_tokens ON refresh_tokens;
CREATE POLICY buyer_isolation_refresh_tokens ON refresh_tokens
    AS PERMISSIVE
    FOR ALL
    TO app_user
    USING (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    )
    WITH CHECK (
        customer_id = NULLIF(current_setting('app.current_customer_id', true), '')
        AND customer_id IS NOT NULL
    );

DROP POLICY IF EXISTS admin_refresh_tokens_policy ON refresh_tokens;
CREATE POLICY admin_refresh_tokens_policy ON refresh_tokens
    AS PERMISSIVE
    FOR ALL
    TO gateway_admin
    USING (true)
    WITH CHECK (true);

-- ==============================================================================
-- 5. Trusted SECURITY DEFINER Functions for Safe Authentication & System Audit
-- ==============================================================================

-- 5.1 Membership Lookup across merchant boundaries (bypasses RLS strictly for authenticated control plane)
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

-- 5.2 Invitation Lookup by exact single-use token_hash
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

-- 5.3 Global Predecessor Hash Retrieval with exclusive advisory lock for concurrency-safe ledger appends
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

-- 5.4 Privileged System Audit Event Insertion with in-database cryptographic hash verification
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
    -- Canonical formula: prev_hash|event_id|transaction_id|event_type|timestamp|payload_json
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

-- ==============================================================================
-- 6. Function Ownership & Role Access Control Hardening
-- ==============================================================================

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

-- ==============================================================================
-- 7. Explicitly ensure All Roles Retain NOBYPASSRLS
-- ==============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_admin') THEN
        ALTER ROLE gateway_admin NOBYPASSRLS;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_auth') THEN
        ALTER ROLE gateway_auth NOBYPASSRLS;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'system_audit_writer') THEN
        ALTER ROLE system_audit_writer NOBYPASSRLS;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        ALTER ROLE app_user NOBYPASSRLS;
    END IF;
END $$;

COMMIT;
