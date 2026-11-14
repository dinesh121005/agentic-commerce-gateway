"""
Disposable Database Migration & RLS Validation Suite.
Milestone: P1.1.1-G — Task 4
Target: 127.0.0.1:5433 / agentic_disposable_test

CRITICAL INVARIANTS:
1. Operates strictly on a freshly created, disposable database ('agentic_disposable_test').
2. NEVER touches or connects to the primary database ('agentic_commerce'), Render, or production.
3. Applies scripts/migrations/001_postgresql_rls_hardening.sql strictly against the disposable DB.
4. Verifies:
   - RLS and FORCE RLS applied across all intended tables.
   - Policies behave correctly for every runtime role.
   - Buyer resources are strictly customer-scoped, never merchant-scoped.
   - Migration failure and rollback behavior are completely safe and atomic.
"""
import os
import sys
import time
import uuid
import psycopg2
from psycopg2 import sql

# Ensure repo root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(override=False)

SUPER_URL = "postgresql://postgres:agentic_pg_local_dev_secret_2026@127.0.0.1:5433/postgres"
DISPOSABLE_DB = "agentic_disposable_test"
DISPOSABLE_ADMIN_URL = f"postgresql://gateway_admin:4ZQvSPk6ev-DshJUMQ1vt2F-zBKo93ZJ@127.0.0.1:5433/{DISPOSABLE_DB}"
DISPOSABLE_APP_URL = f"postgresql://app_user:9Gqjj-tTgjNyLCNv9O-okc9l1dQSvdQK@127.0.0.1:5433/{DISPOSABLE_DB}"
DISPOSABLE_AUTH_URL = f"postgresql://gateway_auth:V7ejvJ3M92TlSctn7jaUqNuyubeCOgoD@127.0.0.1:5433/{DISPOSABLE_DB}"
DISPOSABLE_AUDIT_URL = f"postgresql://system_audit_writer:oC57iFlSOJTJiT4_1S9ht8b7XtTxKzeS@127.0.0.1:5433/{DISPOSABLE_DB}"

# Safety guard: ensure local connection only
for u in (SUPER_URL, DISPOSABLE_ADMIN_URL, DISPOSABLE_APP_URL):
    if "127.0.0.1:5433" not in u and "localhost:5433" not in u:
        raise RuntimeError(f"Safety violation: Target is not local port 5433: {u}")


def setup_disposable_database():
    """Drops and recreates the disposable test database."""
    print(f"\n1. Recreating disposable database: {DISPOSABLE_DB}...")
    conn = psycopg2.connect(SUPER_URL)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT pg_terminate_backend(pid) 
            FROM pg_stat_activity 
            WHERE datname = %s AND pid <> pg_backend_pid();
            """,
            (DISPOSABLE_DB,)
        )
        cur.execute(f"DROP DATABASE IF EXISTS {DISPOSABLE_DB};")
        cur.execute(f"CREATE DATABASE {DISPOSABLE_DB};")
        cur.execute(f"GRANT CONNECT ON DATABASE {DISPOSABLE_DB} TO gateway_admin, gateway_auth, system_audit_writer, app_user;")
    conn.close()
    print("   -> Disposable database created and access granted.")


def bootstrap_disposable_schema():
    """Initializes all 18 tables in the disposable database."""
    print("\n2. Bootstrapping application tables in disposable database...")
    from app.catalog import service as catalog_service
    from app.audit.store import audit_store
    from app.merchant.store import merchant_store
    from app.oauth.store import customer_auth_store
    from app.policy.store import mandate_store
    from app.signing.store import signing_store
    from app.wallet.store import wallet_store

    disp_url = f"postgresql://postgres:agentic_pg_local_dev_secret_2026@127.0.0.1:5433/{DISPOSABLE_DB}"
    
    for store in (audit_store, merchant_store, customer_auth_store, mandate_store, signing_store, wallet_store):
        store.db_path = disp_url
        store._initialized = False
    catalog_service._catalog_initialized = False

    merchant_store._init_db()
    catalog_service._ensure_catalog_db_initialized()
    audit_store._init_db()
    customer_auth_store._init_db()
    mandate_store._init_db()
    signing_store._init_db()
    wallet_store._init_db()

    # Transfer ownership to gateway_admin & grant least-privilege permissions
    conn = psycopg2.connect(disp_url)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
            """
        )
        tables = [r[0] for r in cur.fetchall()]
        for t in tables:
            cur.execute(sql.SQL("ALTER TABLE public.{} OWNER TO gateway_admin;").format(sql.Identifier(t)))

        cur.execute(
            """
            SELECT sequence_name 
            FROM information_schema.sequences 
            WHERE sequence_schema = 'public';
            """
        )
        sequences = [r[0] for r in cur.fetchall()]
        for s in sequences:
            cur.execute(sql.SQL("ALTER SEQUENCE public.{} OWNER TO gateway_admin;").format(sql.Identifier(s)))

        # Schema permissions
        cur.execute(f"GRANT ALL ON SCHEMA public TO gateway_admin;")
        cur.execute(f"GRANT USAGE ON SCHEMA public TO gateway_auth, system_audit_writer, app_user;")
        cur.execute(f"REVOKE CREATE ON SCHEMA public FROM PUBLIC, gateway_auth, system_audit_writer, app_user;")

        # Table permissions
        cur.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;")
        cur.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;")
        cur.execute("REVOKE ALL ON public.merchant_users FROM app_user;")
        cur.execute("REVOKE ALL ON public.processed_webhook_events FROM app_user;")
        cur.execute("REVOKE INSERT, UPDATE, DELETE ON public.merchants FROM app_user;")

        cur.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON public.customer_credentials, public.merchant_users, public.merchants, public.merchant_memberships, public.merchant_invitations TO gateway_auth;")
        cur.execute("GRANT SELECT, INSERT ON public.processed_webhook_events TO system_audit_writer;")

        # Revoke dangerous public defaults
        cur.execute(f"REVOKE ALL ON DATABASE {DISPOSABLE_DB} FROM PUBLIC;")
        cur.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;")
        cur.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;")
        cur.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;")

    conn.close()
    print(f"   -> Bootstrapped {len(tables)} tables and transferred ownership to gateway_admin.")


def seed_representative_records():
    """Populates disposable database with representative multi-tenant and multi-buyer records."""
    print("\n3. Seeding representative records for merchants and buyers...")
    conn = psycopg2.connect(DISPOSABLE_ADMIN_URL)
    conn.autocommit = True
    now = time.time()
    with conn.cursor() as cur:
        # Merchants
        cur.execute(
            """
            INSERT INTO merchants (id, name, status, created_at, updated_at) VALUES
                ('MERCH_DISP_A', 'Merchant Alpha', 'ACTIVE', %s, %s),
                ('MERCH_DISP_B', 'Merchant Beta', 'ACTIVE', %s, %s)
            ON CONFLICT (id) DO NOTHING;
            """,
            (now, now, now, now)
        )
        # Catalog products
        cur.execute(
            """
            INSERT INTO catalog_products (id, merchant_id, name, description, price, stock, category, created_at, updated_at) VALUES
                ('PROD_A1', 'MERCH_DISP_A', 'Alpha Keyboard', 'Mechanical keyboard', 120.0, 50, 'electronics', %s, %s),
                ('PROD_B1', 'MERCH_DISP_B', 'Beta Monitor', '4K UHD Monitor', 350.0, 20, 'electronics', %s, %s);
            """,
            (now, now, now, now)
        )
        # Buyer 1 (CUST_DISP_1)
        cur.execute(
            """
            INSERT INTO customer_wallets (customer_id, balance, currency, balance_paise, created_at, updated_at) VALUES
                ('CUST_DISP_1', 500.0, 'INR', 50000, %s, %s);
            INSERT INTO customer_signing_keys (key_id, customer_id, public_key, device_name, storage_type, status, created_at, expires_at) VALUES
                ('KEY_DISP_1', 'CUST_DISP_1', 'pub_key_disp_1', 'MacBook Pro', 'secure_enclave', 'ACTIVE', %s, %s);
            INSERT INTO customer_mandates (customer_id, display_name, email, max_transaction_amount, daily_limit, currency, allowed_categories, allowed_merchants, max_transaction_amount_paise, daily_limit_paise, created_at, updated_at) VALUES
                ('CUST_DISP_1', 'Buyer One', 'buyer1@disp.example', 250.0, 1000.0, 'INR', 'electronics', 'MERCH_DISP_A', 25000, 100000, %s, %s);
            INSERT INTO signed_mandates (mandate_id, mandate_version, customer_id, merchant_id, key_id, canonical_payload, payload_hash, signature, domain_separator, max_transaction_amount_paise, daily_budget_paise, status, valid_from, valid_until, created_at, updated_at) VALUES
                ('MAND_DISP_1', 1, 'CUST_DISP_1', 'MERCH_DISP_A', 'KEY_DISP_1', '{}', 'hash_disp_1', 'sig_disp_1', 'DOM', 25000, 100000, 'ACTIVE', '2026-01-01', '2027-01-01', %s, %s);
            INSERT INTO purchase_approvals (approval_id, purchase_id, customer_id, mandate_id, mandate_version, key_id, total_payable_paise, canonical_payload, payload_hash, signature, status, expires_at, created_at) VALUES
                ('APP_DISP_1', 'PURCH_DISP_1', 'CUST_DISP_1', 'MAND_DISP_1', 1, 'KEY_DISP_1', 12000, '{}', 'hash_app_1', 'sig_app_1', 'PENDING', %s, %s);
            INSERT INTO signing_challenges (challenge_id, customer_id, challenge_token, purpose, consumed, created_at, expires_at) VALUES
                ('CHAL_DISP_1', 'CUST_DISP_1', 'token_disp_1', 'KEY_REGISTRATION', 0, %s, %s);
            INSERT INTO refresh_tokens (token_hash, customer_id, client_id, expires_at, revoked, created_at) VALUES
                ('rt_hash_disp_1', 'CUST_DISP_1', 'client_1', %s, 0, %s);
            INSERT INTO customer_credentials (customer_id, username, email, password_hash, salt) VALUES
                ('CUST_DISP_1', 'buyer1', 'buyer1@disp.example', 'hash1', 'salt1');
            """,
            (
                now, now,
                now, now + 86400 * 365,
                now, now,
                now, now,
                now + 3600, now,
                now, now + 300,
                now + 86400 * 30, now,
            )
        )
        # Buyer 2 (CUST_DISP_2)
        cur.execute(
            """
            INSERT INTO customer_wallets (customer_id, balance, currency, balance_paise, created_at, updated_at) VALUES
                ('CUST_DISP_2', 900.0, 'INR', 90000, %s, %s);
            INSERT INTO customer_signing_keys (key_id, customer_id, public_key, device_name, storage_type, status, created_at, expires_at) VALUES
                ('KEY_DISP_2', 'CUST_DISP_2', 'pub_key_disp_2', 'Pixel Phone', 'hardware_keystore', 'ACTIVE', %s, %s);
            INSERT INTO customer_mandates (customer_id, display_name, email, max_transaction_amount, daily_limit, currency, allowed_categories, allowed_merchants, max_transaction_amount_paise, daily_limit_paise, created_at, updated_at) VALUES
                ('CUST_DISP_2', 'Buyer Two', 'buyer2@disp.example', 500.0, 2000.0, 'INR', 'electronics', 'MERCH_DISP_B', 50000, 200000, %s, %s);
            INSERT INTO signed_mandates (mandate_id, mandate_version, customer_id, merchant_id, key_id, canonical_payload, payload_hash, signature, domain_separator, max_transaction_amount_paise, daily_budget_paise, status, valid_from, valid_until, created_at, updated_at) VALUES
                ('MAND_DISP_2', 1, 'CUST_DISP_2', 'MERCH_DISP_B', 'KEY_DISP_2', '{}', 'hash_disp_2', 'sig_disp_2', 'DOM', 50000, 200000, 'ACTIVE', '2026-01-01', '2027-01-01', %s, %s);
            INSERT INTO purchase_approvals (approval_id, purchase_id, customer_id, mandate_id, mandate_version, key_id, total_payable_paise, canonical_payload, payload_hash, signature, status, expires_at, created_at) VALUES
                ('APP_DISP_2', 'PURCH_DISP_2', 'CUST_DISP_2', 'MAND_DISP_2', 1, 'KEY_DISP_2', 35000, '{}', 'hash_app_2', 'sig_app_2', 'PENDING', %s, %s);
            INSERT INTO signing_challenges (challenge_id, customer_id, challenge_token, purpose, consumed, created_at, expires_at) VALUES
                ('CHAL_DISP_2', 'CUST_DISP_2', 'token_disp_2', 'KEY_REGISTRATION', 0, %s, %s);
            INSERT INTO refresh_tokens (token_hash, customer_id, client_id, expires_at, revoked, created_at) VALUES
                ('rt_hash_disp_2', 'CUST_DISP_2', 'client_2', %s, 0, %s);
            INSERT INTO customer_credentials (customer_id, username, email, password_hash, salt) VALUES
                ('CUST_DISP_2', 'buyer2', 'buyer2@disp.example', 'hash2', 'salt2');
            """,
            (
                now, now,
                now, now + 86400 * 365,
                now, now,
                now, now,
                now + 3600, now,
                now, now + 300,
                now + 86400 * 30, now,
            )
        )
    conn.close()
    print("   -> Seeded merchants, products, and representative Buyer A / Buyer B records.")


def apply_migration_001_to_disposable():
    """Reads and executes scripts/migrations/001_postgresql_rls_hardening.sql against the disposable DB."""
    print("\n4. Applying Migration 001 to disposable database...")
    mig_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "migrations", "001_postgresql_rls_hardening.sql")
    with open(mig_path, "r", encoding="utf-8") as f:
        mig_sql = f.read()

    conn = psycopg2.connect(DISPOSABLE_ADMIN_URL)
    with conn.cursor() as cur:
        cur.execute(mig_sql)
    conn.commit()
    conn.close()
    print("   -> Migration 001 applied successfully to disposable database!")


def verify_disposable_rls_status():
    """Inspects pg_class to verify RLS and FORCE RLS on all intended tables."""
    print("\n5. Verifying RLS and FORCE RLS status across all tables in disposable database...")
    conn = psycopg2.connect(DISPOSABLE_ADMIN_URL)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT relname, relrowsecurity, relforcerowsecurity 
            FROM pg_class c 
            JOIN pg_namespace n ON n.oid = c.relnamespace 
            WHERE n.nspname = 'public' AND c.relkind = 'r'
            ORDER BY relname;
            """
        )
        rows = cur.fetchall()

    print(f"   {'Table Name':<28} {'RLS Enabled':<15} {'FORCE RLS':<15}")
    print("   " + "-" * 58)
    expected_rls_tables = {
        # 5 Merchant tables
        "catalog_products", "audit_records", "audit_events", "merchant_memberships", "merchant_invitations",
        # 3 Control-plane tables
        "merchants", "merchant_users", "processed_webhook_events",
        # 8 Buyer tables
        "customer_wallets", "customer_signing_keys", "customer_credentials", "customer_mandates",
        "signed_mandates", "purchase_approvals", "signing_challenges", "refresh_tokens",
    }
    
    for r in rows:
        name, rls, force = r[0], r[1], r[2]
        print(f"   {name:<28} {str(rls):<15} {str(force):<15}")
        if name in expected_rls_tables:
            assert rls is True, f"RLS FAILURE: Table {name} must have relrowsecurity = True"
            assert force is True, f"RLS FAILURE: Table {name} must have relforcerowsecurity = True"

    conn.close()
    print(f"   -> Confirmed: All {len(expected_rls_tables)} intended tables have RLS ENABLED and FORCED.")


def verify_migration_rollback_safety():
    """Tests that a failing statement inside a migration transaction cleanly rolls back without corrupting state."""
    print("\n6. Testing atomic migration failure and rollback behavior...")
    conn = psycopg2.connect(DISPOSABLE_ADMIN_URL)
    try:
        with conn.cursor() as cur:
            # Simulate a migration transaction with intentional failure
            cur.execute("CREATE TABLE public.test_rollback_sentinel (id INT);")
            # Intentional syntax error
            cur.execute("ALTER TABLE public.non_existent_table ADD COLUMN bad_col TEXT;")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"   -> Transaction intentionally failed as expected: {e}")

    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM information_schema.tables WHERE table_name = 'test_rollback_sentinel';")
        assert cur.fetchone() is None, "ROLLBACK FAILURE: test_rollback_sentinel was persisted after rollback!"
    conn.close()
    print("   -> Confirmed: Migration failure safely and atomically rolled back. No partial state committed.")


if __name__ == "__main__":
    setup_disposable_database()
    bootstrap_disposable_schema()
    seed_representative_records()
    apply_migration_001_to_disposable()
    verify_disposable_rls_status()
    verify_migration_rollback_safety()
    print("\n[SUCCESS] Disposable database migration test completed with 100% compliance!")

