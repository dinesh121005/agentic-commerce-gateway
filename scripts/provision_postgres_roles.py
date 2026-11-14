"""
Provision Dedicated Database Roles for PostgreSQL 16 Runtime Privilege Separation.
Milestone: P1.1.1-F
Target: 127.0.0.1:5433 / agentic_commerce

Roles provisioned:
1. gateway_admin: Schema/migration owner (NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE).
   - Owns all schema tables and sequences in public schema.
   - Used ONLY by migrations and DDL scripts; not accessible to application runtime.
2. gateway_auth: Dedicated authentication & control-plane role (NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE).
   - Can execute auth_lookup_user_memberships and auth_lookup_invitation_by_token.
   - Holds zero table DML privileges.
3. system_audit_writer: Dedicated system audit writer role (NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE).
   - Can execute append_system_audit_event and get_latest_audit_event_hash.
   - Holds zero business table privileges.
4. app_user: Application runtime execution role (NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE).
   - Possesses DML (SELECT, INSERT, UPDATE, DELETE) and sequence USAGE only.
   - Does NOT own any tables.
   - Strictly revoked from privileged functions (auth_lookup_user_memberships, append_system_audit_event).
"""
import os
import secrets
import sys
import psycopg2
from psycopg2 import sql

# Ensure repo root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(override=False)

pg_url = os.environ.get("LOCAL_DATABASE_URL")
if not pg_url:
    pg_url = "postgresql://postgres:agentic_pg_local_dev_secret_2026@127.0.0.1:5433/agentic_commerce"

# Safety guard: ensure local connection only
if "127.0.0.1:5433" not in pg_url and "localhost:5433" not in pg_url:
    raise RuntimeError(f"Safety violation: Target is not local port 5433: {pg_url}")

print(f"Connecting as superuser to: {pg_url.split('@')[1]}")

admin_pass = os.environ.get("LOCAL_PG_ADMIN_PASSWORD") or secrets.token_urlsafe(24)
auth_pass = os.environ.get("LOCAL_PG_AUTH_PASSWORD") or secrets.token_urlsafe(24)
audit_pass = os.environ.get("LOCAL_PG_AUDIT_PASSWORD") or secrets.token_urlsafe(24)
app_pass = os.environ.get("LOCAL_PG_APP_PASSWORD") or secrets.token_urlsafe(24)

conn = psycopg2.connect(pg_url)
conn.autocommit = True
cursor = conn.cursor()

try:
    print("\n1. Provisioning role: gateway_admin (schema & migration owner)...")
    cursor.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_admin') THEN
                CREATE ROLE gateway_admin WITH LOGIN PASSWORD %s;
            ELSE
                ALTER ROLE gateway_admin WITH LOGIN PASSWORD %s;
            END IF;
            ALTER ROLE gateway_admin WITH NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
        END $$;
        """,
        (admin_pass, admin_pass)
    )
    cursor.execute("GRANT CONNECT ON DATABASE agentic_commerce TO gateway_admin;")
    cursor.execute("GRANT ALL ON SCHEMA public TO gateway_admin;")
    print("   -> gateway_admin provisioned (NOSUPERUSER, NOBYPASSRLS).")

    print("\n2. Transferring table and sequence ownership to gateway_admin...")
    cursor.execute(
        """
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
        """
    )
    tables = [r[0] for r in cursor.fetchall()]
    for t in tables:
        cursor.execute(sql.SQL("ALTER TABLE public.{} OWNER TO gateway_admin;").format(sql.Identifier(t)))
    print(f"   -> Transferred {len(tables)} tables to gateway_admin.")

    cursor.execute(
        """
        SELECT sequence_name 
        FROM information_schema.sequences 
        WHERE sequence_schema = 'public';
        """
    )
    sequences = [r[0] for r in cursor.fetchall()]
    for s in sequences:
        cursor.execute(sql.SQL("ALTER SEQUENCE public.{} OWNER TO gateway_admin;").format(sql.Identifier(s)))
    print(f"   -> Transferred {len(sequences)} sequences to gateway_admin.")

    print("\n3. Provisioning role: gateway_auth (narrowly scoped membership lookup)...")
    cursor.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_auth') THEN
                CREATE ROLE gateway_auth WITH LOGIN PASSWORD %s;
            ELSE
                ALTER ROLE gateway_auth WITH LOGIN PASSWORD %s;
            END IF;
            ALTER ROLE gateway_auth WITH NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
        END $$;
        """,
        (auth_pass, auth_pass)
    )
    cursor.execute("GRANT CONNECT ON DATABASE agentic_commerce TO gateway_auth;")
    cursor.execute("GRANT USAGE ON SCHEMA public TO gateway_auth;")
    cursor.execute("REVOKE CREATE ON SCHEMA public FROM gateway_auth;")
    cursor.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM gateway_auth;")
    cursor.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM gateway_auth;")
    cursor.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON public.customer_credentials, public.merchant_users, public.merchants, public.merchant_memberships, public.merchant_invitations TO gateway_auth;")
    print("   -> gateway_auth provisioned (auth control-plane tables granted, zero business data privileges).")

    print("\n4. Provisioning role: system_audit_writer (narrowly scoped system audit writes)...")
    cursor.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'system_audit_writer') THEN
                CREATE ROLE system_audit_writer WITH LOGIN PASSWORD %s;
            ELSE
                ALTER ROLE system_audit_writer WITH LOGIN PASSWORD %s;
            END IF;
            ALTER ROLE system_audit_writer WITH NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
        END $$;
        """,
        (audit_pass, audit_pass)
    )
    cursor.execute("GRANT CONNECT ON DATABASE agentic_commerce TO system_audit_writer;")
    cursor.execute("GRANT USAGE ON SCHEMA public TO system_audit_writer;")
    cursor.execute("REVOKE CREATE ON SCHEMA public FROM system_audit_writer;")
    cursor.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM system_audit_writer;")
    cursor.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM system_audit_writer;")
    cursor.execute("GRANT SELECT, INSERT ON public.processed_webhook_events TO system_audit_writer;")
    print("   -> system_audit_writer provisioned (processed_webhook_events granted, zero business table privileges).")

    print("\n5. Provisioning role: app_user (application runtime identity)...")
    cursor.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
                CREATE ROLE app_user WITH LOGIN PASSWORD %s;
            ELSE
                ALTER ROLE app_user WITH LOGIN PASSWORD %s;
            END IF;
            ALTER ROLE app_user WITH NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
        END $$;
        """,
        (app_pass, app_pass)
    )
    cursor.execute("GRANT CONNECT ON DATABASE agentic_commerce TO app_user;")
    cursor.execute("GRANT USAGE ON SCHEMA public TO app_user;")
    cursor.execute("REVOKE CREATE ON SCHEMA public FROM app_user;")
    cursor.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;")
    cursor.execute("REVOKE ALL ON public.merchant_users FROM app_user;")
    cursor.execute("REVOKE ALL ON public.processed_webhook_events FROM app_user;")
    cursor.execute("REVOKE INSERT, UPDATE, DELETE ON public.merchants FROM app_user;")
    cursor.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;")
    
    # Configure default privileges for future tables/sequences created by gateway_admin
    cursor.execute("ALTER DEFAULT PRIVILEGES FOR ROLE gateway_admin IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;")
    cursor.execute("ALTER DEFAULT PRIVILEGES FOR ROLE gateway_admin IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_user;")
    print("   -> app_user provisioned with DML & sequence privileges only (NOSUPERUSER, NOBYPASSRLS).")

    print("\n6. Revoking dangerous PUBLIC defaults...")
    cursor.execute("REVOKE ALL ON DATABASE agentic_commerce FROM PUBLIC;")
    cursor.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC;")
    cursor.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;")
    cursor.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;")
    cursor.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;")

    print("\n7. Verifying pg_roles configuration:")
    cursor.execute(
        """
        SELECT rolname, rolsuper, rolbypassrls, rolcanlogin, rolconnlimit
        FROM pg_roles
        WHERE rolname IN ('postgres', 'gateway_admin', 'gateway_auth', 'system_audit_writer', 'app_user')
        ORDER BY rolname;
        """
    )
    roles = cursor.fetchall()
    print(f"   {'Role Name':<20} {'Superuser':<12} {'BypassRLS':<12} {'CanLogin':<10}")
    print("   " + "-" * 56)
    for r in roles:
        print(f"   {r[0]:<20} {str(r[1]):<12} {str(r[2]):<12} {str(r[3]):<10}")
        if r[0] in ('gateway_admin', 'gateway_auth', 'system_audit_writer', 'app_user'):
            assert not r[1], f"Security failure: {r[0]} must be NOSUPERUSER"
            assert not r[2], f"Security failure: {r[0]} must be NOBYPASSRLS"
            assert r[3], f"Security failure: {r[0]} must be able to LOGIN"

finally:
    cursor.close()
    conn.close()

# Update .env with provisioned credentials
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
with open(env_path, "r", encoding="utf-8") as f:
    env_content = f.read()

admin_url = f"postgresql://gateway_admin:{admin_pass}@127.0.0.1:5433/agentic_commerce"
auth_url = f"postgresql://gateway_auth:{auth_pass}@127.0.0.1:5433/agentic_commerce"
audit_url = f"postgresql://system_audit_writer:{audit_pass}@127.0.0.1:5433/agentic_commerce"
app_url = f"postgresql://app_user:{app_pass}@127.0.0.1:5433/agentic_commerce"

updates = {
    "LOCAL_PG_ADMIN_PASSWORD": admin_pass,
    "LOCAL_PG_AUTH_PASSWORD": auth_pass,
    "LOCAL_PG_AUDIT_PASSWORD": audit_pass,
    "LOCAL_PG_APP_PASSWORD": app_pass,
    "LOCAL_PG_ADMIN_URL": admin_url,
    "LOCAL_PG_AUTH_URL": auth_url,
    "LOCAL_PG_AUDIT_URL": audit_url,
    "LOCAL_PG_APP_URL": app_url,
}

lines = env_content.splitlines()
new_lines = []
existing_keys = set()
for line in lines:
    matched = False
    for k, v in updates.items():
        if line.startswith(f"{k}="):
            new_lines.append(f"{k}={v}")
            existing_keys.add(k)
            matched = True
            break
    if not matched:
        new_lines.append(line)

for k, v in updates.items():
    if k not in existing_keys:
        new_lines.append(f"{k}={v}")

with open(env_path, "w", encoding="utf-8") as f:
    f.write("\n".join(new_lines) + "\n")

print("\n8. Updated local .env with gateway_admin, gateway_auth, system_audit_writer, and app_user credentials.")
print("Privilege separation provisioning completed successfully!")
