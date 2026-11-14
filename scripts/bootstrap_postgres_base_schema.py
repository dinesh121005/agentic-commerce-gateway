"""
Bootstrap Base Schema on Local PostgreSQL 16.
Target: 127.0.0.1:5433 / agentic_commerce
"""
import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(override=False)

pg_url = os.environ.get("LOCAL_DATABASE_URL")
if not pg_url:
    pg_url = "postgresql://postgres:agentic_pg_local_dev_secret_2026@127.0.0.1:5433/agentic_commerce"

# Safety guard: ensure local connection only
if "127.0.0.1:5433" not in pg_url and "localhost:5433" not in pg_url:
    raise RuntimeError(f"Safety violation: Target is not local port 5433: {pg_url}")

os.environ["DATABASE_URL"] = pg_url

print(f"Connecting to local PostgreSQL 16 at: {pg_url.split('@')[1]}")

from app.catalog import service as catalog_service
from app.audit.store import audit_store
from app.merchant.store import merchant_store
from app.oauth.store import customer_auth_store
from app.policy.store import mandate_store
from app.signing.store import signing_store
from app.wallet.store import wallet_store
from app.db import get_db_connection

# Point store instances to PostgreSQL URL
for store in (audit_store, merchant_store, customer_auth_store, mandate_store, signing_store, wallet_store):
    store.db_path = pg_url
    store._initialized = False

catalog_service._catalog_initialized = False

print("1. Initializing merchant store tables (merchants, users, memberships, invitations)...")
merchant_store._init_db()

print("2. Initializing catalog service tables (catalog_products, relationships, recommendations)...")
catalog_service._ensure_catalog_db_initialized()

print("3. Initializing audit store tables (audit_records, audit_events, processed_webhook_events)...")
audit_store._init_db()

print("4. Initializing OAuth store tables (customer_credentials, refresh_tokens)...")
customer_auth_store._init_db()

print("5. Initializing policy store tables (customer_mandates)...")
mandate_store._init_db()

print("6. Initializing signing store tables (keys, challenges, signed_mandates, approvals)...")
signing_store._init_db()

print("7. Initializing wallet store tables (customer_wallets)...")
wallet_store._init_db()

print("\nVerifying created tables in agentic_commerce database:")
with get_db_connection(pg_url) as conn:
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        ORDER BY table_name;
        """
    )
    tables = [r[0] for r in cursor.fetchall()]
    for idx, t in enumerate(tables, 1):
        print(f"  {idx:2d}. {t}")

print(f"\nTotal tables bootstrapped: {len(tables)}")

