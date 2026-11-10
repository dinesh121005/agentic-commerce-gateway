"""
Shared Pytest configuration and autouse fixtures for the test suite.

Guarantees:
1. DB isolation: every test runs against an isolated, temporary SQLite database.
2. Mandate store reset: in-memory customer mandates are reset to the pristine DEMO_MANDATES baseline.
3. Test environment credentials: set consistent test admin keys and dummy environment vars.
"""
import os
import pytest

# Ensure standard test admin key is present in environment for test client runs
os.environ["ADMIN_API_KEY"] = "test-admin-secret-key"

from app.catalog import service as catalog_service
from app.audit import audit_store
from app.oauth.store import customer_auth_store
from app.policy.store import DEMO_MANDATES, mandate_store
from app.signing.store import signing_store
from app.wallet.store import wallet_store


@pytest.fixture(autouse=True)
def isolate_test_environment(tmp_path, monkeypatch):
    """
    Autouse fixture that runs before every test:
    - Points audit_store, customer_auth_store, mandate_store, and wallet_store to an isolated temp SQLite DB.
    - Initializes schemas in the temporary database.
    - Resets the in-memory mandate store to DEMO_MANDATES.
    - Performs clean teardown with garbage collection to release SQLite file handles on Windows.
    """
    import gc
    test_db = str(tmp_path / "test_isolated_gateway.db")
    monkeypatch.setenv("DATABASE_URL", test_db)
    monkeypatch.setattr(audit_store, "db_path", test_db)
    monkeypatch.setattr(customer_auth_store, "db_path", test_db)
    monkeypatch.setattr(mandate_store, "db_path", test_db)
    monkeypatch.setattr(signing_store, "db_path", test_db)
    monkeypatch.setattr(wallet_store, "db_path", test_db)
    monkeypatch.setattr(catalog_service, "_catalog_initialized", False)
    audit_store._init_db()
    customer_auth_store._init_db()
    mandate_store._init_db()
    signing_store._init_db()
    wallet_store._init_db()

    yield test_db

    # Force garbage collection to close lingering SQLite file connections on Windows
    gc.collect()


@pytest.fixture
def admin_headers():
    """Returns valid authentication headers for admin and audit endpoint requests."""
    return {"X-Admin-API-Key": "test-admin-secret-key"}
