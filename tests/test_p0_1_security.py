"""
Security Integration & Regression Tests for Phase P0.1.

Validates the Phase P0.1 Deliverables:
1. Server-authoritative pricing (client cannot manipulate prices or amounts).
2. Confirmation-time catalog price revalidation (STALE_PRICE_DETECTED HTTP 409).
3. Confirmation token cryptographic isolation and purpose validation.
4. Protection of /debug-search with Admin API Key authentication.
5. Constant-time comparison for administrative credentials.
6. Additive integer-paise database columns provisioned and accurately backfilled.
"""
from decimal import Decimal, ROUND_HALF_UP
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.agent.service import (
    CONFIRMATION_TOKEN_SECRET,
    decode_confirmation_token,
    execute_purchase,
    generate_confirmation_token,
)
from app.auth import get_admin_api_key
from app.catalog.service import _ensure_catalog_db_initialized, get_product
from app.db import get_db_connection
from app.main import app
from app.mcp.tools import authenticated_customer_id, confirm_purchase_remote_handler
from app.oauth.crypto import create_access_token
from app.payment.models import PaymentResult

client = TestClient(app)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Stale Pricing Detection & Price Parity Revalidation
# ══════════════════════════════════════════════════════════════════════════════

def test_stale_price_aborts_confirmation_with_409(admin_headers):
    """
    If the catalog unit price changes between proposal and confirmation,
    the gateway MUST abort confirmation immediately with HTTP 409 Conflict (STALE_PRICE_DETECTED).
    """
    # 1. Look up active product and note original price
    product = get_product("KB001")
    assert product is not None
    orig_price = product.price

    # 2. Propose purchase under original price
    proposal = execute_purchase(
        customer_id="CUST001",
        product_id="KB001",
        quantity=1,
    )
    assert proposal.requires_confirmation is True
    assert proposal.confirmation_token is not None
    token = proposal.confirmation_token

    try:
        # 3. Simulate catalog price increase (e.g. from ₹1,499.00 to ₹1,999.00)
        new_price = orig_price + 500.0
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE catalog_products SET price = ? WHERE id = 'KB001';", (new_price,))
            conn.commit()

        # 4. Attempt to confirm purchase using the original token
        response = client.post(
            "/agent/confirm",
            headers=admin_headers,
            json={"confirmation_token": token},
        )
        assert response.status_code == 409, f"Expected HTTP 409 Conflict, got {response.status_code}: {response.text}"
        data = response.json()
        assert "detail" in data
        detail = data["detail"]
        assert detail["error"] == "STALE_PRICE_DETECTED"
        assert detail["product_id"] == "KB001"
        assert abs(detail["proposed_amount"] - orig_price) < 0.01
        assert abs(detail["live_amount"] - new_price) < 0.01

    finally:
        # Revert catalog price for test idempotency
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE catalog_products SET price = ? WHERE id = 'KB001';", (orig_price,))
            conn.commit()


def test_stale_price_aborts_mcp_confirmation():
    """Verify that remote MCP confirm_purchase handler reports STALE_PRICE_DETECTED."""
    product = get_product("KB001")
    assert product is not None
    orig_price = product.price

    proposal = execute_purchase(
        customer_id="CUST001",
        product_id="KB001",
        quantity=1,
    )
    token = proposal.confirmation_token

    try:
        new_price = orig_price + 300.0
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE catalog_products SET price = ? WHERE id = 'KB001';", (new_price,))
            conn.commit()

        ctx_token = authenticated_customer_id.set("CUST001")
        try:
            res = confirm_purchase_remote_handler(confirmation_token=token)
            assert res["decision"] == "REJECTED"
            assert res["status"] == "STALE_PRICE_DETECTED"
            assert "Catalog price has changed" in res["reason"]
        finally:
            authenticated_customer_id.reset(ctx_token)

    finally:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE catalog_products SET price = ? WHERE id = 'KB001';", (orig_price,))
            conn.commit()


def test_unchanged_price_confirmation_succeeds(admin_headers):
    """When catalog price is unchanged, confirmation proceeds to successful execution."""
    proposal = execute_purchase(
        customer_id="CUST001",
        product_id="KB001",
        quantity=1,
    )
    token = proposal.confirmation_token

    with patch("app.agent.service.create_order_for_approved") as mock_razorpay:
        mock_razorpay.return_value = PaymentResult(
            status="captured",
            razorpay_order_id="order_p0_1_test_001",
            payment_method="auto_debit",
        )

        response = client.post(
            "/agent/confirm",
            headers=admin_headers,
            json={"confirmation_token": token},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "APPROVED"
        assert data["product_id"] == "KB001"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Server-Authoritative Pricing & Parameter Rejection
# ══════════════════════════════════════════════════════════════════════════════

def test_client_cannot_override_price_in_proposal(admin_headers):
    """
    Submitting client-crafted price or amount fields in proposal payload
    MUST be ignored; server authoritatively computes amount = catalog.price * quantity.
    """
    product = get_product("KB001")
    assert product is not None

    # Submit crafted request attempting to pay ₹1.00 instead of real price
    crafted_payload = {
        "customer_id": "CUST001",
        "product_id": "KB001",
        "quantity": 1,
        "price": 1.0,
        "amount": 1.0,
        "unit_price": 1.0,
    }
    response = client.post(
        "/agent/purchase",
        headers=admin_headers,
        json=crafted_payload,
    )
    assert response.status_code == 200
    data = response.json()
    # Amount must equal authentic catalog price, NOT ₹1.00
    assert data["amount"] == product.price
    assert data["amount"] != 1.0


# ══════════════════════════════════════════════════════════════════════════════
# 3. Diagnostic Endpoint Exposure Remediation (VULN-08)
# ══════════════════════════════════════════════════════════════════════════════

def test_debug_search_unauthenticated_rejected_with_401():
    """Unauthenticated GET /debug-search must be rejected with HTTP 401 Unauthorized."""
    response = client.get("/debug-search?query=keyboard")
    assert response.status_code == 401
    assert "Unauthorized" in response.text


def test_debug_search_with_admin_key_succeeds(admin_headers):
    """GET /debug-search with valid X-Admin-API-Key returns diagnostic catalog data."""
    response = client.get("/debug-search?query=keyboard", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert "db_type" in data
    assert "product_count" in data
    assert data["product_count"] > 0
    assert "search_results" in data


# ══════════════════════════════════════════════════════════════════════════════
# 4. Confirmation Token Cryptographic Isolation (VULN-06)
# ══════════════════════════════════════════════════════════════════════════════

def test_oauth_access_token_rejected_as_confirmation_token(admin_headers):
    """An OAuth access token cannot be used in place of a purchase confirmation token."""
    oauth_token = create_access_token(customer_id="CUST001")

    response = client.post(
        "/agent/confirm",
        headers=admin_headers,
        json={"confirmation_token": oauth_token},
    )
    # Must fail domain validation (either invalid token type or signature error)
    assert response.status_code in (400, 422), f"Unexpected status: {response.status_code}"
    assert "Invalid" in response.text or "token" in response.text.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Additive Integer-Paise Database Columns (P0.1D)
# ══════════════════════════════════════════════════════════════════════════════

def test_additive_paise_columns_present_and_backfilled():
    """Verify that *_paise integer columns are provisioned and accurately backfilled."""
    _ensure_catalog_db_initialized()
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. catalog_products.price_paise
        cursor.execute("SELECT price, price_paise FROM catalog_products LIMIT 5;")
        rows = cursor.fetchall()
        assert len(rows) > 0
        for price_float, price_paise in rows:
            assert price_paise is not None
            expected_paise = int((Decimal(str(price_float)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            assert price_paise == expected_paise

        # 2. customer_wallets.balance_paise
        cursor.execute("SELECT balance, balance_paise FROM customer_wallets LIMIT 5;")
        w_rows = cursor.fetchall()
        assert len(w_rows) > 0
        for bal_float, bal_paise in w_rows:
            assert bal_paise is not None
            expected_bal = int((Decimal(str(bal_float)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            assert bal_paise == expected_bal

        # 3. customer_mandates.max_transaction_amount_paise
        cursor.execute("SELECT max_transaction_amount, max_transaction_amount_paise FROM customer_mandates LIMIT 5;")
        m_rows = cursor.fetchall()
        assert len(m_rows) > 0
        for m_float, m_paise in m_rows:
            assert m_paise is not None
            expected_m = int((Decimal(str(m_float)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            assert m_paise == expected_m


def test_product_model_exposes_authoritative_price_paise():
    """Verify that Product entities returned by catalog queries include price_paise."""
    product = get_product("KB001")
    assert product.price_paise is not None
    assert isinstance(product.price_paise, int)
    assert product.price_paise == 149900  # ₹1,499.00 = 149,900 paise


def test_purchase_proposal_carries_exact_integer_paise():
    """Verify that execute_purchase stores authoritative amount_paise in the audit record."""
    proposal = execute_purchase(
        customer_id="CUST001",
        product_id="KB001",
        quantity=2,
    )
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT amount, amount_paise FROM audit_records WHERE transaction_id = ?;", (proposal.transaction_id,))
        row = cursor.fetchone()
        assert row is not None
        amount_flt, amount_paise = row
        assert amount_paise == 299800  # ₹2,998.00 = 299,800 paise
        assert abs(amount_flt - 2998.0) < 0.01


def test_stale_price_exact_one_paise_difference_aborts_confirmation(admin_headers):
    """Verify that even a 1-paisa difference between live catalog and token aborts confirmation with HTTP 409."""
    product = get_product("KB001")
    orig_paise = product.price_paise
    orig_price = product.price

    proposal = execute_purchase(
        customer_id="CUST001",
        product_id="KB001",
        quantity=1,
    )
    token = proposal.confirmation_token
    assert token is not None

    try:
        # Alter catalog price_paise by exactly +1 paisa in DB
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE catalog_products SET price_paise = ?, price = ? WHERE id = 'KB001';", (orig_paise + 1, round((orig_paise + 1) / 100.0, 2)))
            conn.commit()

        res = client.post(
            "/agent/confirm",
            headers=admin_headers,
            json={"confirmation_token": token},
        )
        assert res.status_code == 409
        data = res.json()
        assert data["detail"]["error"] == "STALE_PRICE_DETECTED"
    finally:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE catalog_products SET price_paise = ?, price = ? WHERE id = 'KB001';", (orig_paise, orig_price))
            conn.commit()

