"""
Phase P0.4: Secure Execution, Concurrency Controls & Saga Rollback Tests.

Validates ADR-02 Concurrency Specifications:
1. High-Concurrency Stock Decrement (VULN-03 Elimination):
   Multi-threaded race for the last item in inventory. Exactly 1 wins, remaining fail. Stock never drops below 0.
2. High-Concurrency Wallet Debit (VULN-04 Elimination):
   Multi-threaded race against customer balance. Exactly 1 wins, remaining fail. Balance never drops below 0.
3. Saga Compensating Rollback Invariant:
   If wallet debit fails after stock decrement, inventory stock is automatically restored.
4. Concurrent Purchase Confirmation & Idempotency:
   Simultaneous confirmation requests for the same token execute payment and stock decrement exactly once.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.agent.service import confirm_purchase, execute_purchase
from app.catalog.service import _ensure_catalog_db_initialized, decrement_stock, get_product, restore_stock
from app.db import get_db_connection
from app.main import app
from app.payment import PaymentResult
from app.wallet.store import wallet_store

client = TestClient(app)


# ══════════════════════════════════════════════════════════════════════════════
# 1. High-Concurrency Inventory Stock Decrement (No Overselling)
# ══════════════════════════════════════════════════════════════════════════════

def test_concurrent_stock_decrement_eliminates_overselling():
    """
    Simulates 10 concurrent threads racing to purchase the last 1 remaining item.
    ADR-02 Invariant: Exactly 1 thread succeeds; 9 fail with stock exhaustion.
    Final stock MUST equal 0, never negative.
    """
    _ensure_catalog_db_initialized()

    # Set KB001 stock to exactly 1
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE catalog_products SET stock = 1, status = 'ACTIVE' WHERE id = 'KB001';")
        conn.commit()

    results = []

    def attempt_decrement():
        return decrement_stock("KB001", quantity=1)

    # Launch 10 concurrent threads simultaneously
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_decrement) for _ in range(10)]
        for f in as_completed(futures):
            results.append(f.result())

    success_count = sum(1 for r in results if r is True)
    failure_count = sum(1 for r in results if r is False)

    assert success_count == 1, f"Expected exactly 1 successful decrement, got {success_count}"
    assert failure_count == 9, f"Expected 9 failed decrements, got {failure_count}"

    # Verify final stock and status in database
    product = get_product("KB001")
    assert product.stock == 0
    assert product.status == "OUT_OF_STOCK"


# ══════════════════════════════════════════════════════════════════════════════
# 2. High-Concurrency Wallet Debit (No Double-Spending)
# ══════════════════════════════════════════════════════════════════════════════

def test_concurrent_wallet_debit_eliminates_double_spending():
    """
    Simulates 10 concurrent threads attempting to debit ₹800.00 from a ₹1,000.00 wallet.
    ADR-02 Invariant: Exactly 1 thread succeeds; 9 fail with insufficient balance.
    Final balance MUST equal ₹200.00, never negative.
    """
    wallet_store.set_balance("CUST001", 1000.0)

    results = []

    def attempt_debit():
        success, remaining, msg = wallet_store.debit("CUST001", 800.0)
        return success, remaining

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_debit) for _ in range(10)]
        for f in as_completed(futures):
            results.append(f.result())

    successes = [r for r in results if r[0] is True]
    failures = [r for r in results if r[0] is False]

    assert len(successes) == 1, f"Expected exactly 1 successful debit, got {len(successes)}"
    assert len(failures) == 9, f"Expected 9 failed debits, got {len(failures)}"

    final_balance = wallet_store.get_balance("CUST001")
    assert abs(final_balance - 200.0) < 0.01


# ══════════════════════════════════════════════════════════════════════════════
# 3. Saga Compensating Rollback (Stock Restoration on Payment Failure)
# ══════════════════════════════════════════════════════════════════════════════

def test_saga_rollback_restores_stock_if_wallet_debit_fails():
    """
    If customer wallet balance is insufficient, stock decremented during the flow
    MUST be restored immediately via Saga compensating rollback (restore_stock).
    """
    _ensure_catalog_db_initialized()

    # Set initial stock to 5
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE catalog_products SET stock = 5, status = 'ACTIVE' WHERE id = 'FD001';")
        conn.commit()

    # Set customer wallet balance to ₹0 (insufficient to buy FD001 at ₹349.00)
    wallet_store.set_balance("CUST001", 0.0)

    with patch("app.agent.service.create_order_for_approved") as mock_pay:
        mock_pay.return_value = PaymentResult(status="created", razorpay_order_id="order_test_saga")

        res = execute_purchase(
            customer_id="CUST001",
            product_id="FD001",
            quantity=1,
        )

    # Must be marked payment failed due to wallet balance failure
    assert res.decision == "PAYMENT_FAILED"
    assert "wallet debit failed" in res.reason.lower()

    # Crucial Saga invariant: stock must remain 5, not 4!
    product = get_product("FD001")
    assert product.stock == 5, f"Stock was not restored! Expected 5, got {product.stock}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Concurrent Confirmation Idempotency
# ══════════════════════════════════════════════════════════════════════════════

def test_concurrent_confirmation_replay_idempotency():
    """
    Two concurrent requests executing confirm_purchase with the same token
    must not result in duplicate stock decrements or double charges.
    """
    _ensure_catalog_db_initialized()

    # Seed stock to 10 and wallet to 10,000
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE catalog_products SET stock = 10, status = 'ACTIVE' WHERE id = 'KB001';")
        conn.commit()
    wallet_store.set_balance("CUST001", 10000.0)

    # Propose gated purchase for KB001 (₹1,499.00 >= ₹500)
    proposal = execute_purchase(
        customer_id="CUST001",
        product_id="KB001",
        quantity=1,
    )
    token = proposal.confirmation_token
    assert token is not None

    with patch("app.agent.service.create_order_for_approved") as mock_pay:
        mock_pay.return_value = PaymentResult(
            status="captured",
            razorpay_order_id="order_concurrent_test_1",
            payment_method="auto_debit",
        )

        results = []

        def run_confirm():
            return confirm_purchase(confirmation_token=token)

        # Run 2 parallel confirm requests
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run_confirm) for _ in range(2)]
            for f in as_completed(futures):
                results.append(f.result())

    # Both return successfully (one through execution, one through cached idempotency replay)
    assert len(results) == 2
    for r in results:
        assert r.decision == "APPROVED"

    # Stock must have decremented by exactly 1 (from 10 to 9, NOT 8!)
    prod = get_product("KB001")
    assert prod.stock == 9, f"Expected stock 9, got {prod.stock}"

    # Wallet must have debited exactly 1,499.00 (from 10,000 to 8,501, NOT 7,002!)
    bal = wallet_store.get_balance("CUST001")
    assert abs(bal - (10000.0 - 1499.0)) < 0.01


def test_wallet_debit_authoritative_integer_paise_boundary():
    """Verify that wallet debit evaluates strictly on integer paise without float threshold leakage."""
    wallet_store.set_balance("CUST_BOUNDARY", 100.00)
    assert wallet_store.get_balance_paise("CUST_BOUNDARY") == 10000

    # 1. Attempt to debit ₹100.01 (10,001 paise) -> MUST fail
    success, rem, msg = wallet_store.debit("CUST_BOUNDARY", 100.01)
    assert success is False
    assert rem == 100.0
    assert wallet_store.get_balance_paise("CUST_BOUNDARY") == 10000

    # 2. Attempt to debit ₹100.00 (10,000 paise) -> MUST succeed
    success, rem, msg = wallet_store.debit("CUST_BOUNDARY", 100.00)
    assert success is True
    assert rem == 0.0
    assert wallet_store.get_balance_paise("CUST_BOUNDARY") == 0


def test_audit_daily_spend_paise_exact_aggregation():
    """Verify that get_daily_spend_paise sums integer paise without binary float accumulation drift."""
    from uuid import uuid4
    from app.audit import audit_store

    cust_id = f"CUST_ACC_{uuid4().hex[:6]}"
    # Record 3 transactions with fractional amounts
    audit_store.write_proposal(
        transaction_id=str(uuid4()),
        customer_id=cust_id,
        product_id="KB001",
        merchant_id="MERCH_ELEC",
        quantity=1,
        amount=33.33,
        decision="APPROVED",
        decision_reason="Approved",
        amount_paise=3333,
    )
    audit_store.write_proposal(
        transaction_id=str(uuid4()),
        customer_id=cust_id,
        product_id="KB001",
        merchant_id="MERCH_ELEC",
        quantity=1,
        amount=33.33,
        decision="APPROVED",
        decision_reason="Approved",
        amount_paise=3333,
    )
    audit_store.write_proposal(
        transaction_id=str(uuid4()),
        customer_id=cust_id,
        product_id="KB001",
        merchant_id="MERCH_ELEC",
        quantity=1,
        amount=33.34,
        decision="APPROVED",
        decision_reason="Approved",
        amount_paise=3334,
    )

    paise_total = audit_store.get_daily_spend_paise(cust_id)
    assert paise_total == 10000  # 3333 + 3333 + 3334 = 10,000 paise exactly
    inr_total = audit_store.get_daily_spend(cust_id)
    assert inr_total == 100.0

