"""
Integration tests for Phase 5 — Razorpay Test Mode payment integration.

All tests in this file mock `app.payment.razorpay_client.create_order` so that
no real network calls are made in the default pytest run. The one exception is
`test_real_razorpay_api`, which is marked `@pytest.mark.integration` and skipped
by default — run it manually with real Test Mode keys to verify pre-demo.

Mock target: `app.payment.razorpay_client.create_order`
"""
import hashlib
import hmac
import json
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from app.audit import audit_store
from app.main import app
from app.payment.service import _rupees_to_paise, create_order_for_approved

client = TestClient(app)

_ADMIN_HEADERS = {"X-Admin-API-Key": "test-admin-secret-key"}

# ─── Mock target path ──────────────────────────────────────────────────────────
_CREATE_ORDER = "app.payment.razorpay_client.create_order"

# ─── Canonical fake Razorpay order response ────────────────────────────────────
_FAKE_ORDER = {
    "id": "order_TestFakeABC123",
    "entity": "order",
    "amount": 149900,
    "currency": "INR",
    "status": "created",
    "receipt": "some-txn-id",
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. Rupee → Paise conversion (pure unit tests, no HTTP)
# ══════════════════════════════════════════════════════════════════════════════

def test_rupee_to_paise_kb001():
    """KB001: ₹1,499.00 → 149900 paise (exact integer)."""
    assert _rupees_to_paise(1499.0) == 149900


def test_rupee_to_paise_fd001():
    """FD001: ₹349.00 → 34900 paise."""
    assert _rupees_to_paise(349.0) == 34900


def test_rupee_to_paise_mn001():
    """MN001: ₹4,999.00 → 499900 paise (over-limit product, conversion still correct)."""
    assert _rupees_to_paise(4999.0) == 499900


def test_rupee_to_paise_rounding():
    """Floating-point edge: ₹10.005 rounds to 1001 paise, not truncated to 1000."""
    assert _rupees_to_paise(10.005) == 1001


# ══════════════════════════════════════════════════════════════════════════════
# 2. APPROVED purchase → Razorpay order created
# ══════════════════════════════════════════════════════════════════════════════

def test_approved_purchase_creates_order():
    """
    CUST001 + FD001 (₹349, within mandate and < ₹500 threshold) → APPROVED.
    Razorpay order created; response includes PaymentResult with status='created'
    and a non-empty razorpay_order_id.
    """
    with patch(_CREATE_ORDER, return_value=_FAKE_ORDER) as mock_create:
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "FD001",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "APPROVED"
    assert data["product_id"] == "FD001"
    assert data["amount"] == 349.0

    # Payment field present and successful
    assert data["payment"] is not None
    assert data["payment"]["status"] == "captured"
    assert data["payment"]["razorpay_order_id"] == "order_TestFakeABC123"
    assert data["payment"]["razorpay_payment_id"] is not None
    assert data["payment"]["razorpay_payment_id"].startswith("pay_mandate_")
    assert data["payment"]["error"] is None

    # Razorpay was called exactly once
    mock_create.assert_called_once()


def test_autopay_immediate_rail_settlement_captured_with_payment_id():
    """
    Verifies Option 1: Automatic Rail Settlement in Auto-Pay.
    Approved auto-pay transactions immediately settle on the payment rail to 'captured'
    with an authentic 'pay_mandate_...' payment ID and unbroken cryptographic audit ledger.
    """
    with patch(_CREATE_ORDER, return_value={"id": "order_AutoSettled_999", "status": "created"}):
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "FD003",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "APPROVED"
    assert data["amount"] == 199.0
    txn_id = data["transaction_id"]

    # Payment response fields
    payment = data["payment"]
    assert payment is not None
    assert payment["status"] == "captured"
    assert payment["razorpay_order_id"] == "order_AutoSettled_999"
    assert payment["razorpay_payment_id"] is not None
    assert payment["razorpay_payment_id"].startswith("pay_mandate_")
    assert payment["payment_method"] == "auto_debit"

    # Verify audit ledger record reflects captured status and razorpay_payment_id
    audit_resp = client.get(f"/audit/{txn_id}", headers=_ADMIN_HEADERS)
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    assert audit_data["transaction_id"] == txn_id
    assert audit_data["decision"] == "APPROVED"
    assert audit_data["payment_status"] == "captured"
    assert audit_data["razorpay_order_id"] == "order_AutoSettled_999"
    assert audit_data["razorpay_payment_id"] == payment["razorpay_payment_id"]

    # Cryptographic integrity check
    verify_resp = client.get("/audit/verify", headers=_ADMIN_HEADERS)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True


def test_approved_contains_transaction_id():
    """Response for APPROVED purchase includes a non-empty transaction_id UUID."""
    with patch(_CREATE_ORDER, return_value=_FAKE_ORDER):
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "FD001",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    data = response.json()
    assert data["decision"] == "APPROVED"
    txn_id = data.get("transaction_id")
    assert txn_id is not None
    assert isinstance(txn_id, str)
    assert len(txn_id) == 36  # UUID4 format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx


def test_transaction_id_passed_as_receipt():
    """
    The gateway's transaction_id is forwarded to Razorpay as the `receipt` field,
    enabling cross-system tracing in the Razorpay dashboard.
    """
    captured = {}

    def capture_create_order(amount_paise, receipt, notes):
        captured["receipt"] = receipt
        captured["amount_paise"] = amount_paise
        return _FAKE_ORDER

    with patch(_CREATE_ORDER, side_effect=capture_create_order):
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "FD001",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    data = response.json()
    assert data["decision"] == "APPROVED"
    # The receipt Razorpay received must equal the transaction_id in the response
    assert captured["receipt"] == data["transaction_id"]
    # Amount must be in paise: ₹349 → 34900
    assert captured["amount_paise"] == 34900


# ══════════════════════════════════════════════════════════════════════════════
# 3. REJECTED purchase → Razorpay never called
# ══════════════════════════════════════════════════════════════════════════════

def test_rejected_purchase_no_payment_call():
    """
    CUST001 + MN001 (₹4,999 > ₹2,000 mandate) → REJECTED.
    Razorpay order.create must never be called (no auto-debit); manual payment link may be provided.
    """
    with patch(_CREATE_ORDER) as mock_create:
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "MN001",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )
        mock_create.assert_not_called()

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "REJECTED"
    if data["payment"] is not None:
        assert data["payment"]["payment_method"] in ["razorpay_link", "gateway_escalation_checkout"]
        assert data["payment"]["payment_url"] is not None


def test_rejected_response_has_payment_link_or_null():
    """Rejected response provides manual checkout link/QR or null payment."""
    with patch(_CREATE_ORDER):
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "MN001",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    data = response.json()
    assert data["decision"] == "REJECTED"
    assert "payment" in data
    if data["payment"] is not None:
        assert data["payment"]["qr_code_url"] is not None


def test_rejected_contains_transaction_id():
    """Even rejected purchases receive a transaction_id for audit trail purposes."""
    with patch(_CREATE_ORDER):
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "MN001",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    data = response.json()
    assert data["decision"] == "REJECTED"
    txn_id = data.get("transaction_id")
    assert txn_id is not None
    assert len(txn_id) == 36


# ══════════════════════════════════════════════════════════════════════════════
# 4. Razorpay SDK failure → isolated, decision is PAYMENT_FAILED
# ══════════════════════════════════════════════════════════════════════════════

def test_razorpay_failure_returns_failed_payment():
    """
    When the Razorpay SDK raises an exception on autonomous execution, the response is HTTP 200.
    The final decision is PAYMENT_FAILED and payment.status == 'failed'.
    """
    with patch(_CREATE_ORDER, side_effect=Exception("Razorpay network timeout")):
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "FD001",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "PAYMENT_FAILED"
    assert data["payment"] is not None
    assert data["payment"]["status"] == "failed"
    assert data["payment"]["razorpay_order_id"] is None
    assert "Razorpay network timeout" in data["payment"]["error"]


def test_service_create_order_success():
    """
    create_order_for_approved() returns PaymentResult(status='created') on SDK success.
    """
    with patch(_CREATE_ORDER, return_value=_FAKE_ORDER):
        result = create_order_for_approved(
            amount_inr=1499.0,
            receipt="txn-unit-test-001",
            customer_id="CUST001",
            product_id="KB001",
        )

    assert result.status == "created"
    assert result.razorpay_order_id == "order_TestFakeABC123"
    assert result.error is None


def test_service_create_order_failure_isolation():
    """
    create_order_for_approved() catches all SDK exceptions and returns
    PaymentResult(status='failed') — never re-raises.
    """
    with patch(_CREATE_ORDER, side_effect=ValueError("bad response")):
        result = create_order_for_approved(
            amount_inr=1499.0,
            receipt="txn-unit-test-002",
            customer_id="CUST001",
            product_id="KB001",
        )

    assert result.status == "failed"
    assert result.razorpay_order_id is None
    assert "bad response" in result.error


def test_service_create_order_missing_status_sets_status_unknown():
    """
    create_order_for_approved() sets status='status_unknown' and populates error
    when the Razorpay response dictionary omits the 'status' key.
    """
    with patch(_CREATE_ORDER, return_value={"id": "order_NoStatus123", "amount": 149900}):
        result = create_order_for_approved(
            amount_inr=1499.0,
            receipt="txn-unit-test-003",
            customer_id="CUST001",
            product_id="KB001",
        )

    assert result.status == "status_unknown"
    assert result.razorpay_order_id == "order_NoStatus123"
    assert "missing 'status' field" in result.error


def test_razorpay_missing_status_recorded_in_purchase_response():
    """
    HTTP /agent/purchase endpoint correctly surfaces status_unknown when
    Razorpay response is missing the 'status' key.
    """
    with patch(_CREATE_ORDER, return_value={"id": "order_NoStatus456"}):
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "FD001",
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    assert response.status_code == 200
    data = response.json()
    assert data["payment"] is not None
    assert data["payment"]["status"] == "status_unknown"
    assert data["payment"]["razorpay_order_id"] == "order_NoStatus456"
    assert "missing 'status' field" in data["payment"]["error"]


# ══════════════════════════════════════════════════════════════════════════════
# 5. Razorpay Webhook & Payment Verification Endpoints
# ══════════════════════════════════════════════════════════════════════════════

def test_webhook_payment_captured_valid_signature():
    """
    POST /payment/webhook with valid HMAC-SHA256 signature updates transaction to 'captured'.
    """
    import hmac
    import hashlib
    import json

    from app.payment.router import get_webhook_secret
    secret = get_webhook_secret()
    payload_dict = {
        "event": "payment.captured",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_WebHookTest123",
                    "order_id": "order_TestFakeABC123",
                    "amount": 34900,
                    "status": "captured",
                    "notes": {
                        "transaction_id": "txn-test-webhook-capture-001"
                    }
                }
            }
        }
    }
    body_bytes = json.dumps(payload_dict).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    # Pre-seed proposal
    from app.audit import audit_store
    audit_store.write_proposal(
        transaction_id="txn-test-webhook-capture-001",
        customer_id="CUST001",
        product_id="FD001",
        merchant_id="MERCH_FOOD",
        quantity=1,
        amount=349.0,
        decision="APPROVED",
        decision_reason="Pre-seed for webhook test",
    )

    resp = client.post(
        "/payment/webhook",
        content=body_bytes,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["status"] == "ok"
    assert res_data["processed"] is True

    record = audit_store.get("txn-test-webhook-capture-001")
    assert record is not None
    assert record.payment_status == "captured"


def test_webhook_invalid_signature_returns_400():
    """
    POST /payment/webhook with invalid or missing signature returns 400 Bad Request.
    """
    resp = client.post(
        "/payment/webhook",
        content=b'{"event": "payment.captured"}',
        headers={"X-Razorpay-Signature": "invalid-sig", "Content-Type": "application/json"},
    )
    assert resp.status_code == 400


def test_webhook_duplicate_event_deduplication():
    """
    POST /payment/webhook with the same event ID returns deduplicated 200 OK without re-processing.
    """
    import hmac
    import hashlib
    import json

    from app.payment.router import get_webhook_secret
    secret = get_webhook_secret()
    payload_dict = {
        "event_id": "evt_dedup_test_999",
        "event": "payment.captured",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_WebHookDedup999",
                    "order_id": "order_Dedup999",
                    "amount": 34900,
                    "status": "captured",
                    "notes": {
                        "transaction_id": "txn-dedup-001"
                    }
                }
            }
        }
    }
    from app.audit import audit_store
    audit_store.write_proposal(
        transaction_id="txn-dedup-001",
        customer_id="CUST001",
        product_id="FD001",
        merchant_id="MERCH_FOOD",
        quantity=1,
        amount=349.0,
        decision="APPROVED",
        decision_reason="Pre-seed for dedup test",
    )

    body_bytes = json.dumps(payload_dict).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    # First delivery
    resp1 = client.post(
        "/payment/webhook",
        content=body_bytes,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json", "X-Razorpay-Event-Id": "evt_dedup_test_999"},
    )
    assert resp1.status_code == 200
    assert resp1.json()["deduplicated"] is False

    # Second delivery (Duplicate retry from Razorpay)
    resp2 = client.post(
        "/payment/webhook",
        content=body_bytes,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json", "X-Razorpay-Event-Id": "evt_dedup_test_999"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["deduplicated"] is True


def test_webhook_payment_failed_restores_inventory():
    """
    POST /payment/webhook on payment.failed automatically restores decremented stock for the product.
    """
    import hmac
    import hashlib
    import json
    from app.catalog.service import get_product, decrement_stock
    from app.audit import audit_store

    from app.payment.router import get_webhook_secret
    secret = get_webhook_secret()
    prod = get_product("HK001")
    initial_stock = prod.stock

    # Pre-seed transaction
    audit_store.write_proposal(
        transaction_id="txn-fail-restore-001",
        customer_id="CUST001",
        product_id="HK001",
        merchant_id="MERCH_ELEC",
        quantity=2,
        amount=998.0,
        decision="APPROVED",
        decision_reason="Pre-seed for failure restore test",
    )
    # Simulate stock decrement in DB
    decrement_stock("HK001", 2)
    assert get_product("HK001").stock == initial_stock - 2

    payload_dict = {
        "event_id": "evt_fail_test_777",
        "event": "payment.failed",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_WebHookFail777",
                    "order_id": "order_Fail777",
                    "amount": 99800,
                    "status": "failed",
                    "notes": {
                        "transaction_id": "txn-fail-restore-001"
                    }
                }
            }
        }
    }
    body_bytes = json.dumps(payload_dict).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    resp = client.post(
        "/payment/webhook",
        content=body_bytes,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json", "X-Razorpay-Event-Id": "evt_fail_test_777"},
    )
    assert resp.status_code == 200
    assert resp.json()["event"] == "payment.failed"

    # Inventory must be restored by +2 in database
    restored_prod = get_product("HK001")
    assert restored_prod.stock == initial_stock

    # Audit status must be failed
    record = audit_store.get("txn-fail-restore-001")
    assert record.payment_status == "failed"


def test_persistent_database_webhook_deduplication():
    """
    Verifies that webhook event deduplication is persisted in the database,
    returning 200 OK with deduplicated: True even across fresh memory state.
    """
    from app.payment.router import get_webhook_secret
    secret = get_webhook_secret()
    event_id = "evt_persistent_dedup_999"

    # Pre-record event in audit store
    audit_store.record_webhook_event(event_id)
    assert audit_store.is_webhook_processed(event_id) is True

    payload_dict = {
        "event_id": event_id,
        "event": "payment.captured",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_Persistent999",
                    "order_id": "order_Persistent999",
                    "amount": 10000,
                    "status": "captured",
                }
            }
        }
    }
    body_bytes = json.dumps(payload_dict).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    resp = client.post(
        "/payment/webhook",
        content=body_bytes,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json", "X-Razorpay-Event-Id": event_id},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["deduplicated"] is True
    assert data["processed"] is True


def test_auto_debit_wallet_settlement():
    """
    Verifies that policy-approved purchases successfully auto-debit the customer's
    pre-authorized mandate wallet balance.
    """
    from app.wallet.store import wallet_store
    wallet_store.set_balance("CUST001", 5000.0)
    initial_balance = wallet_store.get_balance("CUST001")

    with patch(_CREATE_ORDER, return_value=_FAKE_ORDER):
        response = client.post(
            "/agent/purchase",
            json={
                "customer_id": "CUST001",
                "product_id": "FD001",  # ₹349
                "quantity": 1,
            },
            headers=_ADMIN_HEADERS,
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "APPROVED"
    new_balance = wallet_store.get_balance("CUST001")
    assert new_balance == round(initial_balance - 349.0, 2)


def test_payment_link_paid_webhook_updates_ledger():
    """
    Verifies that when a user pays via a manual Razorpay Payment Link (payment_link.paid event),
    the audit ledger record is updated to captured/PAID with the Razorpay order ID.
    """
    txn_id = "txn-plink-test-123"
    audit_store.write_proposal(
        transaction_id=txn_id,
        customer_id="CUST001",
        product_id="MN001",
        merchant_id="MERCH_ELEC",
        quantity=1,
        amount=4999.0,
        decision="REJECTED",
        decision_reason="Exceeds mandate limit",
        idempotency_key="idemp-plink-123",
    )

    from app.payment.router import get_webhook_secret
    secret = get_webhook_secret()
    payload_dict = {
        "event": "payment_link.paid",
        "payload": {
            "payment_link": {
                "entity": {
                    "id": "plink_TestPLink456",
                    "reference_id": txn_id,
                    "amount": 499900,
                    "status": "paid",
                    "notes": {"transaction_id": txn_id},
                }
            },
            "payment": {
                "entity": {
                    "id": "pay_TestPayment789",
                    "amount": 499900,
                    "status": "captured",
                }
            }
        }
    }
    body_bytes = json.dumps(payload_dict).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    resp = client.post(
        "/payment/webhook",
        content=body_bytes,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json", "X-Razorpay-Event-Id": "evt_plink_paid_777"},
    )
    assert resp.status_code == 200
    assert resp.json()["processed"] is True

    record = audit_store.get(txn_id)
    assert record.payment_status == "captured"
    assert record.decision == "APPROVED"


def test_webhook_payment_failed_duplicate_restores_stock_exactly_once():
    """
    P0-E/P0-G: Verifies that multiple distinct failure webhooks (e.g. payment.failed followed by
    payment_link.cancelled or concurrent delivery) restore reserved inventory exactly once.
    """
    import hmac
    import hashlib
    import json
    from app.catalog.service import get_product, decrement_stock
    from app.audit import audit_store
    from app.payment.router import get_webhook_secret

    secret = get_webhook_secret()
    prod = get_product("HK001")
    initial_stock = prod.stock

    txn_id = "txn-fail-dedup-p0e-001"
    audit_store.write_proposal(
        transaction_id=txn_id,
        customer_id="CUST001",
        product_id="HK001",
        merchant_id="MERCH_ELEC",
        quantity=3,
        amount=1497.0,
        decision="APPROVED",
        decision_reason="Pre-seed for exactly-once compensation test",
    )
    # Simulate inventory reservation
    assert decrement_stock("HK001", 3) is True
    assert get_product("HK001").stock == initial_stock - 3

    # Webhook 1: payment.failed with event_id evt_fail_first
    payload_1 = {
        "event_id": "evt_fail_first_001",
        "event": "payment.failed",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_FailFirst001",
                    "order_id": "order_Fail001",
                    "amount": 149700,
                    "status": "failed",
                    "notes": {"transaction_id": txn_id},
                }
            }
        }
    }
    body_1 = json.dumps(payload_1).encode("utf-8")
    sig_1 = hmac.new(secret.encode("utf-8"), body_1, hashlib.sha256).hexdigest()

    resp_1 = client.post(
        "/payment/webhook",
        content=body_1,
        headers={"X-Razorpay-Signature": sig_1, "Content-Type": "application/json", "X-Razorpay-Event-Id": "evt_fail_first_001"},
    )
    assert resp_1.status_code == 200
    assert get_product("HK001").stock == initial_stock

    # Webhook 2: payment_link.cancelled with different event_id evt_cancel_second
    payload_2 = {
        "event_id": "evt_cancel_second_002",
        "event": "payment_link.cancelled",
        "payload": {
            "payment_link": {
                "entity": {
                    "id": "plink_Cancel002",
                    "order_id": "order_Fail001",
                    "status": "cancelled",
                    "notes": {"transaction_id": txn_id},
                }
            }
        }
    }
    body_2 = json.dumps(payload_2).encode("utf-8")
    sig_2 = hmac.new(secret.encode("utf-8"), body_2, hashlib.sha256).hexdigest()

    resp_2 = client.post(
        "/payment/webhook",
        content=body_2,
        headers={"X-Razorpay-Signature": sig_2, "Content-Type": "application/json", "X-Razorpay-Event-Id": "evt_cancel_second_002"},
    )
    assert resp_2.status_code == 200

    # CRITICAL: Stock MUST NOT be incremented a second time (phantom stock prevention)
    assert get_product("HK001").stock == initial_stock


def test_webhook_payment_failed_on_rejected_transaction_does_not_inflate_stock():
    """
    P0-E/P0-G: Verifies that failure webhooks on transactions that were REJECTED (where stock
    was never reserved/decremented) do not restore or inflate inventory.
    """
    import hmac
    import hashlib
    import json
    from app.catalog.service import get_product
    from app.audit import audit_store
    from app.payment.router import get_webhook_secret

    secret = get_webhook_secret()
    prod = get_product("HK001")
    initial_stock = prod.stock

    txn_id = "txn-fail-rejected-p0e-002"
    audit_store.write_proposal(
        transaction_id=txn_id,
        customer_id="CUST001",
        product_id="HK001",
        merchant_id="MERCH_ELEC",
        quantity=5,
        amount=2495.0,
        decision="REJECTED",
        decision_reason="Exceeded limit, stock was never decremented",
    )
    # Confirm initial stock is unchanged
    assert get_product("HK001").stock == initial_stock

    payload = {
        "event_id": "evt_fail_rejected_003",
        "event": "payment.failed",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_FailRej003",
                    "order_id": "order_Rej003",
                    "amount": 249500,
                    "status": "failed",
                    "notes": {"transaction_id": txn_id},
                }
            }
        }
    }
    body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    resp = client.post(
        "/payment/webhook",
        content=body,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json", "X-Razorpay-Event-Id": "evt_fail_rejected_003"},
    )
    assert resp.status_code == 200

    # Stock MUST NOT be inflated
    assert get_product("HK001").stock == initial_stock
    # Transaction payment_status marked failed
    record = audit_store.get(txn_id)
    assert record.payment_status == "failed"


def test_webhook_unprocessed_if_handler_raises_error():
    """
    P0-E: Verifies that if webhook handler processing fails before completion,
    the event is NOT marked as processed, preserving retryability.
    """
    import hmac
    import hashlib
    import json
    from unittest.mock import patch
    from app.audit import audit_store
    from app.payment.router import get_webhook_secret

    secret = get_webhook_secret()
    event_id = "evt_crash_retry_004"
    txn_id = "txn-crash-retry-004"

    audit_store.write_proposal(
        transaction_id=txn_id,
        customer_id="CUST001",
        product_id="HK001",
        merchant_id="MERCH_ELEC",
        quantity=1,
        amount=499.0,
        decision="APPROVED",
        decision_reason="Pre-seed for crash test",
    )

    payload = {
        "event_id": event_id,
        "event": "payment.captured",
        "payload": {
            "payment": {
                "entity": {
                    "id": "pay_Crash004",
                    "order_id": "order_Crash004",
                    "amount": 49900,
                    "status": "captured",
                    "notes": {"transaction_id": txn_id},
                }
            }
        }
    }
    body = json.dumps(payload).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    with patch.object(audit_store, "update_payment_outcome", side_effect=RuntimeError("Simulated DB Crash")):
        try:
            client.post(
                "/payment/webhook",
                content=body,
                headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json", "X-Razorpay-Event-Id": event_id},
            )
        except RuntimeError:
            pass

    # Verify event_id is NOT marked as processed in DB
    assert audit_store.is_webhook_processed(event_id) is False




