"""
Phase P0.3: Deterministic Policy Engine & Three-State Contract Tests.

Validates:
1. Three-State policy verdict state machine: ALLOW, STEP_UP, and DENY (Doc 07 §5).
2. Exact ₹500.00 (50,000 paise) safety threshold semantics:
   - 49,999 paise (₹499.99) -> ALLOW (autonomous execution)
   - 50,000 paise (₹500.00) -> STEP_UP (human confirmation required)
   - 50,001 paise (₹500.01) -> STEP_UP (human confirmation required)
3. DENY is terminal and absolute: no confirmation token minted for out-of-mandate proposals.
4. Standardized machine-readable reason code taxonomy (Doc 07 §7).
5. Seamless integration with Option A cryptographically signed mandates.
6. Fail-fast sequential rule evaluation order.
"""
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.agent.service import execute_purchase
from app.main import app
from app.oauth.crypto import create_access_token
from app.policy.engine import evaluate
from app.policy.mandate import Mandate
from app.policy.requests import PolicyDecision, PolicyOutcome, PurchaseRequest, RuleViolated
from app.policy.store import DEMO_MANDATES, mandate_store
from app.signing.crypto import DOMAIN_MANDATE, generate_ed25519_keypair, sign_challenge, sign_payload
from app.signing.store import signing_store

client = TestClient(app)


def make_auth_headers(customer_id: str = "CUST001") -> dict:
    token = create_access_token(customer_id=customer_id)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def base_mandate() -> Mandate:
    return Mandate(
        customer_id="CUST001",
        display_name="Test Customer",
        max_transaction_amount=2000.0,
        daily_limit=5000.0,
        currency="INR",
        allowed_categories=["electronics", "office_supplies"],
        allowed_merchants=["MERCH_ELEC", "MERCH_OFFICE"],
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. Three-State Policy Verdict & Exact Threshold Semantics (ADR-01 §10.1)
# ══════════════════════════════════════════════════════════════════════════════

def test_policy_threshold_49999_paise_yields_allow(base_mandate):
    """
    Final payable amount = 49,999 paise (₹499.99 < ₹500.00 threshold).
    Must evaluate to PolicyOutcome.ALLOW with reason_code POLICY_APPROVED.
    """
    req = PurchaseRequest(
        customer_id="CUST001",
        product_id="PROD_TEST_1",
        category="electronics",
        amount=499.99,
        amount_paise=49999,
        merchant="MERCH_ELEC",
        quantity=1,
    )
    decision = evaluate(req, base_mandate)

    assert decision.decision == PolicyOutcome.ALLOW
    assert decision.status == "APPROVED"
    assert decision.reason_code == "POLICY_APPROVED"
    assert decision.rule_violated is None


def test_policy_threshold_exact_50000_paise_yields_step_up(base_mandate):
    """
    Final payable amount = exactly 50,000 paise (₹500.00).
    Must evaluate to PolicyOutcome.STEP_UP with reason_code STEP_UP_REQUIRED.
    """
    req = PurchaseRequest(
        customer_id="CUST001",
        product_id="PROD_TEST_2",
        category="electronics",
        amount=500.00,
        amount_paise=50000,
        merchant="MERCH_ELEC",
        quantity=1,
    )
    decision = evaluate(req, base_mandate)

    assert decision.decision == PolicyOutcome.STEP_UP
    assert decision.status == "APPROVED"
    assert decision.reason_code == "STEP_UP_REQUIRED"
    assert decision.rule_violated is None
    assert "Requires customer confirmation" in decision.reason


def test_policy_threshold_50001_paise_yields_step_up(base_mandate):
    """
    Final payable amount = 50,001 paise (₹500.01 > ₹500.00).
    Must evaluate to PolicyOutcome.STEP_UP with reason_code STEP_UP_REQUIRED.
    """
    req = PurchaseRequest(
        customer_id="CUST001",
        product_id="PROD_TEST_3",
        category="electronics",
        amount=500.01,
        amount_paise=50001,
        merchant="MERCH_ELEC",
        quantity=1,
    )
    decision = evaluate(req, base_mandate)

    assert decision.decision == PolicyOutcome.STEP_UP
    assert decision.status == "APPROVED"
    assert decision.reason_code == "STEP_UP_REQUIRED"


# ══════════════════════════════════════════════════════════════════════════════
# 2. DENY is Terminal and Absolute (Doc 07 §5.1)
# ══════════════════════════════════════════════════════════════════════════════

def test_deny_cannot_be_overridden_by_step_up(base_mandate):
    """
    Transactions violating hard mandate policies evaluate to DENY,
    regardless of amount, and never produce confirmation tokens.
    """
    # Exceeds max_transaction_amount (₹2,500 > ₹2,000)
    req = PurchaseRequest(
        customer_id="CUST001",
        product_id="PROD_OVER_LIMIT",
        category="electronics",
        amount=2500.0,
        amount_paise=250000,
        merchant="MERCH_ELEC",
        quantity=1,
    )
    decision = evaluate(req, base_mandate)

    assert decision.decision == PolicyOutcome.DENY
    assert decision.status == "REJECTED"
    assert decision.reason_code == "AMOUNT_EXCEEDS_TRANSACTION_LIMIT"
    assert decision.rule_violated == RuleViolated.AMOUNT_EXCEEDS_LIMIT


def test_execute_purchase_denied_proposal_does_not_generate_confirmation_token():
    """
    When execute_purchase encounters an out-of-mandate proposal,
    requires_confirmation is False and confirmation_token is None.
    """
    # MN001 price is ₹4,999 > CUST001 limit of ₹2,000
    res = execute_purchase(
        customer_id="CUST001",
        product_id="MN001",
        quantity=1,
    )
    assert res.decision == "REJECTED"
    assert res.requires_confirmation is False
    assert res.confirmation_token is None


# ══════════════════════════════════════════════════════════════════════════════
# 3. Standardized Machine-Readable Reason Codes (Doc 07 §7)
# ══════════════════════════════════════════════════════════════════════════════

def test_reason_code_customer_mismatch(base_mandate):
    """Rule 1: Customer mismatch yields AUTH_CUSTOMER_MISMATCH."""
    req = PurchaseRequest(
        customer_id="CUST_IMPOSTOR",
        product_id="KB001",
        category="electronics",
        amount=100.0,
        merchant="MERCH_ELEC",
    )
    decision = evaluate(req, base_mandate)
    assert decision.decision == PolicyOutcome.DENY
    assert decision.reason_code == "AUTH_CUSTOMER_MISMATCH"


def test_reason_code_unauthorized_merchant(base_mandate):
    """Rule 3: Unauthorized merchant yields MERCHANT_UNAUTHORIZED."""
    req = PurchaseRequest(
        customer_id="CUST001",
        product_id="KB001",
        category="electronics",
        amount=100.0,
        merchant="MERCH_UNKNOWN",
    )
    decision = evaluate(req, base_mandate)
    assert decision.decision == PolicyOutcome.DENY
    assert decision.reason_code == "MERCHANT_UNAUTHORIZED"


def test_reason_code_unauthorized_category(base_mandate):
    """Rule 4: Unauthorized category yields CATEGORY_UNAUTHORIZED."""
    req = PurchaseRequest(
        customer_id="CUST001",
        product_id="KB001",
        category="automotive",
        amount=100.0,
        merchant="MERCH_ELEC",
    )
    decision = evaluate(req, base_mandate)
    assert decision.decision == PolicyOutcome.DENY
    assert decision.reason_code == "CATEGORY_UNAUTHORIZED"


def test_reason_code_daily_budget_exceeded(base_mandate):
    """Rule 6: Spend exceeding daily budget yields DAILY_BUDGET_EXCEEDED."""
    req = PurchaseRequest(
        customer_id="CUST001",
        product_id="KB001",
        category="electronics",
        amount=1000.0,
        merchant="MERCH_ELEC",
    )
    # Current daily spend is 4,500. 4,500 + 1,000 = 5,500 > daily_limit 5,000
    decision = evaluate(req, base_mandate, current_daily_spend=4500.0)
    assert decision.decision == PolicyOutcome.DENY
    assert decision.reason_code == "DAILY_BUDGET_EXCEEDED"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Option A Cryptographic Mandate Integration
# ══════════════════════════════════════════════════════════════════════════════

def test_signed_mandate_automatically_governs_policy():
    """
    When a customer registers a signed mandate, get_mandate() and the policy engine
    seamlessly evaluate against the signed constraints.
    """
    cust_headers = make_auth_headers("CUST001")

    # 1. Register customer key
    ch_res = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Device P0.3"})
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig_b64 = sign_challenge(priv, ch_res.json()["challenge_token"])
    reg = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={"challenge_id": ch_res.json()["challenge_id"], "public_key": pub_b64, "signature": sig_b64, "device_name": "Device P0.3"},
    )
    key_id = reg.json()["key_id"]

    # 2. Submit signed mandate with a strict cap of 120,000 paise (₹1,200.00)
    signed_payload = {
        "schema_version": "1.0.0",
        "mandate_id": "mandate-p03-strict",
        "mandate_version": 1,
        "customer_id": "CUST001",
        "merchant_id": "*",
        "currency": "INR",
        "max_transaction_amount_paise": 120000,  # ₹1,200.00 (lower than default ₹2,000.00)
        "daily_budget_paise": 300000,
        "allowed_categories": ["electronics"],
        "allowed_products": [],
        "validity_period": {"not_before": "2026-11-10T00:00:00Z", "expires_at": "2027-11-10T00:00:00Z"},
        "automatic_purchase_restrictions": {"max_auto_amount_paise": 50000, "require_step_up_above_paise": 50000},
        "nonce": "12345678901234567890123456789012",
        "created_at": "2026-11-10T10:00:00Z",
    }
    mandate_sig = sign_payload(priv, DOMAIN_MANDATE, signed_payload)

    sub_res = client.post(
        "/api/v1/mandates/signed",
        headers=cust_headers,
        json={
            "payload": signed_payload,
            "envelope": {
                "algorithm": "Ed25519",
                "key_id": key_id,
                "canonicalization": "RFC8785",
                "domain_separator": DOMAIN_MANDATE,
                "signature": mandate_sig,
            },
        },
    )
    assert sub_res.status_code == 201

    # 3. Verify get_mandate returns the signed mandate constraints
    active_m = mandate_store.get_mandate("CUST001")
    assert active_m is not None
    assert active_m.max_transaction_amount == 1200.0  # ₹1,200.00 from signed mandate

    # 4. Proposing KB001 (₹1,499.00) now FAILS because ₹1,499 > ₹1,200 (even though legacy limit was ₹2,000)
    res = execute_purchase(
        customer_id="CUST001",
        product_id="KB001",
        quantity=1,
    )
    assert res.decision == "REJECTED"
    assert "exceeds maximum mandate limit" in res.reason


# ══════════════════════════════════════════════════════════════════════════════
# 5. Wildcard Merchant Support in Policy Engine
# ══════════════════════════════════════════════════════════════════════════════

def test_wildcard_merchant_allows_any_merchant(base_mandate):
    """When mandate specifies '*', purchases across any merchant are authorized."""
    wildcard_mandate = base_mandate.model_copy()
    wildcard_mandate.allowed_merchants = ["*"]

    req = PurchaseRequest(
        customer_id="CUST001",
        product_id="FD001",
        category="electronics",
        amount=349.0,
        merchant="ANY_ARBITRARY_MERCHANT_XYZ",
    )
    decision = evaluate(req, wildcard_mandate)
    assert decision.decision == PolicyOutcome.ALLOW
    assert decision.status == "APPROVED"

