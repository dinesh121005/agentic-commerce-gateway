"""
Comprehensive Integration & Cryptographic Security Test Suite for Phase P0.2.

Validates:
1. RFC 8785 JSON Canonicalization Scheme (JCS) deterministic byte-for-byte serialization.
2. Ed25519 PureEdDSA cryptographic verification and domain separator binding.
3. Authenticated Key Registration Ceremony (Proof of Possession & single-use challenge burning).
4. Key Revocation and terminal state irreversibility.
5. Signed Spending Mandate ingestion and strict integer-paise schema enforcement.
6. Mandate Versioning & Predecessor Chaining invariants (atomic supersession, hash matching).
7. Anti-tampering protection against forged amounts, altered nonces, and substituted keys.
8. Step-Up Purchase Approval creation and atomic consumption.
"""
import copy
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.oauth.crypto import create_access_token
from app.signing.canonical import (
    build_signing_bytes,
    canonical_json_hash,
    rfc8785_canonicalize,
)
from app.signing.crypto import (
    DOMAIN_APPROVAL,
    DOMAIN_KEY_REGISTRATION,
    DOMAIN_MANDATE,
    generate_ed25519_keypair,
    sign_challenge,
    sign_payload,
    verify_payload_signature,
)
from app.signing.store import signing_store

client = TestClient(app)


# ══════════════════════════════════════════════════════════════════════════════
# Helper Fixtures & Builders
# ══════════════════════════════════════════════════════════════════════════════

def make_customer_auth_header(customer_id: str = "CUST001") -> dict:
    """Generates valid OAuth Bearer Authorization header for customer."""
    token = create_access_token(customer_id=customer_id)
    return {"Authorization": f"Bearer {token}"}


def build_valid_mandate_payload(
    customer_id: str = "CUST001",
    mandate_id: str = "d1e2f3a4-5678-90ab-cdef-1234567890ab",
    mandate_version: int = 1,
    max_tx_paise: int = 250000,
    daily_budget_paise: int = 1000000,
    previous_mandate_id: str = None,
    previous_payload_hash: str = None,
) -> dict:
    """Builds a compliant canonical mandate dictionary."""
    return {
        "schema_version": "1.0.0",
        "mandate_id": mandate_id,
        "mandate_version": mandate_version,
        "customer_id": customer_id,
        "merchant_id": "*",
        "currency": "INR",
        "max_transaction_amount_paise": max_tx_paise,
        "daily_budget_paise": daily_budget_paise,
        "allowed_categories": ["electronics", "office_supplies"],
        "allowed_products": [],
        "validity_period": {
            "not_before": "2026-11-10T00:00:00Z",
            "expires_at": "2027-11-10T00:00:00Z",
        },
        "automatic_purchase_restrictions": {
            "max_auto_amount_paise": 50000,
            "require_step_up_above_paise": 50000,
        },
        "previous_mandate_id": previous_mandate_id,
        "previous_payload_hash": previous_payload_hash,
        "nonce": "a1b2c3d4e5f67890a1b2c3d4e5f67890",
        "created_at": "2026-11-10T10:00:00Z",
    }


# ══════════════════════════════════════════════════════════════════════════════
# 1. RFC 8785 Canonicalization & Determinism Test Vectors
# ══════════════════════════════════════════════════════════════════════════════

def test_rfc8785_canonicalization_sorting_and_whitespace():
    """Validates that keys are lexicographically sorted and whitespace is stripped."""
    input_data = {
        "z": 100,
        "a": "hello \n world",
        "m": [3, 2, 1],
        "nested": {"beta": True, "alpha": False, "null_field": None},
    }
    canon_bytes = rfc8785_canonicalize(input_data)
    canon_str = canon_bytes.decode("utf-8")

    # Invariants: no space outside strings, keys sorted
    assert " " not in canon_str.replace("hello \\n world", "")
    assert canon_str == '{"a":"hello \\n world","m":[3,2,1],"nested":{"alpha":false,"beta":true,"null_field":null},"z":100}'


def test_rfc8785_hash_determinism():
    """Identical data with different key insertion order MUST yield identical SHA-256 hashes."""
    dict1 = {"merchant_id": "MERCH001", "currency": "INR", "amount_paise": 15000}
    dict2 = {"currency": "INR", "amount_paise": 15000, "merchant_id": "MERCH001"}

    hash1 = canonical_json_hash(dict1)
    hash2 = canonical_json_hash(dict2)

    assert hash1 == hash2, "RFC 8785 hash must be completely independent of key insertion order"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Ed25519 PureEdDSA Verification & Domain Separator Binding
# ══════════════════════════════════════════════════════════════════════════════

def test_ed25519_signature_verification_positive():
    """A valid Ed25519 signature over DOMAIN_MANDATE || JCS passes verification."""
    priv, pub_b64, _ = generate_ed25519_keypair()
    payload = build_valid_mandate_payload()

    sig_b64 = sign_payload(priv, DOMAIN_MANDATE, payload)
    assert len(sig_b64) == 86

    is_valid = verify_payload_signature(pub_b64, sig_b64, DOMAIN_MANDATE, payload)
    assert is_valid is True


def test_ed25519_signature_rejected_on_wrong_domain_separator():
    """Signing with one domain separator and verifying with another MUST fail."""
    priv, pub_b64, _ = generate_ed25519_keypair()
    payload = build_valid_mandate_payload()

    # Sign under KEY_REGISTRATION, verify under MANDATE
    sig_b64 = sign_payload(priv, DOMAIN_KEY_REGISTRATION, payload)

    with pytest.raises(Exception):
        verify_payload_signature(pub_b64, sig_b64, DOMAIN_MANDATE, payload)


def test_ed25519_signature_rejected_on_tampered_payload():
    """Any modification to the payload after signing MUST cause verification failure."""
    priv, pub_b64, _ = generate_ed25519_keypair()
    payload = build_valid_mandate_payload(max_tx_paise=100000)

    sig_b64 = sign_payload(priv, DOMAIN_MANDATE, payload)

    # Attacker attempts to increase spending limit from 100,000 to 500,000 paise
    tampered_payload = copy.deepcopy(payload)
    tampered_payload["max_transaction_amount_paise"] = 500000

    with pytest.raises(Exception):
        verify_payload_signature(pub_b64, sig_b64, DOMAIN_MANDATE, tampered_payload)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Key Registration Ceremony (Proof of Possession - ADR-01 §7)
# ══════════════════════════════════════════════════════════════════════════════

def test_key_registration_flow_success():
    """End-to-end customer device key registration with Proof-of-Possession."""
    cust_headers = make_customer_auth_header("CUST001")

    # Step 1: Request Challenge
    ch_res = client.post(
        "/api/v1/signing/keys/challenge",
        headers=cust_headers,
        json={"device_name": "Pixel 8 Pro (Chrome)", "purpose": "KEY_REGISTRATION"},
    )
    assert ch_res.status_code == 201
    ch_data = ch_res.json()
    assert "challenge_id" in ch_data
    assert "challenge_token" in ch_data
    assert ch_data["domain_separator"] == DOMAIN_KEY_REGISTRATION

    # Step 2: Client generates keypair and signs challenge
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig_b64 = sign_challenge(priv, ch_data["challenge_token"])

    # Step 3: Register Public Key
    reg_res = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={
            "challenge_id": ch_data["challenge_id"],
            "public_key": pub_b64,
            "signature": sig_b64,
            "device_name": "Pixel 8 Pro (Chrome)",
            "storage_type": "HARDWARE_KEYSTORE",
            "key_ttl_days": 365,
        },
    )
    assert reg_res.status_code == 201
    reg_data = reg_res.json()
    assert reg_data["customer_id"] == "CUST001"
    assert reg_data["public_key"] == pub_b64
    assert reg_data["status"] == "ACTIVE"
    assert reg_data["storage_type"] == "HARDWARE_KEYSTORE"


def test_challenge_single_use_burning_rejects_replay():
    """A challenge token cannot be consumed more than once (replay attack TH-06)."""
    cust_headers = make_customer_auth_header("CUST001")

    ch_res = client.post(
        "/api/v1/signing/keys/challenge",
        headers=cust_headers,
        json={"device_name": "Device A", "purpose": "KEY_REGISTRATION"},
    )
    ch_data = ch_res.json()

    priv1, pub1_b64, _ = generate_ed25519_keypair()
    sig1_b64 = sign_challenge(priv1, ch_data["challenge_token"])

    # First registration succeeds
    reg1 = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={
            "challenge_id": ch_data["challenge_id"],
            "public_key": pub1_b64,
            "signature": sig1_b64,
            "device_name": "Device A",
        },
    )
    assert reg1.status_code == 201

    # Second registration using identical challenge token MUST fail
    priv2, pub2_b64, _ = generate_ed25519_keypair()
    sig2_b64 = sign_challenge(priv2, ch_data["challenge_token"])

    reg2 = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={
            "challenge_id": ch_data["challenge_id"],
            "public_key": pub2_b64,
            "signature": sig2_b64,
            "device_name": "Device B",
        },
    )
    assert reg2.status_code == 400
    assert "consumed" in reg2.text.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 4. Key Revocation & Terminal State Invariance (ADR-01 §6.1)
# ══════════════════════════════════════════════════════════════════════════════

def test_key_revocation_transitions_to_terminal_state():
    """Customer can revoke a registered key; revoked keys cannot be re-revoked."""
    cust_headers = make_customer_auth_header("CUST001")

    # 1. Register a key
    ch_res = client.post(
        "/api/v1/signing/keys/challenge",
        headers=cust_headers,
        json={"device_name": "Laptop", "purpose": "KEY_REGISTRATION"},
    )
    ch_data = ch_res.json()
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig_b64 = sign_challenge(priv, ch_data["challenge_token"])

    reg = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={
            "challenge_id": ch_data["challenge_id"],
            "public_key": pub_b64,
            "signature": sig_b64,
            "device_name": "Laptop",
        },
    )
    key_id = reg.json()["key_id"]

    # 2. Revoke the key
    rev_res = client.post(
        f"/api/v1/signing/keys/{key_id}/revoke",
        headers=cust_headers,
        json={"reason": "DEVICE_LOST"},
    )
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REVOKED"

    # 3. Attempting to revoke again must fail (irreversible terminal state)
    rev2_res = client.post(
        f"/api/v1/signing/keys/{key_id}/revoke",
        headers=cust_headers,
        json={"reason": "DEVICE_LOST"},
    )
    assert rev2_res.status_code == 400
    assert "already" in rev2_res.text.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 5. Signed Spending Mandate Ingestion & Anti-Tampering (ADR-01 §8)
# ══════════════════════════════════════════════════════════════════════════════

def test_signed_mandate_submission_and_retrieval_success():
    """Valid signed mandate envelope is ingested, verified, and queryable."""
    cust_headers = make_customer_auth_header("CUST001")

    # Register active key
    ch_res = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Phone"})
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig_b64 = sign_challenge(priv, ch_res.json()["challenge_token"])
    reg = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={"challenge_id": ch_res.json()["challenge_id"], "public_key": pub_b64, "signature": sig_b64, "device_name": "Phone"},
    )
    key_id = reg.json()["key_id"]

    # Prepare and sign mandate
    payload = build_valid_mandate_payload(customer_id="CUST001", mandate_id="mandate-test-001", mandate_version=1)
    mandate_sig = sign_payload(priv, DOMAIN_MANDATE, payload)

    envelope_req = {
        "payload": payload,
        "envelope": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "canonicalization": "RFC8785",
            "domain_separator": DOMAIN_MANDATE,
            "signature": mandate_sig,
        },
    }

    sub_res = client.post("/api/v1/mandates/signed", headers=cust_headers, json=envelope_req)
    assert sub_res.status_code == 201
    data = sub_res.json()
    assert data["mandate_id"] == "mandate-test-001"
    assert data["mandate_version"] == 1
    assert data["status"] == "ACTIVE"

    # Query active mandate
    active_res = client.get("/api/v1/mandates/active", headers=cust_headers)
    assert active_res.status_code == 200
    active_data = active_res.json()
    assert active_data["mandate_id"] == "mandate-test-001"
    assert active_data["max_transaction_amount_paise"] == payload["max_transaction_amount_paise"]


def test_mandate_tampering_rejected_with_bad_request():
    """Submitting envelope with forged signature or tampered limit is rejected."""
    cust_headers = make_customer_auth_header("CUST001")

    # Register active key
    ch_res = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Phone"})
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig_b64 = sign_challenge(priv, ch_res.json()["challenge_token"])
    reg = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={"challenge_id": ch_res.json()["challenge_id"], "public_key": pub_b64, "signature": sig_b64, "device_name": "Phone"},
    )
    key_id = reg.json()["key_id"]

    # Customer signed budget of 100,000 paise (₹1,000.00)
    payload = build_valid_mandate_payload(customer_id="CUST001", mandate_id="mandate-tamper-001", daily_budget_paise=100000)
    mandate_sig = sign_payload(priv, DOMAIN_MANDATE, payload)

    # Adversary alters daily budget to 1,000,000 paise (₹10,000.00) in transit
    payload["daily_budget_paise"] = 1000000

    envelope_req = {
        "payload": payload,
        "envelope": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "canonicalization": "RFC8785",
            "domain_separator": DOMAIN_MANDATE,
            "signature": mandate_sig,
        },
    }

    tamper_res = client.post("/api/v1/mandates/signed", headers=cust_headers, json=envelope_req)
    assert tamper_res.status_code == 400
    assert "signature verification failed" in tamper_res.text.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 6. Mandate Versioning & Predecessor Chaining Invariants (ADR-01 §9)
# ══════════════════════════════════════════════════════════════════════════════

def test_mandate_version_supersession_and_chaining():
    """Version 2 cryptographically chains to Version 1 hash and supersedes it atomically."""
    cust_headers = make_customer_auth_header("CUST001")

    ch_res = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Phone"})
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig_b64 = sign_challenge(priv, ch_res.json()["challenge_token"])
    reg = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={"challenge_id": ch_res.json()["challenge_id"], "public_key": pub_b64, "signature": sig_b64, "device_name": "Phone"},
    )
    key_id = reg.json()["key_id"]

    # 1. Submit Mandate Version 1
    m1_payload = build_valid_mandate_payload(mandate_id="mandate-chain-001", mandate_version=1, daily_budget_paise=100000)
    m1_hash = canonical_json_hash(m1_payload)
    m1_sig = sign_payload(priv, DOMAIN_MANDATE, m1_payload)

    sub1 = client.post(
        "/api/v1/mandates/signed",
        headers=cust_headers,
        json={
            "payload": m1_payload,
            "envelope": {
                "algorithm": "Ed25519",
                "key_id": key_id,
                "canonicalization": "RFC8785",
                "domain_separator": DOMAIN_MANDATE,
                "signature": m1_sig,
            },
        },
    )
    assert sub1.status_code == 201

    # 2. Submit Mandate Version 2 chaining to Version 1 hash
    m2_payload = build_valid_mandate_payload(
        mandate_id="mandate-chain-001",
        mandate_version=2,
        daily_budget_paise=200000,
        previous_mandate_id="mandate-chain-001",
        previous_payload_hash=m1_hash,
    )
    m2_sig = sign_payload(priv, DOMAIN_MANDATE, m2_payload)

    sub2 = client.post(
        "/api/v1/mandates/signed",
        headers=cust_headers,
        json={
            "payload": m2_payload,
            "envelope": {
                "algorithm": "Ed25519",
                "key_id": key_id,
                "canonicalization": "RFC8785",
                "domain_separator": DOMAIN_MANDATE,
                "signature": m2_sig,
            },
        },
    )
    assert sub2.status_code == 201
    assert sub2.json()["mandate_version"] == 2

    # 3. Active mandate query must now return Version 2
    active_res = client.get("/api/v1/mandates/active", headers=cust_headers)
    assert active_res.status_code == 200
    assert active_res.json()["mandate_version"] == 2
    assert active_res.json()["daily_budget_paise"] == 200000


def test_mandate_version_supersession_fails_on_hash_mismatch():
    """Version 2 referencing an incorrect predecessor hash MUST be rejected."""
    cust_headers = make_customer_auth_header("CUST001")

    ch_res = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Phone"})
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig_b64 = sign_challenge(priv, ch_res.json()["challenge_token"])
    reg = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={"challenge_id": ch_res.json()["challenge_id"], "public_key": pub_b64, "signature": sig_b64, "device_name": "Phone"},
    )
    key_id = reg.json()["key_id"]

    # Submit Version 1
    m1_payload = build_valid_mandate_payload(mandate_id="mandate-badhash-001", mandate_version=1)
    m1_sig = sign_payload(priv, DOMAIN_MANDATE, m1_payload)
    client.post(
        "/api/v1/mandates/signed",
        headers=cust_headers,
        json={
            "payload": m1_payload,
            "envelope": {"algorithm": "Ed25519", "key_id": key_id, "canonicalization": "RFC8785", "domain_separator": DOMAIN_MANDATE, "signature": m1_sig},
        },
    )

    # Submit Version 2 with corrupted predecessor hash
    bogus_hash = "0" * 64
    m2_payload = build_valid_mandate_payload(
        mandate_id="mandate-badhash-001",
        mandate_version=2,
        previous_mandate_id="mandate-badhash-001",
        previous_payload_hash=bogus_hash,
    )
    m2_sig = sign_payload(priv, DOMAIN_MANDATE, m2_payload)

    sub2 = client.post(
        "/api/v1/mandates/signed",
        headers=cust_headers,
        json={
            "payload": m2_payload,
            "envelope": {"algorithm": "Ed25519", "key_id": key_id, "canonicalization": "RFC8785", "domain_separator": DOMAIN_MANDATE, "signature": m2_sig},
        },
    )
    assert sub2.status_code == 400
    assert "chaining verification failed" in sub2.text.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 7. Step-Up Purchase Approval Lifecycle (ADR-01 §10)
# ══════════════════════════════════════════════════════════════════════════════

def test_step_up_purchase_approval_consumption_success():
    """Customer device signs approval; gateway verifies signature and burns approval atomically."""
    cust_headers = make_customer_auth_header("CUST001")

    # 1. Register key
    ch_res = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Phone"})
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig_b64 = sign_challenge(priv, ch_res.json()["challenge_token"])
    reg = client.post(
        "/api/v1/signing/keys/register",
        headers=cust_headers,
        json={"challenge_id": ch_res.json()["challenge_id"], "public_key": pub_b64, "signature": sig_b64, "device_name": "Phone"},
    )
    key_id = reg.json()["key_id"]

    # 2. Gateway generates pending step-up approval for purchase >= 50,000 paise (₹500.00)
    items = [{"product_id": "KB001", "quantity": 1, "unit_price_paise": 149900, "total_item_amount_paise": 149900}]
    app_data = signing_store.create_purchase_approval(
        purchase_id="purchase-test-001",
        customer_id="CUST001",
        merchant_id="MERCH_ELEC",
        mandate_id="mandate-test-001",
        mandate_version=1,
        key_id=key_id,
        items=items,
        subtotal_paise=149900,
        total_payable_paise=149900,
    )
    approval_id = app_data["approval_id"]
    payload_to_sign = app_data["payload_to_sign"]

    # 3. Customer reviews payload on device and signs DOMAIN_APPROVAL || JCS(payload)
    app_sig = sign_payload(priv, DOMAIN_APPROVAL, payload_to_sign)

    # 4. Submit signature to consume approval
    consume_res = client.post(
        "/api/v1/purchases/purchase-test-001/approvals/verify-and-consume",
        headers=cust_headers,
        json={
            "approval_id": approval_id,
            "key_id": key_id,
            "signature": app_sig,
        },
    )
    assert consume_res.status_code == 200
    assert consume_res.json()["status"] == "CONSUMED"

    # 5. Second attempt to consume MUST fail (single-use burning)
    consume2_res = client.post(
        "/api/v1/purchases/purchase-test-001/approvals/verify-and-consume",
        headers=cust_headers,
        json={
            "approval_id": approval_id,
            "key_id": key_id,
            "signature": app_sig,
        },
    )
    assert consume2_res.status_code == 400
    assert "current status is consumed" in consume2_res.text.lower()


def test_purchase_approval_rejected_if_signed_with_wrong_key():
    """
    If an approval was issued for Key A, submitting a signature from Key B
    (even if Key B is another active key of the same customer) MUST be rejected with HTTP 403.
    """
    cust_headers = make_customer_auth_header("CUST001")

    # 1. Register Key A
    ch_a = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Phone-A"})
    priv_a, pub_a_b64, _ = generate_ed25519_keypair()
    sig_a = sign_challenge(priv_a, ch_a.json()["challenge_token"])
    reg_a = client.post("/api/v1/signing/keys/register", headers=cust_headers, json={
        "challenge_id": ch_a.json()["challenge_id"],
        "public_key": pub_a_b64,
        "signature": sig_a,
        "device_name": "Phone-Key-A"
    }).json()
    key_a_id = reg_a["key_id"]

    # 2. Register Key B
    ch_b = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Laptop-B"})
    priv_b, pub_b_b64, _ = generate_ed25519_keypair()
    sig_b = sign_challenge(priv_b, ch_b.json()["challenge_token"])
    reg_b = client.post("/api/v1/signing/keys/register", headers=cust_headers, json={
        "challenge_id": ch_b.json()["challenge_id"],
        "public_key": pub_b_b64,
        "signature": sig_b,
        "device_name": "Laptop-Key-B"
    }).json()
    key_b_id = reg_b["key_id"]

    # 3. Create approval bound specifically to Key A
    items = [{"product_id": "KB001", "quantity": 1, "unit_price_paise": 149900, "total_item_amount_paise": 149900}]
    app_data = signing_store.create_purchase_approval(
        purchase_id="purchase-key-binding-001",
        customer_id="CUST001",
        merchant_id="MERCH_ELEC",
        mandate_id="mandate-test-002",
        mandate_version=1,
        key_id=key_a_id,
        items=items,
        subtotal_paise=149900,
        total_payable_paise=149900,
    )
    approval_id = app_data["approval_id"]
    payload_to_sign = app_data["payload_to_sign"]

    # 4. Sign with Key B and attempt consumption with key_b_id -> MUST fail with 403 Forbidden
    sig_with_b = sign_payload(priv_b, DOMAIN_APPROVAL, payload_to_sign)
    res = client.post(
        "/api/v1/purchases/purchase-key-binding-001/approvals/verify-and-consume",
        headers=cust_headers,
        json={
            "approval_id": approval_id,
            "key_id": key_b_id,
            "signature": sig_with_b,
        },
    )
    assert res.status_code == 403
    assert "issued specifically for key" in res.text


def test_purchase_approval_rejected_if_expired():
    """Verify that an approval cannot be consumed past its expires_at TTL."""
    cust_headers = make_customer_auth_header("CUST001")
    ch = client.post("/api/v1/signing/keys/challenge", headers=cust_headers, json={"device_name": "Expire-Device"})
    priv, pub_b64, _ = generate_ed25519_keypair()
    sig = sign_challenge(priv, ch.json()["challenge_token"])
    reg = client.post("/api/v1/signing/keys/register", headers=cust_headers, json={
        "challenge_id": ch.json()["challenge_id"],
        "public_key": pub_b64,
        "signature": sig,
        "device_name": "Expire-Key"
    }).json()
    key_id = reg["key_id"]

    # Create approval with negative TTL (-10 seconds)
    items = [{"product_id": "KB001", "quantity": 1, "unit_price_paise": 149900, "total_item_amount_paise": 149900}]
    app_data = signing_store.create_purchase_approval(
        purchase_id="purchase-expired-001",
        customer_id="CUST001",
        merchant_id="MERCH_ELEC",
        mandate_id="mandate-test-003",
        mandate_version=1,
        key_id=key_id,
        items=items,
        subtotal_paise=149900,
        total_payable_paise=149900,
        ttl_seconds=-10,
    )
    approval_id = app_data["approval_id"]
    payload_to_sign = app_data["payload_to_sign"]
    app_sig = sign_payload(priv, DOMAIN_APPROVAL, payload_to_sign)

    res = client.post(
        "/api/v1/purchases/purchase-expired-001/approvals/verify-and-consume",
        headers=cust_headers,
        json={
            "approval_id": approval_id,
            "key_id": key_id,
            "signature": app_sig,
        },
    )
    assert res.status_code == 400
    assert "expired" in res.text.lower()

