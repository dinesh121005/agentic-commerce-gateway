"""
FastAPI Router for Option A Non-Custodial Cryptographic Signing and Mandates.

Exposes REST contracts per ADR-01 §16:
- Key Registration Challenge & Proof of Possession
- Customer Public Key Revocation & Listing
- Signed Mandate Ingestion & Atomic Supersession
- Step-Up Purchase Approval Consumption
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import verify_customer_oauth_token
from app.signing.models import (
    CustomerSigningKeyResponse,
    KeyChallengeRequest,
    KeyChallengeResponse,
    KeyRegisterRequest,
    KeyRevokeRequest,
    KeyRevokeResponse,
    MandateRevokeResponse,
    PurchaseApprovalConsumeRequest,
    PurchaseApprovalConsumeResponse,
    SignedMandateEnvelopeRequest,
    SignedMandateResponse,
)
from app.signing.store import signing_store

router = APIRouter(tags=["cryptographic-signing"])


# ══════════════════════════════════════════════════════════════════════════════
# 1. Key Management Endpoints (ADR-01 §16 Contracts 1 - 3)
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/api/v1/signing/keys/challenge",
    response_model=KeyChallengeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue Key Registration Challenge",
)
def issue_key_challenge_endpoint(
    req: KeyChallengeRequest,
    customer_id: str = Depends(verify_customer_oauth_token),
):
    """
    Issues a CSPRNG challenge token to the authenticated customer device.
    Used for Proof-of-Possession (PoP) key registration.
    """
    try:
        challenge = signing_store.create_challenge(
            customer_id=customer_id,
            purpose=req.purpose,
        )
        return KeyChallengeResponse(**challenge)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/api/v1/signing/keys/register",
    response_model=CustomerSigningKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register Customer Public Signing Key",
)
def register_signing_key_endpoint(
    req: KeyRegisterRequest,
    customer_id: str = Depends(verify_customer_oauth_token),
):
    """
    Registers an Ed25519 public key in the customer signing key directory.
    Validates Proof of Possession against the challenge token and burns the challenge atomically.
    """
    try:
        key_record = signing_store.register_key(
            challenge_id=req.challenge_id,
            customer_id=customer_id,
            public_key=req.public_key,
            signature=req.signature,
            device_name=req.device_name,
            storage_type=req.storage_type,
            key_ttl_days=req.key_ttl_days,
        )
        return CustomerSigningKeyResponse(**key_record)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration failed: {exc}")


@router.post(
    "/api/v1/signing/keys/{key_id}/revoke",
    response_model=KeyRevokeResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke Customer Signing Key",
)
def revoke_signing_key_endpoint(
    key_id: str,
    req: KeyRevokeRequest,
    customer_id: str = Depends(verify_customer_oauth_token),
):
    """
    Immediately transitions a customer signing key to REVOKED.
    Irreversible terminal state per ADR-01 §6.1.
    """
    try:
        result = signing_store.revoke_key(
            key_id=key_id,
            customer_id=customer_id,
            reason=req.reason,
        )
        return KeyRevokeResponse(**result)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/api/v1/signing/keys",
    response_model=List[CustomerSigningKeyResponse],
    status_code=status.HTTP_200_OK,
    summary="List Customer Active Signing Keys",
)
def list_signing_keys_endpoint(
    customer_id: str = Depends(verify_customer_oauth_token),
):
    """Lists all active, non-expired signing keys for the authenticated customer."""
    keys = signing_store.list_active_keys(customer_id=customer_id)
    return [CustomerSigningKeyResponse(**k) for k in keys]


# ══════════════════════════════════════════════════════════════════════════════
# 2. Signed Mandate Endpoints (ADR-01 §16 Contracts 4 - 5)
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/api/v1/mandates/signed",
    response_model=SignedMandateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Cryptographically Signed Spending Mandate",
)
def submit_signed_mandate_endpoint(
    req: SignedMandateEnvelopeRequest,
    customer_id: str = Depends(verify_customer_oauth_token),
):
    """
    Ingests a detached signature envelope containing a customer spending mandate.
    Verifies RFC 8785 canonical bytes and Ed25519 signature against registered customer key.
    Enforces atomic version concurrency and predecessor chaining invariants.
    """
    try:
        result = signing_store.save_signed_mandate(
            payload=req.payload.model_dump(exclude_unset=True),
            envelope=req.envelope.model_dump(exclude_unset=True),
            authenticated_customer_id=customer_id,
        )
        return SignedMandateResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Mandate ingestion failed: {exc}")


@router.post(
    "/api/v1/mandates/{mandate_id}/revoke",
    response_model=MandateRevokeResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke Customer Spending Mandate",
)
def revoke_mandate_endpoint(
    mandate_id: str,
    customer_id: str = Depends(verify_customer_oauth_token),
):
    """Transitions an active signed spending mandate to REVOKED."""
    try:
        result = signing_store.revoke_mandate(
            mandate_id=mandate_id,
            customer_id=customer_id,
        )
        return MandateRevokeResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/api/v1/mandates/active",
    status_code=status.HTTP_200_OK,
    summary="Get Active Signed Mandate",
)
def get_active_mandate_endpoint(
    customer_id: str = Depends(verify_customer_oauth_token),
):
    """Retrieves the latest active signed spending mandate for the authenticated customer."""
    mandate = signing_store.get_active_mandate(customer_id=customer_id)
    if not mandate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active signed mandate found for customer")
    return mandate


# ══════════════════════════════════════════════════════════════════════════════
# 3. Step-Up Purchase Approval Consumption (ADR-01 §16 Contract 7)
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/api/v1/purchases/{purchase_id}/approvals/verify-and-consume",
    response_model=PurchaseApprovalConsumeResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify and Consume Step-Up Purchase Approval",
)
def consume_purchase_approval_endpoint(
    purchase_id: str,
    req: PurchaseApprovalConsumeRequest,
    customer_id: str = Depends(verify_customer_oauth_token),
):
    """
    Submits customer device Ed25519 signature to verify and atomically burn
    a pending step-up purchase approval.
    """
    try:
        result = signing_store.consume_purchase_approval(
            approval_id=req.approval_id,
            customer_id=customer_id,
            key_id=req.key_id,
            signature=req.signature,
        )
        return PurchaseApprovalConsumeResponse(**result)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

