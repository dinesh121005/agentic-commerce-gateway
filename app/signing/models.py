"""
Pydantic Schemas and Data Models for Phase P0.2 Cryptographic Mandates.

Implements ADR-01 specifications:
- RFC 8785 JSON canonical structures.
- Strict integer-paise monetary representation.
- Detached Ed25519 signature envelopes.
- Single-use challenge and approval lifecycle models.
"""
from typing import List, Literal, Optional
from pydantic import BaseModel, Field


# ══════════════════════════════════════════════════════════════════════════════
# 1. Key Registration & Management Models
# ══════════════════════════════════════════════════════════════════════════════

class KeyChallengeRequest(BaseModel):
    """Request to generate a cryptographically random proof-of-possession challenge."""
    device_name: str = Field(..., min_length=1, max_length=128, description="Human-readable device descriptor")
    purpose: Literal["KEY_REGISTRATION", "MANDATE_REVOCATION"] = Field(
        default="KEY_REGISTRATION",
        description="Intended cryptographic purpose of the challenge"
    )


class KeyChallengeResponse(BaseModel):
    """Cryptographic challenge issued to customer device for Proof of Possession."""
    challenge_id: str
    challenge_token: str
    domain_separator: str
    expires_at: str


class KeyRegisterRequest(BaseModel):
    """Public key registration request with proof-of-possession signature."""
    challenge_id: str = Field(..., min_length=1)
    public_key: str = Field(..., pattern=r"^[A-Za-z0-9_-]{43}$", description="Base64URL-encoded 32-byte Ed25519 public key")
    signature: str = Field(..., pattern=r"^[A-Za-z0-9_-]{86}$", description="Base64URL-encoded 64-byte Ed25519 signature")
    device_name: str = Field(..., min_length=1, max_length=128)
    storage_type: Literal["HARDWARE_KEYSTORE", "SOFTWARE_SECURE_STORAGE", "WEB_CRYPTO_INDEXED_DB"] = Field(
        default="SOFTWARE_SECURE_STORAGE",
        description="Client device storage tier (ADR-01 §5.1)"
    )
    key_ttl_days: int = Field(default=365, ge=1, le=365)


class CustomerSigningKeyResponse(BaseModel):
    """Customer signing key registry entry."""
    key_id: str
    customer_id: str
    public_key: str
    device_name: str
    storage_type: str
    status: Literal["PENDING", "ACTIVE", "REVOKED", "EXPIRED"]
    created_at: str
    expires_at: str
    revoked_at: Optional[str] = None


class KeyRevokeRequest(BaseModel):
    """Key revocation request."""
    reason: str = Field(default="EXPLICIT_REVOCATION", max_length=256)


class KeyRevokeResponse(BaseModel):
    """Key revocation outcome."""
    key_id: str
    status: Literal["REVOKED"]
    revoked_at: str


# ══════════════════════════════════════════════════════════════════════════════
# 2. Signed Spending Mandate Models
# ══════════════════════════════════════════════════════════════════════════════

class MandateValidityPeriod(BaseModel):
    """Time validity envelope for a customer mandate."""
    not_before: str = Field(..., description="ISO 8601 UTC timestamp")
    expires_at: str = Field(..., description="ISO 8601 UTC timestamp")


class MandateAutoRestrictions(BaseModel):
    """Autonomous execution spending thresholds (integer paise)."""
    max_auto_amount_paise: int = Field(..., ge=0, description="Maximum amount permissible for unattended execution")
    require_step_up_above_paise: int = Field(..., ge=0, description="Amount above which human approval is required")


class SignedMandatePayload(BaseModel):
    """
    Canonical mandate content according to ADR-01 §8.1.
    All monetary fields are strictly integer paise.
    """
    schema_version: Literal["1.0.0"] = "1.0.0"
    mandate_id: str = Field(..., min_length=1)
    mandate_version: int = Field(..., ge=1)
    customer_id: str = Field(..., pattern=r"^CUST[0-9]{3,}$")
    merchant_id: str = Field(..., min_length=1, description="Target merchant ID or '*' for any merchant")
    currency: Literal["INR"] = "INR"
    max_transaction_amount_paise: int = Field(..., ge=100)
    daily_budget_paise: int = Field(..., ge=100)
    allowed_categories: List[str] = Field(..., min_length=1)
    allowed_products: List[str] = Field(default_factory=list)
    validity_period: MandateValidityPeriod
    automatic_purchase_restrictions: MandateAutoRestrictions
    previous_mandate_id: Optional[str] = None
    previous_payload_hash: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    nonce: str = Field(..., min_length=32, max_length=64)
    created_at: str


class MandateSignatureEnvelope(BaseModel):
    """Detached cryptographic signature envelope according to ADR-01 §8.2."""
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(..., min_length=1)
    canonicalization: Literal["RFC8785"] = "RFC8785"
    domain_separator: Literal["AGENTIC_COMMERCE_MANDATE_V1:"] = "AGENTIC_COMMERCE_MANDATE_V1:"
    signature: str = Field(..., pattern=r"^[A-Za-z0-9_-]{86}$")


class SignedMandateEnvelopeRequest(BaseModel):
    """Complete signed mandate envelope submission request."""
    payload: SignedMandatePayload
    envelope: MandateSignatureEnvelope


class SignedMandateResponse(BaseModel):
    """Response returned upon successful signed mandate ingestion or retrieval."""
    mandate_id: str
    mandate_version: int
    status: Literal["ACTIVE", "SUPERSEDED", "REVOKED", "EXPIRED"]
    customer_id: str
    merchant_id: str
    max_transaction_amount_paise: int
    daily_budget_paise: int
    created_at: str
    expires_at: str


class MandateRevokeResponse(BaseModel):
    """Mandate revocation confirmation."""
    mandate_id: str
    status: Literal["REVOKED"]
    revoked_at: str


# ══════════════════════════════════════════════════════════════════════════════
# 3. Step-Up Purchase Approval Models (ADR-01 §10.2)
# ══════════════════════════════════════════════════════════════════════════════

class PurchaseApprovalItem(BaseModel):
    """Individual item in a step-up purchase approval payload."""
    product_id: str = Field(..., min_length=1)
    quantity: int = Field(..., ge=1)
    unit_price_paise: int = Field(..., ge=1)
    total_item_amount_paise: int = Field(..., ge=1)


class PurchaseApprovalPayload(BaseModel):
    """Canonical purchase approval payload signed by human customer on sovereign device."""
    schema_version: Literal["1.0.0"] = "1.0.0"
    approval_id: str = Field(..., min_length=1)
    purchase_id: str = Field(..., min_length=1)
    customer_id: str = Field(..., pattern=r"^CUST[0-9]{3,}$")
    merchant_id: str = Field(..., min_length=1)
    mandate_id: str = Field(..., min_length=1)
    mandate_version: int = Field(..., ge=1)
    items: List[PurchaseApprovalItem] = Field(..., min_length=1)
    subtotal_paise: int = Field(..., ge=1)
    taxes_paise: int = Field(default=0, ge=0)
    shipping_paise: int = Field(default=0, ge=0)
    fees_paise: int = Field(default=0, ge=0)
    total_payable_paise: int = Field(..., ge=1)
    currency: Literal["INR"] = "INR"
    expires_at: str
    nonce: str = Field(..., min_length=32)
    created_at: str


class PurchaseApprovalCreateResponse(BaseModel):
    """Gateway-generated approval payload for customer signing."""
    approval_id: str
    purchase_id: str
    payload_to_sign: PurchaseApprovalPayload
    domain_separator: Literal["AGENTIC_COMMERCE_APPROVAL_V1:"] = "AGENTIC_COMMERCE_APPROVAL_V1:"
    expires_at: str


class PurchaseApprovalConsumeRequest(BaseModel):
    """Customer device submits Ed25519 signature to consume step-up approval."""
    approval_id: str = Field(..., min_length=1)
    key_id: str = Field(..., min_length=1)
    signature: str = Field(..., pattern=r"^[A-Za-z0-9_-]{86}$")


class PurchaseApprovalConsumeResponse(BaseModel):
    """Approval consumption response."""
    purchase_id: str
    approval_id: str
    status: Literal["CONSUMED"]
    consumed_at: str
    payment_execution_status: str

