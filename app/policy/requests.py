from enum import Enum
from typing import Literal, Optional
from pydantic import BaseModel, Field


class PolicyOutcome(str, Enum):
    """
    Three-state deterministic policy verdict (Doc 07 §5).
    ALLOW: Complies with all mandate constraints and payable amount < ₹500.00.
    STEP_UP: Complies with all mandate constraints but payable amount >= ₹500.00 (requires human confirmation).
    DENY: Mandate or policy invariant violated (terminal rejection).
    """
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    DENY = "DENY"


class RuleViolated(str, Enum):
    """
    Standardized taxonomy of policy rules and reason codes (Doc 07 §7).
    """
    CUSTOMER_MISMATCH = "CUSTOMER_MISMATCH"
    AUTH_CUSTOMER_MISMATCH = "AUTH_CUSTOMER_MISMATCH"
    MANDATE_EXPIRED = "MANDATE_EXPIRED"
    MANDATE_REVOKED = "MANDATE_REVOKED"
    MANDATE_NOT_FOUND = "MANDATE_NOT_FOUND"
    MERCHANT_NOT_ALLOWED = "MERCHANT_NOT_ALLOWED"
    MERCHANT_UNAUTHORIZED = "MERCHANT_UNAUTHORIZED"
    CATEGORY_NOT_ALLOWED = "CATEGORY_NOT_ALLOWED"
    CATEGORY_UNAUTHORIZED = "CATEGORY_UNAUTHORIZED"
    AMOUNT_EXCEEDS_LIMIT = "AMOUNT_EXCEEDS_LIMIT"
    AMOUNT_EXCEEDS_TRANSACTION_LIMIT = "AMOUNT_EXCEEDS_TRANSACTION_LIMIT"
    DAILY_LIMIT_EXCEEDED = "DAILY_LIMIT_EXCEEDED"
    DAILY_BUDGET_EXCEEDED = "DAILY_BUDGET_EXCEEDED"
    STALE_PRICE_DETECTED = "STALE_PRICE_DETECTED"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    POLICY_APPROVED = "POLICY_APPROVED"


class PurchaseRequest(BaseModel):
    """
    Representation of a purchase proposed by an AI Buyer Agent.

    Note: The `amount` field is pre-computed by the caller as `price × quantity`.
    This model and the policy engine never recalculate it.
    """
    customer_id: str = Field(..., description="Customer on whose behalf the agent is acting")
    product_id: str = Field(..., description="ID of the product being purchased")
    category: str = Field(..., description="Category of the product being purchased")
    amount: float = Field(..., gt=0, description="Pre-computed total amount (price × quantity) in INR (₹)")
    amount_paise: Optional[int] = Field(default=None, description="Pre-computed total amount in integer paise")
    merchant: str = Field(..., description="Merchant identifier where the purchase is being proposed")
    quantity: int = Field(default=1, ge=1, description="Quantity of items being purchased")


class PolicyDecision(BaseModel):
    """
    Evaluation verdict returned by the Policy / Mandate Engine.
    Exposes both 3-state verdict (ALLOW, STEP_UP, DENY) and backward-compatible status (APPROVED, REJECTED).
    """
    status: Literal["APPROVED", "REJECTED"] = Field(..., description="Mandate decision status: APPROVED or REJECTED")
    decision: Literal["ALLOW", "STEP_UP", "DENY"] = Field(default="ALLOW", description="Three-state policy verdict: ALLOW, STEP_UP, or DENY")
    reason: str = Field(..., description="Specific, human-readable explanation citing actual values involved")
    rule_violated: Optional[RuleViolated] = Field(default=None, description="Rule that was violated; must be None when APPROVED")
    reason_code: Optional[str] = Field(default=None, description="Standard machine-readable reason code")
