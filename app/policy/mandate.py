from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

# Note: Mandate signing, cryptographic verification, and AP2 verifiable credential machinery are explicitly out of scope.


class Mandate(BaseModel):
    """
    Customer's pre-set spending authorization mandate (AP2-inspired Intent Mandate pattern).
    Defines bounded, pre-authorized constraints that an AI agent cannot expand.
    """
    customer_id: str = Field(..., description="Unique customer identifier who authorized this mandate")
    display_name: str = Field(default="Demo Customer", description="Human display name of the customer (e.g. 'Dinesh Kumar')")
    max_transaction_amount: float = Field(..., gt=0, description="Maximum amount allowed per transaction in mandate currency")
    max_transaction_amount_paise: Optional[int] = Field(default=None, description="Maximum amount allowed per transaction in integer paise")
    daily_limit: Optional[float] = Field(default=5000.0, gt=0, description="Maximum total spend authorized per calendar day in mandate currency")
    daily_limit_paise: Optional[int] = Field(default=None, description="Maximum total spend authorized per calendar day in integer paise")
    currency: str = Field(default="INR", description="Currency code (e.g. INR)")
    allowed_categories: List[str] = Field(..., description="List of product categories authorized under this mandate")
    allowed_merchants: List[str] = Field(..., description="List of merchant identifiers authorized under this mandate")
    email: Optional[str] = Field(default=None, description="Optional email address of the customer")
    expires_at: Optional[datetime] = Field(default=None, description="Expiration timestamp in UTC (AP2-inspired TTL)")
    prompt_playback: Optional[str] = Field(default=None, description="Human-readable summary of what was authorized, for audit trail")

    @property
    def max_amount_paise(self) -> int:
        if self.max_transaction_amount_paise is not None:
            return self.max_transaction_amount_paise
        from decimal import Decimal, ROUND_HALF_UP
        return int((Decimal(str(self.max_transaction_amount)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

    @property
    def daily_limit_in_paise(self) -> Optional[int]:
        if self.daily_limit is None:
            return None
        if self.daily_limit_paise is not None:
            return self.daily_limit_paise
        from decimal import Decimal, ROUND_HALF_UP
        return int((Decimal(str(self.daily_limit)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """
        Pure helper method checking whether the mandate has expired.
        Returns False if expires_at is None. Treats naive datetimes as UTC.
        """
        if self.expires_at is None:
            return False

        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)

        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        return current_time > expiry
