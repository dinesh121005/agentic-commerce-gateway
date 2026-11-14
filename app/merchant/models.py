"""
Pydantic Request and Response Models for Merchant Identity & RBAC.
"""
import re
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


def _validate_email_format(v: str) -> str:
    clean = v.strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean):
        raise ValueError("Invalid email address format.")
    return clean


# ══════════════════════════════════════════════════════════════════════════════
# Authentication & Registration Models
# ══════════════════════════════════════════════════════════════════════════════

class RegisterMerchantRequest(BaseModel):
    """Payload to register a new merchant employee and create a merchant organization."""
    email: str = Field(..., description="Employee corporate email address")
    password: str = Field(..., min_length=8, description="Account password (min 8 characters)")
    full_name: str = Field(..., min_length=2, description="Employee full name")
    merchant_name: str = Field(..., min_length=2, description="Business / Organization name")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email_format(v)


class LoginRequest(BaseModel):
    """Payload for merchant employee authentication."""
    email: str = Field(..., description="Registered employee email")
    password: str = Field(..., description="Account password")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email_format(v)


class LoginResponse(BaseModel):
    """Response returned upon successful merchant authentication."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user_id: str
    merchant_id: str
    role: str


class SwitchMerchantRequest(BaseModel):
    """Payload to switch active tenant context to another authorized merchant organization."""
    target_merchant_id: str = Field(..., description="ID of merchant organization to switch into")


# ══════════════════════════════════════════════════════════════════════════════
# Domain Entity Representation Models
# ══════════════════════════════════════════════════════════════════════════════

class MerchantResponse(BaseModel):
    id: str
    name: str
    status: str
    created_at: float
    updated_at: float


class MerchantUserResponse(BaseModel):
    id: str
    email: str
    status: str
    created_at: float
    updated_at: float


class MerchantMembershipResponse(BaseModel):
    id: str
    merchant_id: str
    user_id: str
    role: str
    status: str
    created_at: float
    updated_at: float


class CreateMerchantRequest(BaseModel):
    name: str = Field(..., min_length=2, description="Name of the new merchant organization")


class CreateMemberRequest(BaseModel):
    email: str = Field(..., description="Corporate email for new member")
    role: str = Field(default="STAFF", description="Role to assign (STAFF, MANAGER, ADMIN)")
    password: Optional[str] = Field(None, min_length=8, description="Initial password if creating new user")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email_format(v)


class UpdateMemberRequest(BaseModel):
    role: Optional[str] = Field(None, description="New role to assign")
    status: Optional[str] = Field(None, description="New status ('ACTIVE', 'DISABLED', 'DEACTIVATED')")


class CreateInvitationRequest(BaseModel):
    email: str = Field(..., description="Recipient email address")
    role: str = Field(default="STAFF", description="Role to grant upon acceptance")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email_format(v)


class InvitationResponse(BaseModel):
    id: str
    merchant_id: str
    email: str
    role: str
    status: str
    expires_at: float
    created_at: float
    token: Optional[str] = None  # Returned only on creation for out-of-band delivery


class AcceptInvitationRequest(BaseModel):
    token: str = Field(..., description="Invitation token string")
    password: str = Field(..., min_length=8, description="Account password")
    full_name: Optional[str] = Field(None, description="Full name")


class CurrentUserProfile(BaseModel):
    user_id: str
    email: str
    status: str


class CurrentMerchantProfile(BaseModel):
    merchant_id: str
    name: str
    status: str
    role: str
    permissions: List[str]


class AvailableMerchantOrganization(BaseModel):
    merchant_id: str
    name: str
    role: str
    status: str


class MeResponse(BaseModel):
    """Complete profile of the authenticated employee in their active tenant context."""
    user: CurrentUserProfile
    active_merchant: CurrentMerchantProfile
    available_organizations: List[AvailableMerchantOrganization]
