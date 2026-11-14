"""
Cryptographic utilities for Merchant Identity & Authentication.

Provides:
- Argon2id password hashing and constant-time verification.
- Dedicated Merchant Employee JWT token generation and validation.
- Cryptographic token generation and hashing for merchant invitations.
"""
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

import argon2
import jwt

# Dedicated secret for merchant employee JWTs (strictly decoupled from Buyer JWT_SECRET)
MERCHANT_JWT_SECRET = os.getenv(
    "MERCHANT_JWT_SECRET",
    "dev-merchant-jwt-secret-key-32chars-min-change-prod",
)
MERCHANT_JWT_ALGORITHM = "HS256"
MERCHANT_JWT_ISSUER = "merchant-platform"
MERCHANT_JWT_AUDIENCE = "merchant-platform"
MERCHANT_TOKEN_EXPIRY_SECONDS = 3600  # 1 hour

_argon2_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=argon2.Type.ID,
)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    return _argon2_hasher.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against an Argon2id hash.
    Returns True if valid, False on mismatch or error.
    """
    try:
        return _argon2_hasher.verify(hashed_password, password)
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Enforces password complexity:
    - Minimum 8 characters.
    - At least one letter.
    - At least one digit.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    return True, None


def create_merchant_access_token(
    user_id: str,
    merchant_id: str,
    role: str,
    token_version: int,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Mints a signed JWT access token specifically for a merchant employee.
    Enforces dedicated audience, token type, and token versioning for immediate revocation.
    """
    now = datetime.now(timezone.utc)
    expiry = now + (expires_delta or timedelta(seconds=MERCHANT_TOKEN_EXPIRY_SECONDS))

    payload: Dict[str, Any] = {
        "sub": user_id,
        "type": "merchant_employee",
        "aud": MERCHANT_JWT_AUDIENCE,
        "iss": MERCHANT_JWT_ISSUER,
        "merchant_id": merchant_id,
        "role": role,
        "token_version": token_version,
        "jti": str(uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(expiry.timestamp()),
    }
    return jwt.encode(payload, MERCHANT_JWT_SECRET, algorithm=MERCHANT_JWT_ALGORITHM)


def verify_merchant_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a merchant employee access token.
    Enforces strict signature verification, expiration, audience, and token type.
    """
    payload = jwt.decode(
        token,
        MERCHANT_JWT_SECRET,
        algorithms=[MERCHANT_JWT_ALGORITHM],
        audience=MERCHANT_JWT_AUDIENCE,
        issuer=MERCHANT_JWT_ISSUER,
    )
    if payload.get("type") != "merchant_employee":
        raise jwt.InvalidTokenError("Token is not a valid merchant employee token.")
    if not payload.get("sub"):
        raise jwt.InvalidTokenError("Token missing subject claim.")
    if not payload.get("merchant_id"):
        raise jwt.InvalidTokenError("Token missing merchant_id claim.")
    return payload


def generate_invitation_token() -> str:
    """Generates a cryptographically secure random invitation token."""
    return secrets.token_urlsafe(32)


def hash_invitation_token(raw_token: str) -> str:
    """Computes a deterministic SHA-256 hash of an invitation token for safe storage."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

