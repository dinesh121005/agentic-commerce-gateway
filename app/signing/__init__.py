"""
Option A Non-Custodial Cryptographic Mandates & Signing Package.
"""
from app.signing.canonical import canonical_json_hash, rfc8785_canonicalize
from app.signing.crypto import (
    DOMAIN_APPROVAL,
    DOMAIN_KEY_REGISTRATION,
    DOMAIN_MANDATE,
    generate_ed25519_keypair,
    sign_payload,
    verify_payload_signature,
)
from app.signing.router import router as signing_router
from app.signing.store import signing_store

__all__ = [
    "rfc8785_canonicalize",
    "canonical_json_hash",
    "DOMAIN_KEY_REGISTRATION",
    "DOMAIN_MANDATE",
    "DOMAIN_APPROVAL",
    "generate_ed25519_keypair",
    "sign_payload",
    "verify_payload_signature",
    "signing_router",
    "signing_store",
]

