"""
Ed25519 Cryptographic Verification and Key Helpers for Option A.

Strict Invariants:
- Ed25519 (PureEdDSA over Curve25519) exclusively.
- Base64URL unpadded encoding (RFC 4648 §5).
- Deterministic byte construction: DomainSeparatorBytes || CanonicalJsonBytes.
- Gateway stores public keys only. No private keys inside gateway infrastructure.
"""
import base64
from typing import Any, Tuple
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.signing.canonical import build_signing_bytes

# Frozen Domain Separators (ADR-01 §4.1)
DOMAIN_KEY_REGISTRATION = "AGENTIC_COMMERCE_KEY_REGISTRATION_V1:"
DOMAIN_MANDATE = "AGENTIC_COMMERCE_MANDATE_V1:"
DOMAIN_APPROVAL = "AGENTIC_COMMERCE_APPROVAL_V1:"


def encode_base64url(data: bytes) -> str:
    """Encodes raw bytes into unpadded Base64URL string (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_base64url(s: str) -> bytes:
    """Decodes unpadded or padded Base64URL string into raw bytes."""
    clean = s.strip()
    rem = len(clean) % 4
    if rem > 0:
        clean += "=" * (4 - rem)
    return base64.urlsafe_b64decode(clean.encode("ascii"))


def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, str, str]:
    """
    Generates a new Ed25519 keypair for client-side simulation, test fixtures,
    and cross-language verification test vectors.
    Returns (private_key_obj, public_key_b64url, private_key_b64url).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes_raw()
    priv_bytes = private_key.private_bytes_raw()
    return private_key, encode_base64url(pub_bytes), encode_base64url(priv_bytes)


def sign_payload(
    private_key: ed25519.Ed25519PrivateKey,
    domain_separator: str,
    payload: Any,
) -> str:
    """
    Constructs deterministic signing bytes and signs with Ed25519 private key.
    Returns unpadded Base64URL 64-byte signature string (86 chars).
    """
    signing_bytes = build_signing_bytes(domain_separator, payload)
    sig_raw = private_key.sign(signing_bytes)
    return encode_base64url(sig_raw)


def sign_challenge(
    private_key: ed25519.Ed25519PrivateKey,
    challenge_token: str,
) -> str:
    """
    Signs a key-registration proof-of-possession challenge:
    SigningBytes = AGENTIC_COMMERCE_KEY_REGISTRATION_V1: || challenge_token (UTF-8).
    """
    signing_bytes = (DOMAIN_KEY_REGISTRATION + challenge_token).encode("utf-8")
    sig_raw = private_key.sign(signing_bytes)
    return encode_base64url(sig_raw)


def verify_payload_signature(
    public_key_b64url: str,
    signature_b64url: str,
    domain_separator: str,
    payload: Any,
) -> bool:
    """
    Verifies an Ed25519 signature over deterministic signing bytes.
    Returns True if valid; raises InvalidSignature or ValueError if malformed or invalid.
    """
    try:
        pub_bytes = decode_base64url(public_key_b64url)
        sig_bytes = decode_base64url(signature_b64url)
    except Exception as exc:
        raise ValueError(f"Failed to decode Base64URL cryptographic parameter: {exc}") from exc

    if len(pub_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be exactly 32 bytes, got {len(pub_bytes)}")
    if len(sig_bytes) != 64:
        raise ValueError(f"Ed25519 signature must be exactly 64 bytes, got {len(sig_bytes)}")

    signing_bytes = build_signing_bytes(domain_separator, payload)
    pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    pub_key_obj.verify(sig_bytes, signing_bytes)
    return True


def verify_challenge_signature(
    public_key_b64url: str,
    signature_b64url: str,
    challenge_token: str,
) -> bool:
    """
    Verifies proof-of-possession signature over registration challenge:
    SigningBytes = AGENTIC_COMMERCE_KEY_REGISTRATION_V1: || challenge_token (UTF-8).
    """
    try:
        pub_bytes = decode_base64url(public_key_b64url)
        sig_bytes = decode_base64url(signature_b64url)
    except Exception as exc:
        raise ValueError(f"Failed to decode Base64URL cryptographic parameter: {exc}") from exc

    if len(pub_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be exactly 32 bytes, got {len(pub_bytes)}")
    if len(sig_bytes) != 64:
        raise ValueError(f"Ed25519 signature must be exactly 64 bytes, got {len(sig_bytes)}")

    signing_bytes = (DOMAIN_KEY_REGISTRATION + challenge_token).encode("utf-8")
    pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    pub_key_obj.verify(sig_bytes, signing_bytes)
    return True

