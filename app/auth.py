import logging
import os
import secrets
from typing import Optional
from fastapi import Header, HTTPException, Request, status

logger = logging.getLogger("gateway.auth")

_AUTO_GENERATED_PROD_KEY: Optional[str] = None


def get_admin_api_key() -> str:
    """
    Retrieve the configured ADMIN_API_KEY from the environment.
    
    Security Posture:
    - In Development/Testing: Defaults to 'dev-admin-secret-key' for developer ergonomics.
    - In Production: If ADMIN_API_KEY is not set or set to default, securely auto-generates
      an ephemeral 256-bit cryptographic token (preventing default credential compromise)
      and logs a prominent security warning for the operator.
    """
    global _AUTO_GENERATED_PROD_KEY
    env_key = os.environ.get("ADMIN_API_KEY")
    is_prod = os.environ.get("ENVIRONMENT", os.environ.get("ENV", "development")).lower() == "production"

    if env_key and env_key != "dev-admin-secret-key":
        return env_key

    if is_prod:
        if _AUTO_GENERATED_PROD_KEY is None:
            _AUTO_GENERATED_PROD_KEY = secrets.token_urlsafe(32)
            logger.warning(
                "====================================================================\n"
                "🔒 PRODUCTION SECURITY ALERT: ADMIN_API_KEY not configured!\n"
                "To prevent unauthorized access with default credentials, an ephemeral\n"
                "cryptographic secret was auto-generated for this session:\n"
                "  ADMIN_API_KEY: %s\n"
                "Please set ADMIN_API_KEY in your hosting environment variables.\n"
                "====================================================================",
                _AUTO_GENERATED_PROD_KEY,
            )
        return _AUTO_GENERATED_PROD_KEY

    return "dev-admin-secret-key"


def verify_admin_key(request: Request) -> str:
    """
    FastAPI dependency validating that the caller holds valid admin credentials.
    Accepts either:
      - 'X-Admin-API-Key: <key>'
      - 'Authorization: Bearer <key>'
    """
    expected_key = get_admin_api_key()

    provided_key = request.headers.get("x-admin-api-key")
    if not provided_key:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            provided_key = auth_header[len("Bearer "):].strip()

    if not provided_key or not secrets.compare_digest(provided_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing or invalid Admin API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return provided_key


def verify_agent_or_admin_auth(request: Request) -> dict:
    """
    FastAPI dependency validating that the caller is authenticated as an AI Agent
    (via OAuth 2.1 Bearer JWT token) OR as a System Administrator (via Admin API Key).

    Returns a dict with:
      {"auth_type": "admin", "customer_id": None} OR
      {"auth_type": "oauth", "customer_id": "<sub_claim>"}
    """
    expected_admin_key = get_admin_api_key()

    # 1. Check X-Admin-API-Key with constant-time comparison
    x_admin_key = request.headers.get("x-admin-api-key")
    if x_admin_key and secrets.compare_digest(x_admin_key.strip(), expected_admin_key):
        return {"auth_type": "admin", "customer_id": None}

    # 2. Check Authorization Header with constant-time comparison
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):].strip()
        if secrets.compare_digest(token, expected_admin_key):
            return {"auth_type": "admin", "customer_id": None}

        # Attempt to decode as OAuth JWT Access Token
        try:
            from app.oauth.crypto import verify_access_token
            payload = verify_access_token(token)
            customer_id = payload.get("sub")
            if not customer_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Unauthorized: Access token missing 'sub' claim",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return {"auth_type": "oauth", "customer_id": customer_id}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unauthorized: Invalid or expired OAuth access token ({str(exc)})",
                headers={"WWW-Authenticate": "Bearer"},
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Valid OAuth Bearer token or Admin API Key required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def verify_customer_oauth_token(request: Request) -> str:
    """
    FastAPI dependency strictly requiring customer authentication via OAuth 2.1 Bearer JWT.
    Extracts the authenticated customer_id from the 'sub' claim (ADR-01 §7.1 Identity Grounding).
    Rejects administrative API keys, as non-custodial signing is sovereign to the customer.
    """
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing OAuth Bearer token in Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[len("Bearer "):].strip()
    try:
        from app.oauth.crypto import verify_access_token
        payload = verify_access_token(token)
        customer_id = payload.get("sub")
        if not customer_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Access token missing 'sub' claim",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return customer_id
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unauthorized: Invalid or expired OAuth access token ({str(exc)})",
            headers={"WWW-Authenticate": "Bearer"},
        )


