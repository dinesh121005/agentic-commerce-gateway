"""
Store for customer credentials, short-lived authorization codes, static OAuth client config,
and persisted refresh tokens with rotation.
"""
import base64
import contextlib
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

from app.oauth.crypto import hash_password, verify_password
from app.oauth.models import CustomerCredentials

# Static OAuth Client Configuration
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "claude-desktop-client")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "claude-demo-secret")

ALLOWED_CLIENT_IDS: Set[str] = {
    OAUTH_CLIENT_ID,
    "claude-desktop-client",
    "chatgpt",
    "chatgpt-connector",
    "chatgpt-client",
    "openai",
    "mcp-client",
    "ai-agent",
    "razorpay-mcp",
}


def is_allowed_client_id(client_id: Optional[str]) -> bool:
    """Validates whether a client_id is allowed for OAuth authorization and token exchange."""
    if not client_id:
        return False
    if client_id in ALLOWED_CLIENT_IDS:
        return True
    clean = client_id.strip().lower()
    if clean.startswith(("chatgpt", "openai", "claude", "mcp", "razorpay")):
        return True
    return False


# Google OAuth SSO Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://razorpay-c454.onrender.com/oauth/google/callback",
)

ALLOWED_REDIRECT_URIS: Set[str] = {
    "https://claude.ai/api/mcp/oauth_callback",
    "https://claude.ai/oauth/callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/api/aip/v1/auth/oauth/callback",
    "https://chat.openai.com/aip/v1/auth/oauth/callback",
    "http://localhost:8000/oauth/callback",
    "https://localhost:8000/oauth/callback",
    "http://127.0.0.1:8000/oauth/callback",
    "https://127.0.0.1:8000/oauth/callback",
    "http://localhost:3000/callback",
}


def register_dynamic_client(client_id: str, client_secret: str, redirect_uris: List[str]) -> None:
    """Registers an OAuth client dynamically per RFC 7591."""
    ALLOWED_CLIENT_IDS.add(client_id)
    for uri in redirect_uris:
        if uri:
            ALLOWED_REDIRECT_URIS.add(uri)



def is_allowed_redirect_uri(redirect_uri: Optional[str]) -> bool:
    """Validates whether a redirect_uri is allowed for OAuth authentication."""
    if not redirect_uri:
        return False
    if redirect_uri in ALLOWED_REDIRECT_URIS:
        return True
    from urllib.parse import urlparse
    try:
        parsed = urlparse(redirect_uri)
        netloc = parsed.netloc.lower()
        if (
            netloc in ("claude.ai", "www.claude.ai", "staging.claude.ai", "chatgpt.com", "chat.openai.com", "localhost", "127.0.0.1")
            or netloc.endswith(".claude.ai")
            or netloc.endswith(".anthropic.com")
            or netloc.endswith(".openai.com")
            or netloc.endswith(".chatgpt.com")
        ):
            return True
        if netloc.startswith("localhost:") or netloc.startswith("127.0.0.1:"):
            return True
    except Exception:
        pass
    return False



def _hash_token(raw_token: str) -> str:
    """Computes SHA-256 hash of an opaque high-entropy token for safe storage at rest."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def verify_pkce(
    code_verifier: Optional[str],
    code_challenge: Optional[str],
    method: Optional[str] = "S256",
) -> bool:
    """
    Verifies an RFC 7636 code_verifier against a code_challenge.
    Supports S256 (default) and plain.
    """
    if not code_verifier or not code_challenge:
        return False

    clean_method = (method or "S256").strip().upper()
    if clean_method == "S256":
        hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(hashed).decode("ascii").rstrip("=")
        target = code_challenge.rstrip("=")
        return hmac.compare_digest(computed, target)
    elif clean_method == "PLAIN":
        return hmac.compare_digest(code_verifier, code_challenge)
    return False


class AuthCodeRecord:
    """Represents a temporary, single-use authorization code with optional PKCE challenge."""
    def __init__(
        self,
        code: str,
        customer_id: str,
        client_id: str,
        redirect_uri: str,
        expires_at: float,
        scope: str = "purchase",
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ):
        self.code = code
        self.customer_id = customer_id
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.expires_at = expires_at
        self.scope = scope
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method


class AuthorizationCodeStore:
    """Manages short-lived single-use authorization codes with 5-minute TTL and RFC 7636 PKCE validation."""
    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._codes: Dict[str, AuthCodeRecord] = {}

    def issue_code(
        self,
        customer_id: str,
        client_id: str,
        redirect_uri: str,
        scope: str = "purchase",
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> str:
        code = secrets.token_urlsafe(32)
        record = AuthCodeRecord(
            code=code,
            customer_id=customer_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            expires_at=time.time() + self.ttl_seconds,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        self._codes[code] = record
        return code

    def get_code_record(self, code: str) -> Optional[AuthCodeRecord]:
        """Peeks at the code record without consuming it (useful for credential validation)."""
        return self._codes.get(code)

    def consume_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> Optional[str]:
        """
        Validates and burns (consumes) an authorization code.
        If the code was issued with a PKCE code_challenge, code_verifier must be verified.
        Returns customer_id if valid, or None if expired/invalid/already used/PKCE failed.
        """
        record = self._codes.pop(code, None)
        if record is None:
            return None

        # Check expiration
        if time.time() > record.expires_at:
            return None

        # Check client_id and redirect_uri binding
        if record.client_id != client_id or record.redirect_uri != redirect_uri:
            return None

        # Check PKCE if code was issued with code_challenge
        if record.code_challenge:
            if not verify_pkce(code_verifier, record.code_challenge, record.code_challenge_method):
                return None

        return record.customer_id


class CustomerAuthStore:
    """
    Persisted SQLite credentials and refresh tokens store for customer OAuth logins.
    Seeded with canonical demo users (CUST001, CUST002) upon initialization.
    """
    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path
        self._initialized = False

    @property
    def db_path(self) -> str:
        if self._db_path is None:
            raw_url = os.getenv("DATABASE_URL", "gateway.db")
            if raw_url.startswith("sqlite:///"):
                self._db_path = raw_url.replace("sqlite:///", "")
            else:
                self._db_path = raw_url
        return self._db_path

    @db_path.setter
    def db_path(self, value: str) -> None:
        self._db_path = value
        self._initialized = False

    @contextlib.contextmanager
    def _get_connection(self) -> Generator[Any, None, None]:
        """Create a new database connection (SQLite or PostgreSQL) via universal connection manager."""
        from app.db import get_db_connection
        with get_db_connection(self.db_path) as conn:
            yield conn

    @contextlib.contextmanager
    def _get_auth_connection(self) -> Generator[Any, None, None]:
        """
        Provides an authentication database connection (role: gateway_auth) for customer credential operations.
        Fails closed if the required gateway_auth credential is not configured.
        """
        from app.db import is_postgres_url, get_db_connection
        if is_postgres_url(self.db_path):
            auth_url = os.environ.get("LOCAL_PG_AUTH_URL") or os.environ.get("PG_AUTH_URL")
            if not auth_url:
                raise RuntimeError(
                    "Security failure: Missing required database connection URL for gateway_auth role: LOCAL_PG_AUTH_URL"
                )
            with get_db_connection(auth_url) as conn:
                yield conn
        else:
            with self._get_connection() as conn:
                yield conn


    def _ensure_db_initialized(self) -> None:
        """Ensure the table schema and seeds exist before operations."""
        if not self._initialized:
            from app.db import is_postgres_url
            if is_postgres_url(self.db_path):
                try:
                    with self._get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'customer_credentials';"
                        )
                        if cursor.fetchone():
                            self._initialized = True
                            return
                except Exception:
                    pass
            self._init_db()
            self._initialized = True

    def _init_db(self) -> None:
        """Ensure the customer_credentials and refresh_tokens tables exist and are seeded."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS customer_credentials (
                    customer_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
                """
            )
            # Seed demo users if not already present
            self._seed_demo_users(cursor)
            conn.commit()

    def _seed_demo_users(self, cursor: sqlite3.Cursor) -> None:
        """Seed canonical demo users (CUST001, CUST002) if not present."""
        # CUST001: dinesh / password123
        cursor.execute("SELECT 1 FROM customer_credentials WHERE customer_id = 'CUST001'")
        if cursor.fetchone() is None:
            h1, s1 = hash_password("password123")
            cursor.execute(
                """
                INSERT INTO customer_credentials (customer_id, username, email, password_hash, salt)
                VALUES ('CUST001', 'dinesh', 'dinesh@example.com', ?, ?)
                ON CONFLICT (customer_id) DO NOTHING;
                """,
                (h1, s1),
            )

        # CUST002: alex / password123
        cursor.execute("SELECT 1 FROM customer_credentials WHERE customer_id = 'CUST002'")
        if cursor.fetchone() is None:
            h2, s2 = hash_password("password123")
            cursor.execute(
                """
                INSERT INTO customer_credentials (customer_id, username, email, password_hash, salt)
                VALUES ('CUST002', 'alex', 'alex@example.com', ?, ?)
                ON CONFLICT (customer_id) DO NOTHING;
                """,
                (h2, s2),
            )

    def authenticate(self, username_or_email: str, password: str) -> Optional[str]:
        """
        Authenticates user credentials against the persisted store via auth control plane.
        Returns customer_id on success, or None on failure.
        """
        self._ensure_db_initialized()
        clean = username_or_email.strip().lower()

        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT customer_id, password_hash, salt
                FROM customer_credentials
                WHERE LOWER(username) = ? OR LOWER(email) = ?
                LIMIT 1
                """,
                (clean, clean),
            )
            row = cursor.fetchone()

        if row is None:
            return None

        customer_id, pw_hash, salt = row
        if verify_password(password, pw_hash, salt):
            return customer_id
        return None

    def register_user(
        self,
        customer_id: str,
        username: str,
        email: Optional[str],
        password: str,
    ) -> CustomerCredentials:
        """
        Registers new customer credentials via auth control plane.
        Raises ValueError if customer_id or username already exists.
        """
        self._ensure_db_initialized()
        clean_user = username.strip().lower()

        pw_hash, salt = hash_password(password)

        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM customer_credentials WHERE customer_id = ?", (customer_id,))
            if cursor.fetchone() is not None:
                raise ValueError(f"Credentials for customer_id '{customer_id}' already exist.")

            cursor.execute("SELECT 1 FROM customer_credentials WHERE LOWER(username) = ?", (clean_user,))
            if cursor.fetchone() is not None:
                raise ValueError(f"Username '{username}' is already taken.")

            cursor.execute(
                """
                INSERT INTO customer_credentials (customer_id, username, email, password_hash, salt)
                VALUES (?, ?, ?, ?, ?)
                """,
                (customer_id, clean_user, email, pw_hash, salt),
            )
            conn.commit()

        return CustomerCredentials(
            customer_id=customer_id,
            username=clean_user,
            email=email or f"{clean_user}@example.com",
            password_hash=pw_hash,
            salt=salt,
        )

    def get_user_by_customer_id(self, customer_id: str) -> Optional[CustomerCredentials]:
        """Fetch user credentials by customer_id via auth control plane."""
        self._ensure_db_initialized()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT customer_id, username, email, password_hash, salt FROM customer_credentials WHERE customer_id = ?",
                (customer_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return CustomerCredentials(
            customer_id=row[0],
            username=row[1],
            email=row[2],
            password_hash=row[3],
            salt=row[4],
        )

    def get_user_by_username(self, username: str) -> Optional[CustomerCredentials]:
        """Fetch user credentials by username via auth control plane."""
        self._ensure_db_initialized()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT customer_id, username, email, password_hash, salt FROM customer_credentials WHERE LOWER(username) = ?",
                (username.strip().lower(),),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return CustomerCredentials(
            customer_id=row[0],
            username=row[1],
            email=row[2],
            password_hash=row[3],
            salt=row[4],
        )

    def get_user_by_email(self, email: str) -> Optional[CustomerCredentials]:
        """Fetch user credentials by email address via auth control plane."""
        self._ensure_db_initialized()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT customer_id, username, email, password_hash, salt FROM customer_credentials WHERE LOWER(email) = ?",
                (email.strip().lower(),),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return CustomerCredentials(
            customer_id=row[0],
            username=row[1],
            email=row[2],
            password_hash=row[3],
            salt=row[4],
        )

    def delete_user(self, customer_id: str) -> bool:
        """Deletes credentials for a customer (e.g. for atomic rollback)."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM customer_credentials WHERE customer_id = ?", (customer_id,))
            conn.commit()
            return cursor.rowcount > 0

    # -------------------------------------------------------------------------
    # Refresh Token Management (SHA-256 Hashed at rest with Rotation)
    # -------------------------------------------------------------------------
    def issue_refresh_token(
        self,
        customer_id: str,
        client_id: str,
        ttl_days: int = 30,
    ) -> str:
        """
        Generates a high-entropy opaque refresh token, hashes it via SHA-256,
        and stores the record in SQLite with a 30-day default TTL.
        Returns the raw opaque token string to the client.
        """
        self._ensure_db_initialized()
        raw_token = secrets.token_urlsafe(48)
        token_hash = _hash_token(raw_token)
        now = time.time()
        expires_at = now + (ttl_days * 86400)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO refresh_tokens (token_hash, customer_id, client_id, expires_at, revoked, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (token_hash, customer_id, client_id, expires_at, now),
            )
            conn.commit()

        return raw_token

    def rotate_refresh_token(
        self,
        raw_refresh_token: str,
        client_id: str,
        ttl_days: int = 30,
    ) -> Optional[Tuple[str, str]]:
        """
        Validates an existing refresh token, revokes (burns) it, and issues a new rotated refresh token.
        Enforces Refresh Token Rotation (RTR).
        Returns (customer_id, new_raw_refresh_token) on success, or None if invalid/expired/revoked.
        """
        self._ensure_db_initialized()
        if not raw_refresh_token:
            return None

        old_token_hash = _hash_token(raw_refresh_token)
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT customer_id, client_id, expires_at, revoked
                FROM refresh_tokens
                WHERE token_hash = ?
                """,
                (old_token_hash,),
            )
            row = cursor.fetchone()
            if row is None:
                return None

            customer_id, bound_client_id, expires_at, revoked = row

            # Reject if already revoked, expired, or bound to another client
            if revoked != 0 or now > expires_at or bound_client_id != client_id:
                return None

            # Mark old refresh token revoked
            cursor.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
                (old_token_hash,),
            )

            # Issue new rotated refresh token
            new_raw_token = secrets.token_urlsafe(48)
            new_token_hash = _hash_token(new_raw_token)
            new_expires_at = now + (ttl_days * 86400)

            cursor.execute(
                """
                INSERT INTO refresh_tokens (token_hash, customer_id, client_id, expires_at, revoked, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (new_token_hash, customer_id, client_id, new_expires_at, now),
            )
            conn.commit()

        return customer_id, new_raw_token


# Singleton instances
auth_code_store = AuthorizationCodeStore()
customer_auth_store = CustomerAuthStore()


def provision_new_customer(
    display_name: str,
    username: Optional[str] = None,
    email: Optional[str] = None,
    password: Optional[str] = None,
    initial_budget: float = 2000.0,
) -> Tuple[str, CustomerCredentials]:
    """
    Provisions a new customer account in both customer_auth_store and mandate_store.
    Returns (customer_id, CustomerCredentials).
    """
    import uuid
    from app.policy.store import mandate_store

    clean_email = email.strip().lower() if email else None

    # Generate unique customer_id with random hex suffix
    suffix = uuid.uuid4().hex[:6].upper()
    customer_id = f"CUST_{suffix}"

    # Generate unique username
    if not username:
        if clean_email:
            base_user = clean_email.split("@")[0]
        else:
            base_user = display_name.lower().replace(" ", "")
        username = base_user
    clean_username = username.strip().lower()

    # Ensure username is unique
    existing = customer_auth_store.get_user_by_username(clean_username)
    if existing:
        clean_username = f"{clean_username}_{suffix[:4].lower()}"

    pw = password or secrets.token_urlsafe(16)

    # Register in auth store
    creds = customer_auth_store.register_user(
        customer_id=customer_id,
        username=clean_username,
        email=clean_email or f"{clean_username}@example.com",
        password=pw,
    )

    # Create standard mandate in policy store
    try:
        mandate_store.create_mandate(
            customer_id=customer_id,
            display_name=display_name,
            mandate_limit=initial_budget,
            allowed_categories=["electronics", "home_kitchen", "apparel", "food"],
            allowed_merchants=["MERCH_ELEC", "MERCH_FOOD"],
            email=clean_email or f"{clean_username}@example.com",
        )
    except Exception as e:
        customer_auth_store.delete_user(customer_id)
        raise e

    return customer_id, creds

