"""
Persistent Storage Layer for Cryptographic Signing Keys, Challenges, Signed Mandates, and Approvals.

Implements ADR-01 specifications:
- Stores public keys exclusively (Option A Non-Custodial).
- Atomic challenge check & burn for proof-of-possession.
- Atomic mandate predecessor verification and version supersession.
- Single-use step-up purchase approval consumption.
"""
import contextlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Generator, List, Optional
from uuid import uuid4

from app.audit.store import audit_store
from app.db import get_db_connection
from app.signing.canonical import canonical_json_hash, rfc8785_canonicalize
from app.signing.crypto import (
    DOMAIN_APPROVAL,
    DOMAIN_MANDATE,
    verify_challenge_signature,
    verify_payload_signature,
)


class SigningStore:
    """
    Persistent store for Option A Non-Custodial signing entities.
    Compatible with SQLite and PostgreSQL via universal connection manager.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path
        self._initialized = False

    @property
    def db_path(self) -> str:
        if self._db_path is None:
            raw_url = os.environ.get("DATABASE_URL", "gateway.db")
            if raw_url.startswith("sqlite:///"):
                raw_url = raw_url[len("sqlite:///"):]
            elif raw_url.startswith("sqlite://"):
                raw_url = raw_url[len("sqlite://"):]
            self._db_path = raw_url
        return self._db_path

    @db_path.setter
    def db_path(self, value: str) -> None:
        self._db_path = value
        self._initialized = False

    @contextlib.contextmanager
    def _get_connection(self) -> Generator[Any, None, None]:
        with get_db_connection(self.db_path) as conn:
            yield conn

    def _ensure_db_initialized(self) -> None:
        if not self._initialized:
            self._init_db()
            self._initialized = True

    def _init_db(self) -> None:
        """Initializes tables for signing keys, challenges, signed mandates, and approvals."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Customer Signing Keys (stores public keys only)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS customer_signing_keys (
                    key_id TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    storage_type TEXT NOT NULL DEFAULT 'SOFTWARE_SECURE_STORAGE',
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_signing_keys_cust_status ON customer_signing_keys (customer_id, status);"
            )

            # 2. Signing Challenges (single-use PoP tokens)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS signing_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL,
                    challenge_token TEXT NOT NULL UNIQUE,
                    purpose TEXT NOT NULL DEFAULT 'KEY_REGISTRATION',
                    consumed INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_challenges_cust_unconsumed ON signing_challenges (customer_id, consumed, expires_at);"
            )

            # 3. Signed Mandates Ledger
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS signed_mandates (
                    mandate_id TEXT NOT NULL,
                    mandate_version INTEGER NOT NULL DEFAULT 1,
                    customer_id TEXT NOT NULL,
                    merchant_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    canonical_payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    domain_separator TEXT NOT NULL DEFAULT 'AGENTIC_COMMERCE_MANDATE_V1:',
                    max_transaction_amount_paise INTEGER NOT NULL,
                    daily_budget_paise INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    valid_from TEXT NOT NULL,
                    valid_until TEXT NOT NULL,
                    previous_mandate_id TEXT,
                    previous_payload_hash TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (mandate_id, mandate_version)
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_signed_mandates_cust_status ON signed_mandates (customer_id, status);"
            )

            # 4. Purchase Approvals (Step-up authorizations)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS purchase_approvals (
                    approval_id TEXT PRIMARY KEY,
                    purchase_id TEXT NOT NULL UNIQUE,
                    customer_id TEXT NOT NULL,
                    mandate_id TEXT NOT NULL,
                    mandate_version INTEGER NOT NULL,
                    key_id TEXT NOT NULL,
                    total_payable_paise INTEGER NOT NULL,
                    canonical_payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    signature TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
                    expires_at REAL NOT NULL,
                    consumed_at REAL,
                    created_at REAL NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_purchase_approvals_status ON purchase_approvals (purchase_id, status, expires_at);"
            )

            conn.commit()

    # ══════════════════════════════════════════════════════════════════════════
    # Key Registration & Challenges
    # ══════════════════════════════════════════════════════════════════════════

    def create_challenge(
        self,
        customer_id: str,
        purpose: str = "KEY_REGISTRATION",
        ttl_seconds: int = 300,
    ) -> dict:
        """Issues a new cryptographic challenge token for Proof of Possession."""
        self._ensure_db_initialized()
        import secrets
        from app.signing.crypto import DOMAIN_KEY_REGISTRATION

        challenge_id = str(uuid4())
        # Generate >= 32 bytes entropy
        challenge_token = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + ttl_seconds
        expires_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO signing_challenges (
                    challenge_id, customer_id, challenge_token, purpose, consumed, created_at, expires_at
                ) VALUES (?, ?, ?, ?, 0, ?, ?);
                """,
                (challenge_id, customer_id, challenge_token, purpose, now, expires_at),
            )
            conn.commit()

        # Append audit event
        audit_store.append_event(
            transaction_id=f"KEY_CHALLENGE_{challenge_id[:8]}",
            event_type="KEY_CHALLENGE_ISSUED",
            payload_dict={"customer_id": customer_id, "challenge_id": challenge_id, "purpose": purpose},
        )

        return {
            "challenge_id": challenge_id,
            "challenge_token": challenge_token,
            "domain_separator": DOMAIN_KEY_REGISTRATION,
            "expires_at": expires_iso,
        }

    def register_key(
        self,
        challenge_id: str,
        customer_id: str,
        public_key: str,
        signature: str,
        device_name: str,
        storage_type: str = "SOFTWARE_SECURE_STORAGE",
        key_ttl_days: int = 365,
    ) -> dict:
        """
        Verifies Proof of Possession against the challenge and registers the public key as ACTIVE.
        Atomically burns the challenge token.
        """
        self._ensure_db_initialized()
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT customer_id, challenge_token, consumed, expires_at FROM signing_challenges WHERE challenge_id = ?;",
                (challenge_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError("Challenge token not found")

            c_cust_id, token, consumed, expires_at = row[0], row[1], int(row[2]), float(row[3])
            if consumed == 1:
                raise ValueError("Challenge token has already been consumed")
            if expires_at < now:
                raise ValueError("Challenge token has expired")
            if c_cust_id != customer_id:
                raise ValueError("Challenge token does not match authenticated customer identity")

            # Verify Proof-of-Possession signature
            try:
                verify_challenge_signature(public_key, signature, token)
            except Exception as exc:
                raise ValueError(f"Proof of Possession signature verification failed: {exc}") from exc

            # Burn challenge atomically
            cursor.execute("UPDATE signing_challenges SET consumed = 1 WHERE challenge_id = ?;", (challenge_id,))

            key_id = str(uuid4())
            key_expires_at = now + (key_ttl_days * 86400)
            created_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
            expires_iso = datetime.fromtimestamp(key_expires_at, tz=timezone.utc).isoformat()

            cursor.execute(
                """
                INSERT INTO customer_signing_keys (
                    key_id, customer_id, public_key, device_name, storage_type, status, created_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, NULL);
                """,
                (key_id, customer_id, public_key, device_name, storage_type, now, key_expires_at),
            )
            conn.commit()

        # Append audit event
        audit_store.append_event(
            transaction_id=f"KEY_REG_{key_id[:8]}",
            event_type="KEY_REGISTERED",
            payload_dict={
                "key_id": key_id,
                "customer_id": customer_id,
                "storage_type": storage_type,
                "device_name": device_name,
            },
        )

        return {
            "key_id": key_id,
            "customer_id": customer_id,
            "public_key": public_key,
            "device_name": device_name,
            "storage_type": storage_type,
            "status": "ACTIVE",
            "created_at": created_iso,
            "expires_at": expires_iso,
            "revoked_at": None,
        }

    def revoke_key(self, key_id: str, customer_id: str, reason: str = "EXPLICIT_REVOCATION") -> dict:
        """Transitions a customer signing key to REVOKED (terminal state)."""
        self._ensure_db_initialized()
        now = time.time()
        now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT customer_id, status FROM customer_signing_keys WHERE key_id = ?;",
                (key_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyError(f"Key ID '{key_id}' not found")
            if row[0] != customer_id:
                raise PermissionError("Key does not belong to the authenticated customer")
            if row[1] == "REVOKED":
                raise ValueError("Key is already in terminal state REVOKED")

            cursor.execute(
                "UPDATE customer_signing_keys SET status = 'REVOKED', revoked_at = ? WHERE key_id = ?;",
                (now, key_id),
            )
            conn.commit()

        audit_store.append_event(
            transaction_id=f"KEY_REV_{key_id[:8]}",
            event_type="KEY_REVOKED",
            payload_dict={"key_id": key_id, "customer_id": customer_id, "reason": reason},
        )

        return {
            "key_id": key_id,
            "status": "REVOKED",
            "revoked_at": now_iso,
        }

    def get_key(self, key_id: str) -> Optional[dict]:
        """Fetches a signing key by ID."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT key_id, customer_id, public_key, device_name, storage_type, status, created_at, expires_at, revoked_at
                FROM customer_signing_keys WHERE key_id = ?;
                """,
                (key_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "key_id": row[0],
                "customer_id": row[1],
                "public_key": row[2],
                "device_name": row[3],
                "storage_type": row[4],
                "status": row[5],
                "created_at": datetime.fromtimestamp(float(row[6]), tz=timezone.utc).isoformat(),
                "expires_at": datetime.fromtimestamp(float(row[7]), tz=timezone.utc).isoformat(),
                "revoked_at": datetime.fromtimestamp(float(row[8]), tz=timezone.utc).isoformat() if row[8] else None,
            }

    def list_active_keys(self, customer_id: str) -> List[dict]:
        """Lists active, non-expired keys for a customer."""
        self._ensure_db_initialized()
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT key_id, customer_id, public_key, device_name, storage_type, status, created_at, expires_at, revoked_at
                FROM customer_signing_keys
                WHERE customer_id = ? AND status = 'ACTIVE' AND expires_at > ?
                ORDER BY created_at DESC;
                """,
                (customer_id, now),
            )
            rows = cursor.fetchall()
            return [
                {
                    "key_id": r[0],
                    "customer_id": r[1],
                    "public_key": r[2],
                    "device_name": r[3],
                    "storage_type": r[4],
                    "status": r[5],
                    "created_at": datetime.fromtimestamp(float(r[6]), tz=timezone.utc).isoformat(),
                    "expires_at": datetime.fromtimestamp(float(r[7]), tz=timezone.utc).isoformat(),
                    "revoked_at": None,
                }
                for r in rows
            ]

    # ══════════════════════════════════════════════════════════════════════════
    # Signed Spending Mandate Ledger
    # ══════════════════════════════════════════════════════════════════════════

    def save_signed_mandate(
        self,
        payload: dict,
        envelope: dict,
        authenticated_customer_id: str,
    ) -> dict:
        """
        Validates cryptographic envelope and saves signed spending mandate.
        Enforces ADR-01 §9 Mandate Replacement Invariants:
        - Version N+1 references predecessor payload hash.
        - Exactly one ACTIVE version per mandate chain.
        - Atomic supersession of predecessor in a single transaction.
        """
        self._ensure_db_initialized()

        # 1. Identity grounding
        if payload.get("customer_id") != authenticated_customer_id:
            raise ValueError("Mandate customer_id does not match authenticated session identity")

        # 2. Key status check
        key_id = envelope.get("key_id")
        key = self.get_key(key_id)
        if not key:
            raise ValueError(f"Signing key '{key_id}' not found")
        if key["customer_id"] != authenticated_customer_id:
            raise PermissionError("Signing key does not belong to the mandate customer")
        if key["status"] != "ACTIVE":
            raise ValueError(f"Signing key is not ACTIVE (current status: {key['status']})")

        # 3. Cryptographic signature verification over RFC 8785 canonical bytes
        try:
            verify_payload_signature(
                public_key_b64url=key["public_key"],
                signature_b64url=envelope.get("signature"),
                domain_separator=DOMAIN_MANDATE,
                payload=payload,
            )
        except Exception as exc:
            raise ValueError(f"Mandate Ed25519 signature verification failed: {exc}") from exc

        canonical_bytes = rfc8785_canonicalize(payload)
        payload_hash = canonical_json_hash(payload)
        mandate_id = payload["mandate_id"]
        version = int(payload["mandate_version"])
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 4. Enforce Versioning & Predecessor Invariants
            if version == 1:
                # Version 1 must have no existing active mandate with same ID
                cursor.execute(
                    "SELECT 1 FROM signed_mandates WHERE customer_id = ? AND mandate_id = ? AND status = 'ACTIVE';",
                    (authenticated_customer_id, mandate_id),
                )
                if cursor.fetchone() is not None:
                    raise ValueError(f"Active mandate '{mandate_id}' already exists. Incremented version required.")
            else:
                # Version > 1 must chain to previous version
                prev_id = payload.get("previous_mandate_id")
                prev_hash = payload.get("previous_payload_hash")
                if not prev_id or not prev_hash:
                    raise ValueError("Version > 1 mandates must specify previous_mandate_id and previous_payload_hash")

                cursor.execute(
                    """
                    SELECT mandate_version, payload_hash, status
                    FROM signed_mandates
                    WHERE customer_id = ? AND mandate_id = ? AND status = 'ACTIVE';
                    """,
                    (authenticated_customer_id, prev_id),
                )
                prev_row = cursor.fetchone()
                if not prev_row:
                    raise ValueError(f"Active predecessor mandate '{prev_id}' not found for replacement")

                prev_version, stored_prev_hash, _ = int(prev_row[0]), prev_row[1], prev_row[2]
                if version != prev_version + 1:
                    raise ValueError(f"Invalid version sequence: expected version {prev_version + 1}, got {version}")
                if prev_hash.lower() != stored_prev_hash.lower():
                    raise ValueError("Predecessor payload hash mismatch: cryptographic chaining verification failed")

                # Atomic supersession: mark predecessor as SUPERSEDED
                cursor.execute(
                    """
                    UPDATE signed_mandates
                    SET status = 'SUPERSEDED', updated_at = ?
                    WHERE customer_id = ? AND mandate_id = ? AND status = 'ACTIVE';
                    """,
                    (now, authenticated_customer_id, prev_id),
                )

            # Insert new ACTIVE version
            cursor.execute(
                """
                INSERT INTO signed_mandates (
                    mandate_id, mandate_version, customer_id, merchant_id, key_id,
                    canonical_payload, payload_hash, signature, domain_separator,
                    max_transaction_amount_paise, daily_budget_paise, status,
                    valid_from, valid_until, previous_mandate_id, previous_payload_hash,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?);
                """,
                (
                    mandate_id,
                    version,
                    authenticated_customer_id,
                    payload["merchant_id"],
                    key_id,
                    canonical_bytes.decode("utf-8"),
                    payload_hash,
                    envelope["signature"],
                    DOMAIN_MANDATE,
                    int(payload["max_transaction_amount_paise"]),
                    int(payload["daily_budget_paise"]),
                    payload["validity_period"]["not_before"],
                    payload["validity_period"]["expires_at"],
                    payload.get("previous_mandate_id"),
                    payload.get("previous_payload_hash"),
                    now,
                    now,
                ),
            )
            conn.commit()

        # Append audit event
        audit_event_type = "MANDATE_REGISTERED" if version == 1 else "MANDATE_SUPERSEDED"
        audit_store.append_event(
            transaction_id=f"MANDATE_{mandate_id[:8]}_v{version}",
            event_type=audit_event_type,
            payload_dict={
                "mandate_id": mandate_id,
                "version": version,
                "customer_id": authenticated_customer_id,
                "payload_hash": payload_hash,
            },
        )

        return {
            "mandate_id": mandate_id,
            "mandate_version": version,
            "status": "ACTIVE",
            "customer_id": authenticated_customer_id,
            "merchant_id": payload["merchant_id"],
            "max_transaction_amount_paise": int(payload["max_transaction_amount_paise"]),
            "daily_budget_paise": int(payload["daily_budget_paise"]),
            "created_at": payload["created_at"],
            "expires_at": payload["validity_period"]["expires_at"],
        }

    def revoke_mandate(self, mandate_id: str, customer_id: str) -> dict:
        """Transitions an active mandate to REVOKED (terminal state)."""
        self._ensure_db_initialized()
        now = time.time()
        now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE signed_mandates
                SET status = 'REVOKED', updated_at = ?
                WHERE customer_id = ? AND mandate_id = ? AND status = 'ACTIVE';
                """,
                (now, customer_id, mandate_id),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"No active mandate '{mandate_id}' found for revocation")
            conn.commit()

        audit_store.append_event(
            transaction_id=f"MANDATE_REV_{mandate_id[:8]}",
            event_type="MANDATE_REVOKED",
            payload_dict={"mandate_id": mandate_id, "customer_id": customer_id},
        )

        return {
            "mandate_id": mandate_id,
            "status": "REVOKED",
            "revoked_at": now_iso,
        }

    def get_active_mandate(self, customer_id: str) -> Optional[dict]:
        """Fetches the latest active signed mandate for a customer."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT mandate_id, mandate_version, customer_id, merchant_id, key_id,
                       canonical_payload, payload_hash, max_transaction_amount_paise,
                       daily_budget_paise, valid_from, valid_until, created_at
                FROM signed_mandates
                WHERE customer_id = ? AND status = 'ACTIVE'
                ORDER BY mandate_version DESC
                LIMIT 1;
                """,
                (customer_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            payload_dict = json.loads(row[5])
            return {
                "mandate_id": row[0],
                "mandate_version": int(row[1]),
                "customer_id": row[2],
                "merchant_id": row[3],
                "key_id": row[4],
                "payload": payload_dict,
                "payload_hash": row[6],
                "max_transaction_amount_paise": int(row[7]),
                "daily_budget_paise": int(row[8]),
                "valid_from": row[9],
                "valid_until": row[10],
                "created_at": datetime.fromtimestamp(float(row[11]), tz=timezone.utc).isoformat(),
            }

    # ══════════════════════════════════════════════════════════════════════════
    # Purchase Approvals (Step-up Authorizations)
    # ══════════════════════════════════════════════════════════════════════════

    def create_purchase_approval(
        self,
        purchase_id: str,
        customer_id: str,
        merchant_id: str,
        mandate_id: str,
        mandate_version: int,
        key_id: str,
        items: list,
        subtotal_paise: int,
        total_payable_paise: int,
        taxes_paise: int = 0,
        shipping_paise: int = 0,
        fees_paise: int = 0,
        ttl_seconds: int = 300,
    ) -> dict:
        """Generates a pending PurchaseApproval payload for sovereign client-side signing."""
        self._ensure_db_initialized()
        import secrets

        approval_id = str(uuid4())
        now = time.time()
        expires_at = now + ttl_seconds
        created_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        expires_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()

        approval_payload = {
            "schema_version": "1.0.0",
            "approval_id": approval_id,
            "purchase_id": purchase_id,
            "customer_id": customer_id,
            "merchant_id": merchant_id,
            "mandate_id": mandate_id,
            "mandate_version": mandate_version,
            "items": items,
            "subtotal_paise": subtotal_paise,
            "taxes_paise": taxes_paise,
            "shipping_paise": shipping_paise,
            "fees_paise": fees_paise,
            "total_payable_paise": total_payable_paise,
            "currency": "INR",
            "expires_at": expires_iso,
            "nonce": secrets.token_hex(16),
            "created_at": created_iso,
        }

        canonical_bytes = rfc8785_canonicalize(approval_payload)
        payload_hash = canonical_json_hash(approval_payload)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO purchase_approvals (
                    approval_id, purchase_id, customer_id, mandate_id, mandate_version, key_id,
                    total_payable_paise, canonical_payload, payload_hash, signature, status,
                    expires_at, consumed_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'PENDING_APPROVAL', ?, NULL, ?);
                """,
                (
                    approval_id,
                    purchase_id,
                    customer_id,
                    mandate_id,
                    mandate_version,
                    key_id,
                    total_payable_paise,
                    canonical_bytes.decode("utf-8"),
                    payload_hash,
                    expires_at,
                    now,
                ),
            )
            conn.commit()

        audit_store.append_event(
            transaction_id=purchase_id,
            event_type="PURCHASE_APPROVAL_CREATED",
            payload_dict={"approval_id": approval_id, "total_payable_paise": total_payable_paise},
        )

        return {
            "approval_id": approval_id,
            "purchase_id": purchase_id,
            "payload_to_sign": approval_payload,
            "domain_separator": DOMAIN_APPROVAL,
            "expires_at": expires_iso,
        }

    def consume_purchase_approval(
        self,
        approval_id: str,
        customer_id: str,
        key_id: str,
        signature: str,
    ) -> dict:
        """
        Verifies client-provided Ed25519 signature and atomically burns the approval to CONSUMED.
        """
        self._ensure_db_initialized()
        now = time.time()
        now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

        key = self.get_key(key_id)
        if not key or key["customer_id"] != customer_id or key["status"] != "ACTIVE":
            raise ValueError(f"Active key '{key_id}' not found for customer")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT purchase_id, customer_id, canonical_payload, status, expires_at
                FROM purchase_approvals
                WHERE approval_id = ?;
                """,
                (approval_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError("Approval record not found")

            purchase_id, app_cust_id, payload_json, status, expires_at = row[0], row[1], row[2], row[3], float(row[4])
            if app_cust_id != customer_id:
                raise PermissionError("Approval does not belong to the authenticated customer")
            if status != "PENDING_APPROVAL":
                raise ValueError(f"Approval cannot be consumed: current status is {status}")
            if expires_at < now:
                raise ValueError("Approval request has expired")

            payload_dict = json.loads(payload_json)

            # Verify Ed25519 signature over DOMAIN_APPROVAL || CanonicalJsonBytes
            try:
                verify_payload_signature(
                    public_key_b64url=key["public_key"],
                    signature_b64url=signature,
                    domain_separator=DOMAIN_APPROVAL,
                    payload=payload_dict,
                )
            except Exception as exc:
                raise ValueError(f"Approval signature verification failed: {exc}") from exc

            # Atomic single-use consumption
            cursor.execute(
                """
                UPDATE purchase_approvals
                SET status = 'CONSUMED', signature = ?, consumed_at = ?
                WHERE approval_id = ? AND status = 'PENDING_APPROVAL';
                """,
                (signature, now, approval_id),
            )
            if cursor.rowcount == 0:
                raise ValueError("Concurrent consumption detected: approval already consumed")
            conn.commit()

        audit_store.append_event(
            transaction_id=purchase_id,
            event_type="PURCHASE_APPROVAL_CONSUMED",
            payload_dict={"approval_id": approval_id, "key_id": key_id},
        )

        return {
            "purchase_id": purchase_id,
            "approval_id": approval_id,
            "status": "CONSUMED",
            "consumed_at": now_iso,
            "payment_execution_status": "APPROVED",
        }


signing_store = SigningStore()

