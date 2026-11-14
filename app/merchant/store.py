"""
Persistent Storage Layer for Multi-Tenant Merchant Identity, Memberships, and Invitations.

Compatible with both SQLite and PostgreSQL via universal connection manager.
Guarantees idempotent seeding of canonical legacy merchant ('MERCH_ELEC') to preserve
P0 cryptographic mandate signatures.
"""
import contextlib
import os
import time
from typing import Any, Dict, Generator, List, Optional, Tuple
from uuid import uuid4

from app.db import get_db_connection


class MerchantStore:
    """
    Thread-safe persistent storage for multi-tenant merchant organizations,
    employee accounts, memberships, and invitations.
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

    @contextlib.contextmanager
    def _get_auth_connection(self) -> Generator[Any, None, None]:
        """
        Provides an authentication database connection (role: gateway_auth) for privileged auth lookup.
        Fails closed if the required gateway_auth credential is not configured.
        """
        from app.db import is_postgres_url
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
        if not self._initialized:
            from app.db import is_postgres_url
            if is_postgres_url(self.db_path):
                try:
                    with self._get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'merchants';"
                        )
                        if cursor.fetchone():
                            self._initialized = True
                            return
                except Exception:
                    pass
            self._init_db()
            self._initialized = True

    def _init_db(self) -> None:
        """Creates tables for merchants, merchant_users, merchant_memberships, and merchant_invitations."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Merchants Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS merchants (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_merchants_status ON merchants (status);")

            # 2. Merchant Users Table (Employee Accounts)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS merchant_users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    token_version INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_merch_users_email ON merchant_users (email);")

            # 3. Merchant Memberships Table (Multi-Tenant Org Assignment & Role)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS merchant_memberships (
                    id TEXT PRIMARY KEY,
                    merchant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'STAFF',
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    UNIQUE(merchant_id, user_id)
                );
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_memberships_user ON merchant_memberships (user_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_memberships_merch ON merchant_memberships (merchant_id);")

            # 4. Merchant Invitations Table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS merchant_invitations (
                    id TEXT PRIMARY KEY,
                    merchant_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'STAFF',
                    token_hash TEXT UNIQUE NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    created_by TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_invitations_hash ON merchant_invitations (token_hash);")

            # 5. Idempotently Seed Canonical Legacy Merchant ('MERCH_ELEC')
            # This preserves existing Ed25519 signed mandate payloads and audit records
            now = time.time()
            cursor.execute(
                """
                INSERT INTO merchants (id, name, status, created_at, updated_at)
                VALUES ('MERCH_ELEC', 'Electronics Demo Merchant', 'ACTIVE', ?, ?)
                ON CONFLICT (id) DO NOTHING;
                """,
                (now, now),
            )
            conn.commit()

    # ══════════════════════════════════════════════════════════════════════════
    # Merchant Organization Methods
    # ══════════════════════════════════════════════════════════════════════════

    def create_merchant(self, name: str, merchant_id: Optional[str] = None, status: str = "ACTIVE") -> Dict[str, Any]:
        """Creates a new merchant organization via control-plane connection."""
        self._ensure_db_initialized()
        mid = merchant_id or f"merch_{uuid4().hex[:12]}"
        now = time.time()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO merchants (id, name, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (mid, name.strip(), status.upper(), now, now),
            )
            conn.commit()
        return self.get_merchant(mid)  # type: ignore

    def get_merchant(self, merchant_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a merchant organization by ID."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, status, created_at, updated_at FROM merchants WHERE id = ?;",
                (merchant_id.strip(),),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "name": row[1],
            "status": row[2],
            "created_at": row[3],
            "updated_at": row[4],
        }

    def list_merchants(self) -> List[Dict[str, Any]]:
        """Lists all merchant organizations."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, status, created_at, updated_at FROM merchants ORDER BY created_at ASC;")
            rows = cursor.fetchall()
        return [
            {"id": r[0], "name": r[1], "status": r[2], "created_at": r[3], "updated_at": r[4]}
            for r in rows
        ]

    # ══════════════════════════════════════════════════════════════════════════
    # Merchant User Methods
    # ══════════════════════════════════════════════════════════════════════════

    def create_user(
        self,
        email: str,
        password_hash: str,
        user_id: Optional[str] = None,
        status: str = "ACTIVE",
    ) -> Dict[str, Any]:
        """Creates a new merchant employee account via auth control plane."""
        self._ensure_db_initialized()
        uid = user_id or f"usr_{uuid4().hex[:12]}"
        now = time.time()
        clean_email = email.strip().lower()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO merchant_users (id, email, password_hash, status, token_version, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?);
                """,
                (uid, clean_email, password_hash, status.upper(), now, now),
            )
            conn.commit()
        return self.get_user_by_id(uid)  # type: ignore

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user by ID via auth control plane."""
        self._ensure_db_initialized()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, email, password_hash, status, token_version, created_at, updated_at FROM merchant_users WHERE id = ?;",
                (user_id.strip(),),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "email": row[1],
            "password_hash": row[2],
            "status": row[3],
            "token_version": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user by normalized email via auth control plane."""
        self._ensure_db_initialized()
        clean_email = email.strip().lower()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, email, password_hash, status, token_version, created_at, updated_at FROM merchant_users WHERE email = ?;",
                (clean_email,),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "email": row[1],
            "password_hash": row[2],
            "status": row[3],
            "token_version": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }

    def increment_user_token_version(self, user_id: str) -> int:
        """
        Increments token_version for a user via auth control plane, immediately revoking all previously issued JWTs.
        """
        self._ensure_db_initialized()
        now = time.time()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE merchant_users
                SET token_version = token_version + 1, updated_at = ?
                WHERE id = ?;
                """,
                (now, user_id.strip()),
            )
            conn.commit()
        user = self.get_user_by_id(user_id)
        return user["token_version"] if user else 1

    def update_user_status(self, user_id: str, status: str) -> bool:
        """Updates user account status (e.g. 'DEACTIVATED') via auth control plane."""
        self._ensure_db_initialized()
        now = time.time()
        with self._get_auth_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE merchant_users
                SET status = ?, token_version = token_version + 1, updated_at = ?
                WHERE id = ?;
                """,
                (status.upper(), now, user_id.strip()),
            )
            conn.commit()
            return cursor.rowcount > 0

    # ══════════════════════════════════════════════════════════════════════════
    # Merchant Membership Methods
    # ══════════════════════════════════════════════════════════════════════════

    def create_membership(
        self,
        merchant_id: str,
        user_id: str,
        role: str,
        membership_id: Optional[str] = None,
        status: str = "ACTIVE",
    ) -> Dict[str, Any]:
        """Creates a membership associating a user with a merchant organization."""
        self._ensure_db_initialized()
        mid = membership_id or f"mem_{uuid4().hex[:12]}"
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO merchant_memberships (id, merchant_id, user_id, role, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (mid, merchant_id.strip(), user_id.strip(), role.upper(), status.upper(), now, now),
            )
            conn.commit()
        return self.get_membership(merchant_id, user_id)  # type: ignore

    def get_membership(self, merchant_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an active or pending membership for a specific merchant and user."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, merchant_id, user_id, role, status, created_at, updated_at
                FROM merchant_memberships
                WHERE merchant_id = ? AND user_id = ?;
                """,
                (merchant_id.strip(), user_id.strip()),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "merchant_id": row[1],
            "user_id": row[2],
            "role": row[3],
            "status": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }

    def get_membership_by_id(self, membership_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a membership by ID."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, merchant_id, user_id, role, status, created_at, updated_at
                FROM merchant_memberships
                WHERE id = ?;
                """,
                (membership_id.strip(),),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "merchant_id": row[1],
            "user_id": row[2],
            "role": row[3],
            "status": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }

    def _has_pg_auth_functions(self, cursor: Any) -> bool:
        """Checks if trusted PostgreSQL auth functions exist in the database."""
        from app.db import is_postgres_url
        if not is_postgres_url(self.db_path):
            return False
        if getattr(self, "_pg_auth_funcs_available", None) is not None:
            return self._pg_auth_funcs_available
        try:
            cursor.execute("SELECT to_regproc('public.auth_lookup_user_memberships') IS NOT NULL;")
            row = cursor.fetchone()
            self._pg_auth_funcs_available = bool(row and row[0])
        except Exception:
            self._pg_auth_funcs_available = False
        return self._pg_auth_funcs_available

    def list_user_memberships(self, user_id: str) -> List[Dict[str, Any]]:
        """Lists all organizations a user belongs to."""
        self._ensure_db_initialized()
        clean_user_id = user_id.strip()
        from app.db import is_postgres_url
        if is_postgres_url(self.db_path):
            with self._get_auth_connection() as conn:
                cursor = conn.cursor()
                if self._has_pg_auth_functions(cursor):
                    cursor.execute(
                        """
                        SELECT id, merchant_id, role, status, merchant_name
                        FROM public.auth_lookup_user_memberships(?);
                        """,
                        (clean_user_id,),
                    )
                    rows = cursor.fetchall()
                    return [
                        {
                            "id": r[0],
                            "merchant_id": r[1],
                            "user_id": clean_user_id,
                            "role": r[2],
                            "status": r[3],
                            "created_at": None,
                            "updated_at": None,
                            "merchant_name": r[4],
                        }
                        for r in rows
                    ]

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT m.id, m.merchant_id, m.user_id, m.role, m.status, m.created_at, m.updated_at, o.name
                FROM merchant_memberships m
                JOIN merchants o ON m.merchant_id = o.id
                WHERE m.user_id = ? AND m.status = 'ACTIVE' AND o.status = 'ACTIVE'
                ORDER BY m.created_at ASC;
                """,
                (clean_user_id,),
            )
            rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "merchant_id": r[1],
                "user_id": r[2],
                "role": r[3],
                "status": r[4],
                "created_at": r[5],
                "updated_at": r[6],
                "merchant_name": r[7],
            }
            for r in rows
        ]

    def list_merchant_members(self, merchant_id: str) -> List[Dict[str, Any]]:
        """Lists all employee memberships belonging to a merchant organization."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT m.id, m.merchant_id, m.user_id, m.role, m.status, m.created_at, m.updated_at, u.email
                FROM merchant_memberships m
                JOIN merchant_users u ON m.user_id = u.id
                WHERE m.merchant_id = ?
                ORDER BY m.created_at ASC;
                """,
                (merchant_id.strip(),),
            )
            rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "merchant_id": r[1],
                "user_id": r[2],
                "role": r[3],
                "status": r[4],
                "created_at": r[5],
                "updated_at": r[6],
                "email": r[7],
            }
            for r in rows
        ]

    def count_active_owners(self, merchant_id: str) -> int:
        """Counts how many active OWNER memberships exist for a merchant."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM merchant_memberships
                WHERE merchant_id = ? AND role = 'OWNER' AND status = 'ACTIVE';
                """,
                (merchant_id.strip(),),
            )
            return cursor.fetchone()[0]

    def update_membership(
        self,
        membership_id: str,
        role: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Updates a membership's role or status."""
        self._ensure_db_initialized()
        existing = self.get_membership_by_id(membership_id)
        if not existing:
            return None

        new_role = role.upper() if role else existing["role"]
        new_status = status.upper() if status else existing["status"]
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE merchant_memberships
                SET role = ?, status = ?, updated_at = ?
                WHERE id = ?;
                """,
                (new_role, new_status, now, membership_id.strip()),
            )
            conn.commit()

        return self.get_membership_by_id(membership_id)

    def delete_membership(self, membership_id: str) -> bool:
        """Deletes a membership record."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM merchant_memberships WHERE id = ?;",
                (membership_id.strip(),),
            )
            conn.commit()
            return cursor.rowcount > 0

    # ══════════════════════════════════════════════════════════════════════════
    # Merchant Invitations Methods
    # ══════════════════════════════════════════════════════════════════════════

    def create_invitation(
        self,
        merchant_id: str,
        email: str,
        role: str,
        token_hash: str,
        created_by: str,
        expires_at: float,
    ) -> Dict[str, Any]:
        """Creates an invitation record with token stored securely as SHA-256 hash."""
        self._ensure_db_initialized()
        inv_id = f"inv_{uuid4().hex[:12]}"
        now = time.time()
        clean_email = email.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO merchant_invitations (
                    id, merchant_id, email, role, token_hash, status, created_by, expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?);
                """,
                (inv_id, merchant_id.strip(), clean_email, role.upper(), token_hash, created_by.strip(), expires_at, now, now),
            )
            conn.commit()
        return {
            "id": inv_id,
            "merchant_id": merchant_id,
            "email": clean_email,
            "role": role.upper(),
            "status": "PENDING",
            "created_by": created_by,
            "expires_at": expires_at,
            "created_at": now,
            "updated_at": now,
        }

    def get_invitation_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieves an invitation by token hash."""
        self._ensure_db_initialized()
        clean_hash = token_hash.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if self._has_pg_auth_functions(cursor):
                cursor.execute(
                    """
                    SELECT id, merchant_id, email, role, status, created_by, expires_at
                    FROM public.auth_lookup_invitation_by_token(?);
                    """,
                    (clean_hash,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    "id": row[0],
                    "merchant_id": row[1],
                    "email": row[2],
                    "role": row[3],
                    "token_hash": clean_hash,
                    "status": row[4],
                    "created_by": row[5],
                    "expires_at": row[6],
                    "created_at": None,
                    "updated_at": None,
                }

            cursor.execute(
                """
                SELECT id, merchant_id, email, role, token_hash, status, created_by, expires_at, created_at, updated_at
                FROM merchant_invitations
                WHERE token_hash = ?;
                """,
                (clean_hash,),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "merchant_id": row[1],
            "email": row[2],
            "role": row[3],
            "token_hash": row[4],
            "status": row[5],
            "created_by": row[6],
            "expires_at": row[7],
            "created_at": row[8],
            "updated_at": row[9],
        }

    def update_invitation_status(
        self,
        invitation_id: str,
        status: str,
        expected_status: Optional[str] = None,
    ) -> bool:
        """Updates invitation status ('ACCEPTED', 'REVOKED', 'EXPIRED')."""
        self._ensure_db_initialized()
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if expected_status:
                cursor.execute(
                    """
                    UPDATE merchant_invitations
                    SET status = ?, updated_at = ?
                    WHERE id = ? AND status = ?;
                    """,
                    (status.upper(), now, invitation_id.strip(), expected_status.upper()),
                )
            else:
                cursor.execute(
                    """
                    UPDATE merchant_invitations
                    SET status = ?, updated_at = ?
                    WHERE id = ?;
                    """,
                    (status.upper(), now, invitation_id.strip()),
                )
            conn.commit()
            return cursor.rowcount > 0

    def list_merchant_invitations(self, merchant_id: str) -> List[Dict[str, Any]]:
        """Lists all invitations issued for a merchant organization."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, merchant_id, email, role, status, created_by, expires_at, created_at, updated_at
                FROM merchant_invitations
                WHERE merchant_id = ?
                ORDER BY created_at DESC;
                """,
                (merchant_id.strip(),),
            )
            rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "merchant_id": r[1],
                "email": r[2],
                "role": r[3],
                "status": r[4],
                "created_by": r[5],
                "expires_at": r[6],
                "created_at": r[7],
                "updated_at": r[8],
            }
            for r in rows
        ]


# Singleton instance
merchant_store = MerchantStore()

