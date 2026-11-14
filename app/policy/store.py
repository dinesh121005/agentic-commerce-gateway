import contextlib
from datetime import datetime, timezone
import json
import os
import sqlite3
import time
from typing import Any, Dict, Generator, List, Optional
from app.policy.mandate import Mandate

# Single source of truth for initial demo customer mandates
DEMO_MANDATES: Dict[str, Mandate] = {
    "CUST001": Mandate(
        customer_id="CUST001",
        display_name="Dinesh Kumar",
        email="dinesh@example.com",
        max_transaction_amount=2000.0,
        currency="INR",
        allowed_categories=["electronics", "home_kitchen", "apparel", "food"],
        allowed_merchants=["MERCH_ELEC", "MERCH_FOOD"],
        expires_at=None,
        prompt_playback="Pre-authorized spending up to ₹2,000 for electronics, home & kitchen, apparel, and food from verified demo merchants (MERCH_ELEC, MERCH_FOOD)."
    ),
    "CUST002": Mandate(
        customer_id="CUST002",
        display_name="Alex Smith",
        email="alex@example.com",
        max_transaction_amount=1500.0,
        currency="INR",
        allowed_categories=["electronics", "home_kitchen"],
        allowed_merchants=["MERCH_ELEC"],
        expires_at=None,
        prompt_playback="Pre-authorized spending up to ₹1,500 for electronics and home & kitchen from MERCH_ELEC only."
    ),
    "ai-buyer": Mandate(
        customer_id="ai-buyer",
        display_name="AI Buyer Autonomous Vault",
        email="ai-buyer@agentic-commerce.internal",
        max_transaction_amount=2000.0,
        daily_limit=5000.0,
        currency="INR",
        allowed_categories=["electronics", "home_kitchen", "apparel", "food"],
        allowed_merchants=["MERCH_ELEC", "MERCH_FOOD"],
        expires_at=None,
        prompt_playback="Pre-authorized AI Buyer Vault with ₹2,000 transaction limit for food, electronics, apparel, and kitchen essentials."
    ),
}


class MandateStore:
    """
    Persistent storage for customer spending mandates backed by SQLite (and DATABASE_URL).
    Seeded from DEMO_MANDATES on first startup, persists across server restarts and reloads.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path
        self._initialized = False

    @property
    def db_path(self) -> str:
        """Resolve database path lazily from constructor argument or DATABASE_URL."""
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
        """Create a new database connection (SQLite or PostgreSQL) via universal connection manager."""
        from app.db import get_db_connection
        with get_db_connection(self.db_path) as conn:
            yield conn


    def _ensure_db_initialized(self) -> None:
        """Ensure customer_mandates table exists and seed demo data."""
        if not self._initialized:
            from app.db import is_postgres_url
            if is_postgres_url(self.db_path):
                try:
                    with self._get_connection() as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'customer_mandates';"
                        )
                        if cursor.fetchone():
                            self._initialized = True
                            return
                except Exception:
                    pass
            self._init_db()
            self._initialized = True

    def _init_db(self) -> None:
        """Creates table customer_mandates and seeds DEMO_MANDATES if absent."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS customer_mandates (
                    customer_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    email TEXT,
                    max_transaction_amount REAL NOT NULL,
                    daily_limit REAL NOT NULL DEFAULT 5000.0,
                    currency TEXT NOT NULL DEFAULT 'INR',
                    allowed_categories TEXT NOT NULL,
                    allowed_merchants TEXT NOT NULL,
                    expires_at TEXT,
                    prompt_playback TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_mandates_email ON customer_mandates (email)"
            )
            conn.commit()

            # Seed demo mandates if not present
            now = time.time()
            for m in DEMO_MANDATES.values():
                cursor.execute(
                    "SELECT 1 FROM customer_mandates WHERE customer_id = ?",
                    (m.customer_id,),
                )
                if cursor.fetchone() is None:
                    cursor.execute(
                        """
                        INSERT INTO customer_mandates (
                            customer_id, display_name, email, max_transaction_amount,
                            daily_limit, currency, allowed_categories, allowed_merchants,
                            expires_at, prompt_playback, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            m.customer_id,
                            m.display_name,
                            m.email,
                            m.max_transaction_amount,
                            m.daily_limit or 5000.0,
                            m.currency,
                            json.dumps(m.allowed_categories),
                            json.dumps(m.allowed_merchants),
                            m.expires_at.isoformat() if m.expires_at else None,
                            m.prompt_playback,
                            now,
                            now,
                        ),
                    )
            conn.commit()

            # Safe migration: ensure paise columns exist (P0.1D Additive Migration)
            cursor.execute("SELECT * FROM customer_mandates LIMIT 0;")
            existing_cols = [desc[0].lower() for desc in (cursor.description or [])]
            if "max_transaction_amount_paise" not in existing_cols:
                try:
                    cursor.execute("ALTER TABLE customer_mandates ADD COLUMN max_transaction_amount_paise INTEGER;")
                    cursor.execute("ALTER TABLE customer_mandates ADD COLUMN daily_limit_paise INTEGER;")
                    conn.commit()
                except Exception:
                    pass
                try:
                    from decimal import Decimal, ROUND_HALF_UP
                    cursor.execute("SELECT customer_id, max_transaction_amount, daily_limit FROM customer_mandates WHERE max_transaction_amount_paise IS NULL;")
                    for cid, max_amt, d_limit in cursor.fetchall():
                        m_paise = int((Decimal(str(max_amt)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
                        d_paise = int((Decimal(str(d_limit or 5000.0)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
                        cursor.execute("UPDATE customer_mandates SET max_transaction_amount_paise = ?, daily_limit_paise = ? WHERE customer_id = ?;", (m_paise, d_paise, cid))
                    conn.commit()
                except Exception:
                    pass

    def _row_to_mandate(self, row: tuple) -> Mandate:
        """Convert a database row into a Pydantic Mandate instance."""
        if len(row) == 12:
            (
                customer_id,
                display_name,
                email,
                max_amount,
                daily_limit,
                currency,
                cats_json,
                merchs_json,
                exp_str,
                playback,
                _,
                _,
            ) = row
        else:
            (
                customer_id,
                display_name,
                email,
                max_amount,
                currency,
                cats_json,
                merchs_json,
                exp_str,
                playback,
                _,
                _,
            ) = row
            daily_limit = 5000.0

        cats = json.loads(cats_json) if isinstance(cats_json, str) else list(cats_json)
        merchs = json.loads(merchs_json) if isinstance(merchs_json, str) else list(merchs_json)
        exp_dt = datetime.fromisoformat(exp_str) if exp_str else None

        return Mandate(
            customer_id=customer_id,
            display_name=display_name,
            email=email,
            max_transaction_amount=float(max_amount),
            daily_limit=float(daily_limit) if daily_limit is not None else 5000.0,
            currency=currency or "INR",
            allowed_categories=cats,
            allowed_merchants=merchs,
            expires_at=exp_dt,
            prompt_playback=playback,
        )


    def get_mandate(self, customer_id: str) -> Optional[Mandate]:
        """
        Retrieve spending mandate for a specific customer.
        Prioritizes cryptographically signed mandates from Option A (signed_mandates);
        falls back to customer_mandates for legacy demo accounts.
        Returns None if no mandate is found.
        """
        self._ensure_db_initialized()

        # 1. Option A Signed Mandate Lookup
        try:
            from app.signing.store import signing_store
            active_signed = signing_store.get_active_mandate(customer_id)
            if active_signed:
                payload = active_signed.get("payload", {})
                exp_str = active_signed.get("valid_until") or payload.get("validity_period", {}).get("expires_at")
                exp_dt = datetime.fromisoformat(exp_str) if exp_str else None
                merch_id = active_signed.get("merchant_id", "*")
                merchs = [merch_id] if merch_id != "*" else ["*"]
                return Mandate(
                    customer_id=active_signed["customer_id"],
                    display_name=payload.get("display_name", f"Signed Mandate ({customer_id})"),
                    max_transaction_amount=float(active_signed["max_transaction_amount_paise"]) / 100.0,
                    daily_limit=float(active_signed["daily_budget_paise"]) / 100.0,
                    currency="INR",
                    allowed_categories=payload.get("allowed_categories", []),
                    allowed_merchants=merchs,
                    expires_at=exp_dt,
                    prompt_playback=payload.get("prompt_playback", "Option A Cryptographically Signed Spending Mandate"),
                )
        except Exception:
            pass

        # 2. Fallback to customer_mandates database table
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT customer_id, display_name, email, max_transaction_amount,
                       currency, allowed_categories, allowed_merchants,
                       expires_at, prompt_playback, created_at, updated_at
                FROM customer_mandates
                WHERE customer_id = ?
                """,
                (customer_id,),
            )
            row = cursor.fetchone()

        if row is None:
            return None
        return self._row_to_mandate(row)

    def find_by_identifier(self, identifier: str) -> List[Mandate]:
        """
        Find customer mandates matching a human identifier (name, email, or customer ID).
        Returns list of matching mandates.
        """
        if not identifier or not identifier.strip():
            return []

        clean = identifier.strip().lower()
        self._ensure_db_initialized()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT customer_id, display_name, email, max_transaction_amount,
                       currency, allowed_categories, allowed_merchants,
                       expires_at, prompt_playback, created_at, updated_at
                FROM customer_mandates
                """
            )
            rows = cursor.fetchall()

        all_mandates = [self._row_to_mandate(r) for r in rows]
        exact_matches: List[Mandate] = []
        partial_matches: List[Mandate] = []

        for mandate in all_mandates:
            if mandate.email and mandate.email.strip().lower() == clean:
                exact_matches.append(mandate)
                continue
            if mandate.customer_id.strip().lower() == clean:
                exact_matches.append(mandate)
                continue
            if mandate.display_name.strip().lower() == clean:
                exact_matches.append(mandate)
                continue
            if clean in mandate.display_name.strip().lower():
                partial_matches.append(mandate)

        results = exact_matches if exact_matches else partial_matches
        seen = set()
        deduped = []
        for m in results:
            if m.customer_id not in seen:
                seen.add(m.customer_id)
                deduped.append(m)
        return deduped

    def save_mandate(self, mandate: Mandate) -> None:
        """Store or update a customer mandate in SQLite."""
        self._ensure_db_initialized()
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO customer_mandates (
                    customer_id, display_name, email, max_transaction_amount,
                    daily_limit, currency, allowed_categories, allowed_merchants,
                    expires_at, prompt_playback, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(customer_id) DO UPDATE SET
                    display_name = excluded.display_name,
                    email = excluded.email,
                    max_transaction_amount = excluded.max_transaction_amount,
                    daily_limit = excluded.daily_limit,
                    currency = excluded.currency,
                    allowed_categories = excluded.allowed_categories,
                    allowed_merchants = excluded.allowed_merchants,
                    expires_at = excluded.expires_at,
                    prompt_playback = excluded.prompt_playback,
                    updated_at = excluded.updated_at
                """,
                (
                    mandate.customer_id,
                    mandate.display_name,
                    mandate.email,
                    mandate.max_transaction_amount,
                    mandate.daily_limit if mandate.daily_limit is not None else 5000.0,
                    mandate.currency,
                    json.dumps(mandate.allowed_categories),
                    json.dumps(mandate.allowed_merchants),
                    mandate.expires_at.isoformat() if mandate.expires_at else None,
                    mandate.prompt_playback,
                    now,
                    now,
                ),
            )
            conn.commit()

    def create_mandate(
        self,
        customer_id: str,
        mandate_limit: float,
        allowed_categories: List[str],
        allowed_merchants: List[str],
        display_name: str = "Demo Customer",
        email: Optional[str] = None,
        daily_limit: Optional[float] = 5000.0,
        expires_at: Optional[datetime] = None,
    ) -> Mandate:
        """Creates and stores a new customer mandate in SQLite."""
        self._ensure_db_initialized()
        existing = self.get_mandate(customer_id)
        if existing:
            raise ValueError(f"Mandate for customer '{customer_id}' already exists")

        cats_str = ", ".join(allowed_categories)
        merchs_str = ", ".join(allowed_merchants)
        playback = (
            f"Pre-authorized spending up to ₹{mandate_limit:,.0f} per transaction (₹{daily_limit:,.0f} daily) "
            f"for {cats_str} from verified demo merchants ({merchs_str})."
        )
        mandate = Mandate(
            customer_id=customer_id,
            display_name=display_name,
            email=email,
            max_transaction_amount=mandate_limit,
            daily_limit=daily_limit,
            currency="INR",
            allowed_categories=allowed_categories,
            allowed_merchants=allowed_merchants,
            expires_at=expires_at,
            prompt_playback=playback,
        )
        self.save_mandate(mandate)
        return mandate.model_copy()

    def update_mandate(
        self,
        customer_id: str,
        new_limit: Optional[float] = None,
        add_merchant: Optional[str] = None,
        add_category: Optional[str] = None,
    ) -> Mandate:
        """
        Updates spending limit, adds allowed merchant, and/or adds allowed category for an existing mandate.
        Persists changes to database and returns a verified Mandate instance reloaded from storage.
        """
        self._ensure_db_initialized()
        mandate = self.get_mandate(customer_id)
        if mandate is None:
            raise KeyError(f"Mandate for customer '{customer_id}' not found")

        if new_limit is not None:
            mandate.max_transaction_amount = float(new_limit)

        if add_merchant and add_merchant.strip():
            clean_m = add_merchant.strip()
            existing_merchs_upper = [m.upper() for m in mandate.allowed_merchants]
            if clean_m.upper() not in existing_merchs_upper:
                mandate.allowed_merchants.append(clean_m)

        if add_category and add_category.strip():
            clean_c = add_category.strip().lower()
            existing_cats_lower = [c.lower() for c in mandate.allowed_categories]
            if clean_c not in existing_cats_lower:
                mandate.allowed_categories.append(clean_c)

        cats_str = ", ".join(mandate.allowed_categories)
        merchs_str = ", ".join(mandate.allowed_merchants)
        mandate.prompt_playback = (
            f"Pre-authorized spending up to ₹{mandate.max_transaction_amount:,.0f} for {cats_str} "
            f"from verified merchants ({merchs_str})."
        )
        self.save_mandate(mandate)

        reloaded = self.get_mandate(customer_id)
        if reloaded is None:
            raise RuntimeError(f"Mandate for customer '{customer_id}' could not be reloaded after update.")
        return reloaded

    def update_mandate_limit(
        self,
        customer_id: str,
        new_limit: float,
    ) -> Mandate:
        """Updates the transaction limit for an existing customer mandate in database."""
        return self.update_mandate(customer_id=customer_id, new_limit=new_limit)

    def list_mandates(self) -> Dict[str, Mandate]:
        """List all stored mandates from SQLite."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT customer_id, display_name, email, max_transaction_amount,
                       currency, allowed_categories, allowed_merchants,
                       expires_at, prompt_playback, created_at, updated_at
                FROM customer_mandates
                ORDER BY created_at ASC
                """
            )
            rows = cursor.fetchall()

        return {r[0]: self._row_to_mandate(r) for r in rows}

    def delete_mandate(self, customer_id: str) -> bool:
        """Deletes a customer mandate from SQLite."""
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM customer_mandates WHERE customer_id = ?", (customer_id,))
            conn.commit()
            return cursor.rowcount > 0

    @property
    def _mandates(self) -> Dict[str, Mandate]:
        """Backwards-compatibility property returning dictionary of all mandates."""
        return self.list_mandates()


# Module-level singleton instance
mandate_store = MandateStore()

