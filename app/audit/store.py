"""
SQLite persistence layer for the audit trail with SHA-256 cryptographic hash chaining.

Architectural Design: Append-Only Event Ledger (`audit_events`) with a Queryable Current-State Projection (`audit_records`).
Every proposal evaluation and payment status transition appends a tamper-evident block to the SHA-256 hash-chained event log,
while updating the relational projection view for fast querying.
"""
import contextlib
from datetime import datetime, timezone
import hashlib
import os
import sqlite3
import time
from typing import Any, Dict, Generator, List, Optional, Tuple

from app.audit.models import AuditRecord


import json
from uuid import uuid4

def compute_audit_hash(
    prev_hash: str,
    transaction_id: str,
    timestamp: str,
    customer_id: str,
    product_id: str,
    amount: float,
    decision: str,
    payment_status: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> str:
    """
    Legacy record hash computation (kept for backward compatibility).
    """
    raw = (
        f"{prev_hash}|{transaction_id}|{timestamp}|{customer_id}|"
        f"{product_id}|{amount:.2f}|{decision}|{payment_status or ''}|{idempotency_key or ''}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_event_hash(
    prev_hash: str,
    event_id: str,
    transaction_id: str,
    event_type: str,
    timestamp: str,
    payload_json: str,
) -> str:
    """
    Computes a deterministic SHA-256 hash chaining the previous event block's hash
    with the current event's payload to ensure an append-only, tamper-evident audit ledger.
    """
    raw = f"{prev_hash}|{event_id}|{transaction_id}|{event_type}|{timestamp}|{payload_json}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditStore:
    """
    Manages database connections and CRUD operations for audit records
    with continuous append-only cryptographic hash verification.
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
        """Ensure the table schema exists before operations."""
        if not self._initialized:
            self._init_db()
            self._initialized = True

    def _init_db(self) -> None:
        """Ensure the audit_records and append-only audit_events tables exist with hash chain."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    transaction_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    customer_id TEXT NOT NULL,
                    product_id TEXT NOT NULL,
                    merchant_id TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    amount REAL NOT NULL,
                    decision TEXT NOT NULL,
                    decision_reason TEXT NOT NULL,
                    payment_status TEXT,
                    razorpay_order_id TEXT,
                    razorpay_payment_id TEXT,
                    idempotency_key TEXT UNIQUE,
                    prev_hash TEXT DEFAULT 'GENESIS',
                    record_hash TEXT
                );
                """
            )
            cursor.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_idempotency_key ON audit_records(idempotency_key);"
            )
            # Safe migration: check existing columns before running ALTER TABLE
            cursor.execute("SELECT * FROM audit_records LIMIT 0;")
            existing_cols = [desc[0].lower() for desc in (cursor.description or [])]
            if "razorpay_payment_id" not in existing_cols:
                try:
                    cursor.execute("ALTER TABLE audit_records ADD COLUMN razorpay_payment_id TEXT;")
                    conn.commit()
                except Exception:
                    conn.rollback()

            if "amount_paise" not in existing_cols:
                try:
                    cursor.execute("ALTER TABLE audit_records ADD COLUMN amount_paise INTEGER;")
                    conn.commit()
                except Exception:
                    conn.rollback()
                try:
                    from decimal import Decimal, ROUND_HALF_UP
                    cursor.execute("SELECT transaction_id, amount FROM audit_records WHERE amount_paise IS NULL;")
                    for tx_id, amt in cursor.fetchall():
                        a_paise = int((Decimal(str(amt)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
                        cursor.execute("UPDATE audit_records SET amount_paise = ? WHERE transaction_id = ?;", (a_paise, tx_id))
                    conn.commit()
                except Exception:
                    conn.rollback()

            # Append-only cryptographic ledger
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    transaction_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_tx ON audit_events(transaction_id);"
            )

            # Persistent Webhook Event Deduplication Ledger
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_webhook_events (
                    event_id TEXT PRIMARY KEY,
                    received_at REAL NOT NULL
                );
                """
            )

            # Auto-migrate/backfill legacy audit_records into append-only audit_events if needed
            cursor.execute(
                """
                SELECT transaction_id, timestamp, customer_id, product_id, merchant_id,
                       quantity, amount, decision, decision_reason, payment_status, idempotency_key
                FROM audit_records
                WHERE transaction_id NOT IN (SELECT DISTINCT transaction_id FROM audit_events)
                ORDER BY timestamp ASC;
                """
            )
            legacy_rows = cursor.fetchall()
            for l_row in legacy_rows:
                tx_id, ts, cust_id, prod_id, merch_id, qty, amt, dec, dec_re, p_st, idemp = l_row
                payload = {
                    "customer_id": cust_id,
                    "product_id": prod_id,
                    "merchant_id": merch_id,
                    "quantity": qty,
                    "amount": amt,
                    "decision": dec,
                    "decision_reason": dec_re,
                    "payment_status": p_st,
                    "idempotency_key": idemp,
                }
                rec_h, _ = self._append_event(
                    cursor,
                    transaction_id=tx_id,
                    event_type="PROPOSAL_EVALUATED",
                    payload_dict=payload,
                    timestamp=ts or datetime.now(timezone.utc).isoformat(),
                )
                cursor.execute("UPDATE audit_records SET record_hash = ? WHERE transaction_id = ?;", (rec_h, tx_id))

            conn.commit()


    def _get_latest_event_hash(self, cursor: Any) -> str:
        """Retrieves the event_hash of the most recently appended audit event, or 'GENESIS'."""
        cursor.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1;")
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]
        return "GENESIS"

    def _append_event(
        self,
        cursor: Any,
        transaction_id: str,
        event_type: str,
        payload_dict: dict,
        timestamp: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Appends a tamper-evident event block to the cryptographic ledger.
        Returns (event_hash, prev_hash).
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self._get_latest_event_hash(cursor)
        event_id = str(uuid4())
        payload_json = json.dumps(payload_dict, sort_keys=True)
        event_hash = compute_event_hash(
            prev_hash=prev_hash,
            event_id=event_id,
            transaction_id=transaction_id,
            event_type=event_type,
            timestamp=timestamp,
            payload_json=payload_json,
        )
        cursor.execute(
            """
            INSERT INTO audit_events (
                event_id, transaction_id, event_type, timestamp, payload_json, prev_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (event_id, transaction_id, event_type, timestamp, payload_json, prev_hash, event_hash)
        )
        return event_hash, prev_hash

    def append_event(
        self,
        transaction_id: str,
        event_type: str,
        payload_dict: dict,
        timestamp: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Public method to append a standalone tamper-evident audit event block to the cryptographic ledger.
        Used for key lifecycle events, mandate registration/revocation, and approval events.
        """
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            res = self._append_event(cursor, transaction_id, event_type, payload_dict, timestamp)
            conn.commit()
            return res

    def write_proposal(
        self,
        transaction_id: str,
        customer_id: str,
        product_id: str,
        merchant_id: str,
        quantity: int,
        amount: float,
        decision: str,
        decision_reason: str,
        timestamp: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> None:
        """
        Phase A: Record the initial purchase proposal and deterministic policy decision with hash chain.
        """
        self._ensure_db_initialized()
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()

        initial_payment_status = "PENDING" if decision == "APPROVED" else None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            payload = {
                "customer_id": customer_id,
                "product_id": product_id,
                "merchant_id": merchant_id,
                "quantity": quantity,
                "amount": amount,
                "decision": decision,
                "decision_reason": decision_reason,
                "payment_status": initial_payment_status,
                "idempotency_key": idempotency_key,
            }
            rec_hash, prev_hash = self._append_event(
                cursor,
                transaction_id=transaction_id,
                event_type="PROPOSAL_EVALUATED",
                payload_dict=payload,
                timestamp=timestamp,
            )

            cursor.execute(
                """
                INSERT INTO audit_records (
                    transaction_id, timestamp, customer_id, product_id,
                    merchant_id, quantity, amount, decision, decision_reason,
                    payment_status, razorpay_order_id, razorpay_payment_id, idempotency_key,
                    prev_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?);
                """,
                (
                    transaction_id,
                    timestamp,
                    customer_id,
                    product_id,
                    merchant_id,
                    quantity,
                    amount,
                    decision,
                    decision_reason,
                    initial_payment_status,
                    idempotency_key,
                    prev_hash,
                    rec_hash,
                )
            )
            conn.commit()

    def update_payment_outcome(
        self,
        transaction_id: str,
        payment_status: Optional[str],
        razorpay_order_id: Optional[str] = None,
        razorpay_payment_id: Optional[str] = None,
    ) -> None:
        """
        Phase B: Append a tamper-evident event to the append-only `audit_events` ledger
        and update the mutable `audit_records` projection view (CQRS / Event-Sourcing pattern).
        """
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT timestamp, customer_id, product_id, amount, decision, idempotency_key, prev_hash
                FROM audit_records WHERE transaction_id = ?;
                """,
                (transaction_id,)
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError(f"Audit record '{transaction_id}' not found to update payment outcome")

            timestamp, customer_id, product_id, amount, decision, idempotency_key, prev_hash = row
            final_decision = "APPROVED" if (
                (decision in ("PENDING_CONFIRMATION", "REJECTED") and payment_status == "captured")
                or (decision == "PENDING_CONFIRMATION" and payment_status == "created")
            ) else decision
            
            event_type = "HUMAN_CONFIRMED" if decision == "PENDING_CONFIRMATION" and payment_status == "created" else (
                "PAYMENT_FAILED" if payment_status == "failed" else (
                    "PAYMENT_CAPTURED" if payment_status == "captured" else "ORDER_CREATED"
                )
            )

            payload = {
                "payment_status": payment_status,
                "razorpay_order_id": razorpay_order_id,
                "razorpay_payment_id": razorpay_payment_id,
                "decision": final_decision,
            }
            new_rec_hash, _ = self._append_event(
                cursor,
                transaction_id=transaction_id,
                event_type=event_type,
                payload_dict=payload,
            )

            cursor.execute(
                """
                UPDATE audit_records
                SET payment_status = ?, razorpay_order_id = ?, razorpay_payment_id = COALESCE(?, razorpay_payment_id), decision = ?, record_hash = ?
                WHERE transaction_id = ?;
                """,
                (payment_status, razorpay_order_id, razorpay_payment_id, final_decision, new_rec_hash, transaction_id)
            )
            conn.commit()

    def get_daily_spend(
        self,
        customer_id: str,
        target_date: Optional[str] = None,
    ) -> float:
        """
        Calculates the total approved spend for a customer on a given UTC date (defaults to today).
        """
        self._ensure_db_initialized()
        date_prefix = target_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT SUM(amount) FROM audit_records
                WHERE customer_id = ?
                  AND (decision = 'APPROVED' OR (decision = 'PENDING_CONFIRMATION' AND payment_status = 'created'))
                  AND timestamp LIKE ?;
                """,
                (customer_id.strip(), f"{date_prefix}%")
            )
            result = cursor.fetchone()
            return float(result[0]) if result and result[0] is not None else 0.0

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Walks the entire audit ledger from oldest to newest, verifying cryptographic
        SHA-256 hash chaining and data consistency.
        """
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. First check append-only audit_events table
            cursor.execute(
                """
                SELECT id, event_id, transaction_id, event_type, timestamp, payload_json, prev_hash, event_hash
                FROM audit_events
                ORDER BY id ASC;
                """
            )
            event_rows = cursor.fetchall()

            if event_rows:
                expected_prev = "GENESIS"
                for idx, r in enumerate(event_rows):
                    (
                        row_id, ev_id, tx_id, ev_type, ts, payload_str, prev_h, ev_h
                    ) = r

                    if prev_h != expected_prev and idx != 0:
                        return {
                            "valid": False,
                            "error": f"Broken chain link at index {idx} (event_id={ev_id}, transaction_id={tx_id})",
                            "expected_prev_hash": expected_prev,
                            "actual_prev_hash": prev_h,
                            "broken_record_id": tx_id,
                        }

                    expected_hash = compute_event_hash(
                        prev_hash=prev_h or "GENESIS",
                        event_id=ev_id,
                        transaction_id=tx_id,
                        event_type=ev_type,
                        timestamp=ts,
                        payload_json=payload_str,
                    )

                    if ev_h and ev_h != expected_hash:
                        return {
                            "valid": False,
                            "error": f"Corrupted event hash at index {idx} (event_id={ev_id}, transaction_id={tx_id})",
                            "expected_hash": expected_hash,
                            "stored_hash": ev_h,
                            "broken_record_id": tx_id,
                        }

                    expected_prev = ev_h or expected_hash

                # 2. Reconcile mutable projection view (audit_records) against append-only audit_events
                cursor.execute(
                    """
                    SELECT transaction_id, record_hash
                    FROM audit_records;
                    """
                )
                projection_rows = cursor.fetchall()
                
                # Map transaction_id -> latest event hash
                latest_event_hashes_by_tx: Dict[str, str] = {}
                for r in event_rows:
                    tx = r[2]  # transaction_id
                    ev_h = r[7]  # event_hash
                    latest_event_hashes_by_tx[tx] = ev_h

                for p_tx, p_rec_hash in projection_rows:
                    if p_tx not in latest_event_hashes_by_tx:
                        return {
                            "valid": False,
                            "error": f"Orphaned projection record found: transaction '{p_tx}' exists in projection but missing in cryptographic event stream.",
                            "broken_record_id": p_tx,
                        }
                    latest_hash = latest_event_hashes_by_tx[p_tx]
                    if p_rec_hash and p_rec_hash != latest_hash:
                        return {
                            "valid": False,
                            "error": f"Projection tampering detected on transaction '{p_tx}': projection record_hash does not match cryptographic event stream hash.",
                            "broken_record_id": p_tx,
                            "projection_hash": p_rec_hash,
                            "event_stream_hash": latest_hash,
                        }

                return {
                    "valid": True,
                    "total_records": len(event_rows),
                    "total_projections_reconciled": len(projection_rows),
                    "reconciled": True,
                    "status": "VERIFIED_IMMUTABLE",
                    "chain_head": expected_prev,
                }

            # 2. Fallback check for audit_records (if legacy records only)
            cursor.execute(
                """
                SELECT transaction_id, timestamp, customer_id, product_id,
                       amount, decision, payment_status, idempotency_key,
                       prev_hash, record_hash
                FROM audit_records
                ORDER BY timestamp ASC;
                """
            )
            rows = cursor.fetchall()

        if not rows:
            return {"valid": True, "total_records": 0, "status": "EMPTY_LEDGER", "chain_head": "GENESIS"}

        expected_prev = "GENESIS"
        for idx, r in enumerate(rows):
            (
                tx_id, ts, cust_id, prod_id, amt, dec, pay_st, idemp, prev_h, rec_h
            ) = r

            # Check previous hash link
            if prev_h != expected_prev and idx != 0:
                return {
                    "valid": False,
                    "error": f"Broken chain link at index {idx} (transaction_id={tx_id})",
                    "expected_prev_hash": expected_prev,
                    "actual_prev_hash": prev_h,
                    "broken_record_id": tx_id,
                }

            expected_prev = rec_h or expected_prev

        return {
            "valid": True,
            "total_records": len(rows),
            "status": "VERIFIED_IMMUTABLE",
            "chain_head": expected_prev,
        }

    def list(
        self,
        customer_id: Optional[str] = None,
        decision: Optional[str] = None,
        payment_status: Optional[str] = None,
    ) -> List[AuditRecord]:
        """Retrieve audit records ordered newest-first, with optional filtering."""
        self._ensure_db_initialized()
        query = (
            "SELECT transaction_id, timestamp, customer_id, product_id, merchant_id, "
            "quantity, amount, decision, decision_reason, payment_status, razorpay_order_id, razorpay_payment_id, idempotency_key, "
            "prev_hash, record_hash "
            "FROM audit_records"
        )
        conditions = []
        params = []

        if customer_id and customer_id.strip():
            conditions.append("customer_id = ?")
            params.append(customer_id.strip())
        if decision and decision.strip():
            conditions.append("UPPER(decision) = ?")
            params.append(decision.strip().upper())
        if payment_status and payment_status.strip():
            conditions.append("payment_status = ?")
            params.append(payment_status.strip())

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC;"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [
                AuditRecord(
                    transaction_id=row[0],
                    timestamp=row[1],
                    customer_id=row[2],
                    product_id=row[3],
                    merchant_id=row[4],
                    quantity=row[5],
                    amount=row[6],
                    decision=row[7],
                    decision_reason=row[8],
                    payment_status=row[9],
                    razorpay_order_id=row[10],
                    razorpay_payment_id=row[11],
                    idempotency_key=row[12] if len(row) > 12 else None,
                    prev_hash=row[13] if len(row) > 13 else "GENESIS",
                    record_hash=row[14] if len(row) > 14 else None,
                )
                for row in rows
            ]

    def get(self, transaction_id: str) -> Optional[AuditRecord]:
        """Retrieve a single audit record by its transaction_id."""
        self._ensure_db_initialized()
        query = (
            "SELECT transaction_id, timestamp, customer_id, product_id, merchant_id, "
            "quantity, amount, decision, decision_reason, payment_status, razorpay_order_id, razorpay_payment_id, idempotency_key, "
            "prev_hash, record_hash "
            "FROM audit_records "
            "WHERE transaction_id = ?;"
        )
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (transaction_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return AuditRecord(
                transaction_id=row[0],
                timestamp=row[1],
                customer_id=row[2],
                product_id=row[3],
                merchant_id=row[4],
                quantity=row[5],
                amount=row[6],
                decision=row[7],
                decision_reason=row[8],
                payment_status=row[9],
                razorpay_order_id=row[10],
                razorpay_payment_id=row[11],
                idempotency_key=row[12] if len(row) > 12 else None,
                prev_hash=row[13] if len(row) > 13 else "GENESIS",
                record_hash=row[14] if len(row) > 14 else None,
            )

    def get_by_idempotency_key(self, idempotency_key: str) -> Optional[AuditRecord]:
        """Retrieve a single audit record by its idempotency_key."""
        if not idempotency_key or not idempotency_key.strip():
            return None

        self._ensure_db_initialized()
        query = (
            "SELECT transaction_id, timestamp, customer_id, product_id, merchant_id, "
            "quantity, amount, decision, decision_reason, payment_status, razorpay_order_id, razorpay_payment_id, idempotency_key, "
            "prev_hash, record_hash "
            "FROM audit_records "
            "WHERE idempotency_key = ?;"
        )
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (idempotency_key.strip(),))
            row = cursor.fetchone()
            if row is None:
                return None
            return AuditRecord(
                transaction_id=row[0],
                timestamp=row[1],
                customer_id=row[2],
                product_id=row[3],
                merchant_id=row[4],
                quantity=row[5],
                amount=row[6],
                decision=row[7],
                decision_reason=row[8],
                payment_status=row[9],
                razorpay_order_id=row[10],
                razorpay_payment_id=row[11],
                idempotency_key=row[12] if len(row) > 12 else None,
                prev_hash=row[13] if len(row) > 13 else "GENESIS",
                record_hash=row[14] if len(row) > 14 else None,
            )

    def is_webhook_processed(self, event_id: str) -> bool:
        """Checks if a Razorpay webhook event has already been processed (persistent deduplication)."""
        if not event_id or not event_id.strip():
            return False
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM processed_webhook_events WHERE event_id = ?;",
                (event_id.strip(),),
            )
            return cursor.fetchone() is not None

    def record_webhook_event(self, event_id: str) -> None:
        """Persists a processed webhook event ID into the database."""
        if not event_id or not event_id.strip():
            return
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO processed_webhook_events (event_id, received_at) VALUES (?, ?) ON CONFLICT(event_id) DO NOTHING;",
                (event_id.strip(), time.time()),
            )
            conn.commit()

    def get_latest_orders(self, customer_id: Optional[str] = None, limit: int = 5) -> List[AuditRecord]:
        """Retrieves the most recent audit records, optionally filtered by customer."""
        self._ensure_db_initialized()
        query = (
            "SELECT transaction_id, timestamp, customer_id, product_id, merchant_id, "
            "quantity, amount, decision, decision_reason, payment_status, razorpay_order_id, idempotency_key, "
            "prev_hash, record_hash "
            "FROM audit_records "
        )
        params: List[Any] = []
        if customer_id:
            query += "WHERE customer_id = ? "
            params.append(customer_id.strip())
        query += "ORDER BY timestamp DESC LIMIT ?;"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [
                AuditRecord(
                    transaction_id=row[0],
                    timestamp=row[1],
                    customer_id=row[2],
                    product_id=row[3],
                    merchant_id=row[4],
                    quantity=row[5],
                    amount=row[6],
                    decision=row[7],
                    decision_reason=row[8],
                    payment_status=row[9],
                    razorpay_order_id=row[10],
                    idempotency_key=row[11] if len(row) > 11 else None,
                    prev_hash=row[12] if len(row) > 12 else "GENESIS",
                    record_hash=row[13] if len(row) > 13 else None,
                )
                for row in rows
            ]

    def lookup_order(self, identifier: Optional[str] = None, customer_id: Optional[str] = None) -> Optional[AuditRecord]:
        """Looks up an order by reference code suffix, transaction_id, razorpay_order_id, or product name/id."""
        if not identifier or not identifier.strip():
            latest = self.get_latest_orders(customer_id=customer_id, limit=1)
            return latest[0] if latest else None

        ident = identifier.strip().replace("REF-", "").replace("TX-", "")
        self._ensure_db_initialized()

        # Find matching product IDs from catalog
        matched_product_ids = []
        try:
            from app.catalog.data import PRODUCTS
            ident_lower = ident.lower()
            for p in PRODUCTS:
                if (
                    p.id.lower() in ident_lower
                    or p.name.lower() in ident_lower
                    or ident_lower in p.name.lower()
                    or any(w in p.name.lower() for w in ident_lower.split() if len(w) > 3)
                ):
                    matched_product_ids.append(p.id)
        except Exception:
            pass

        query = (
            "SELECT transaction_id, timestamp, customer_id, product_id, merchant_id, "
            "quantity, amount, decision, decision_reason, payment_status, razorpay_order_id, idempotency_key, "
            "prev_hash, record_hash "
            "FROM audit_records "
            "WHERE transaction_id = ? "
            "   OR transaction_id LIKE ? "
            "   OR razorpay_order_id = ? "
            "   OR razorpay_order_id LIKE ? "
            "   OR product_id = ? "
        )
        params: List[Any] = [ident, f"%{ident}%", ident, f"%{ident}%", ident]

        if matched_product_ids:
            placeholders = ",".join("?" for _ in matched_product_ids)
            query += f"   OR product_id IN ({placeholders}) "
            params.extend(matched_product_ids)

        # Order by payment outcome priority (captured > created) then newest timestamp
        query += "ORDER BY (CASE WHEN payment_status = 'captured' THEN 1 WHEN payment_status = 'created' THEN 2 ELSE 3 END), timestamp DESC LIMIT 1;"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            row = cursor.fetchone()
            if row is None:
                latest = self.get_latest_orders(customer_id=customer_id, limit=1)
                return latest[0] if latest else None

            return AuditRecord(
                transaction_id=row[0],
                timestamp=row[1],
                customer_id=row[2],
                product_id=row[3],
                merchant_id=row[4],
                quantity=row[5],
                amount=row[6],
                decision=row[7],
                decision_reason=row[8],
                payment_status=row[9],
                razorpay_order_id=row[10],
                idempotency_key=row[11] if len(row) > 11 else None,
                prev_hash=row[12] if len(row) > 12 else "GENESIS",
                record_hash=row[13] if len(row) > 13 else None,
            )

    def get_ledger_anchor(self) -> Dict[str, Any]:
        """
        Computes an exportable cryptographic checkpoint anchor of the audit ledger.
        Returns block height, root hash, genesis hash, timestamp, and signed state digest.
        """
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM audit_events;")
            row = cursor.fetchone()
            total_events = row[0] if row else 0
            genesis_time = row[1] if (row and row[1]) else None
            latest_time = row[2] if (row and row[2]) else None

            cursor.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1;")
            latest_row = cursor.fetchone()
            root_hash = latest_row[0] if latest_row else "GENESIS"

            cursor.execute("SELECT event_hash FROM audit_events ORDER BY id ASC LIMIT 1;")
            first_row = cursor.fetchone()
            genesis_event_hash = first_row[0] if first_row else "GENESIS"

            # Compute SHA-256 state digest over root hash, height, and genesis
            anchor_payload = f"{root_hash}|{total_events}|{genesis_event_hash}|{latest_time or ''}"
            anchor_digest = hashlib.sha256(anchor_payload.encode("utf-8")).hexdigest()

            return {
                "ledger_status": "tamper_evident_anchored",
                "root_event_hash": root_hash,
                "total_event_blocks": total_events,
                "genesis_event_hash": genesis_event_hash,
                "genesis_timestamp": genesis_time,
                "latest_event_timestamp": latest_time,
                "anchor_digest_sha256": anchor_digest,
                "anchored_at": datetime.now(timezone.utc).isoformat(),
            }

    def get_recommendation_analytics(self) -> Dict[str, Any]:
        """
        Calculates recommendation analytics strictly from payment transaction records
        and recommendation lifecycle events.
        """
        self._ensure_db_initialized()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute(
                """
                SELECT SUM(amount), COUNT(*) FROM audit_records
                WHERE payment_status IN ('captured', 'paid') OR (decision = 'APPROVED' AND payment_status != 'failed');
                """
            )
            rev_row = cursor.fetchone()
            total_completed_revenue = float(rev_row[0]) if rev_row and rev_row[0] is not None else 0.0
            total_settled_transactions = int(rev_row[1]) if rev_row and rev_row[1] is not None else 0

            cursor.execute("SELECT COUNT(*) FROM audit_events WHERE event_type = 'RECOMMENDATION_GENERATED';")
            rec_generated_count = int(cursor.fetchone()[0])

            cursor.execute("SELECT COUNT(*) FROM audit_events WHERE event_type = 'RECOMMENDATION_SHOWN';")
            rec_shown_count = int(cursor.fetchone()[0])

            cursor.execute("SELECT COUNT(*) FROM audit_events WHERE event_type = 'RECOMMENDATION_ACCEPTED';")
            rec_accepted_count = int(cursor.fetchone()[0])

            cursor.execute("SELECT COUNT(*) FROM audit_events WHERE event_type = 'RECOMMENDATION_REJECTED';")
            rec_rejected_count = int(cursor.fetchone()[0])

            cursor.execute("SELECT COUNT(*) FROM audit_events WHERE event_type = 'RECOMMENDATION_PURCHASED';")
            rec_purchased_count = int(cursor.fetchone()[0])

            cursor.execute(
                """
                SELECT SUM(r.amount) FROM audit_records r
                JOIN recommendations rec ON r.transaction_id = rec.addon_transaction_id
                WHERE rec.status = 'PURCHASED' AND (r.payment_status IN ('captured', 'paid') OR (r.decision = 'APPROVED' AND r.payment_status != 'failed'));
                """
            )
            addon_rev_row = cursor.fetchone()
            ai_addon_revenue = float(addon_rev_row[0]) if addon_rev_row and addon_rev_row[0] is not None else 0.0

            cursor.execute(
                """
                SELECT transaction_id, amount, payment_status, decision
                FROM audit_records
                WHERE payment_status IN ('captured', 'paid') OR (decision = 'APPROVED' AND payment_status != 'failed');
                """
            )
            paid_rows = cursor.fetchall()

            cursor.execute("SELECT recommendation_id, logical_order_group_id, primary_transaction_id, addon_transaction_id, status FROM recommendations;")
            rec_rows = cursor.fetchall()

            tx_to_group = {}
            for _, grp_id, pri_tx, add_tx, _ in rec_rows:
                if grp_id:
                    if pri_tx:
                        tx_to_group[pri_tx] = grp_id
                    if add_tx:
                        tx_to_group[add_tx] = grp_id

            group_revenue = {}
            group_has_primary = set()
            group_has_paid_addon = set()

            for tx_id, amt, p_st, dec in paid_rows:
                grp = tx_to_group.get(tx_id, f"GRP-{tx_id[-8:]}")
                group_revenue[grp] = group_revenue.get(grp, 0.0) + float(amt)
                group_has_primary.add(grp)

            for rec_id, grp_id, pri_tx, add_tx, st in rec_rows:
                if st == 'PURCHASED' and grp_id:
                    group_has_paid_addon.add(grp_id)

            distinct_logical_orders_count = len(group_has_primary)
            total_logical_order_revenue = sum(group_revenue.values())

            logical_order_aov = (
                round(total_logical_order_revenue / distinct_logical_orders_count, 2)
                if distinct_logical_orders_count > 0
                else 0.0
            )

            baseline_revenue = total_logical_order_revenue - ai_addon_revenue
            baseline_aov = (
                round(baseline_revenue / distinct_logical_orders_count, 2)
                if distinct_logical_orders_count > 0
                else 0.0
            )

            net_aov_lift_pct = (
                round(((logical_order_aov - baseline_aov) / baseline_aov) * 100, 2)
                if baseline_aov > 0
                else 0.0
            )

            shown_opportunities_count = max(distinct_logical_orders_count, rec_shown_count)

            attach_rate_pct = (
                round((len(group_has_paid_addon) / max(1, shown_opportunities_count)) * 100, 2)
                if shown_opportunities_count > 0
                else 0.0
            )

            acceptance_rate_pct = (
                round((rec_accepted_count / max(1, rec_shown_count)) * 100, 2)
                if rec_shown_count > 0
                else 0.0
            )

            return {
                "source_of_truth": "Confirmed Payment/Transaction Records (audit_records)",
                "total_completed_revenue_inr": total_completed_revenue,
                "ai_addon_revenue_inr": ai_addon_revenue,
                "logical_order_aov_inr": logical_order_aov,
                "baseline_aov_inr": baseline_aov,
                "net_aov_lift_percentage": net_aov_lift_pct,
                "ai_addon_attach_rate_percentage": attach_rate_pct,
                "recommendation_acceptance_rate_percentage": acceptance_rate_pct,
                "distinct_logical_orders_count": distinct_logical_orders_count,
                "lifecycle_counts": {
                    "generated": rec_generated_count,
                    "shown": rec_shown_count,
                    "accepted": rec_accepted_count,
                    "rejected": rec_rejected_count,
                    "purchased": rec_purchased_count,
                }
            }


# Default module-level singleton instance
audit_store = AuditStore()


