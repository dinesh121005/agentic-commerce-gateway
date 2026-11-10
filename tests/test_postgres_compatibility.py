"""
tests/test_postgres_compatibility.py
P0-F: PostgreSQL Compatibility and Dialect Translation Test Suite.

Validates that all gateway database abstractions, SQL queries, transaction boundaries,
and dialect conversions (SQLite -> PostgreSQL) execute cleanly according to ADR-02.
"""
import os
import unittest.mock as mock
import pytest

from app.db import (
    is_postgres_url,
    normalize_postgres_url,
    PostgresCursorWrapper,
    PostgresConnectionWrapper,
    get_db_connection,
)


class TestUrlNormalizationAndDetection:
    """Verifies database connection URL detection and protocol normalization."""

    def test_postgres_url_detection(self):
        assert is_postgres_url("postgresql://user:pass@localhost:5432/gateway") is True
        assert is_postgres_url("postgres://user:pass@ep-cool-db.us-east-2.aws.neon.tech/db") is True
        assert is_postgres_url("POSTGRESQL://localhost/db") is True
        assert is_postgres_url("sqlite:///gateway.db") is False
        assert is_postgres_url("gateway.db") is False
        assert is_postgres_url("") is False
        assert is_postgres_url(None) is False

    def test_postgres_url_normalization(self):
        assert (
            normalize_postgres_url("postgres://user:pass@host:5432/dbname")
            == "postgresql://user:pass@host:5432/dbname"
        )
        assert (
            normalize_postgres_url("postgresql://user:pass@host:5432/dbname")
            == "postgresql://user:pass@host:5432/dbname"
        )
        assert normalize_postgres_url("gateway.db") == "gateway.db"


class TestPostgresCursorWrapperTranslation:
    """Verifies that SQLite dialect queries are translated to valid PostgreSQL dialect."""

    def test_autoincrement_translation(self):
        mock_raw_cursor = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw_cursor)

        query = (
            "CREATE TABLE IF NOT EXISTS audit_events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "event_id TEXT UNIQUE NOT NULL);"
        )
        wrapper.execute(query)

        mock_raw_cursor.execute.assert_called_once()
        executed_query = mock_raw_cursor.execute.call_args[0][0]
        assert "SERIAL PRIMARY KEY" in executed_query
        assert "AUTOINCREMENT" not in executed_query

    def test_insert_or_ignore_translation(self):
        mock_raw_cursor = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw_cursor)

        query = "INSERT OR IGNORE INTO processed_webhook_events (event_id, received_at) VALUES (?, ?);"
        wrapper.execute(query, ("evt_001", "2026-11-10T00:00:00Z"))

        mock_raw_cursor.execute.assert_called_once()
        executed_query, params = mock_raw_cursor.execute.call_args[0]
        assert "INSERT INTO processed_webhook_events" in executed_query
        assert "ON CONFLICT DO NOTHING" in executed_query
        assert "?" not in executed_query
        assert "%s" in executed_query
        assert params == ("evt_001", "2026-11-10T00:00:00Z")

    def test_insert_or_ignore_with_existing_on_conflict_not_duplicated(self):
        mock_raw_cursor = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw_cursor)

        query = "INSERT OR IGNORE INTO records (id) VALUES (?) ON CONFLICT (id) DO NOTHING;"
        wrapper.execute(query, ("rec_1",))

        executed_query = mock_raw_cursor.execute.call_args[0][0]
        assert executed_query.count("ON CONFLICT") == 1

    def test_placeholder_translation_single_and_multiple(self):
        mock_raw_cursor = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw_cursor)

        query = (
            "SELECT * FROM audit_records "
            "WHERE customer_id = ? AND decision = ? AND amount_paise >= ?;"
        )
        params = ("CUST001", "APPROVED", 10000)
        wrapper.execute(query, params)

        executed_query, executed_params = mock_raw_cursor.execute.call_args[0]
        assert "?" not in executed_query
        assert executed_query.count("%s") == 3
        assert executed_params == ("CUST001", "APPROVED", 10000)

    def test_executemany_translation(self):
        mock_raw_cursor = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw_cursor)

        query = "INSERT OR IGNORE INTO tags (tag, item_id) VALUES (?, ?);"
        params_list = [("elec", 1), ("gadget", 2)]
        wrapper.executemany(query, params_list)

        mock_raw_cursor.executemany.assert_called_once()
        executed_query, executed_seq = mock_raw_cursor.executemany.call_args[0]
        assert "INSERT INTO tags" in executed_query
        assert "ON CONFLICT DO NOTHING" in executed_query
        assert "?" not in executed_query
        assert "%s" in executed_query
        assert executed_seq == params_list

    def test_cursor_passthrough_methods(self):
        mock_raw_cursor = mock.MagicMock()
        mock_raw_cursor.fetchone.return_value = ("row1",)
        mock_raw_cursor.fetchall.return_value = [("row1",), ("row2",)]
        mock_raw_cursor.fetchmany.return_value = [("row1",)]
        mock_raw_cursor.rowcount = 42
        mock_raw_cursor.description = [("col1",), ("col2",)]

        wrapper = PostgresCursorWrapper(mock_raw_cursor)

        assert wrapper.fetchone() == ("row1",)
        assert wrapper.fetchall() == [("row1",), ("row2",)]
        assert wrapper.fetchmany(1) == [("row1",)]
        assert wrapper.rowcount == 42
        assert wrapper.description == [("col1",), ("col2",)]

        wrapper.close()
        mock_raw_cursor.close.assert_called_once()

    def test_cursor_context_manager(self):
        mock_raw_cursor = mock.MagicMock()
        with PostgresCursorWrapper(mock_raw_cursor) as cur:
            cur.execute("SELECT 1;")
        mock_raw_cursor.close.assert_called_once()


class TestPostgresConnectionWrapper:
    """Verifies PostgresConnectionWrapper delegates transaction management to raw connection."""

    def test_connection_wrapper_delegation(self):
        mock_raw_conn = mock.MagicMock()
        conn_wrapper = PostgresConnectionWrapper(mock_raw_conn)

        cur = conn_wrapper.cursor()
        assert isinstance(cur, PostgresCursorWrapper)

        conn_wrapper.commit()
        mock_raw_conn.commit.assert_called_once()

        conn_wrapper.rollback()
        mock_raw_conn.rollback.assert_called_once()

        conn_wrapper.close()
        mock_raw_conn.close.assert_called_once()


class TestGetDbConnectionContextManager:
    """Verifies transaction rollback and resource cleanup on exceptions in get_db_connection."""

    def test_postgres_context_manager_rolls_back_on_exception(self):
        mock_raw_conn = mock.MagicMock()
        with mock.patch("psycopg2.connect", return_value=mock_raw_conn):
            with pytest.raises(ZeroDivisionError):
                with get_db_connection("postgresql://user:pass@localhost:5432/testdb") as conn:
                    conn.cursor().execute("SELECT 1;")
                    _ = 1 / 0

            # Must roll back on exception
            mock_raw_conn.rollback.assert_called_once()
            mock_raw_conn.close.assert_called_once()

    def test_postgres_context_manager_normal_exit_closes_connection(self):
        mock_raw_conn = mock.MagicMock()
        with mock.patch("psycopg2.connect", return_value=mock_raw_conn):
            with get_db_connection("postgresql://user:pass@localhost:5432/testdb") as conn:
                cur = conn.cursor()
                cur.execute("SELECT 1;")
                conn.commit()

            mock_raw_conn.commit.assert_called_once()
            mock_raw_conn.rollback.assert_not_called()
            mock_raw_conn.close.assert_called_once()


class TestGatewayStoreSQLCompatibility:
    """
    Validates that SQL statements used across gateway stores translate into valid PostgreSQL
    syntax with correct placeholder parameter bindings.
    """

    def test_audit_store_ddl_and_dml_translation(self):
        mock_raw = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw)

        # 1. Audit events DDL (AUTOINCREMENT translation)
        audit_events_ddl = """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                transaction_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
        """
        wrapper.execute(audit_events_ddl)
        assert "SERIAL PRIMARY KEY" in mock_raw.execute.call_args[0][0]
        assert "AUTOINCREMENT" not in mock_raw.execute.call_args[0][0]

        # 2. Daily spend query (aggregate with integer paise)
        spend_query = """
            SELECT SUM(COALESCE(amount_paise, CAST(ROUND(amount * 100) AS INTEGER))) FROM audit_records
            WHERE customer_id = ?
              AND (decision = 'APPROVED' OR (decision = 'PENDING_CONFIRMATION' AND payment_status = 'created'))
              AND timestamp LIKE ?;
        """
        wrapper.execute(spend_query, ("CUST001", "2026-11-10%"))
        q, p = mock_raw.execute.call_args[0]
        assert "?" not in q
        assert q.count("%s") == 2
        assert p == ("CUST001", "2026-11-10%")

        # 3. Atomic confirmation claim (ADR-02 conditional update)
        claim_query = """
            UPDATE audit_records
            SET decision = 'CONFIRMING'
            WHERE transaction_id = ? AND decision = 'PENDING_CONFIRMATION';
        """
        wrapper.execute(claim_query, ("tx_123",))
        q, p = mock_raw.execute.call_args[0]
        assert "?" not in q
        assert "%s" in q
        assert p == ("tx_123",)

        # 4. Atomic compensation claim (P0-E/P0-G conditional update)
        comp_query = """
            UPDATE audit_records
            SET payment_status = 'failed'
            WHERE transaction_id = ?
              AND decision = 'APPROVED'
              AND payment_status IN ('created', 'PENDING');
        """
        wrapper.execute(comp_query, ("tx_comp_123",))
        q, p = mock_raw.execute.call_args[0]
        assert "?" not in q
        assert "%s" in q
        assert p == ("tx_comp_123",)

    def test_wallet_store_atomic_conditional_debit_translation(self):
        mock_raw = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw)

        debit_query = """
            UPDATE customer_wallets
            SET balance_paise = balance_paise - ?,
                balance = ROUND((balance_paise - ?) / 100.0, 2),
                updated_at = ?
            WHERE customer_id = ?
              AND balance_paise >= ?;
        """
        params = (5000, 5000, "2026-11-10T00:00:00Z", "CUST001", 5000)
        wrapper.execute(debit_query, params)
        q, p = mock_raw.execute.call_args[0]
        assert "?" not in q
        assert q.count("%s") == 5
        assert p == params

    def test_catalog_inventory_reservation_and_compensation_translation(self):
        mock_raw = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw)

        # Atomic reservation (conditional decrement)
        decrement_query = "UPDATE catalog_products SET stock = stock - ? WHERE id = ? AND stock >= ?;"
        wrapper.execute(decrement_query, (2, "HK001", 2))
        q, p = mock_raw.execute.call_args[0]
        assert "?" not in q
        assert q.count("%s") == 3
        assert p == (2, "HK001", 2)

        # Exactly-once compensation (restoration)
        restore_query = "UPDATE catalog_products SET stock = stock + ? WHERE id = ?;"
        wrapper.execute(restore_query, (2, "HK001"))
        q, p = mock_raw.execute.call_args[0]
        assert "?" not in q
        assert q.count("%s") == 2
        assert p == (2, "HK001")

    def test_signing_store_key_and_approval_translation(self):
        mock_raw = mock.MagicMock()
        wrapper = PostgresCursorWrapper(mock_raw)

        # Conditional approval consumption
        consume_query = """
            UPDATE purchase_approvals
            SET status = 'CONSUMED', consumed_at = ?
            WHERE approval_id = ? AND status = 'ACTIVE';
        """
        wrapper.execute(consume_query, ("2026-11-10T00:00:00Z", "appr_123"))
        q, p = mock_raw.execute.call_args[0]
        assert "?" not in q
        assert q.count("%s") == 2
        assert p == ("2026-11-10T00:00:00Z", "appr_123")

