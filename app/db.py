"""
Universal Database Access Layer for SQLite and PostgreSQL.
Supports local SQLite files (e.g. gateway.db) and cloud PostgreSQL instances (e.g. Render / Supabase).
"""
import contextlib
import os
import re
import sqlite3
from typing import Any, Generator, Optional, Sequence, Tuple, Union

try:
    import psycopg2
    from psycopg2.extensions import connection as PgConnection
    from psycopg2.extensions import cursor as PgCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    PgConnection = Any
    PgCursor = Any


def is_postgres_url(url: Optional[str]) -> bool:
    """Returns True if the database URL points to a PostgreSQL instance."""
    if not url:
        return False
    clean = url.strip().lower()
    return clean.startswith("postgresql://") or clean.startswith("postgres://")


def normalize_postgres_url(url: str) -> str:
    """Ensures postgres:// prefix is normalized to postgresql://."""
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


class PostgresCursorWrapper:
    """Wraps psycopg2 cursor to translate SQLite '?' placeholders to '%s'."""

    def __init__(self, raw_cursor: PgCursor):
        self._cursor = raw_cursor

    def execute(self, query: str, params: Optional[Sequence[Any]] = None) -> Any:
        clean_query = query
        # Translate SQLite AUTOINCREMENT
        if "INTEGER PRIMARY KEY AUTOINCREMENT" in clean_query:
            clean_query = clean_query.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        elif "AUTOINCREMENT" in clean_query:
            clean_query = clean_query.replace("AUTOINCREMENT", "")

        # Translate SQLite INSERT OR IGNORE INTO
        if "INSERT OR IGNORE INTO" in clean_query:
            clean_query = clean_query.replace("INSERT OR IGNORE INTO", "INSERT INTO")
            if "ON CONFLICT" not in clean_query:
                clean_query = clean_query.rstrip("; \r\n\t") + " ON CONFLICT DO NOTHING"

        # Translate SQLite ? placeholders to PostgreSQL %s
        if "?" in clean_query:
            clean_query = clean_query.replace("?", "%s")

        if params is not None:
            return self._cursor.execute(clean_query, tuple(params))
        return self._cursor.execute(clean_query)

    def executemany(self, query: str, seq_of_params: Sequence[Sequence[Any]]) -> Any:
        clean_query = query
        if "INSERT OR IGNORE INTO" in clean_query:
            clean_query = clean_query.replace("INSERT OR IGNORE INTO", "INSERT INTO")
            if "ON CONFLICT" not in clean_query:
                clean_query = clean_query.rstrip("; \r\n\t") + " ON CONFLICT DO NOTHING"
        if "?" in clean_query:
            clean_query = clean_query.replace("?", "%s")
        return self._cursor.executemany(clean_query, seq_of_params)

    def fetchone(self) -> Optional[Tuple[Any, ...]]:
        return self._cursor.fetchone()

    def fetchall(self) -> Sequence[Tuple[Any, ...]]:
        return self._cursor.fetchall()

    def fetchmany(self, size: int = 1) -> Sequence[Tuple[Any, ...]]:
        return self._cursor.fetchmany(size)

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    @property
    def description(self) -> Any:
        return self._cursor.description

    def close(self) -> None:
        self._cursor.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class PostgresConnectionWrapper:
    """Wraps psycopg2 connection to provide cursor wrapper."""

    def __init__(self, raw_conn: PgConnection):
        self._conn = raw_conn

    def cursor(self) -> PostgresCursorWrapper:
        return PostgresCursorWrapper(self._conn.cursor())

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()


@contextlib.contextmanager
def get_db_connection(db_path_or_url: Optional[str] = None) -> Generator[Any, None, None]:
    """
    Yields an active database connection (SQLite or PostgreSQL) based on configuration.
    Propagates trusted request-scoped TenantContext into PostgreSQL transactions via SET LOCAL.
    """
    raw_url = db_path_or_url or os.getenv("DATABASE_URL", "gateway.db")

    if is_postgres_url(raw_url):
        if not HAS_PSYCOPG2:
            raise RuntimeError(
                "psycopg2-binary is required for PostgreSQL connections. "
                "Run: pip install psycopg2-binary"
            )
        pg_url = normalize_postgres_url(raw_url)
        raw_conn = psycopg2.connect(pg_url, connect_timeout=10)
        wrapper = PostgresConnectionWrapper(raw_conn)

        # Propagate trusted server-side TenantContext and CustomerContext into the PostgreSQL transaction
        from app.core.context import get_current_tenant_context, get_current_customer_context
        tenant_ctx = get_current_tenant_context()
        customer_ctx = get_current_customer_context()
        try:
            with raw_conn.cursor() as cur:
                if tenant_ctx is not None and tenant_ctx.merchant_id:
                    cur.execute("SET LOCAL app.current_merchant_id = %s;", (tenant_ctx.merchant_id.strip(),))
                else:
                    cur.execute("SET LOCAL app.current_merchant_id = '';")

                if customer_ctx is not None and customer_ctx.customer_id:
                    cur.execute("SET LOCAL app.current_customer_id = %s;", (customer_ctx.customer_id.strip(),))
                else:
                    cur.execute("SET LOCAL app.current_customer_id = '';")
            yield wrapper
        except Exception:
            wrapper.rollback()
            raise
        finally:
            wrapper.close()
    else:
        # SQLite
        path = raw_url
        if path.startswith("sqlite:///"):
            path = path[len("sqlite:///"):]
        elif path.startswith("sqlite://"):
            path = path[len("sqlite://"):]
        conn = sqlite3.connect(path, timeout=5.0)
        try:
            yield conn
        finally:
            conn.close()
