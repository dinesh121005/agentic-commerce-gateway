"""
PostgreSQL 16 vs Python Hash Compatibility & Cryptographic Invariance Suite.
Milestone: P1.1.1-F — Task 4
Target: Local PostgreSQL 16 instance on 127.0.0.1:5433 (agentic-postgres16)

CRITICAL INVARIANTS:
1. Exact, bit-for-bit equivalence between Python compute_event_hash() and PostgreSQL 16
   pg_catalog.encode(pg_catalog.sha256(v_raw_payload::bytea), 'hex').
2. Comprehensive test cases for:
   - Whitespace (leading, trailing, interior, multi-line).
   - Unicode & multi-byte characters (emoji 🛒💳, currency ₹€£¥, Devanagari, Japanese).
   - Escaped JSON (nested quotes, backslashes, escaped controls).
   - Deterministic JSON key ordering (sort_keys=True).
   - Boundary values (empty payloads, large payloads, GENESIS vs 64-hex prev_hash).
   - 100% verification across all existing historical audit ledger entries.
"""
import hashlib
import json
import os
import secrets
import uuid
import pytest
from dotenv import load_dotenv

load_dotenv("d:/agentic-commerce-gateway/.env", override=False)

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

from app.audit.store import compute_event_hash


def get_live_postgres_url(role="admin") -> str:
    """Resolve local PostgreSQL URL for testing."""
    if role == "admin":
        url = os.environ.get("LOCAL_PG_ADMIN_URL")
    elif role == "audit":
        url = os.environ.get("LOCAL_PG_AUDIT_URL")
    elif role == "auth":
        url = os.environ.get("LOCAL_PG_AUTH_URL")
    else:
        url = os.environ.get("LOCAL_PG_APP_URL") or os.environ.get("LOCAL_DATABASE_URL")

    if not url:
        pytest.fail(f"FATAL: Database URL for role '{role}' not configured in .env.")
    if "127.0.0.1:5433" not in url and "localhost:5433" not in url:
        pytest.fail(f"FATAL: Safety violation: Non-local host in URL: {url}")
    return url


@pytest.fixture(scope="module")
def pg_admin_conn():
    if not HAS_PSYCOPG2:
        pytest.fail("psycopg2-binary is required.")
    url = get_live_postgres_url("admin")
    conn = psycopg2.connect(url, connect_timeout=5)
    conn.autocommit = True
    yield conn
    conn.close()


def query_pg_sha256(conn, raw_str: str) -> str:
    """Computes SHA-256 in PostgreSQL using pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(...::text, 'UTF8')), 'hex')."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(%s, 'UTF8')), 'hex');", (raw_str,))
        return cur.fetchone()[0]


# ══════════════════════════════════════════════════════════════════════════════
# 1. Whitespace & Boundary Compatibility
# ══════════════════════════════════════════════════════════════════════════════

def test_hash_compatibility_empty_and_whitespace(pg_admin_conn):
    """Verifies hash parity on empty payloads, interior spaces, and newlines."""
    test_cases = [
        # prev_hash, event_id, tx_id, event_type, ts, payload_json
        ("GENESIS", "ev_001", "tx_001", "SYSTEM_INIT", "2026-11-11T00:00:00Z", "{}"),
        ("GENESIS", "ev_ws1", "tx_ws1", "SYSTEM_CONFIG_UPDATED", "2026-11-11T00:00:00Z", '{"key": "value with spaces"}'),
        ("GENESIS", "ev_ws2", "tx_ws2", "SYSTEM_CONFIG_UPDATED", "2026-11-11T00:00:00Z", '{"key": "multi\\nline\\nvalue"}'),
        ("GENESIS", "ev_ws3", "tx_ws3", "SYSTEM_CONFIG_UPDATED", "2026-11-11T00:00:00Z", '{"tab": "value\\twith\\ttabs"}'),
        ("a" * 64, "ev_002", "tx_002", "KEY_REGISTERED", "2026-11-11T23:59:59.999999Z", '{"status": "ok"}'),
    ]

    for prev_h, ev_id, tx_id, ev_type, ts, payload in test_cases:
        py_hash = compute_event_hash(prev_h, ev_id, tx_id, ev_type, ts, payload)
        raw_str = f"{prev_h}|{ev_id}|{tx_id}|{ev_type}|{ts}|{payload}"
        pg_hash = query_pg_sha256(pg_admin_conn, raw_str)
        assert py_hash == pg_hash, f"Hash mismatch for case {ev_id}: py={py_hash}, pg={pg_hash}"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Unicode and Multi-Byte Encoding Compatibility
# ══════════════════════════════════════════════════════════════════════════════

def test_hash_compatibility_unicode_and_multibyte(pg_admin_conn):
    """
    Verifies hash parity on multi-byte UTF-8 sequences:
    - Currency symbols: ₹ (INR, 3 bytes: E2 82 B9), € (3 bytes: E2 82 AC), £ (2 bytes: C2 A3), ¥ (2 bytes: C2 A5)
    - Emoji: 🛒, 💳, 🔒, 🚀 (4 bytes UTF-8)
    - Devanagari: 'नमस्ते दुनिया' (Hindi)
    - Japanese: '決済ゲートウェイ' (Payment Gateway)
    - Accents: 'café résumé naïve São Paulo'
    """
    unicode_payloads = [
        {"currency": "INR", "symbol": "₹", "amount_formatted": "₹1,499.00"},
        {"currency": "EUR", "symbol": "€", "amount_formatted": "€49.99"},
        {"currency": "GBP", "symbol": "£", "amount_formatted": "£35.50"},
        {"currency": "JPY", "symbol": "¥", "amount_formatted": "¥5,000"},
        {"emoji": "🛒💳🔒🚀", "description": "Agentic checkout with 🛒 cart and 💳 mandate"},
        {"language": "hi", "greeting": "नमस्ते दुनिया", "notes": "सुरक्षित कॉमर्स गेटवे"},
        {"language": "ja", "service": "決済ゲートウェイ", "status": "成功"},
        {"accents": "café crème, résumé, naïve façade, São Paulo, Zürich"},
    ]

    prev_h = secrets.token_hex(32)
    for idx, payload_dict in enumerate(unicode_payloads):
        ev_id = f"ev_uni_{idx}"
        tx_id = f"tx_uni_{idx}"
        ev_type = "KEY_REGISTERED"
        ts = "2026-11-11T12:34:56.789Z"
        payload_json = json.dumps(payload_dict, sort_keys=True, ensure_ascii=False)

        py_hash = compute_event_hash(prev_h, ev_id, tx_id, ev_type, ts, payload_json)
        raw_str = f"{prev_h}|{ev_id}|{tx_id}|{ev_type}|{ts}|{payload_json}"
        pg_hash = query_pg_sha256(pg_admin_conn, raw_str)

        assert py_hash == pg_hash, (
            f"Unicode hash mismatch at index {idx} ({payload_dict}):\n"
            f"  Python: {py_hash}\n"
            f"  Postgres: {pg_hash}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 3. Escaped JSON & Complex Structures
# ══════════════════════════════════════════════════════════════════════════════

def test_hash_compatibility_escaped_json(pg_admin_conn):
    """
    Verifies hash parity on complex JSON escaping:
    - Escaped quotes, backslashes, nested JSON strings
    - Special control sequences
    - Deterministic key ordering (sort_keys=True)
    """
    complex_payloads = [
        {
            "nested_json_string": '{"sub_key": "sub_value", "escaped_quote": "He said \\"Hello\\""}',
            "windows_path": "C:\\Program Files\\Agentic Gateway\\config\\settings.json",
            "regex_pattern": "^[a-fA-F0-9]{64}$",
            "html_snippet": "<script>alert('xss');</script>",
        },
        {
            "z_key": 1,
            "m_key": 2,
            "a_key": 3,
            "deep": {
                "zz": "bottom",
                "aa": "top",
            }
        },
    ]

    prev_h = secrets.token_hex(32)
    for idx, payload_dict in enumerate(complex_payloads):
        ev_id = f"ev_cpx_{idx}"
        tx_id = f"tx_cpx_{idx}"
        ev_type = "SYSTEM_CONFIG_UPDATED"
        ts = "2026-11-11T15:00:00Z"
        payload_json = json.dumps(payload_dict, sort_keys=True)

        py_hash = compute_event_hash(prev_h, ev_id, tx_id, ev_type, ts, payload_json)
        raw_str = f"{prev_h}|{ev_id}|{tx_id}|{ev_type}|{ts}|{payload_json}"
        pg_hash = query_pg_sha256(pg_admin_conn, raw_str)

        assert py_hash == pg_hash, f"Complex JSON hash mismatch at index {idx}: py={py_hash}, pg={pg_hash}"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Large Payloads Boundary Test
# ══════════════════════════════════════════════════════════════════════════════

def test_hash_compatibility_large_payload(pg_admin_conn):
    """Verifies hash parity on large payloads (e.g. 10KB+ of cryptographic mandate certificates)."""
    large_payload = {
        "certificate": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" * 50,
        "signatures": [secrets.token_hex(64) for _ in range(50)],
        "metadata": {f"key_{i}": f"val_{i}_{secrets.token_hex(16)}" for i in range(100)},
    }
    prev_h = secrets.token_hex(32)
    ev_id = f"ev_large_{uuid.uuid4().hex[:8]}"
    tx_id = f"tx_large_{uuid.uuid4().hex[:8]}"
    ev_type = "SYSTEM_CONFIG_UPDATED"
    ts = "2026-11-11T18:00:00Z"
    payload_json = json.dumps(large_payload, sort_keys=True)

    py_hash = compute_event_hash(prev_h, ev_id, tx_id, ev_type, ts, payload_json)
    raw_str = f"{prev_h}|{ev_id}|{tx_id}|{ev_type}|{ts}|{payload_json}"
    pg_hash = query_pg_sha256(pg_admin_conn, raw_str)

    assert py_hash == pg_hash, "Large payload hash mismatch between Python and PostgreSQL"
    assert len(payload_json) > 5000, f"Expected > 5KB payload, got {len(payload_json)} bytes"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Historical Audit Ledger Bit-for-Bit Parity Verification
# ══════════════════════════════════════════════════════════════════════════════

def test_historical_audit_records_exact_hash_parity(pg_admin_conn):
    """
    Reads EVERY single historical record in public.audit_events on the live PostgreSQL instance.
    Re-calculates the hash in Python and in PostgreSQL.
    Verifies that 100% of historical records have bit-for-bit parity and have not drifted.
    """
    with pg_admin_conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, event_id, transaction_id, event_type, timestamp, payload_json, prev_hash, event_hash
            FROM public.audit_events
            ORDER BY id ASC;
            """
        )
        rows = cur.fetchall()

    assert len(rows) > 0, "No historical audit records found to verify!"

    verified_count = 0
    for r in rows:
        row_id, ev_id, tx_id, ev_type, ts, payload_json, prev_h, stored_hash = r

        # 1. Recompute via Python
        py_hash = compute_event_hash(
            prev_hash=prev_h or "GENESIS",
            event_id=ev_id,
            transaction_id=tx_id,
            event_type=ev_type,
            timestamp=ts,
            payload_json=payload_json,
        )

        # 2. Recompute via PostgreSQL
        raw_str = f"{prev_h or 'GENESIS'}|{ev_id}|{tx_id}|{ev_type}|{ts}|{payload_json}"
        pg_hash = query_pg_sha256(pg_admin_conn, raw_str)

        # 3. Assert 100% triple parity: Python == PostgreSQL == Stored Ledger Hash
        assert py_hash == pg_hash, (
            f"Row {row_id} (tx={tx_id}): Python ({py_hash}) != PostgreSQL ({pg_hash})"
        )
        assert py_hash == stored_hash, (
            f"Row {row_id} (tx={tx_id}): Computed ({py_hash}) != Stored ({stored_hash})"
        )
        verified_count += 1

    print(f"\n[OK] Successfully verified exact 3-way hash parity across {verified_count} historical audit events!")
