# ADR-02: PostgreSQL Production Database and Concurrency Model

- **ADR ID**: `ADR-02`
- **Title**: PostgreSQL Production Database Selection, Isolation Level, and Concurrency Model
- **Status**: `PROPOSED` (Pending Dedicated PostgreSQL CI Integration Test Harness Setup)
- **Author**: Principal Software Architect & Senior Security Architect
- **Date**: `2026-11-09`
- **Target Implementation**: Phase P0.4 (Secure Execution & Concurrency)

---

## 1. Context

The Agentic Commerce Gateway prototype relies on SQLite by default (`gateway.db`) with a fallback connection wrapper for PostgreSQL (`PostgresCursorWrapper` in [`app/db.py`](file:///d:/agentic-commerce-gateway/app/db.py)). SQLite operates with coarse database-level file locks and lacks row-level locking, `SELECT ... FOR UPDATE`, high-concurrency connection pooling, and strict decimal types.

In production, multiple Autonomous AI Agents may simultaneously attempt to purchase the same inventory items or debit the same customer wallet balance. Furthermore, automated payment webhooks and confirmation requests run concurrently.

---

## 2. Problem Statement

Relying naively on `SELECT ... FOR UPDATE` or SQLite file locking does not constitute a robust concurrency architecture. A complete production concurrency and database model must address twelve interrelated operational challenges:
1. **Transaction Boundaries**: Where do database transactions start and end across the multi-step purchase flow?
2. **Transaction Isolation Level**: What isolation level balances throughput against phantom reads and serialization anomalies?
3. **Atomic Conditional Updates**: How can check-then-act races be eliminated without excessive row locking?
4. **Unique Constraints**: What database constraints enforce idempotency and prevent replay attacks?
5. **Lock Ordering**: How are multiple database locks ordered to prevent deadlocks under heavy concurrent load?
6. **Deadlock Detection & Retry Handling**: How does the application detect and recover from deadlock exceptions?
7. **Idempotency Scope**: What constitutes the unique key and lease TTL for concurrent request deduplication?
8. **Reservation Expiry**: How do temporary inventory and budget reservations expire safely?
9. **Reservation Recovery**: How are orphaned reservations swept and restored after application crashes?
10. **Wallet Debit Consistency**: How is customer balance protected against simultaneous double-debit races?
11. **Inventory Consistency**: How is physical stock protected against simultaneous overselling?
12. **PostgreSQL vs. SQLite Testing**: How can concurrency correctness be validated when local test suites run on SQLite?

---

## 3. Considered Options

### Option A: Continue Dual SQLite/PostgreSQL with Application-Level In-Memory Locks
- *Mechanism*: Use Python `asyncio.Lock` or `threading.Lock` around critical sections, writing to SQLite or PostgreSQL.
- *Pros*: Zero external database infrastructure required for development.
- *Cons*: **Fatal Multi-Worker Flaw**: Application-level memory locks fail completely as soon as Uvicorn runs with multiple worker processes (`--workers > 1`) or scales horizontally across cloud containers (Render / Kubernetes).

### Option B: PostgreSQL with `SERIALIZABLE` Isolation Level
- *Mechanism*: Run all transactions under PostgreSQL `SERIALIZABLE` isolation.
- *Pros*: Mathematical guarantee of serial execution; eliminates race conditions by aborting conflicting transactions.
- *Cons*: Severe serialization failure rate (`40001`) under high write contention; requires retry loops around every transaction; significant latency overhead.

### Option C: PostgreSQL with `READ COMMITTED`, Atomic Conditional Updates, and Row-Level Locks (Proposed)
- *Mechanism*: Standardize production on PostgreSQL 15+ running at `READ COMMITTED` isolation. Utilize **atomic conditional SQL updates** (`UPDATE ... WHERE balance >= amount`) as the primary concurrency control, supplemented by `SELECT ... FOR UPDATE` with explicit primary key ordering where multi-row transactions are mandatory.
- *Pros*: High throughput, minimal lock contention, native deadlock detection, predictable error semantics.
- *Cons*: Requires real PostgreSQL service containers in CI/CD pipeline.

---

## 4. Decision

We **propose adopting Option C (PostgreSQL with `READ COMMITTED`, Atomic Conditional Updates, and Strict Lock Ordering)** for all multi-tenant and production deployments.

### 4.1 Technical Architecture Specification

1. **Production Engine Requirement**:
   - Production environments must strictly enforce PostgreSQL 15+. SQLite is restricted solely to in-memory/isolated developer unit testing.
2. **Transaction Boundaries**:
   - Transactions must be short-lived. Database transactions **MUST NEVER** enclose external network calls (such as calling the Razorpay API or Google OAuth). The Saga pattern must be used across the external dual-write boundary.
3. **Primary Concurrency Primitive: Atomic Conditional Updates**:
   - To eliminate check-then-act races in wallet debits:
     ```sql
     UPDATE customer_wallets
     SET balance_paise = balance_paise - :amount_paise,
         updated_at = :now
     WHERE customer_id = :customer_id
       AND balance_paise >= :amount_paise;
     ```
     Inspect `cursor.rowcount`. If `0`, immediately raise `InsufficientBalanceError`.
   - To eliminate check-then-act races in inventory decrements:
     ```sql
     UPDATE catalog_products
     SET stock = stock - :quantity,
         status = CASE WHEN stock - :quantity = 0 THEN 'OUT_OF_STOCK' ELSE status END,
         updated_at = :now
     WHERE id = :product_id
       AND stock >= :quantity;
     ```
     Inspect `cursor.rowcount`. If `0`, immediately raise `InsufficientStockError`.
4. **Lock Ordering to Prevent Deadlocks**:
   - When multi-item transactions must acquire row locks via `SELECT ... FOR UPDATE`, locks must **ALWAYS be acquired in ascending sorted primary key order**:
     ```sql
     SELECT id, stock FROM catalog_products
     WHERE id IN (:id1, :id2)
     ORDER BY id ASC
     FOR UPDATE;
     ```
   - Enforcing strict ascending key order mathematically prevents cyclic lock waits and eliminates deadlocks.
5. **Deadlock Detection & Retry Protocol**:
   - When PostgreSQL raises error `40P01` (deadlock detected), the application transaction manager must catch the exception, execute `ROLLBACK`, and retry the operation with exponential backoff and jitter:
     $$\text{delay} = \text{random}(0.01, 0.05) \times 2^{\text{attempt}} \quad (\text{max 3 retries})$$
6. **Confirmation-Token Single-Use Invalidation**:
   - Create table `approval_records (jti TEXT PRIMARY KEY, transaction_id TEXT, status TEXT, consumed_at TIMESTAMP)`.
   - At the beginning of `confirm_purchase()`, execute atomic insert:
     ```sql
     INSERT INTO approval_records (jti, transaction_id, status, consumed_at)
     VALUES (:jti, :tx_id, 'CONSUMED', CURRENT_TIMESTAMP);
     ```
     If a unique violation (`23505`) occurs, abort immediately with `CONFIRMATION_TOKEN_REPLAYED`.
7. **Reservation Expiry & Sweeper Reaper**:
   - Spending and inventory reservations (`spending_reservations`) carry a 5-minute TTL.
   - An asynchronous background daemon polls for reservations with `status='HELD'` where `expires_at < CURRENT_TIMESTAMP`, restoring stock and releasing budget holds.
8. **PostgreSQL CI/CD Testing Requirement**:
   - Concurrency and race condition test suites must run against real PostgreSQL instances in CI (via GitHub Actions `services: postgres` or testcontainers-python). Tests passing on SQLite provide zero assurance of PostgreSQL concurrency safety.

---

## 5. Consequences

### Positive Consequences
- Mathematically eliminates double-spending of wallet balances and overselling of inventory stock under concurrent load.
- Prevents database deadlocks through deterministic lock ordering.
- Ensures single-use confirmation token execution across distributed gateway instances.

### Negative / Operational Consequences
- Requires operational PostgreSQL database infrastructure (e.g. AWS RDS, Render PostgreSQL, Supabase) for local integration testing and staging.
- Requires replacing custom SQL string replacement (`app/db.py`) with parameterized queries and Alembic versioned migrations.

---

## 6. Security Implications

- **Financial Integrity**: Solves `VULN-02` (Wallet debit TOCTOU race condition).
- **Physical Inventory Truth**: Solves `VULN-03` (Inventory overselling race condition).
- **Replay Elimination**: Solves `VULN-04` (Confirmation token concurrent replay race).

---

## 7. Implementation Requirements (Phase P0.4)

1. Provision an automated PostgreSQL container harness for CI integration tests.
2. Initialize versioned Alembic migrations targeting PostgreSQL with proper unique constraints and foreign keys.
3. Refactor `wallet_store.debit()` and `decrement_stock()` to use atomic conditional `UPDATE` statements inspecting `rowcount`.
4. Deploy the background reservation reaper worker to sweep expired `HELD` reservations.

---

## 8. Measurable Acceptance Criteria

1. **Zero Wallet Overdraft under Concurrency**: 50 concurrent requests competing for a single ₹500 wallet balance must result in exactly one successful debit and 49 rejections; final balance must equal ₹0.
2. **Zero Inventory Oversell under Concurrency**: 50 concurrent requests competing for 1 remaining stock item must result in exactly one successful decrement and 49 rejections; final stock must equal 0.
3. **Deadlock Free Execution**: Under 100 concurrent multi-item requests, zero unhandled deadlock exceptions (`40P01`) escape the transaction retry manager.
4. **Token Replay Immunity**: 10 simultaneous identical confirmation requests result in exactly 1 order creation and 9 immediate replay rejections.

