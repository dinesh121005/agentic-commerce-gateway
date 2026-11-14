# Architecture Specification: Multi-Tenant Isolation Architecture

**Document ID:** ARCH-P1.1.1-01  
**Milestone:** P1.1.1 — Tenant Isolation Hardening  
**Target:** Multi-Tenant Merchant Platform  
**Status:** Implemented & Verified  

---

## 1. Executive Summary & Core Security Invariant

The Agentic Commerce Platform operates as a merchant-first, multi-tenant system where each merchant organization acts as a sovereign tenant.

### Core Security Invariant
> **A merchant must never be able to read, modify, delete, reserve, purchase, or otherwise manipulate another merchant's resources.**

This invariant is enforced across:
1. REST APIs (merchant employee endpoints and public catalog routes)
2. Model Context Protocol (MCP) tool discovery and execution
3. Internal domain service layers (`catalog`, `agent`, `payment`, `audit`)
4. Relational database storage (compound keys and scoped queries)
5. Inventory stock reservations and Saga compensating rollbacks
6. Cryptographic audit trail logs and transaction inspection

---

## 2. Multi-Tenant Security Domains

The platform rigorously segregates authentication into three distinct security domains:

| Domain | Principal Identity | Credential / Token Type | Audience (`aud`) | Permitted Boundaries |
| :--- | :--- | :--- | :--- | :--- |
| **Merchant Employee** | Merchant User (`usr_...`) | Merchant JWT (`Argon2id` auth) | `merchant-platform` | Merchant REST APIs, Organization Admin, Store Catalog |
| **Autonomous AI Buyer** | Customer Identifier (`CUST...`) | Buyer OAuth Bearer JWT | `gateway-buyer-api` | Public Catalog, MCP Tools, Spending Mandates |
| **Merchant AI Worker** | Internal Machine Principal | Internal Domain Tool Call | `merchant-internal` | Typed Domain Operations, Scoped to `merchant_id` |

### Cross-Domain Token Rejection
- Merchant employee JWTs are rejected immediately by Buyer OAuth MCP endpoints.
- Buyer OAuth JWTs are rejected immediately by Merchant Management endpoints.
- Tokens from one domain cannot be replayed or substituted across boundaries.

---

## 3. Request-Scoped Tenant Context & Async Propagation

### 3.1 Immutable Context Object
Tenant context is encapsulated in the immutable `TenantContext` dataclass ([`app/core/context.py`](file:///d:/agentic-commerce-gateway/app/core/context.py)):

```python
@dataclass(frozen=True)
class TenantContext:
    user_id: str
    merchant_id: str
    membership_id: str
    role: str
    permissions: Set[str] = field(default_factory=set)
```

### 3.2 Async-Safe Context Propagation
Tenant identity is bound to Python `contextvars.ContextVar("current_tenant_context")`:
- Each asynchronous asyncio Task inherits an isolated context copy.
- Background tasks and concurrent requests cannot bleed tenant context into concurrent coroutines.
- Verified under high concurrency: 50 concurrent interleaved threads demonstrated 0% tenant context leakage.

### 3.3 Immediate Session Revocation
- Merchant users possess a database `token_version` integer.
- User logout or administrator deactivation increments `token_version`.
- All access tokens carrying stale versions are rejected with HTTP 401 on the subsequent request without waiting for JWT TTL expiration.

---

## 4. Commerce Data Layer Isolation

### 4.1 SKU / Product ID Collision Independence
Previous architectures used a global single primary key on `catalog_products.id`. If Merchant A and Merchant B both sold an item with SKU `PROD001`, database primary key collisions occurred.

In P1.1.1, `catalog_products` is hardened with a **compound primary key**:
```sql
CREATE TABLE catalog_products (
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    merchant_id TEXT NOT NULL DEFAULT 'MERCH_ELEC',
    price REAL NOT NULL,
    price_paise INTEGER,
    stock INTEGER NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (merchant_id, id)
);
```

#### Collision Guarantee
- Merchant A can create `SKU001` at ₹500.
- Merchant B can create `SKU001` at ₹999.
- Both records coexist without collision. Each merchant receives their respective pricing and inventory.

### 4.2 Inventory Stock Reservation Isolation
Atomic inventory stock reservations enforce tenant scoping to prevent cross-tenant stock manipulation:
```sql
UPDATE catalog_products
SET stock = stock - :quantity,
    status = CASE WHEN stock - :quantity = 0 THEN 'OUT_OF_STOCK' ELSE status END,
    updated_at = :now
WHERE id = :product_id 
  AND merchant_id = :merchant_id 
  AND stock >= :quantity;
```
If an actor attempts to claim stock for `SKU001` with an unauthorized `merchant_id`, `rowcount` returns 0 and reservation fails.

### 4.3 Audit Ledger Scoping
Every transaction audit record embeds `merchant_id`. Audit query methods in `AuditStore` enforce:
- Merchant employees querying `/api/v1/merchants/{merchant_id}/audit` only receive transactions matching their active `tenant_context.merchant_id`.
- Single-record fetches verify `record.merchant_id == tenant_context.merchant_id`, returning 404/403 for unauthorized attempts.

---

## 5. Model Context Protocol (MCP) Tool Scoping

AI shopping agents interact via Model Context Protocol tools ([`app/mcp/tools.py`](file:///d:/agentic-commerce-gateway/app/mcp/tools.py)):
- Buyer tool `search_products_handler` checks the active customer's pre-authorized spending mandate (`mandate.allowed_merchants`).
- If a customer is authorized only for `['MERCH_ELEC']`, queries never return products owned by `MERCH_FOOD` or other merchant organizations.
- In demo/stdio mode, search defaults strictly to `MERCH_ELEC`, ensuring zero product cross-talk.

---

## 6. Login Rate Limiting (Brute Force Defense)

To prevent credential stuffing and brute force attacks against merchant accounts:
- In-memory thread-safe sliding window rate limiter ([`app/merchant/rate_limit.py`](file:///d:/agentic-commerce-gateway/app/merchant/rate_limit.py)).
- Window: 300 seconds (5 minutes). Threshold: 5 failed attempts per `ip:account_email`.
- 6th failed attempt within window returns **HTTP 429 Too Many Requests** with `Retry-After` header.
- Successful login immediately resets the failed attempts counter.

---

## 7. PostgreSQL Row-Level Security (RLS) & Connection Pooling

### 7.1 Connection Pool Bleed Risk
When using physical connection poolers (PgBouncer, SQLAlchemy QueuePool, asyncpg):
```
Request 1 (Merchant A) ───► Pooled Connection #1 ───► SET app.current_merchant_id = 'MERCH_A'
Request 2 (Merchant B) ───► Reuses Connection #1 ───► LEAK: Still sees MERCH_A if not wiped!
```

### 7.2 Transaction-Scoped `SET LOCAL` Architecture
To eliminate connection pool bleeding, the platform mandates transaction-scoped configuration:
```sql
BEGIN;
SET LOCAL app.current_merchant_id = 'MERCH_A';
-- All queries within this transaction execute under Merchant A RLS policy
SELECT * FROM catalog_products; 
COMMIT; -- app.current_merchant_id is automatically wiped upon COMMIT or ROLLBACK
```

### 7.3 DDL Specification
The migration script is provided at [`scripts/migrations/001_postgresql_rls_hardening.sql`](file:///d:/agentic-commerce-gateway/scripts/migrations/001_postgresql_rls_hardening.sql):
```sql
ALTER TABLE catalog_products ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalog_products FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_catalog ON catalog_products
    AS RESTRICTIVE
    FOR ALL
    USING (merchant_id = NULLIF(current_setting('app.current_merchant_id', true), ''))
    WITH CHECK (merchant_id = NULLIF(current_setting('app.current_merchant_id', true), ''));
```

---

## 8. Verified Test Matrix

| Category | Description | Status | Evidence |
| :--- | :--- | :--- | :--- |
| **Category A** | Cross-tenant REST API reads | **PASS** | 403 Forbidden verified |
| **Category B** | Cross-tenant REST API writes | **PASS** | 403 Forbidden verified |
| **Category C** | Parameter tampering / payload spoofing | **PASS** | Server-derived context overrides payload |
| **Category D** | Privilege escalation & final owner guard | **PASS** | Last owner demotion rejected |
| **Category E** | Buyer OAuth vs Merchant JWT separation | **PASS** | Mutual cross-domain 401 rejection |
| **Category F** | Immediate token revocation on logout | **PASS** | `token_version` increment revokes session |
| **Category G** | Concurrency ContextVar isolation | **PASS** | 50 concurrent interleaved requests pass |
| **Category J** | Product ID collision & independent pricing | **PASS** | Compound PK verified |
| **Category K** | Cross-tenant inventory decrement denial | **PASS** | Stock manipulation blocked |
| **Category L** | Cross-tenant audit trail inspection denial | **PASS** | Scoped queries verified |
| **Category M** | MCP tool product search scoping | **PASS** | Mandate merchant filter verified |
| **Category N** | Login brute force rate limiting | **PASS** | 5 failures $\rightarrow$ 6th is 429 with `Retry-After` |
| **Category O** | PostgreSQL Row-Level Security | **NOT RUN** | Documented DDL; skipped on local SQLite |
| **Category P** | P0 Transaction & Cryptographic Invariants | **PASS** | `MERCH_ELEC` preserved; Ed25519 valid |

