# ADR-004: PostgreSQL Dual-Axis Row-Level Security, Control-Plane Isolation, and Verified Migration Readiness

**Status:** Accepted & Verified (Milestone P1.1.1-G: Buyer Isolation, Control-Plane Protection & Disposable Database Validation)  
**Date:** 2026-11-11  
**Authors:** Antigravity Orchestrator & Principal Database Security Architect  
**Milestone:** P1.1.1-G (Buyer Isolation, Control-Plane Security, and Migration Validation)

---

## 1. Context and Problem Statement

In milestones P1.1.1-A through P1.1.1-F, database-level Row-Level Security (RLS), transaction context lifecycles, privileged function protections, and runtime role separation (`gateway_admin`, `gateway_auth`, `system_audit_writer`, `app_user`) were designed, implemented, and hardened.

However, prior to final approval of Migration 001 (`001_postgresql_rls_hardening.sql`), two critical isolation domains required formal resolution:
1. **Buyer-Level Isolation:** Buyer-owned resources (`customer_wallets`, `customer_signing_keys`, `customer_credentials`, `customer_mandates`, `signed_mandates`, `purchase_approvals`, `signing_challenges`, `refresh_tokens`) were not yet protected by independent customer-scoped RLS policies. Buyers must have strict tenant-independent isolation ensuring that Buyer A cannot read or mutate Buyer B's assets, while allowing buyers to interact seamlessly across multiple independent merchants without mandate fragmentation.
2. **Control-Plane Protection:** Ordinary application runtime (`app_user`) previously retained table-level DML on global control-plane tables (`merchants`, `merchant_users`, `processed_webhook_events`), creating potential enumeration and spoofing risks.
3. **Migration Verification on Disposable Database:** Migration 001 needed verifiable dry-run execution against an isolated disposable database (`agentic_disposable_test`), confirming RLS on all 16 target tables, verifying fail-closed behavior, and demonstrating safe atomic transaction rollback before any production activation.

---

## 2. Decision Drivers

- **Dual-Axis Transaction Isolation:** Enforce two independent, non-conflicting isolation dimensions within PostgreSQL:
  - *Merchant Tenant Scoping:* Scoped via `app.current_merchant_id` for merchant-owned data (`catalog_products`, `audit_records`, `audit_events`, `merchant_memberships`, `merchant_invitations`).
  - *Buyer Customer Scoping:* Scoped via `app.current_customer_id` for buyer-owned data (`customer_wallets`, `customer_signing_keys`, `customer_credentials`, `customer_mandates`, `signed_mandates`, `purchase_approvals`, `signing_challenges`, `refresh_tokens`).
- **Control-Plane Least-Privilege Hardening:** Completely revoke table-level privileges on `merchant_users` and `processed_webhook_events` from `app_user`. Restrict `merchants` table to `SELECT`-only for `app_user`. Route administrative and employee authentication operations strictly through `gateway_auth`, and webhook idempotency through `system_audit_writer`.
- **Fail-Closed Missing Context Behavior:** In the absence of an authenticated context (or if parameters evaluate to `''` or `NULL`), RLS predicates evaluate to `UNKNOWN` (falsy in SQL), ensuring zero rows are returned and all write operations fail closed.
- **Connection Pool Safety:** All context propagation MUST use `SET LOCAL` within explicit transaction blocks (`BEGIN ... COMMIT / ROLLBACK`), ensuring automatic erasure on transaction termination and preventing cross-transaction connection bleed.
- **Disposable Dry-Run Validation:** Validate Migration 001 exclusively on a dedicated disposable database (`agentic_disposable_test`), verifying that `agentic_commerce` on port 5433 remains strictly unexecuted (`relrowsecurity = False`).
- **Cryptographic & Historical Invariance:** Historical signed mandate payloads (Ed25519) and audit ledger hashes (SHA-256) must remain 100% bit-for-bit immutable and verifiable.

---

## 3. Architectural Decisions

### 3.1. Dual-Axis Context Architecture & Lifecycle

The gateway establishes a dual-axis isolation model enforced at the PostgreSQL kernel level:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            API REQUEST LIFECYCLE                            │
├──────────────────────────────────────┬──────────────────────────────────────┤
│ 1. Bearer JWT / Ed25519 Auth Token   │ 2. Buyer OAuth / Session Token       │
│    Extracted & Cryptographically     │    Extracted & Cryptographically     │
│    Validated in Application Layer    │    Validated in Application Layer    │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ Authoritative Merchant Context:      │ Authoritative Customer Context:      │
│ TenantContext(merchant_id='MERCH_A') │ CustomerContext(customer_id='CUST_1')│
└──────────────────────────────────────┴──────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    POSTGRESQL TRANSACTION BOUNDARY (app/db.py)              │
├─────────────────────────────────────────────────────────────────────────────┤
│ BEGIN;                                                                      │
│   SET LOCAL app.current_merchant_id = 'MERCH_A'; -- or '' if unauthenticated│
│   SET LOCAL app.current_customer_id = 'CUST_1';  -- or '' if unauthenticated│
│                                                                             │
│   -- Queries executed under active transaction...                           │
│ COMMIT; -- or ROLLBACK (GUCs automatically erased by PostgreSQL engine)     │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
┌───────────────────────────────────┐       ┌─────────────────────────────────┐
│     MERCHANT TENANT DOMAIN        │       │       BUYER CUSTOMER DOMAIN     │
├───────────────────────────────────┤       ├─────────────────────────────────┤
│ RLS Predicate:                    │       │ RLS Predicate:                  │
│ merchant_id = NULLIF(             │       │ customer_id = NULLIF(           │
│   current_setting(                │       │   current_setting(              │
│     'app.current_merchant_id',true│       │     'app.current_customer_id',  │
│   ), '')                          │       │     true), '')                  │
│ AND merchant_id IS NOT NULL       │       │ AND customer_id IS NOT NULL     │
├───────────────────────────────────┤       ├─────────────────────────────────┤
│ - catalog_products                │       │ - customer_wallets              │
│ - audit_records                   │       │ - customer_signing_keys         │
│ - audit_events (merchant events)  │       │ - customer_credentials          │
│ - merchant_memberships            │       │ - customer_mandates             │
│ - merchant_invitations            │       │ - signed_mandates               │
│ - merchants (SELECT-only)         │       │ - purchase_approvals            │
│                                   │       │ - signing_challenges            │
│                                   │       │ - refresh_tokens                │
└───────────────────────────────────┘       └─────────────────────────────────┘
```

#### Grounding & Limitations of PostgreSQL GUCs:
1. **Connection-Level Configuration Variables:** PostgreSQL `current_setting('app.current_customer_id', true)` is an application-level variable. It does NOT independently authenticate the user; the application authentication middleware (Argon2id password verification, Ed25519 cryptographic signatures, JWT signature verification) is strictly responsible for authenticating the caller and populating `CustomerContext` and `TenantContext`.
2. **Transaction Scope Requirement:** `SET LOCAL` is mandatory. Session-level `SET` is strictly forbidden because database connections are pooled and shared across requests. `SET LOCAL` binds the variable exclusively to the current transaction; upon `COMMIT` or `ROLLBACK`, the variable automatically reverts to default/unset.
3. **Fail-Closed Semantics:** Wrapping the GUC lookup in `NULLIF(..., '')` guarantees that if the GUC is absent, empty, or uninitialized, the expression evaluates to `NULL`. In SQL, `customer_id = NULL` evaluates to `UNKNOWN` (falsy in RLS predicates), completely blocking access.

---

### 3.2. Control-Plane Isolation Design

To prevent ordinary tenant runtime (`app_user`) from enumerating or modifying platform and employee data:

1. **`merchant_users` (Employee Credentials):**
   - `REVOKE ALL ON public.merchant_users FROM app_user;`
   - `GRANT SELECT, INSERT, UPDATE, DELETE ON public.merchant_users TO gateway_auth;`
   - Direct queries by `app_user` fail closed with `psycopg2.errors.InsufficientPrivilege: permission denied for table merchant_users`.
   - Employee authentication, registration, and status updates are executed exclusively via `gateway_auth` connections.

2. **`processed_webhook_events` (Payment Idempotency):**
   - `REVOKE ALL ON public.processed_webhook_events FROM app_user;`
   - `GRANT SELECT, INSERT ON public.processed_webhook_events TO system_audit_writer;`
   - Ordinary tenant runtime cannot inspect or fabricate webhook idempotency records.

3. **`merchants` (Organization Directory):**
   - `REVOKE INSERT, UPDATE, DELETE ON public.merchants FROM app_user;`
   - `GRANT SELECT ON public.merchants TO app_user;`
   - RLS policy `tenant_isolation_merchants_select` permits `app_user` to read ONLY its own active tenant record (`id = NULLIF(current_setting('app.current_merchant_id', true), '')`).
   - Tenant creation and administrative updates are restricted to `gateway_auth` / `gateway_admin`.

---

### 3.3. Comprehensive Table Ownership & Permissions Matrix

All 18 tables in schema `public` are owned by `gateway_admin`. Runtime roles hold strictly partitioned least-privilege grants:

| Table Name | Resource Domain | Ownership / Boundary | `app_user` Grants | `gateway_auth` Grants | `system_audit_writer` Grants | `gateway_admin` Grants | RLS Policy Status (Migration 001) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `catalog_products` | Merchant Data | `merchant_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`tenant_isolation_catalog`) |
| `audit_records` | Merchant Data | `merchant_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`tenant_isolation_audit_records`) |
| `audit_events` | Global Ledger | `merchant_id` / NULL | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`tenant_isolation_audit_events_app_user`) |
| `merchant_memberships` | Merchant Data | `merchant_id` | SELECT, INSERT, UPDATE, DELETE | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`tenant_isolation_memberships`) |
| `merchant_invitations` | Merchant Data | `merchant_id` | SELECT, INSERT, UPDATE, DELETE | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`tenant_isolation_invitations`) |
| `merchants` | Control-Plane | Platform Root | **SELECT Only** (Revoked DML) | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`tenant_isolation_merchants_select`) |
| `merchant_users` | Control-Plane | User Directory | **NONE** (Completely Revoked) | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`admin_merchant_users_policy`) |
| `processed_webhook_events` | Control-Plane | Provider Event | **NONE** (Completely Revoked) | NONE (Revoked) | SELECT, INSERT | ALL (Owner) | **ENABLE + FORCE RLS** (`admin_webhook_events_policy`) |
| `customer_wallets` | **Buyer Resource** | `customer_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`buyer_isolation_wallets`) |
| `customer_signing_keys` | **Buyer Resource** | `customer_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`buyer_isolation_signing_keys`) |
| `customer_credentials` | **Buyer Resource** | `customer_id` | SELECT, INSERT, UPDATE, DELETE | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`buyer_isolation_credentials`) |
| `customer_mandates` | **Buyer Resource** | `customer_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`buyer_isolation_mandates`) |
| `signed_mandates` | **Buyer Resource** | `customer_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`buyer_isolation_signed_mandates`) |
| `purchase_approvals` | **Buyer Resource** | `customer_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`buyer_isolation_purchase_approvals`) |
| `signing_challenges` | **Buyer Resource** | `customer_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`buyer_isolation_signing_challenges`) |
| `refresh_tokens` | **Buyer Resource** | `customer_id` | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | **ENABLE + FORCE RLS** (`buyer_isolation_refresh_tokens`) |
| `product_relationships` | Graph Data | Derived | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | Excluded from RLS (Tenant-filtered in service layer) |
| `recommendations` | Graph Data | Derived | SELECT, INSERT, UPDATE, DELETE | NONE (Revoked) | NONE (Revoked) | ALL (Owner) | Excluded from RLS (Tenant-filtered in service layer) |

---

### 3.4. Privileged Functions & Access Control Matrix

| Function Signature | Owner | Security Definer | `search_path` | Public Exec | `app_user` | `gateway_auth` | `system_audit_writer` | `gateway_admin` | In-Function Security Gate |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `auth_lookup_user_memberships(TEXT)` | `gateway_admin` | **YES** | `pg_catalog, public` | **REVOKED** | **REVOKED** | **GRANTED** | **REVOKED** | **GRANTED** | `SESSION_USER IN ('gateway_auth', 'gateway_admin', 'postgres')` |
| `append_system_audit_event(7 params)` | `gateway_admin` | **YES** | `pg_catalog, public` | **REVOKED** | **REVOKED** | **REVOKED** | **GRANTED** | **GRANTED** | `SESSION_USER IN ('system_audit_writer', 'gateway_admin', 'postgres')` + Event type whitelist + UTF-8 SHA-256 verification |
| `get_latest_audit_event_hash()` | `gateway_admin` | **YES** | `pg_catalog, public` | **REVOKED** | **GRANTED** | **GRANTED** | **GRANTED** | **GRANTED** | Exclusive advisory lock (`pg_advisory_xact_lock`), returns 64-hex hash |
| `auth_lookup_invitation_by_token(TEXT)` | `gateway_admin` | **YES** | `pg_catalog, public` | **REVOKED** | **GRANTED** | **GRANTED** | **REVOKED** | **GRANTED** | SHA-256 token hash format check; expiry check |

---

## 4. Disposable Database Migration Validation & Verification

### 4.1. Disposable Database Isolation
- A clean, dedicated PostgreSQL 16 database (`agentic_disposable_test`) was provisioned on local port `5433`.
- All 18 application tables were bootstrapped and transferred to `gateway_admin`.
- Representative multi-tenant, multi-buyer, and control-plane records were seeded:
  - Merchants: `MERCH_DISP_A`, `MERCH_DISP_B`
  - Buyers: `CUST_DISP_1`, `CUST_DISP_2`
  - Employees: `USER_DISP_A`, `USER_DISP_B`
  - Cryptographically signed mandates (Ed25519) and hash-chained audit events (SHA-256).
- `001_postgresql_rls_hardening.sql` was executed **exclusively** against `agentic_disposable_test`.
- The primary database (`agentic_commerce`) was verified to remain **100% UNTOUCHED** (`relrowsecurity = False` across all tables).

### 4.2. RLS Status Verification Across All 18 Tables
| Table | RLS Enabled | FORCE RLS | Verification Outcome |
| :--- | :--- | :--- | :--- |
| `audit_events` | **True** | **True** | PASS |
| `audit_records` | **True** | **True** | PASS |
| `catalog_products` | **True** | **True** | PASS |
| `customer_credentials` | **True** | **True** | PASS |
| `customer_mandates` | **True** | **True** | PASS |
| `customer_signing_keys` | **True** | **True** | PASS |
| `customer_wallets` | **True** | **True** | PASS |
| `merchant_invitations` | **True** | **True** | PASS |
| `merchant_memberships` | **True** | **True** | PASS |
| `merchant_users` | **True** | **True** | PASS |
| `merchants` | **True** | **True** | PASS |
| `processed_webhook_events` | **True** | **True** | PASS |
| `product_relationships` | False | False | PASS (Excluded - derived graph) |
| `purchase_approvals` | **True** | **True** | PASS |
| `recommendations` | False | False | PASS (Excluded - derived graph) |
| `refresh_tokens` | **True** | **True** | PASS |
| `signed_mandates` | **True** | **True** | PASS |
| `signing_challenges` | **True** | **True** | PASS |

### 4.3. Atomic Rollback Verification
- An intentional syntax/catalog error was injected inside an atomic transaction block during migration testing.
- Verified that the migration failure safely and completely rolled back: zero partial DDL, zero corrupted table flags.

---

## 5. Adversarial Verification Suite (12 Required Scenarios)

The test suite `tests/security/test_postgresql_p1_1_1_g_adversarial.py` was authored and executed against `agentic_disposable_test`, achieving **12 out of 12 PASSED (100% compliance)**:

1. **`test_buyer_cannot_read_other_buyer_wallet` (PASSED):**
   - Buyer 1 querying `customer_wallets WHERE customer_id = 'CUST_DISP_2'` returned 0 rows.
   - Unfiltered `SELECT` returned exactly Buyer 1's wallet.
   - Targeted `UPDATE` on Buyer 2's wallet affected 0 rows.
2. **`test_buyer_cannot_modify_other_buyer_signing_keys` (PASSED):**
   - Cross-buyer `UPDATE` affected 0 rows.
   - Cross-buyer `DELETE` affected 0 rows.
   - Forged key insertion under Buyer 2's `customer_id` failed with RLS check violation.
3. **`test_buyer_cannot_retrieve_other_buyer_mandates` (PASSED):**
   - Cross-buyer query on `customer_mandates` and `signed_mandates` returned 0 rows.
   - Cross-buyer updates on signed mandates affected 0 rows.
4. **`test_buyer_cannot_consume_other_buyer_purchase_approvals` (PASSED):**
   - Cross-buyer query on `purchase_approvals` returned 0 rows.
   - Cross-buyer approval update affected 0 rows.
   - Approval injection under Buyer 2's `customer_id` failed with RLS check violation.
5. **`test_missing_customer_context_fails_closed` (PASSED):**
   - When `app.current_customer_id = ''`, all 8 buyer tables returned 0 rows for `SELECT COUNT(*)`.
   - Inserts into buyer tables failed with RLS check violation.
6. **`test_customer_context_cannot_leak_across_pooled_transactions` (PASSED):**
   - Multi-transaction lifecycle over a single physical connection demonstrated that `SET LOCAL app.current_customer_id` automatically erases upon `COMMIT` or `ROLLBACK`. Unauthenticated subsequent transactions on the same connection saw 0 rows.
7. **`test_merchant_cannot_access_other_merchant_control_plane` (PASSED):**
   - Merchant Alpha querying `merchants WHERE id = 'MERCH_DISP_B'` returned 0 rows.
   - Querying `merchant_memberships` and `merchant_invitations` returned only Merchant Alpha's records.
8. **`test_tenant_runtime_cannot_modify_or_read_merchant_users` (PASSED):**
   - `app_user` attempting `SELECT` or `INSERT` on `merchant_users` failed with `permission denied for table merchant_users`.
   - `gateway_auth` executed queries on `merchant_users` successfully.
9. **`test_tenant_runtime_cannot_insert_or_modify_processed_webhooks` (PASSED):**
   - `app_user` attempting `SELECT` or `INSERT` on `processed_webhook_events` failed with `permission denied for table processed_webhook_events`.
   - `system_audit_writer` inserted and read webhook idempotency records successfully.
10. **`test_existing_merchant_isolation_rls_passes_on_migrated_db` (PASSED):**
    - Catalog products, audit records, and audit events enforced merchant isolation under active RLS. Cross-merchant inserts blocked by RLS check.
11. **`test_system_audit_writes_remain_restricted` (PASSED):**
    - `app_user` blocked from `append_system_audit_event()`.
    - `system_audit_writer` successfully appended system events with verified hash and advisory lock.
    - Verified inserted system event strictly forced `merchant_id IS NULL`.
12. **`test_audit_hash_compatibility_and_signed_mandates_verifiable` (PASSED):**
    - Seeded signed mandate `MAND_DISP_1` cryptographically verified via Ed25519 public key.
    - Seeded audit event hashes matched Python `compute_event_hash` and PostgreSQL SHA-256 with 100% triple parity.

---

## 6. Consequences & Operational Readiness

### Positive Consequences
- **Complete Dual-Axis Isolation:** Merchant data is tenant-isolated; buyer data is customer-isolated. Neither can cross-contaminate.
- **Micro-Partitioned Least Privilege:** Control-plane and identity operations are restricted to `gateway_auth`; webhook deduplication and system audit are restricted to `system_audit_writer`; application runtime `app_user` has zero access to administrative tables.
- **Provable Dry-Run Safety:** Migration 001 was validated end-to-end on a disposable PostgreSQL 16 database with zero side effects on the primary database or historical records.

### Remaining Pre-Migration Constraints
- `001_postgresql_rls_hardening.sql` must NOT be executed against `agentic_commerce` on port 5433 or production without final user architectural sign-off.
- All connections to Render remain strictly severed.
