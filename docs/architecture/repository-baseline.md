# Verified Repository Baseline Report

- **Document ID**: `P1-ARCH-01-BASELINE`
- **Milestone**: P1.0 — Architecture and Repository Preparation
- **Author**: Antigravity Lead Orchestrator
- **Status**: VERIFIED & AUTHORITATIVE
- **Git Commit**: `01a6d2c` (Branch: `main`)
- **Inspection Date**: 2026-11-10

---

## 1. Executive Summary

This document establishes the empirically verified baseline of the **Agentic Commerce Gateway** repository (`d:\agentic-commerce-gateway`). It reflects physical inspection of the codebase, static analysis of all application modules, inspection of the persistent database storage, and the execution of the full automated test suite (279 passed, 1 deselected, 0 failed).

The repository currently operates as a **merchant-side gateway and reverse proxy** enabling autonomous buyer AI agents to interact with a single merchant's catalog under deterministic spending mandates and Razorpay test rails. 

To transform this gateway into a **Merchant-First Agentic Commerce Platform** powered by Paytm payment orchestration, we must transition from single-merchant/buyer-centric assumptions to a true multi-tenant merchant control plane without compromising the strict security and financial integrity guarantees (P0) established in the baseline.

---

## 2. Source Control & Environment State

| Attribute | Verified State | Epistemic Status | Notes / Reference |
|---|---|---|---|
| **Branch** | `main` | `[VERIFIED]` | Clean working tree; no uncommitted changes |
| **Commit Hash** | `01a6d2c` | `[VERIFIED]` | `test(p0-f): author postgresql dialect translation and compatibility test suite` |
| **Runtime Version** | Python 3.12.2 (Windows x86_64) | `[VERIFIED]` | Compatible with Python 3.11+ |
| **Package Management** | `requirements.txt` (pip) | `[VERIFIED]` | Commingles test & production dependencies; lacks upper bounds |
| **Test Runner** | pytest 9.1.1 (pluggy 1.6.0) | `[VERIFIED]` | Configured via `pytest.ini` (`-m "not integration" --basetemp=.pytest_temp`) |
| **Test Suite Baseline** | 279 passed, 1 deselected, 0 failed | `[VERIFIED]` | Execution time: 120.63s across 24 test files |
| **Working Tree Cleanliness**| Clean | `[VERIFIED]` | `git status` clean |

---

## 3. Physical Subsystem Inspection

### 3.1 Backend Architecture & Application Entrypoints
- **Entrypoint**: [`app/main.py`](file:///d:/agentic-commerce-gateway/app/main.py) initializes a standard FastAPI application (`title="Agentic Commerce Gateway"`, `version="1.0.0"`).
- **Lifespan Management**: `remote_mcp_lifespan` manages remote MCP session lifecycle.
- **Middleware**:
  - `CORSMiddleware`: Permissive CORS (`allow_origins=["*"]`) for web MCP clients and local test dashboards.
  - `McpNormalizeMiddleware`: Custom ASGI middleware rewriting `/mcp` to `/mcp/` and ensuring `Accept: text/event-stream` header normalization for ChatGPT/Claude HTTP clients.
- **Static Mounting**: Mounts `/static` directory to serve admin UI and checkout page.
- **Diagnostic Endpoint**: `/debug-search` guarded by `verify_admin_key` (`VULN-08` remediation).

### 3.2 Authentication & Authorization Foundation
- **Admin Authentication** ([`app/auth.py`](file:///d:/agentic-commerce-gateway/app/auth.py)):
  - Validates `X-Admin-API-Key` or `Authorization: Bearer <key>`.
  - In development, defaults to `'dev-admin-secret-key'`. In production, auto-generates an ephemeral 256-bit token if unconfigured.
  - Constant-time comparison (`secrets.compare_digest`).
- **Agent / Customer Authentication** ([`app/auth.py`](file:///d:/agentic-commerce-gateway/app/auth.py), [`app/oauth/`](file:///d:/agentic-commerce-gateway/app/oauth/)):
  - Evaluates OAuth 2.1 Bearer JWT tokens signed with `JWT_SECRET` (HS256).
  - Enforces token-purpose separation (`type == 'access_token'`); rejects confirmation tokens passed as bearer tokens (`VULN-06` remediation).
  - RFC 7636 PKCE validation on authorization code exchange.
- **Deficiency**: There is currently **zero merchant employee authentication** or merchant organization identity. Admin access is a single flat key.

### 3.3 Database Abstraction Layer ([`app/db.py`](file:///d:/agentic-commerce-gateway/app/db.py))
- **Dialect Handling**: Dual SQLite and PostgreSQL support governed by `DATABASE_URL`.
- **Query Translation**: `PostgresCursorWrapper` performs runtime string manipulation on SQL queries:
  - Translates `INTEGER PRIMARY KEY AUTOINCREMENT` -> `SERIAL PRIMARY KEY`.
  - Translates `INSERT OR IGNORE INTO` -> `INSERT INTO ... ON CONFLICT DO NOTHING`.
  - Translates `?` parameter markers -> `%s`.
- **Limitations**:
  - No ORM or migration manager (e.g., Alembic, SQLAlchemy).
  - Each domain module manages its own DDL via ad-hoc `CREATE TABLE IF NOT EXISTS` inside initialization methods (`_init_db`).
  - No connection pooling for PostgreSQL (opens and closes `psycopg2.connect` per context).

### 3.4 Catalog & Inventory Subsystem ([`app/catalog/`](file:///d:/agentic-commerce-gateway/app/catalog/))
- **Storage**: `catalog_products`, `product_relationships`, and `recommendations` tables.
- **Monetary Representation**: Integer `price_paise` column backed by float `price` for backwards compatibility.
- **Inventory Concurrency**: Atomic conditional updates (`UPDATE catalog_products SET stock = stock - ? WHERE id = ? AND stock >= ?`) preventing negative stock and overselling (`VULN-03` remediation).
- **Stock Restoration**: Saga compensation restores stock if downstream payment fails.
- **Hardcoded Multi-tenancy**: All catalog items carry `merchant_id TEXT NOT NULL DEFAULT 'MERCH_ELEC'`. Multi-store or multi-merchant catalog isolation is non-existent.

### 3.5 AI Agent Execution & MCP Interfaces ([`app/agent/`](file:///d:/agentic-commerce-gateway/app/agent/), [`app/mcp/`](file:///d:/agentic-commerce-gateway/app/mcp/), [`app/merchant_agent/`](file:///d:/agentic-commerce-gateway/app/merchant_agent/))
- **Buyer AI Agent Support**:
  - `app/agent/service.py` handles purchase proposals (`propose_purchase`), deterministic policy checks, and confirmation execution (`confirm_purchase`).
  - Gated confirmation: Orders $\ge$ ₹500 require a short-lived, signed JWT confirmation token (`CONFIRMATION_TOKEN_SECRET`) with token-purpose binding.
- **MCP Server**:
  - Dual transport: Local stdio (`MCPServer`) and Remote Streamable HTTP mounted at `/mcp`.
  - Remote MCP middleware (`McpAuthMiddleware`) extracts customer identity from OAuth JWT `sub` claim.
  - Exposed tools: `inquire_merchant`, `suggest_addons`, `respond_to_recommendation`, `search_products`, `propose_purchase`, `confirm_purchase`, `get_spending_mandate`.
- **Merchant Sales AI Agent**:
  - `app/merchant_agent/service.py` provides natural language procurement assistance and cross-sell add-on recommendations.
  - Grounds LLM responses against the catalog using Google Gemini (`gemini-2.5-flash`) or local semantic fallback (`SEMANTIC_FEATURE_MAP`).
  - Add-on lifecycle tracked in `recommendations` table with state machine (`GENERATED`, `ACCEPTED`, `REJECTED`, `PURCHASED`).

### 3.6 Spending Mandates & Cryptographic Signatures ([`app/policy/`](file:///d:/agentic-commerce-gateway/app/policy/), [`app/signing/`](file:///d:/agentic-commerce-gateway/app/signing/))
- **Mandates**:
  - Customer spending limits stored in `customer_mandates` and `signed_mandates`.
  - Enforces `max_transaction_amount_paise`, `daily_budget_paise`, allowed categories, and allowed merchants.
- **Cryptographic Grounding**:
  - Ed25519 asymmetric signatures over canonical JSON (RFC 8785) with domain separators (`AGENTIC_COMMERCE_MANDATE_V1:`, `AGENTIC_COMMERCE_APPROVAL_V1:`).
  - Non-custodial public keys registered via single-use proof-of-possession challenges (`signing_challenges`).
  - Purchase approvals (`purchase_approvals`) are bound to specific `key_id`, amount, and purchase intent, consumed exactly once.

### 3.7 Payment Processing & Rails ([`app/payment/`](file:///d:/agentic-commerce-gateway/app/payment/))
- **Current Rail**: Exclusively Razorpay Test Mode (`razorpay_client.py`).
- **Payment Flows**:
  - Auto-debit: Pre-authorized debit against simulated wallet (`customer_wallets`).
  - Escalation checkout: Razorpay Payment Link or hosted `/checkout` page with dynamic UPI QR code.
- **Webhook Security**:
  - HMAC-SHA256 signature verification (`X-Razorpay-Signature`).
  - Event deduplication table `processed_webhook_events` preventing replay attacks.
  - Server-side amount validation matching original transaction ledger.
- **Paytm Infrastructure**: Completely absent. Not a single line of Paytm integration exists.

### 3.8 Cryptographic Audit Ledger ([`app/audit/`](file:///d:/agentic-commerce-gateway/app/audit/))
- **Structure**: Append-only event ledger `audit_events` with SHA-256 hash chaining (`prev_hash` -> `event_hash`).
- **Query Projection**: `audit_records` table provides relational current-state projection for UI and reporting.
- **Idempotency**: Strict unique index `idx_audit_idempotency_key` on `audit_records`.

---

## 4. Frontend Baseline & Discrepancy Analysis

> [!WARNING]
> **Major Discrepancy Found: Frontend Architecture**
> The project description assumes an *"Existing React application, with Next.js only if justified by the actual repository."*
> Physical repository inspection confirms **there is NO React application and NO `package.json` in the entire repository.**

### Actual Frontend Inventory:
1. **Admin Web Dashboard**:
   - Location: [`static/admin/index.html`](file:///d:/agentic-commerce-gateway/static/admin/index.html), [`static/admin/app.js`](file:///d:/agentic-commerce-gateway/static/admin/app.js), [`static/admin/style.css`](file:///d:/agentic-commerce-gateway/static/admin/style.css).
   - Technology: Vanilla JavaScript (ES6+), HTML5, CSS3.
   - Mechanism: Direct DOM manipulation, native `fetch()` calls to `/admin/customers`, `/catalog/products`, `/audit/transactions`.
   - Security: Admin API key stored in browser `localStorage`.
2. **Self-Checkout Page**:
   - Location: [`static/checkout/index.html`](file:///d:/agentic-commerce-gateway/static/checkout/index.html).
   - Technology: Vanilla HTML/JS loading Razorpay Checkout JS SDK (`https://checkout.razorpay.com/v1/checkout.js`).
   - Security: Verifies cryptographically signed HMAC token (`token`) matching order query parameters.

### Architectural Impact on P1:
Because there is no legacy React build pipeline to preserve or strangle, P1 can deliberately choose between:
- Enhancing the vanilla dashboard.
- Introducing a modern, typed frontend framework (e.g., Next.js / Vite + React) in a dedicated `frontend/` directory, leaving the static gateway fallbacks intact.

---

## 5. Database Baseline & Schema Inventory

The repository interacts with SQLite (`gateway.db`) or PostgreSQL (`DATABASE_URL`). Schema inspection reveals 12 active tables across the system:

| Table Name | Defined In | Primary Key | Key Columns | Tenant Column | Notes |
|---|---|---|---|---|---|
| `catalog_products` | `catalog/service.py` | `id` (TEXT) | `name`, `category`, `price_paise`, `stock`, `status` | `merchant_id` (TEXT, default 'MERCH_ELEC') | Monolithic catalog; no store relation |
| `product_relationships` | `catalog/service.py` | `id` (AUTOINCREMENT) | `source_product_id`, `target_product_id`, `relationship_type` | None | Product affinity graph |
| `recommendations` | `catalog/service.py` | `recommendation_id` (TEXT) | `primary_product_id`, `addon_product_id`, `status` | None | Add-on recommendation lifecycle |
| `customer_mandates` | `policy/store.py` | `customer_id` (TEXT) | `display_name`, `max_transaction_amount`, `daily_limit` | None | Legacy customer spending limits |
| `signed_mandates` | `signing/store.py` | `(mandate_id, mandate_version)` | `customer_id`, `key_id`, `payload_hash`, `signature` | `merchant_id` (TEXT) | Ed25519 cryptographically signed mandate |
| `customer_signing_keys` | `signing/store.py` | `key_id` (TEXT) | `customer_id`, `public_key`, `status` | None | Option A Non-custodial public keys |
| `signing_challenges` | `signing/store.py` | `challenge_id` (TEXT) | `customer_id`, `challenge_token`, `consumed` | None | Single-use PoP tokens |
| `purchase_approvals` | `signing/store.py` | `approval_id` (TEXT) | `purchase_id`, `customer_id`, `key_id`, `signature` | None | Consumed step-up approvals |
| `audit_events` | `audit/store.py` | `id` (AUTOINCREMENT) | `event_id`, `transaction_id`, `prev_hash`, `event_hash` | None | Append-only SHA-256 hash-chained ledger |
| `audit_records` | `audit/store.py` | `transaction_id` (TEXT) | `customer_id`, `product_id`, `amount_paise`, `idempotency_key` | `merchant_id` (TEXT) | Relational projection of transactions |
| `customer_wallets` | `wallet/store.py` | `customer_id` (TEXT) | `balance_paise`, `currency` | None | Pre-authorized auto-debit balances |
| `customer_credentials` | `oauth/store.py` | `customer_id` (TEXT) | `username`, `email`, `password_hash`, `salt` | None | Customer OAuth identity |
| `refresh_tokens` | `oauth/store.py` | `token_hash` (TEXT) | `customer_id`, `client_id`, `expires_at`, `revoked` | None | Rotated OAuth refresh tokens |
| `processed_webhook_events`| `payment/router.py` | `event_id` (TEXT) | `received_at` | None | Webhook deduplication store |

---

## 6. Infrastructure & Deployment Assumptions

1. **Containerization**: No `Dockerfile` or `docker-compose.yml` is present in the repository. Local execution relies on direct host Python environment (`python -m uvicorn app.main:app`).
2. **Background Jobs & Scheduling**: No asynchronous task runner (Celery, RQ, ARQ, or Redis) exists. All tasks execute synchronously within the ASGI request-response loop.
3. **Caching & In-Memory Stores**: No Redis or external cache. In-memory sets and dicts exist for webhook deduplication (`_processed_webhook_event_ids`) and OAuth codes (`_codes`), backed by database fallback.
4. **Secrets Management**: Read directly from process environment or `.env` via `python-dotenv`. Default fallback strings exist in development mode (`dev-admin-secret-key`, `dev-secret-key-change-in-production`).
5. **Hosting Assumptions**: Built for Render (`https://razorpay-c454.onrender.com`) with Supabase/Render PostgreSQL.

---

## 7. Component Status Classification

In accordance with Phase A specifications, every core component is classified into one of the six standard states:

| Component / Subsystem | Status Classification | Evidence & Justification |
|---|---|---|
| **FastAPI REST Entrypoint** | **Implemented** | Functional routing, CORS, exception handling, OpenAPI docs |
| **Admin API Key Auth** | **Implemented** | Constant-time comparison, auto-generation in production |
| **Customer OAuth 2.1 Server** | **Implemented** | PKCE RFC 7636, refresh token rotation, JWT verification |
| **Catalog Query & CRUD** | **Implemented** | Full filtering, search, pagination, admin CRUD |
| **Atomic Inventory Reservation** | **Implemented** | Row-level conditional update preventing overselling |
| **Cryptographic Mandate Signing** | **Implemented** | Ed25519 Option A, RFC 8785 canonical JSON, version supersession |
| **Audit Ledger & Hash Chaining** | **Implemented** | SHA-256 tamper-evident chain with relational projection |
| **Razorpay Test Rail Integration** | **Implemented** | Orders, Links, Webhooks, HMAC verification |
| **Buyer MCP Tools Interface** | **Implemented** | stdio & remote Streamable HTTP MCP tools |
| **Merchant Sales AI Reasoning** | **Partially implemented**| Basic Gemini grounding & semantic fallback; limited cross-sell |
| **PostgreSQL Dialect Support** | **Partially implemented**| Custom string-wrapper translation; lacks connection pooling & migrations |
| **Frontend Admin Dashboard** | **Partially implemented**| Functional vanilla JS dashboard; lacks multi-tenant auth & workforce UI |
| **Self-Checkout Page** | **Partially implemented**| Works with Razorpay; lacks Paytm checkout rails |
| **Simulated Customer Wallet** | **Mocked / simulated** | Local in-database balance ledger, not a real payment instrument |
| **Multi-Store Management** | **Intended but missing** | No store entities, store connection tokens, or sync pipelines |
| **Merchant Organization Identity**| **Intended but missing** | No merchant table, no employee roles, no organization onboarding |
| **Paytm Payment Orchestration** | **Intended but missing** | No Paytm client, routing policy, or provider abstraction |
| **Merchant AI Workforce Foundation**| **Intended but missing** | No agent registry, agent provisioning, or role-based agent permissions |
| **WooCommerce / Shopify Adapter**| **Intended but missing** | No external commerce connectors or webhook receivers |
| **Durable Outbox / Task Queue** | **Intended but missing** | No background worker or outbox pattern |
| **Frontend React Framework** | **Broken or inconsistent**| Repository assumed React; actually contains vanilla JS/HTML |
| **Database Migration Tooling** | **Broken or inconsistent**| Fragmented `_init_db()` calls across modules without Alembic versioning |

---

## 8. Baseline Test Suite Verification

- **Command Executed**: `pytest`
- **Output Summary**:
  ```text
  collected 280 items / 1 deselected / 279 selected
  tests\test_admin.py .............                                        [  4%]
  tests\test_agent_router.py .................                             [ 10%]
  tests\test_audit.py ..........                                           [ 14%]
  tests\test_catalog.py ..........                                         [ 17%]
  tests\test_checkout_security.py ...........                              [ 21%]
  tests\test_customer_mandate.py ..................                        [ 28%]
  tests\test_dashboard.py ...                                              [ 29%]
  tests\test_gemini_grounding.py ...                                       [ 30%]
  tests\test_google_oauth_and_signup.py .....                              [ 32%]
  tests\test_mcp.py ..........................                             [ 41%]
  tests\test_mcp_remote.py ..........                                      [ 45%]
  tests\test_merchant_agent.py ..........                                  [ 48%]
  tests\test_oauth.py ....................                                 [ 55%]
  tests\test_p0_1_security.py ...........                                  [ 59%]
  tests\test_p0_2_crypto_mandates.py ...............                       [ 65%]
  tests\test_p0_3_policy_engine.py ...........                             [ 69%]
  tests\test_p0_4_concurrency.py ........                                  [ 72%]
  tests\test_payments.py ..........................                        [ 81%]
  tests\test_policy_engine.py .........................                    [ 90%]
  tests\test_postgres_compatibility.py ................                    [ 96%]
  tests\test_recommendation_lifecycle.py ...........                       [100%]

  ========== 279 passed, 1 deselected, 2 warnings in 120.63s ==========
  ```
- **Integrity Statement**: All 279 selected unit and security tests pass cleanly on the current commit (`01a6d2c`). Zero existing tests were modified or skipped.

