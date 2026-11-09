# Gateway Repository Baseline & Environment Analysis

- **Document ID**: `PHASE-0-DOC-01`
- **Revision**: `1.1.0` (Corrected Test Execution History & Environment Baseline)
- **Status**: `APPROVED / ARCHITECTURAL BASELINE`
- **Author**: Principal Software Architect & Senior Security Architect
- **Timestamp**: `2026-11-09T18:05:00Z`
- **Target Repository**: `d:\agentic-commerce-gateway`

---

## 1. Executive Summary

This document establishes the definitive Phase 0 technical baseline for the **Agentic Commerce Gateway** repository. It captures source control state, runtime dependencies, test suite execution history, configuration hygiene, verified capabilities, and technical constraints.

The Agentic Commerce Gateway is a merchant-side reverse proxy and control plane designed to enable Autonomous Buyer AI Agents (e.g., Claude Desktop, ChatGPT Custom GPTs, programmatic agents) to transact safely with an e-commerce catalog under strict, deterministic human spending mandates and Razorpay payment rails.

All observations in this document are categorized using strict epistemic tags:
- **`[VERIFIED]`**: Directly confirmed via code inspection, git metadata, or test outputs.
- **`[INFERRED]`**: Logically deduced from code structures, conventions, and documentation.
- **`[ASSUMPTION]`**: Hypothesized based on industry standard practices, awaiting runtime profiling.
- **`[RECOMMENDATION]`**: Architectural proposal to address gaps, technical debt, or operational risks.

---

## 2. Source Control & Git Baseline

| Metric | Inspected Value | Evidence / Source | Classification |
|---|---|---|---|
| **Branch** | `main` | `.git/HEAD` -> `ref: refs/heads/main` | `[VERIFIED]` |
| **Commit Hash** | `a1cf61215bae7249b5ae3495a6286fbc2d3fa1fb` | `.git/refs/heads/main` | `[VERIFIED]` |
| **Remote Origin** | `https://github.com/dinesh121005/agentic-commerce-gateway.git` | `.git/config` | `[VERIFIED]` |
| **Working Tree Status** | Clean (no uncommitted source files in baseline) | Git reflog / clean clone state | `[VERIFIED]` |
| **Clone Author & Date** | `SuryaSK-dev <suryasenthilkumar.dev@gmail.com>` | `.git/logs/HEAD` (timestamp `1794223612`) | `[VERIFIED]` |
| **Monorepo / Subtree** | Standalone single-service repository | Root file layout inspection | `[VERIFIED]` |

---

## 3. Technology Stack & Dependency Inventory

### 3.1 Core Runtime Environment
- **Python Version**: Python 3.12.2 (compatible with Python 3.11+) `[VERIFIED]`
- **Framework**: FastAPI (async ASGI framework based on Starlette and Pydantic) `[VERIFIED]`
- **Server Engine**: Uvicorn (ASGI web server) `[VERIFIED]`

### 3.2 Production Dependencies ([`requirements.txt`](file:///d:/agentic-commerce-gateway/requirements.txt))

| Package | Pinned Constraint | Purpose in Gateway Architecture | Verification State |
|---|---|---|---|
| `fastapi` | `>=0.110.0` | Primary REST API routing, OpenAPI docs generation, DI dependency injection | `[VERIFIED]` |
| `uvicorn` | `>=0.28.0` | ASGI application server runtime | `[VERIFIED]` |
| `pydantic` | `>=2.6.0` | Strict data validation, schema enforcement, JSON serialization | `[VERIFIED]` |
| `pytest` | `>=8.0.0` | Test runner and test fixture harness | `[VERIFIED]` |
| `httpx` | `>=0.27.0` | Async HTTP client for outbound Google SSO & LLM inference calls | `[VERIFIED]` |
| `razorpay` | `>=1.3.0` | Official Razorpay Python SDK for Orders, Links, and Signature verification | `[VERIFIED]` |
| `python-dotenv` | `>=1.0.0` | Environment variable management from `.env` file | `[VERIFIED]` |
| `mcp` | `>=1.2.0` | Official Model Context Protocol SDK for stdio & Streamable HTTP transports | `[VERIFIED]` |
| `pyjwt` | `>=2.8.0` | HS256 JWT encoding/decoding for confirmation tokens & OAuth 2.1 access tokens | `[VERIFIED]` |
| `psycopg2-binary` | `>=2.9.9` | PostgreSQL database adapter for production hosted storage (e.g., Render) | `[VERIFIED]` |
| `python-multipart` | `>=0.0.9` | Form data parsing for OAuth `/oauth/authorize` and `/oauth/token` forms | `[VERIFIED]` |
| `cryptography` | `>=42.0.0` | Underlying cryptographic primitives, secure token generation, PKCE hashing | `[VERIFIED]` |

### 3.3 Dependency Analysis Findings
1. **No Separate Development Requirements File**: The project lacks a `requirements-dev.txt` or `pyproject.toml`. Test dependencies (`pytest`) are commingled with production dependencies in [`requirements.txt`](file:///d:/agentic-commerce-gateway/requirements.txt). `[VERIFIED]`
2. **Missing Code Coverage Tooling**: `pytest-cov` is not declared in [`requirements.txt`](file:///d:/agentic-commerce-gateway/requirements.txt) or configured in [`pytest.ini`](file:///d:/agentic-commerce-gateway/pytest.ini). Test coverage reporting is therefore unavailable without ad-hoc pip installation. `[VERIFIED]`
3. **Dual Database Driver Strategy**: The repository supports both SQLite (built-in `sqlite3`) and PostgreSQL (`psycopg2-binary`). The abstraction is handled via custom wrappers in [`app/db.py`](file:///d:/agentic-commerce-gateway/app/db.py). `[VERIFIED]`
4. **Permissive Lower Bounds**: All dependencies specify `>=` constraints without upper bounds (`<`). This presents risks of breaking changes during unattended CI/CD builds or container rebuilds. `[RECOMMENDATION]`

---

## 4. Test Execution & Coverage Baseline

### 4.1 Pytest Harness Configuration ([`pytest.ini`](file:///d:/agentic-commerce-gateway/pytest.ini))
```ini
[pytest]
testpaths = tests
markers =
    integration: marks tests as hitting real external APIs (deselect with '-m "not integration"')
addopts = -m "not integration" --basetemp=.pytest_temp
```
- **Test Discovery Directory**: `tests/`
- **Default Exclusion**: Integration tests hitting live Razorpay APIs are excluded by default via `-m "not integration"`. `[VERIFIED]`
- **Temporary Database Directory**: `--basetemp=.pytest_temp` isolates SQLite temporary test databases. `[VERIFIED]`

### 4.2 Two-Stage Test Execution History

To preserve absolute factual rigor, the test execution history is documented across its two distinct phases:

#### Stage A: Initial Execution Failure (Clean Clone Environment) `[VERIFIED]`
- **Command Executed**: `pytest -v`
- **Execution State**: Failed at collection / fixture loading stage.
- **Root Cause**: `ImportError while loading conftest 'D:\agentic-commerce-gateway\tests\conftest.py'`.
- **Traceback**:
  ```
  tests\conftest.py:17: in <module>
      from app.oauth.store import customer_auth_store
  app\oauth\__init__.py:4: in <module>
      from app.oauth.router import router as oauth_router
  app\oauth\router.py:14: in <module>
      from app.oauth.crypto import create_access_token
  app\oauth\crypto.py:10: in <module>
      import jwt
  E   ModuleNotFoundError: No module named 'jwt'
  ```
- **Explanation**: In the initial host Python environment (`C:\Program Files\Python312\python.exe`), several declared dependencies from `requirements.txt` (`pyjwt`, `razorpay`, `mcp`, `python-multipart`) had not yet been installed into user site-packages. Conftest loading imports `jwt` transitively through `app.oauth`, causing pytest to terminate with exit code 1 before collecting or executing any tests.

#### Stage B: Remediation & Subsequent Execution (Dependency-Installed Environment) `[VERIFIED]`
- **Remediation Action**: Executed `pip install -r requirements.txt`, satisfying the project's declared dependencies (`PyJWT-2.15.1`, `razorpay-2.0.1`, `mcp-2.3.0`, `python-multipart-0.0.33`, and related sub-dependencies).
- **Subsequent Test Command**: `pytest` (defaulting to flags from `pytest.ini`: `-m "not integration" --basetemp=.pytest_temp`).
- **Platform**: `win32 -- Python 3.12.2, pytest-9.1.1, pluggy-1.6.0`
- **Total Test Cases Collected**: `206 items`
- **Tests Selected**: `205 items`
- **Tests Passed**: **`205 passed`** (100% of selected tests)
- **Tests Deselected**: **`1 deselected`** (`tests/test_live_razorpay_checkout.py::test_live_razorpay_checkout_lifecycle`)
- **Tests Failed**: **`0 failed`**
- **Warnings**: `1` (`StarletteDeprecationWarning: 'HTTP_422_UNPROCESSABLE_ENTITY' is deprecated. Use 'HTTP_422_UNPROCESSABLE_CONTENT' instead.`)
- **Execution Duration**: `131.54s`

> [!WARNING]
> **Integration Behavior Boundary Disclaimer**  
> The 1 deselected test (`tests/test_live_razorpay_checkout.py::test_live_razorpay_checkout_lifecycle`) exercises live order creation, HMAC signature verification, and ledger transition against Razorpay's live Test Mode API. Because it was deselected by the default `-m "not integration"` marker, **it did not execute and cannot be claimed as passed**. Live third-party payment integration behavior remains unvalidated in the automated test suite run.

### 4.3 Test Suite Inventory & Coverage Breadth

| Test Suite File | Test Count | Scope & Coverage Area | Status in Baseline Run |
|---|---:|---|---|
| [`tests/test_policy_engine.py`](file:///d:/agentic-commerce-gateway/tests/test_policy_engine.py) | 25 | Deterministic 6-rule policy evaluation, boundary values, category/merchant allowlists, daily limits | **Passed** |
| [`tests/test_payments.py`](file:///d:/agentic-commerce-gateway/tests/test_payments.py) | 23 | Razorpay order creation, payment links, webhook verification, dedup ledger, stock compensation | **Passed** |
| [`tests/test_mcp.py`](file:///d:/agentic-commerce-gateway/tests/test_mcp.py) | 26 | Stdio transport MCP tools, confirmation tokens, order status, data minimization projection | **Passed** |
| [`tests/test_agent_router.py`](file:///d:/agentic-commerce-gateway/tests/test_agent_router.py) | 17 | POST `/agent/purchase`, POST `/agent/confirm`, ₹500 threshold gating, replay protection | **Passed** |
| [`tests/test_oauth.py`](file:///d:/agentic-commerce-gateway/tests/test_oauth.py) | 20 | OAuth 2.1 RFC compliance, PKCE verification, token rotation, PBKDF2 credential hashing | **Passed** |
| [`tests/test_admin.py`](file:///d:/agentic-commerce-gateway/tests/test_admin.py) | 13 | Mandate provisioning, spending limit updates, admin API key enforcement | **Passed** |
| [`tests/test_checkout_security.py`](file:///d:/agentic-commerce-gateway/tests/test_checkout_security.py) | 11 | Hosted checkout tampering, amount tampering rejection, signature verification, token validation | **Passed** |
| [`tests/test_recommendation_lifecycle.py`](file:///d:/agentic-commerce-gateway/tests/test_recommendation_lifecycle.py) | 11 | Recommendation generation, acceptance, rejection, expiration, and idempotency | **Passed** |
| [`tests/test_catalog.py`](file:///d:/agentic-commerce-gateway/tests/test_catalog.py) | 10 | Multi-word fuzzy search, category filtering, stock decrement & restoration, admin CRUD | **Passed** |
| [`tests/test_mcp_remote.py`](file:///d:/agentic-commerce-gateway/tests/test_mcp_remote.py) | 10 | Streamable HTTP MCP transport mounted at `/mcp`, OAuth Bearer token middleware, session lifecycle | **Passed** |
| [`tests/test_merchant_agent.py`](file:///d:/agentic-commerce-gateway/tests/test_merchant_agent.py) | 10 | Semantic feature inquiry mapping, quote grounding, add-on suggestion headroom checks | **Passed** |
| [`tests/test_audit.py`](file:///d:/agentic-commerce-gateway/tests/test_audit.py) | 10 | Two-phase ledger persistence, cryptographic SHA-256 hash chaining, corruption detection | **Passed** |
| [`tests/test_customer_mandate.py`](file:///d:/agentic-commerce-gateway/tests/test_customer_mandate.py) | 8 | Conversational spending mandate queries, two-step signed modification challenge tokens | **Passed** |
| [`tests/test_google_oauth_and_signup.py`](file:///d:/agentic-commerce-gateway/tests/test_google_oauth_and_signup.py) | 5 | Google SSO authorization redirects, callback handling, automated customer provisioning | **Passed** |
| [`tests/test_dashboard.py`](file:///d:/agentic-commerce-gateway/tests/test_dashboard.py) | 3 | Admin dashboard HTML serving, static asset mounting, cache headers | **Passed** |
| [`tests/test_gemini_grounding.py`](file:///d:/agentic-commerce-gateway/tests/test_gemini_grounding.py) | 3 | Anti-hallucination overrides, dropping fictional product IDs, price/stock database grounding | **Passed** |
| [`tests/test_live_razorpay_checkout.py`](file:///d:/agentic-commerce-gateway/tests/test_live_razorpay_checkout.py) | 1 | End-to-end checkout with live Razorpay Test API (hits external network) | **Deselected** |

---

## 5. Configuration & Environment Setup

### 5.1 Environment File Delta
- **`.env.example`**: Present in root directory. `[VERIFIED]`
- **`.env`**: **Absent by default** in clean clones. `[VERIFIED]`
- **Configuration Loading**: [`app/main.py`](file:///d:/agentic-commerce-gateway/app/main.py#L7) executes `load_dotenv(override=False)`, ensuring real process environment variables override `.env` values. `[VERIFIED]`

### 5.2 Environment Variable Matrix

| Variable | Purpose | Default / Fallback Behavior | Security Criticality |
|---|---|---|---|
| `ADMIN_API_KEY` | Authenticates administrative & audit REST endpoints | Dev: `"dev-admin-secret-key"`. Prod: Auto-generates ephemeral 256-bit token with warning log. | **HIGH**: Protects admin control plane |
| `JWT_SECRET` | Signs confirmation tokens & OAuth 2.1 access tokens | `"dev-oauth-jwt-secret-key-change-in-prod-32chars"` / `"dev-secret-key-change-in-production"` | **HIGH**: Protects token authenticity |
| `DATABASE_URL` | Connection string for SQLite or PostgreSQL | `"gateway.db"` (local SQLite file) | **HIGH**: Governs data storage target |
| `RAZORPAY_KEY_ID` | Razorpay API Key ID | None / `"rzp_test_51tPkUG58N7Lkg"` in fallback checkout | **MEDIUM**: Required for live order creation |
| `RAZORPAY_KEY_SECRET` | Razorpay API Key Secret | None / `"dev-razorpay-secret"` | **HIGH**: Computes & verifies payment HMACs |
| `RAZORPAY_WEBHOOK_SECRET` | Verifies inbound Razorpay webhook callbacks | `"dev-webhook-secret"` | **HIGH**: Prevents webhook spoofing |
| `GEMINI_API_KEY` | Enables Generative AI for Merchant Sales AI | None (falls back to local semantic keyword matcher) | **LOW**: LLM reasoning enrichment only |
| `OPENAI_API_KEY` | Secondary Generative AI provider | None (falls back to Gemini or local semantic matcher) | **LOW**: LLM reasoning enrichment only |
| `GOOGLE_CLIENT_ID` | Google OAuth SSO Client ID | `""` (disables Google SSO login) | **MEDIUM**: Customer OAuth SSO |
| `GOOGLE_CLIENT_SECRET` | Google OAuth SSO Client Secret | `""` | **HIGH**: Customer OAuth SSO |
| `GOOGLE_REDIRECT_URI` | Google OAuth SSO Callback URL | `"https://razorpay-c454.onrender.com/oauth/google/callback"` | **MEDIUM**: OAuth redirect integrity |
| `BASE_URL` | Root URL for generating payment URLs | `"https://razorpay-c454.onrender.com"` | **MEDIUM**: Hosted checkout generation |
| `PORT` | Web server listening port | `8000` | **LOW**: Network configuration |
| `HOST` | Web server listening bind address | `0.0.0.0` | **LOW**: Network configuration |

---

## 6. Existing Working Features Baseline

1. **Three-Tier Purchase Execution Engine**:
   - **Tier 1 (Autonomous Micro-Purchases)**: Transactions `< ₹500` approved by policy execute immediately via auto-debit against a simulated pre-authorized mandate balance (`AUTO-PAID`). `[VERIFIED]`
   - **Tier 2 (Token-Gated Human Confirmation)**: Transactions `₹500 ≤ amount ≤ mandate limit` require explicit human authorization via a cryptographically signed, 5-minute JWT confirmation token (`PENDING_CONFIRMATION` -> `APPROVED`). `[VERIFIED]`
   - **Tier 3 (Hosted-Checkout Escalation)**: Transactions exceeding the autonomous mandate limit (e.g. `> ₹2,000`) gracefully escalate to an official Razorpay hosted checkout URL and dynamic UPI QR code (`REJECTED` / `PENDING-PAYMENT`). `[VERIFIED]`
2. **Deterministic Mandate Policy Engine**:
   - Sequential, fail-fast evaluation of 6 strict rules: Customer Match, Expiry, Merchant Allowlist, Category Allowlist, Transaction Cap, Cumulative Daily Cap. Zero LLM involvement in authorization verdicts. `[VERIFIED]`
3. **Cryptographically Hash-Chained Audit Ledger**:
   - Append-only event store (`audit_events`) with SHA-256 hash chaining linked back to `GENESIS`. Relational projection view (`audit_records`) for sub-millisecond querying. Public `/audit/verify` integrity checker and `/audit/anchor` state exporter. `[VERIFIED]`
4. **Dual-Transport Model Context Protocol (MCP)**:
   - **Stdio Transport**: Local single-user runner for Claude Desktop (`python -m app.mcp.server`).
   - **Remote Streamable HTTP Transport**: Mounted at `/mcp` on FastAPI, secured by OAuth 2.1 Bearer authentication with client identity bound to the JWT `sub` claim. `[VERIFIED]`
5. **Self-Contained OAuth 2.1 Authorization Server**:
   - PKCE (RFC 7636) code verification, dynamic client registration (RFC 7591), token rotation for refresh tokens, and discovery metadata endpoints (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`). `[VERIFIED]`
6. **Merchant Sales AI & Grounding Guardrails**:
   - Gemini 2.5 Flash / OpenAI reasoning engine with mandatory database grounding: drops hallucinated product IDs and overrides hallucinated prices/stock counts with authoritative catalog truth. `[VERIFIED]`
7. **Razorpay Rails & Webhook Processing**:
   - Test mode order creation, hosted payment link generation, client-side signature verification (`verify_payment_signature`), and HMAC-SHA256 server-to-server webhook handling with persistent database deduplication and automated inventory compensation. `[VERIFIED]`
8. **Admin Command Centre Dashboard**:
   - Interactive web console (`/admin/dashboard`) with live telemetry, KPI cards, visual mandate manager, catalog inventory browser, and audit log explorer. `[VERIFIED]`

---

## 7. Known Limitations & Technical Constraints

1. **Simulated Settlement on Tier 1 (Sandbox Wallet)**: Autonomous purchases (< ₹500) and gated confirmed purchases do not move live funds; they debit an internal `customer_wallets` SQLite/Postgres ledger. Live UPI AutoPay / e-Mandate rails are not yet integrated. `[VERIFIED]`
2. **Currency Precision (Float vs Integer Paise)**: While Razorpay APIs correctly receive integer paise (`_rupees_to_paise`), the catalog prices, mandate limits, purchase calculations, and wallet stores use Python `float` and SQL `REAL`. This introduces subtle IEEE 754 precision risks if fractional amounts are processed. `[VERIFIED]`
3. **Concurrency Race Condition in Wallet Debit**: `wallet_store.debit()` executes a select balance check followed by a separate `UPDATE` statement without row-level locking (`SELECT ... FOR UPDATE`) or atomic SQL decrement (`UPDATE customer_wallets SET balance = balance - ? WHERE balance >= ?`). Highly concurrent micro-transactions for the same customer could permit balance overdraws. `[VERIFIED]`
4. **PostgresCursorWrapper Parameter Translation Edge Cases**: [`app/db.py`](file:///d:/agentic-commerce-gateway/app/db.py#L58) replaces `?` with `%s` via a naive string `.replace("?", "%s")`. Queries containing literal question marks in strings (e.g. search queries or URLs) would suffer syntax errors on PostgreSQL. `[VERIFIED]`
5. **Single-Merchant Gateway Operational Assumptions**: While catalog items have distinct `merchant_id` tags (e.g., `MERCH_ELEC`, `MERCH_FOOD`), the gateway runs as a single control plane with one Razorpay merchant credential set. True multi-merchant payout routing (Razorpay Route) is not yet implemented. `[INFERRED]`
6. **Ledger Immutability Boundary**: The audit ledger is tamper-evident via internal SHA-256 hash chaining, but not externally immutable. An attacker with root database write access could recalculate hashes from a modified record to the tip. External anchoring (`/audit/anchor`) must be persisted to independent storage to achieve non-repudiation. `[VERIFIED]`

---

## 8. Epistemic Classification Registry

| ID | Finding / Assertion | Classification | Architectural Impact |
|---|---|---|---|
| **F-01** | Git repository is at commit `a1cf61215bae7249b5ae3495a6286fbc2d3fa1fb` on branch `main`. | `[VERIFIED]` | Absolute reference point for Phase 0 baseline. |
| **F-02** | Initial test execution failed due to uninstalled dependencies (`ModuleNotFoundError: No module named 'jwt'`). | `[VERIFIED]` | Baseline requires explicit `requirements.txt` environment installation. |
| **F-03** | Subsequent test execution passed 205 tests with 1 deselected by marker; zero failures. | `[VERIFIED]` | Verified test stability baseline for unit/mock test suite. |
| **F-04** | Live Razorpay integration test was deselected and not validated in test execution. | `[VERIFIED]` | Live third-party payment integration remains unvalidated. |
| **F-05** | `pytest-cov` is omitted from `requirements.txt`. | `[VERIFIED]` | Quantitative line coverage is currently unmeasured in CI. |
| **F-06** | The gateway runs without an active `.env` file using hardcoded dev defaults. | `[VERIFIED]` | High risk if deployed to production without explicit environment variables. |
| **F-07** | Remote MCP requests bind customer identity to verified OAuth JWT `sub` claim. | `[VERIFIED]` | Eliminates agent identity spoofing over remote transport. |
| **F-08** | Local stdio MCP transport accepts client-supplied `customer_id` parameter. | `[VERIFIED]` | Acceptable for local single-user Claude Desktop, invalid for multi-tenant. |
| **F-09** | Monetary values are stored as Python `float` and SQL `REAL`. | `[VERIFIED]` | Minor precision risk for INR paise; requires standardization to integer paise. |
| **F-10** | `PostgresCursorWrapper` uses naive string replacement for SQL placeholders. | `[VERIFIED]` | Vulnerable to syntax corruption on PostgreSQL if parameters contain `?`. |
| **F-11** | Production hosted deployment on Render uses Supabase/Render PostgreSQL. | `[INFERRED]` | Inferred from `DATABASE_URL` check and `debug-search` diagnostic code. |
| **F-12** | Total vulnerability findings: 8; Critical vulnerability findings: 3. | `[VERIFIED]` | Reconciled vulnerability baseline across all Phase 0 documentation. |
| **F-13** | Atomic SQL update should replace read-modify-write pattern in `wallet_store`. | `[RECOMMENDATION]` | Eliminates race condition in concurrent auto-debit settlements. |

---
*End of Document `01_REPOSITORY_BASELINE.md`*
