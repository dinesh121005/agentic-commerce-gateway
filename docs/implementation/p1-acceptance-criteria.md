# P1 Milestones Acceptance Criteria & Quality Gates

- **Document ID**: `P1-IMPL-04-ACCEPTANCE-CRITERIA`
- **Milestone**: P1.0 — Architecture and Repository Preparation
- **Author**: Antigravity Lead Orchestrator & QA Lead
- **Status**: PROPOSED QUALITY GATES SPECIFICATION

---

## 1. Overview & Verification Standards

A milestone in the P1 program is considered **COMPLETE** if and only if all listed acceptance criteria and quality gates are physically verified through automated test suites, static analysis, and code review. "Honor system" approvals or unverified assumptions are strictly prohibited.

---

## 2. Milestone-by-Milestone Acceptance Criteria

### Milestone P1.0: Architecture Specification & Baseline
- [x] **AC-1.0.1**: Repository baseline physically inspected and documented (`repository-baseline.md`).
- [x] **AC-1.0.2**: Database schema inspected in active storage; all 12 existing tables mapped.
- [x] **AC-1.0.3**: Discrepancy regarding frontend architecture (vanilla JS vs. assumed React) explicitly documented.
- [x] **AC-1.0.4**: Six-layer target architecture specified with module ownership and Mermaid diagrams (`target-architecture.md`).
- [x] **AC-1.0.5**: Domain boundaries and module migration map specified (`domain-boundaries.md`, `module-migration-map.md`).
- [x] **AC-1.0.6**: Multi-tenant database design and ERD authored with compound keys and RLS policies (`database-design.md`, `database-erd.md`).
- [x] **AC-1.0.7**: Provider-neutral payment orchestration architecture specified with Paytm capabilities analyzed (`payment-architecture.md`).
- [x] **AC-1.0.8**: Initial REST API contracts defined with request/response JSON schemas (`api-contracts.md`).
- [x] **AC-1.0.9**: All 9 required Architecture Decision Records authored (`ADR-001` through `ADR-009`).
- [x] **AC-1.0.10**: End-to-end migration and rollback plans documented (`migration-plan.md`, `rollback-plan.md`).
- [x] **AC-1.0.11**: Security threat model authored with STRIDE risk matrix and P0 preservation proof (`security-threat-model.md`).
- [x] **AC-1.0.12**: Full test suite executed with verified baseline: 279 passed, 1 deselected, 0 failed.
- [x] **AC-1.0.13**: Zero unreviewed application source code modifications; working tree clean.

---

### Milestone P1.1: Multi-Tenant Merchant Identity & Tenant Isolation (PRIMARY GATE)
- [x] **AC-1.1.1**: New tables `merchants`, `merchant_users`, `merchant_memberships`, `merchant_invitations` created in PostgreSQL and SQLite test harness (`app/merchant/store.py`).
- [x] **AC-1.1.2**: Default tenant `MERCH_ELEC` seeded automatically to preserve Ed25519 signature validity on existing signed mandates (`test_merch_elec_preserved_and_seeded`).
- [x] **AC-1.1.3**: Merchant registration endpoint (`POST /api/v1/auth/register`) creates merchant organization and owner member in an atomic transaction (`test_merchant_registration_and_switching_flow`).
- [x] **AC-1.1.4**: Merchant employee login (`POST /api/v1/auth/login`) issues employee JWT with `type: "merchant_employee"`, bound to `MERCHANT_JWT_SECRET` (strictly isolated from Buyer `JWT_SECRET`).
- [x] **AC-1.1.5**: **Auth Domain Separation**: Verified automated test proves that Merchant Employee JWT is rejected at Buyer MCP endpoints (`401 Unauthorized`), and Buyer OAuth token is rejected at Merchant Admin endpoints (`401/403`) (`test_merchant_employee_token_rejected_at_buyer_mcp_endpoint`, `test_buyer_oauth_token_rejected_at_merchant_api`).
- [x] **AC-1.1.6**: `TenantContext` extracts and binds verified `merchant_id` to async request context (`contextvars`); client-supplied `merchant_id` in bodies/headers is strictly ignored for authorization (`test_payload_spoofing_does_not_override_server_tenant_context`).
- [x] **AC-1.1.7**: **Connection Pool Gate**: Zero session variable bleed across pooled connections confirmed under 50 concurrent interleaved requests (`test_connection_pool_tenant_concurrency_isolation`).
- [x] **AC-1.1.8**: **Primary Gate — Adversarial Tenant Isolation Suite (PASSED)**:
  - Test 1: Cross-tenant reads (Merchant A querying Merchant B data) return `403 Forbidden` (`test_cross_tenant_read_members_denied`).
  - Test 2: Cross-tenant writes (Merchant A mutating Merchant B records) return `403 Forbidden` (`test_cross_tenant_create_invitation_denied`, `test_cross_tenant_modify_member_denied`).
  - Test 3: Client payload tenant spoofing fails closed (`test_payload_spoofing_does_not_override_server_tenant_context`).
  - Test 4: Role escalation prevention verified: Staff cannot invite, Admin cannot create Owner, cannot remove last Owner (`test_staff_cannot_invite_members`, `test_admin_cannot_grant_or_invite_owner`, `test_cannot_demote_or_disable_final_active_owner`).
  - Test 5: Immediate session revocation on logout and account deactivation verified (`test_immediate_session_revocation_on_logout`, `test_immediate_token_rejection_on_account_deactivation`).
- [x] **AC-1.1.9**: Employee invitation and acceptance flow verified with single-use cryptographic token expiration and reuse prevention (`test_invitation_lifecycle_flow`).
- [x] **AC-1.1.10**: All 279 legacy gateway tests continue to pass without regression (Total suite: 296 passed, 1 skipped, 1 deselected).

---

### Milestone P1.2: Merchant Onboarding & Configuration
- [ ] **AC-1.2.1**: Tables `stores`, `store_connections`, `merchant_settings`, `integration_credentials` created.
- [ ] **AC-1.2.2**: Additive columns `merchant_id` and `store_id` added to `catalog_products`, `audit_records`, and `audit_events`.
- [ ] **AC-1.2.3**: Legacy records successfully backfilled with `MERCH_DEFAULT` and `STORE_DEFAULT`.
- [ ] **AC-1.2.4**: Referential integrity audit confirms 0 rows with `merchant_id IS NULL`.
- [ ] **AC-1.2.5**: Integration credentials stored encrypted using AES-256-GCM; verified by direct database query showing ciphertext.
- [ ] **AC-1.2.6**: Merchant settings update endpoint persists custom `max_auto_approval_limit_paise`.

---

### Milestone P1.3: Store Integration Framework (WooCommerce First)
- [ ] **AC-1.3.1**: `IStoreConnector` interface implemented for WooCommerce REST v3.
- [ ] **AC-1.3.2**: On-demand catalog sync imports external products into `catalog_products` with prices converted to integer paise.
- [ ] **AC-1.3.3**: Real-time webhook receiver validates `X-WC-Webhook-Signature` before processing.
- [ ] **AC-1.3.4**: Outbox table `event_outbox` commits events atomically with business transactions.
- [ ] **AC-1.3.5**: Outbox worker polls using `FOR UPDATE SKIP LOCKED`, processes tasks, and executes exponential backoff on failure.
- [ ] **AC-1.3.6**: Stock updates in WooCommerce reflect accurately in platform inventory within 5 seconds.

---

### Milestone P1.4: AI Workforce Foundation & Payment Orchestration
- [ ] **AC-1.4.1**: `agent_definitions` seeded with Sales, Customer Support, and Inventory specialist templates.
- [ ] **AC-1.4.2**: Merchant can provision an agent instance with custom system instructions.
- [ ] **AC-1.4.3**: Agent tool executions run within merchant tenant context; unauthorized tool invocations rejected.
- [ ] **AC-1.4.4**: Agent actions exceeding merchant `max_auto_approval_limit_paise` enter `AWAITING_APPROVAL` status and emit approval records.
- [ ] **AC-1.4.5**: Human approval endpoint transitions task to `RUNNING` and executes gated action.
- [ ] **AC-1.4.6**: `IPaymentProvider` implemented for Paytm (All-in-One PG) and preserved for Razorpay.
- [ ] **AC-1.4.7**: Paytm Checksum signature verification validated against simulated and real webhook payloads.
- [ ] **AC-1.4.8**: Ambiguous timeout polling resolves pending payments without duplicate charging or phantom stock holds.

---

### Milestone P1.5: Merchant Dashboard & Analytics
- [ ] **AC-1.5.1**: Merchant dashboard renders live gross sales (in ₹ from paise), order count, and AOV uplift percentage.
- [ ] **AC-1.5.2**: Connected store status displays green/synced status with timestamp of last sync.
- [ ] **AC-1.5.3**: Pending approvals tab displays escalated agent actions with one-click "Approve" / "Reject" controls.
- [ ] **AC-1.5.4**: End-to-end integration test passes: Merchant registers -> connects store -> provisions Sales Agent -> Buyer AI purchases item -> Payment settles via Paytm -> Dashboard updates metrics.
- [ ] **AC-1.5.5**: Zero high or critical vulnerabilities reported by automated security scans (`bandit`, `pip-audit`).

