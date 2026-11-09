# Gateway Dependency Matrix & Data Flow Analysis

- **Document ID**: `PHASE-0-DOC-04`
- **Revision**: `1.0.0`
- **Status**: `APPROVED / ARCHITECTURAL BASELINE`
- **Author**: System Architect Specialist
- **Timestamp**: `2026-11-09T17:42:00Z`
- **Target Repository**: `d:\agentic-commerce-gateway`

---

## 1. Module Interdependency Matrix

The following matrix documents direct import and call dependencies across the internal codebase modules. High cohesion is maintained in the policy engine, while the purchase orchestrator (`app.agent.service`) acts as the central coordinator.

| Module | `main` | `auth` | `agent` | `policy` | `mcp` | `audit` | `payment` | `catalog` | `wallet` | `oauth` | `admin` | `db` |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`app/main.py`** | — | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ |
| **`app/auth.py`** | — | — | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | **DEP** | ✕ | ✕ |
| **`app/agent/service.py`** | ✕ | ✕ | — | **DEP** | ✕ | **DEP** | **DEP** | **DEP** | **DEP** | **DEP** | ✕ | ✕ |
| **`app/agent/router.py`** | ✕ | **DEP** | **DEP** | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ |
| **`app/policy/engine.py`** | ✕ | ✕ | ✕ | — | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ |
| **`app/policy/store.py`** | ✕ | ✕ | ✕ | **DEP** | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | **DEP** |
| **`app/mcp/server.py`** | ✕ | ✕ | ✕ | ✕ | — | ✕ | ✕ | ✕ | ✕ | **DEP** | ✕ | ✕ |
| **`app/mcp/tools.py`** | ✕ | ✕ | **DEP** | **DEP** | ✕ | **DEP** | ✕ | **DEP** | ✕ | **DEP** | ✕ | ✕ |
| **`app/audit/store.py`** | ✕ | ✕ | ✕ | ✕ | ✕ | — | ✕ | ✕ | ✕ | ✕ | ✕ | **DEP** |
| **`app/audit/router.py`** | ✕ | **DEP** | ✕ | ✕ | ✕ | **DEP** | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ |
| **`app/payment/service.py`** | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | — | ✕ | **DEP** | ✕ | ✕ | ✕ |
| **`app/payment/router.py`** | ✕ | **DEP** | ✕ | ✕ | ✕ | **DEP** | **DEP** | **DEP** | ✕ | ✕ | ✕ | ✕ |
| **`app/catalog/service.py`** | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | — | ✕ | ✕ | ✕ | **DEP** |
| **`app/catalog/router.py`** | ✕ | **DEP** | ✕ | ✕ | ✕ | ✕ | ✕ | **DEP** | ✕ | ✕ | ✕ | ✕ |
| **`app/wallet/store.py`** | ✕ | ✕ | ✕ | **DEP** | ✕ | ✕ | ✕ | ✕ | — | ✕ | ✕ | **DEP** |
| **`app/oauth/router.py`** | ✕ | ✕ | ✕ | **DEP** | ✕ | ✕ | ✕ | ✕ | ✕ | **DEP** | ✕ | ✕ |
| **`app/oauth/store.py`** | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | **DEP** | ✕ | **DEP** |
| **`app/admin/router.py`** | ✕ | **DEP** | ✕ | **DEP** | ✕ | ✕ | ✕ | ✕ | ✕ | **DEP** | — | ✕ |
| **`app/db.py`** | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | ✕ | — |

*Legend: `DEP` indicates that the row module depends on and calls the column module. `✕` indicates no direct dependency.*

### Architectural Dependency Inversion Analysis
- **Domain Independence**: `app/policy/engine.py` is completely isolated; it has zero dependencies on databases, HTTP libraries, or payment gateways.
- **Service Orchestration**: `app/agent/service.py` functions as the composite domain coordinator, delegating policy evaluation to `policy.engine`, inventory checks to `catalog.service`, settlement to `payment.service` / `wallet.store`, and audit logging to `audit.store`.
- **Circular Dependencies**: Zero circular package imports exist across the codebase.

---

## 2. Monetary Data Flow & Precision Trace

### 2.1 End-to-End Monetary Transformation Pipeline

```mermaid
flowchart LR
    Catalog["1. Catalog Price\nProduct.price\n(float / SQL REAL)\ne.g. 1499.0"]
    PurchaseSvc["2. Purchase Service\namount = price * qty\n(float)\ne.g. 1499.0"]
    PolicyReq["3. Policy Request\nPurchaseRequest.amount\n(float gt=0)\ne.g. 1499.0"]
    MandateEngine["4. Mandate Engine\namount <= max_limit\n(float comparison)\ne.g. 1499.0 <= 2000.0"]
    ConfirmToken["5. Confirmation Token\nJWT payload['amount']\n(float)\ne.g. 1499.0"]
    PaiseConversion["6. Paise Conversion\n_rupees_to_paise(amount)\nint(round(amount * 100))\ne.g. 149900"]
    RazorpayAPI["7. Payment Provider\nRazorpay Orders API\n'amount': 149900 (paise)"]
    AuditLedger["8. Audit Ledger\nAuditRecord.amount\n(float / SQL REAL)\ne.g. 1499.0"]
    WalletStore["9. Mandate Wallet\nnew_bal = round(bal - amt, 2)\n(float / SQL REAL)"]

    Catalog --> PurchaseSvc
    PurchaseSvc --> PolicyReq
    PolicyReq --> MandateEngine
    MandateEngine --> ConfirmToken
    ConfirmToken --> PaiseConversion
    PaiseConversion --> RazorpayAPI
    PurchaseSvc --> AuditLedger
    PurchaseSvc --> WalletStore
```

### 2.2 Monetary Field Specification Table

| Stage | Data Object & Field | Code Location | Data Type | Currency Unit | Precision Risk / Behavior |
|---|---|---|---|---|---|
| **1. Catalog** | `Product.price` / `catalog_products.price` | [`app/catalog/models.py#L13`](file:///d:/agentic-commerce-gateway/app/catalog/models.py#L13) | `float` / SQL `REAL` | INR (₹) | Potential float representation artifacts for fractional prices. |
| **2. Purchase Service** | `amount = product.price * quantity` | [`app/agent/service.py#L270`](file:///d:/agentic-commerce-gateway/app/agent/service.py#L270) | `float` | INR (₹) | Standard IEEE 754 multiplication. |
| **3. Policy Request** | `PurchaseRequest.amount` | [`app/policy/requests.py#L28`](file:///d:/agentic-commerce-gateway/app/policy/requests.py#L28) | `float` (`gt=0`) | INR (₹) | Pre-computed total; never recomputed by policy engine. |
| **4. Mandate Comparison** | `mandate.max_transaction_amount` & `daily_limit` | [`app/policy/engine.py#L59-L80`](file:///d:/agentic-commerce-gateway/app/policy/engine.py#L59-L80) | `float` | INR (₹) | Inclusive comparison (`amount > max_transaction_amount`). |
| **5. Confirmation Token** | `payload["amount"]` in HS256 JWT | [`app/agent/service.py#L75`](file:///d:/agentic-commerce-gateway/app/agent/service.py#L75) | `float` | INR (₹) | Serialized in JSON token payload. |
| **6. Payment Gateway** | `amount_paise = _rupees_to_paise(amount_inr)` | [`app/payment/service.py#L22`](file:///d:/agentic-commerce-gateway/app/payment/service.py#L22) | `int` | INR (Paise) | `int(round(amount_inr * 100))`. Correctly conforms to Razorpay API specs. |
| **7. External Razorpay** | `payload["amount"]` | [`app/payment/razorpay_client.py#L59`](file:///d:/agentic-commerce-gateway/app/payment/razorpay_client.py#L59) | `int` | INR (Paise) | Integer paise accepted by Razorpay Orders & Payment Links API. |
| **8. Audit Store** | `AuditRecord.amount` / `audit_records.amount` | [`app/audit/models.py#L41`](file:///d:/agentic-commerce-gateway/app/audit/models.py#L41) | `float` / SQL `REAL` | INR (₹) | Formatted as `f"{amount:.2f}"` in cryptographic record hashes. |
| **9. Mandate Wallet** | `customer_wallets.balance` | [`app/wallet/store.py#L119`](file:///d:/agentic-commerce-gateway/app/wallet/store.py#L119) | `float` / SQL `REAL` | INR (₹) | Calculated via `round(current_bal - amount, 2)`. |

### 2.3 Evaluation of Currency Precision (Integer Paise for INR)
- **Current Posture**: The application switches between `float` (rupees) in domain services and `int` (paise) at the payment boundary.
- **Architectural Risk**:
  - In Indian banking systems, sub-rupee fractional currency is denominated in integer paise (1 Rupee = 100 Paise).
  - While existing demo prices are whole integers (₹1,499.00, ₹4,999.00) or clean decimals (₹179.00, ₹349.00), floating-point operations can introduce cumulative rounding errors (e.g. `0.1 + 0.2 = 0.30000000000000004`).
  - Daily spend accumulation `SUM(amount)` on SQL `REAL` can diverge slightly from exact paise totals over thousands of transactions.
- **Architectural Recommendation**: Standardize internal storage and policy arithmetic on either Python `Decimal` or pure `int` (paise), converting to rupees strictly at the presentation layer. `[RECOMMENDATION]`

---

## 3. Identity Data Flow & Anti-Spoofing Analysis

### 3.1 Identity Lifecycle & Provenance

```mermaid
sequenceDiagram
    autonumber
    participant Client as AI Agent Client
    participant OAuth as OAuth 2.1 Server
    participant MCPMid as McpAuthMiddleware
    participant AgentRouter as Agent Purchase Router
    participant PolicyEng as Policy Mandate Engine
    participant AuditLedger as Audit Ledger

    Note over Client,OAuth: Phase 1: Authentication & Token Minting
    Client->>OAuth: POST /oauth/token (code + PKCE verifier)
    OAuth->>OAuth: Validate PKCE & verify customer_credentials
    OAuth-->>Client: JWT Access Token (sub='CUST001', iss='ai-buyer-gateway')

    Note over Client,AgentRouter: Phase 2: Purchase Proposal (Remote HTTP MCP or REST)
    Client->>MCPMid: JSON-RPC propose_purchase(product_id='KB001') + Authorization: Bearer JWT
    MCPMid->>MCPMid: verify_access_token(JWT) -> extracts sub='CUST001'
    MCPMid->>MCPMid: authenticated_customer_id.set('CUST001')
    MCPMid->>AgentRouter: execute_purchase(customer_id='CUST001', product_id='KB001')

    Note over AgentRouter,PolicyEng: Phase 3: Policy Validation & Identity Binding
    AgentRouter->>PolicyEng: evaluate(PurchaseRequest(customer_id='CUST001'), Mandate('CUST001'))
    PolicyEng->>PolicyEng: Check 1: request.customer_id == mandate.customer_id
    PolicyEng-->>AgentRouter: PolicyDecision(status='APPROVED')

    Note over AgentRouter,AuditLedger: Phase 4: Audit Attribution
    AgentRouter->>AuditLedger: write_proposal(customer_id='CUST001', tx_id=UUID)
    AuditLedger-->>AgentRouter: Committed with record_hash
    AgentRouter-->>Client: PurchaseResponse (REF-XXXXXXXX, customer details omitted)
```

### 3.2 Identity Trace Across System Boundaries

| Boundary | Identity Representation | Resolution Mechanism | Security / Anti-Spoofing Guarantee |
|---|---|---|---|
| **1. OAuth 2.1 Provider** | `customer_id` (`CUST001`) | Authenticates username/password in `customer_credentials` or Google SSO callback | Salted PBKDF2 verification; PKCE protects code exchange. |
| **2. Access Token** | `payload["sub"]` | Signed HS256 JWT minted by `create_access_token` | Tamper-proof signature verification; 1-hour expiration. |
| **3. Remote MCP Transport** | `authenticated_customer_id` | `McpAuthMiddleware` decodes token and sets contextvar | AI agent cannot specify `customer_id` in remote tool call. |
| **4. REST API Endpoint** | `effective_customer_id` | [`app/agent/router.py#L44-L50`](file:///d:/agentic-commerce-gateway/app/agent/router.py#L44-L50) checks `auth["auth_type"]` | If `auth_type == "oauth"`, strictly binds to `auth["customer_id"]`. Client-supplied `customer_id` is discarded. |
| **5. Policy Engine** | `PurchaseRequest.customer_id` | Checked against `Mandate.customer_id` | Fail-fast Rule 1 rejects immediately on mismatch (`CUSTOMER_MISMATCH`). |
| **6. Confirmation Token** | `payload["sub"]` | Signed HS256 JWT minted by `generate_confirmation_token` | Token binds original `customer_id`. Checked against caller ID at confirmation time. |
| **7. Payment Provider** | `notes["customer_id"]` | Passed to Razorpay API in metadata notes dictionary | Immutable tracking reference in Razorpay Dashboard. |
| **8. Audit Ledger** | `audit_records.customer_id` | Persisted in relational and cryptographic event tables | Non-repudiable audit trail linking action to verified customer. |

### 3.3 Customer ID Spoofing Threat Analysis

| Threat Vector | Attack Scenario | Gateway Defense Mechanism | Residual Risk Level |
|---|---|---|---|
| **Vector 1: Remote MCP Parameter Injection** | Malicious agent submits `customer_id="CUST002"` to debit another user's balance. | [`register_remote_tools`](file:///d:/agentic-commerce-gateway/app/mcp/tools.py#L906) does **not** accept `customer_id` as a parameter. It forces `authenticated_customer_id.get()` from the verified OAuth JWT. | **NONE / MITIGATED** |
| **Vector 2: REST Payload Spoofing** | Attacker holding valid token for `CUST001` sends POST `/agent/purchase` with `{"customer_id": "CUST002"}`. | [`app/agent/router.py#L46`](file:///d:/agentic-commerce-gateway/app/agent/router.py#L46) overrides request body: `effective_customer_id = auth["customer_id"]`. `CUST002` is ignored. | **NONE / MITIGATED** |
| **Vector 3: Stdio MCP Parameter Tampering** | Local user specifies `customer_id="CUST002"` in Claude Desktop. | Stdio transport accepts `customer_id` parameter without token. Intended strictly for single-user local debugging. | **LOW (LOCAL ONLY)** |
| **Vector 4: Confirmation Token Theft** | Attacker intercepts 5-minute confirmation token generated for `CUST001` and calls `/agent/confirm` using `CUST002` credentials. | [`app/agent/service.py#L448-L451`](file:///d:/agentic-commerce-gateway/app/agent/service.py#L448-L451) asserts `caller_customer_id == payload["sub"]`. Rejects with `InvalidPurchaseError`. | **NONE / MITIGATED** |

---

## 4. Transaction Data Flow & Field Provenance

### 4.1 Authoritative Field Registry

| Field Name | Authoritative Generator | Primary Storage Table / Token | Format / Cryptographic Algorithm | Purpose & Scope |
|---|---|---|---|---|
| `transaction_id` | [`app/agent/service.py#L287`](file:///d:/agentic-commerce-gateway/app/agent/service.py#L287) (`str(uuid4())`) | `audit_records.transaction_id`, `audit_events.transaction_id` | UUID v4 (36-char string) | Universal cross-system correlation key; mapped to Razorpay `receipt`. |
| `idempotency_key` | Client or [`app/agent/service.py#L55`](file:///d:/agentic-commerce-gateway/app/agent/service.py#L55) | `audit_records.idempotency_key` | SHA-256 (32-char prefix hex) | Prevents duplicate charges from agent retry storms within 60-second buckets. |
| `confirmation_token` | [`app/agent/service.py#L82`](file:///d:/agentic-commerce-gateway/app/agent/service.py#L82) | Ephemeral bearer JWT (client-held) | JWT HS256 (`JWT_SECRET`, 5-min TTL) | Authorizes human confirmation for purchases `>= ₹500` or mandate limit. |
| `razorpay_order_id` | Razorpay Orders API | `audit_records.razorpay_order_id`, `audit_events.payload_json` | String (`order_...` / fallback `order_<receipt>`) | Official payment order tracking identifier from Razorpay. |
| `razorpay_payment_id` | Razorpay Checkout / Auto-debit | `audit_records.razorpay_payment_id`, `audit_events.payload_json` | String (`pay_...` / `pay_mandate_<uuid>`) | Official payment capture identifier indicating finalized fund settlement. |
| `event_hash` | [`app/audit/store.py#L55`](file:///d:/agentic-commerce-gateway/app/audit/store.py#L55) | `audit_events.event_hash` | SHA-256 (64-char hex string) | Cryptographic block hash sealing event log sequentially to `prev_hash`. |

---

## 5. End-to-End Purchase Proposal & Confirmation Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor User as Human Buyer
    participant BuyerAgent as Buyer AI Agent
    participant Gateway as Agentic Commerce Gateway
    participant Policy as Policy Engine
    participant Audit as Audit Ledger
    participant Wallet as Wallet Store
    participant Razorpay as Razorpay API

    User->>BuyerAgent: "Buy the Mechanical Gaming Keyboard (KB001)"
    BuyerAgent->>Gateway: POST /agent/purchase (product_id='KB001', qty=1)
    Gateway->>Policy: evaluate(KB001, CUST001, amount=₹1,499.00)
    Policy-->>Gateway: APPROVED (within ₹2,000 mandate limit)
    
    Note over Gateway: ₹1,499.00 >= ₹500 Threshold -> TRIGGER HUMAN GATE
    Gateway->>Gateway: Mints 5-min JWT confirmation_token
    Gateway->>Audit: write_proposal(status='PENDING_CONFIRMATION')
    Gateway-->>BuyerAgent: requires_confirmation=true, confirmation_token='eyJ...'

    BuyerAgent->>User: "Quote: Mechanical Gaming Keyboard is ₹1,499.00. Confirm purchase?"
    User->>BuyerAgent: "Yes, proceed with order"

    BuyerAgent->>Gateway: POST /agent/confirm (confirmation_token='eyJ...')
    Gateway->>Gateway: decode_confirmation_token() -> verify signature & TTL
    Gateway->>Policy: Re-evaluate policy against current daily spend
    Policy-->>Gateway: APPROVED
    Gateway->>Razorpay: create_order(amount_paise=149900, receipt=tx_id)
    Razorpay-->>Gateway: order_id='order_Live123'
    Gateway->>Wallet: debit('CUST001', ₹1,499.00)
    Wallet-->>Gateway: Success (balance: ₹3,501.00)
    Gateway->>Audit: update_payment_outcome(payment_status='captured', decision='APPROVED')
    Audit->>Audit: Append PAYMENT_CAPTURED to SHA-256 hash chain
    Gateway-->>BuyerAgent: PurchaseResponse (decision='APPROVED', ref='REF-XXXXXXXX')
    BuyerAgent->>User: "Order confirmed! Reference code: REF-XXXXXXXX"
```

---

## 6. Cryptographic Hash Chain Structure

```mermaid
flowchart TD
    Genesis["Block 0: Genesis\nprev_hash: 'GENESIS'"]
    
    Block1["Block 1: PROPOSAL_EVALUATED\nevent_id: ev-001\ntransaction_id: tx-001\nprev_hash: 'GENESIS'\nevent_hash: sha256(GENESIS | ev-001 | tx-001 | payload)"]
    
    Block2["Block 2: HUMAN_CONFIRMED\nevent_id: ev-002\ntransaction_id: tx-001\nprev_hash: Block 1 event_hash\nevent_hash: sha256(Block 1 hash | ev-002 | tx-001 | payload)"]
    
    Block3["Block 3: PAYMENT_CAPTURED\nevent_id: ev-003\ntransaction_id: tx-001\nprev_hash: Block 2 event_hash\nevent_hash: sha256(Block 2 hash | ev-003 | tx-001 | payload)"]

    Genesis --> Block1
    Block1 --> Block2
    Block2 --> Block3

    subgraph Verification["Integrity Verification (/audit/verify)"]
        Verify["Walks index 0 to N\nRecomputes SHA-256 at each step\nReconciles audit_records.record_hash against audit_events tip"]
    end
```

---
*End of Document `04_DEPENDENCY_AND_DATA_FLOW.md`*
