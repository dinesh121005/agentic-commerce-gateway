# Multi-Tenant REST API Contract Specification

- **Document ID**: `P1-ARCH-08-API-CONTRACTS`
- **Milestone**: P1.0 — Architecture and Repository Preparation
- **Author**: Antigravity Lead Orchestrator & API Architect
- **Status**: PROPOSED CONTRACT SPECIFICATION (DO NOT IMPLEMENT IN P1.0)
- **Standard**: OpenAPI 3.1 & RFC 7807 Problem Details

---

## 1. Global API Conventions

1. **Base URL**: All P1 multi-tenant endpoints reside under `/api/v1/`. Legacy endpoints (`/catalog`, `/agent`, `/payment`, `/admin`, `/mcp`) remain mounted for backward compatibility.
2. **Authentication**: All protected endpoints require `Authorization: Bearer <JWT>` header containing a verified merchant employee token, or `X-Admin-API-Key` for platform super-admin access.
3. **Tenant Context**: The `merchant_id` is resolved exclusively from the server-side validated JWT `claims["merchant_id"]`. Client-supplied tenant IDs are rejected or ignored.
4. **Idempotency**: All state-mutating `POST` and `PUT` endpoints accept an optional or mandatory `Idempotency-Key: <UUID>` header.
5. **Standardized Error Envelope** (RFC 7807):
   ```json
   {
     "type": "https://api.agentic-commerce.internal/errors/insufficient-stock",
     "title": "Insufficient Stock",
     "status": 409,
     "detail": "Requested 5 units of 'KB001', but only 2 units are currently available.",
     "instance": "/api/v1/commerce/orders",
     "code": "INSUFFICIENT_STOCK",
     "timestamp": "2026-11-10T07:15:00Z"
   }
   ```

---

## 2. Authentication & Merchant Identity Endpoints

### 2.1 `POST /api/v1/auth/register`
- **Purpose**: Registers a new merchant administrator and creates the root merchant organization.
- **Auth**: Public.
- **Permissions**: None.
- **Request Schema**:
  ```json
  {
    "email": "owner@acme-goods.com",
    "password": "SecurePassword123!",
    "full_name": "Rohan Sharma",
    "merchant_name": "Acme Goods India",
    "currency": "INR"
  }
  ```
- **Response Schema** (`201 Created`):
  ```json
  {
    "user_id": "usr_01j7x01",
    "merchant_id": "merch_01j7x01",
    "access_token": "eyJhbGciOiJIUzI1Ni...",
    "refresh_token": "rt_89f0a21...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
  ```
- **Validation**: Email RFC 5322 format; password minimum 10 characters with uppercase, number, symbol.
- **Error Codes**: `400 Bad Request` (validation error), `409 Conflict` (email already registered).

---

### 2.2 `POST /api/v1/auth/login`
- **Purpose**: Authenticates a merchant employee and returns an access token bound to their active merchant organization.
- **Auth**: Public.
- **Request Schema**:
  ```json
  {
    "email": "rohan@acme-goods.com",
    "password": "SecurePassword123!"
  }
  ```
- **Response Schema** (`200 OK`): Same token structure as 2.1.
- **Error Codes**: `401 Unauthorized` (invalid credentials or deactivated user).

---

### 2.3 `GET /api/v1/merchants/me`
- **Purpose**: Returns the profile, settings, and role permissions of the currently authenticated merchant organization.
- **Auth**: Bearer JWT.
- **Permissions**: `merchants:read`.
- **Response Schema** (`200 OK`):
  ```json
  {
    "id": "merch_01j7x01",
    "name": "Acme Goods India",
    "legal_name": "Acme Goods Private Limited",
    "currency": "INR",
    "status": "ACTIVE",
    "current_user": {
      "user_id": "usr_01j7x01",
      "email": "rohan@acme-goods.com",
      "display_name": "Rohan Sharma",
      "role": "OWNER",
      "permissions": ["*"]
    },
    "settings": {
      "max_auto_approval_limit_paise": 50000,
      "notifications_enabled": true
    }
  }
  ```

---

### 2.4 `POST /api/v1/merchants/invitations`
- **Purpose**: Invites an employee to join the merchant organization under a specific role.
- **Auth**: Bearer JWT.
- **Permissions**: `members:manage`.
- **Request Schema**:
  ```json
  {
    "email": "sarah@acme-goods.com",
    "role_id": "STORE_MANAGER"
  }
  ```
- **Response Schema** (`201 Created`):
  ```json
  {
    "invitation_id": "inv_01j7x99",
    "email": "sarah@acme-goods.com",
    "role_id": "STORE_MANAGER",
    "expires_at": "2026-11-17T07:00:00Z"
  }
  ```
- **Error Codes**: `403 Forbidden` (insufficient privileges), `409 Conflict` (user already invited).

---

### 2.5 `GET /api/v1/merchants/members`
- **Purpose**: Lists all active and invited employees within the merchant organization.
- **Auth**: Bearer JWT.
- **Permissions**: `members:read`.
- **Response Schema** (`200 OK`):
  ```json
  {
    "members": [
      {
        "id": "mem_01j7x01",
        "email": "rohan@acme-goods.com",
        "display_name": "Rohan Sharma",
        "role_id": "OWNER",
        "status": "ACTIVE"
      }
    ]
  }
  ```

---

## 3. Store Connection & Channel Synchronization Endpoints

### 3.1 `POST /api/v1/stores`
- **Purpose**: Registers a new e-commerce storefront under the merchant organization.
- **Auth**: Bearer JWT.
- **Permissions**: `stores:manage`.
- **Request Schema**:
  ```json
  {
    "name": "Main WooCommerce Store",
    "platform": "WOOCOMMERCE",
    "store_url": "https://store.acme-goods.com",
    "sync_interval_seconds": 3600
  }
  ```
- **Response Schema** (`201 Created`): Returns registered store entity with `status = "DISCONNECTED"`.

---

### 3.2 `POST /api/v1/stores/{id}/connect`
- **Purpose**: Submits and encrypts API credentials (consumer key and secret) for store connector.
- **Auth**: Bearer JWT.
- **Permissions**: `stores:manage`.
- **Request Schema**:
  ```json
  {
    "consumer_key": "ck_xxxxxxxxxxxxxxxxxxxx",
    "consumer_secret": "cs_xxxxxxxxxxxxxxxxxxxx"
  }
  ```
- **Response Schema** (`200 OK`):
  ```json
  {
    "store_id": "store_01j7x55",
    "status": "CONNECTED",
    "message": "Connection verified successfully with WooCommerce v3 API."
  }
  ```
- **Security Requirement**: In-flight payload parsed into memory, immediately AES-256-GCM encrypted, and raw secrets zeroed out.

---

### 3.3 `POST /api/v1/stores/{id}/sync`
- **Purpose**: Enqueues an on-demand catalog and inventory synchronization job in the transactional outbox.
- **Auth**: Bearer JWT.
- **Permissions**: `stores:sync`.
- **Response Schema** (`202 Accepted`):
  ```json
  {
    "task_id": "sync_01j7x88",
    "status": "QUEUED",
    "enqueued_at": "2026-11-10T07:15:30Z"
  }
  ```

---

### 3.4 `GET /api/v1/stores/{id}/sync-status`
- **Purpose**: Checks the progress and error logs of the latest catalog synchronization.
- **Auth**: Bearer JWT.
- **Permissions**: `stores:read`.
- **Response Schema** (`200 OK`):
  ```json
  {
    "store_id": "store_01j7x55",
    "status": "IDLE",
    "last_sync": {
      "synced_at": "2026-11-10T06:00:00Z",
      "products_imported": 142,
      "products_updated": 8,
      "errors_count": 0
    }
  }
  ```

---

## 4. AI Workforce Management Endpoints

### 4.1 `GET /api/v1/workforce/agents`
- **Purpose**: Lists all provisioned AI workers for the merchant organization.
- **Auth**: Bearer JWT.
- **Permissions**: `workforce:read`.
- **Response Schema** (`200 OK`):
  ```json
  {
    "agents": [
      {
        "id": "agent_sales_01",
        "agent_type": "SALES",
        "display_name": "Frontline Sales Assistant",
        "status": "ACTIVE",
        "permissions": [
          {"tool_name": "search_products", "is_allowed": true},
          {"tool_name": "create_quote", "is_allowed": true, "max_amount_paise": 200000}
        ]
      }
    ]
  }
  ```

---

### 4.2 `POST /api/v1/workforce/agents`
- **Purpose**: Provisions a new specialist AI agent from a system template.
- **Auth**: Bearer JWT.
- **Permissions**: `workforce:manage`.
- **Request Schema**:
  ```json
  {
    "agent_type": "INVENTORY",
    "display_name": "Stock Monitoring Worker",
    "custom_instructions": "Notify store manager if any SKU drops below 5 units."
  }
  ```
- **Response Schema** (`201 Created`): Provisioned agent record.

---

### 4.3 `GET /api/v1/workforce/tasks`
- **Purpose**: Queries the execution history and current status of agent tasks.
- **Auth**: Bearer JWT.
- **Permissions**: `workforce:read`.
- **Query Params**: `status`, `agent_instance_id`, `limit`, `offset`.
- **Response Schema** (`200 OK`): Paginated task records with approval status.

---

## 5. Merchant Dashboard & Analytics Endpoint

### 5.1 `GET /api/v1/dashboard/overview`
- **Purpose**: Aggregates organization-wide metrics for the main merchant dashboard.
- **Auth**: Bearer JWT.
- **Permissions**: `dashboard:read`.
- **Response Schema** (`200 OK`):
  ```json
  {
    "merchant_id": "merch_01j7x01",
    "period": "TODAY",
    "currency": "INR",
    "metrics": {
      "gross_sales_paise": 4850000,
      "order_count": 42,
      "aov_paise": 115476,
      "aov_uplift_pct": 14.8,
      "connected_stores": 2,
      "active_agents": 4,
      "pending_approvals_count": 1
    },
    "recent_orders": [],
    "recent_agent_activity": []
  }
  ```

