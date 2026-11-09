"""
Pre-P0 Security Regression Tests: Mandate Escalation Containment (VULN-05).

Verifies the inviolable security invariant:
"An external AI agent must never be able to increase, extend, or otherwise
escalate a customer's spending authority through conversational tool calls."

Ensures that:
1. Remote MCP server tools list does NOT expose `modify_spending_mandate`.
2. Local stdio MCP server tools list does NOT expose `modify_spending_mandate`.
3. Remote MCP handler `modify_spending_mandate_remote_handler` fails closed (FORBIDDEN).
4. Direct handler invocation `modify_spending_mandate_handler` fails closed (FORBIDDEN).
5. No confirmation tokens are issued to callers attempting mandate modifications.
6. Spending limits, allowed merchants, and allowed categories cannot be altered via MCP.
7. Customer identity cannot be spoofed in mandate queries (authenticated context takes precedence).
8. Legitimate customer mandate inspection continues to work.
9. Separately authenticated admin mandate management (`/admin/customers/{id}/mandate`) remains functional.
10. Separately authenticated customer self-service mandate update (`/oauth/customer/mandate/update`) remains functional.
11. Standard purchase proposal and confirmation flows continue to work unhindered.
"""
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.mcp.server import create_mcp_server, create_remote_mcp_server
from app.mcp.tools import (
    authenticated_customer_id,
    confirm_purchase_remote_handler,
    get_spending_mandate_handler,
    get_spending_mandate_remote_handler,
    modify_spending_mandate_handler,
    modify_spending_mandate_remote_handler,
    propose_purchase_remote_handler,
)
from app.policy.store import mandate_store

client = TestClient(app)

_CREATE_ORDER = "app.payment.razorpay_client.create_order"
_FAKE_ORDER = {
    "id": "order_PreP0_Test123",
    "entity": "order",
    "amount": 149900,
    "currency": "INR",
    "status": "created",
    "receipt": "prep0-receipt-123",
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. Mandate Inspection & Identity Isolation Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_get_spending_mandate_read_only():
    """Verify that an authenticated customer can inspect their active mandate bounds (read-only)."""
    token = authenticated_customer_id.set("CUST001")
    try:
        res = get_spending_mandate_handler(customer_id="CUST001")
        assert res["mandate_found"] is True
        assert res["status"] == "SUCCESS"
        assert res["customer_id"] == "CUST001"
        assert res["max_limit_per_transaction"] > 0
        assert "electronics" in res["allowed_categories"]
        assert "read-only" in res["message"].lower()
    finally:
        authenticated_customer_id.reset(token)


def test_get_spending_mandate_remote_authenticated():
    """Verify remote mandate lookup correctly binds to the authenticated OAuth identity."""
    token = authenticated_customer_id.set("CUST002")
    try:
        res = get_spending_mandate_remote_handler()
        assert res["mandate_found"] is True
        assert res["status"] == "SUCCESS"
        assert res["customer_id"] == "CUST002"
    finally:
        authenticated_customer_id.reset(token)


def test_get_spending_mandate_anti_spoofing():
    """
    Verify that when an authenticated OAuth context exists, a caller-supplied
    customer_id cannot spoof or inspect another customer's mandate.
    """
    token = authenticated_customer_id.set("CUST001")
    try:
        # Attempt to inspect CUST002 while authenticated as CUST001
        res = get_spending_mandate_handler(customer_id="CUST002")
        assert res["mandate_found"] is False
        assert res["status"] == "FORBIDDEN"
        assert "Access denied" in res["error"]
        assert "does not match authenticated identity" in res["error"]
    finally:
        authenticated_customer_id.reset(token)


def test_remote_handler_without_auth_context_returns_unauthorized():
    """Remote mandate handler without an active authenticated OAuth session returns UNAUTHORIZED."""
    # Ensure context is empty
    token = authenticated_customer_id.set(None)
    try:
        res = get_spending_mandate_remote_handler()
        assert res["mandate_found"] is False
        assert res["status"] == "UNAUTHORIZED"
        assert "Authentication required" in res["error"]
    finally:
        authenticated_customer_id.reset(token)


def test_remote_handler_cannot_accept_caller_controlled_customer_id():
    """Remote mandate handler does not accept a customer_id parameter from the caller."""
    import inspect
    sig = inspect.signature(get_spending_mandate_remote_handler)
    assert len(sig.parameters) == 0, (
        "CRITICAL: get_spending_mandate_remote_handler must not accept any arguments."
    )
    # Direct attempt to pass customer_id must raise TypeError
    with pytest.raises(TypeError):
        get_spending_mandate_remote_handler(customer_id="CUST002")  # type: ignore


def test_direct_handler_without_identity_cannot_retrieve_cust001_by_default():
    """Direct handler invocation without authenticated session cannot retrieve CUST001 by default."""
    token = authenticated_customer_id.set(None)
    try:
        # 1. Calling without arguments returns UNAUTHORIZED (not CUST001)
        res_no_args = get_spending_mandate_handler()
        assert res_no_args["mandate_found"] is False
        assert res_no_args["status"] == "UNAUTHORIZED"
        assert "Authentication required" in res_no_args["error"]

        # 2. Calling with caller-supplied customer_id without session returns UNAUTHORIZED
        res_with_id = get_spending_mandate_handler(customer_id="CUST001")
        assert res_with_id["mandate_found"] is False
        assert res_with_id["status"] == "UNAUTHORIZED"
        assert "Authentication required" in res_with_id["error"]
    finally:
        authenticated_customer_id.reset(token)


def test_local_stdio_cannot_query_arbitrary_customer_without_auth():
    """Local stdio MCP tool rejects arbitrary customer mandate inspection without authenticated context."""
    pytest.importorskip("anyio")
    import anyio

    token = authenticated_customer_id.set(None)
    try:
        server = create_mcp_server()

        async def _check_unauth():
            # Calling stdio tool with customer_id="CUST002" without auth must return UNAUTHORIZED
            result = await server.call_tool("get_spending_mandate", {"customer_id": "CUST002"})
            assert result.structured_content is not None
            res = result.structured_content["result"]
            assert res["mandate_found"] is False
            assert res["status"] == "UNAUTHORIZED"
            assert "Authentication required" in res["error"]

        anyio.run(_check_unauth)
    finally:
        authenticated_customer_id.reset(token)

    # When authenticated as CUST001, querying CUST002 via stdio tool must return FORBIDDEN
    auth_token = authenticated_customer_id.set("CUST001")
    try:
        server = create_mcp_server()

        async def _check_spoof():
            result = await server.call_tool("get_spending_mandate", {"customer_id": "CUST002"})
            assert result.structured_content is not None
            res = result.structured_content["result"]
            assert res["mandate_found"] is False
            assert res["status"] == "FORBIDDEN"
            assert "Access denied" in res["error"]

        anyio.run(_check_spoof)
    finally:
        authenticated_customer_id.reset(auth_token)


# ══════════════════════════════════════════════════════════════════════════════
# 2. MCP Server Tool Registration Isolation Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_remote_mcp_server_omits_modify_spending_mandate_tool():
    """Verify that remote MCP server does NOT expose modify_spending_mandate to remote AI agents."""
    remote_server = create_remote_mcp_server()
    pytest.importorskip("anyio")

    async def _check():
        tools = await remote_server.list_tools()
        tool_names = [t.name for t in tools]
        assert "modify_spending_mandate" not in tool_names
        assert "get_spending_mandate" in tool_names
        assert "propose_purchase" in tool_names
        assert "confirm_purchase" in tool_names

    import anyio
    anyio.run(_check)


def test_stdio_mcp_server_omits_modify_spending_mandate_tool():
    """Verify that local stdio MCP server does NOT expose modify_spending_mandate to AI agents."""
    stdio_server = create_mcp_server()
    pytest.importorskip("anyio")

    async def _check():
        tools = await stdio_server.list_tools()
        tool_names = [t.name for t in tools]
        assert "modify_spending_mandate" not in tool_names
        assert "get_spending_mandate" in tool_names
        assert "propose_purchase" in tool_names
        assert "confirm_purchase" in tool_names

    import anyio
    anyio.run(_check)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Remote MCP Handler Containment Tests (Fail Closed)
# ══════════════════════════════════════════════════════════════════════════════

def test_remote_mcp_cannot_increase_spending_limit():
    """Verify remote MCP client cannot increase spending limit."""
    mandate_before = mandate_store.get_mandate("CUST001")
    initial_limit = mandate_before.max_transaction_amount

    token = authenticated_customer_id.set("CUST001")
    try:
        res = modify_spending_mandate_remote_handler(new_limit=45000.0)
        assert res["success"] is False
        assert res["status"] == "FORBIDDEN"
        assert "disabled for security" in res["error"]
        assert "confirmation_token" not in res

        # Verify database was NOT modified
        mandate_after = mandate_store.get_mandate("CUST001")
        assert mandate_after.max_transaction_amount == initial_limit
    finally:
        authenticated_customer_id.reset(token)


def test_remote_mcp_cannot_add_merchant():
    """Verify remote MCP client cannot authorize a new merchant."""
    mandate_before = mandate_store.get_mandate("CUST001")
    assert "UNAUTHORIZED_MERCHANT" not in mandate_before.allowed_merchants

    token = authenticated_customer_id.set("CUST001")
    try:
        res = modify_spending_mandate_remote_handler(add_merchant="UNAUTHORIZED_MERCHANT")
        assert res["success"] is False
        assert res["status"] == "FORBIDDEN"

        # Verify database was NOT modified
        mandate_after = mandate_store.get_mandate("CUST001")
        assert "UNAUTHORIZED_MERCHANT" not in mandate_after.allowed_merchants
    finally:
        authenticated_customer_id.reset(token)


def test_remote_mcp_cannot_add_category():
    """Verify remote MCP client cannot authorize a new product category."""
    mandate_before = mandate_store.get_mandate("CUST001")
    assert "prohibited_category" not in mandate_before.allowed_categories

    token = authenticated_customer_id.set("CUST001")
    try:
        res = modify_spending_mandate_remote_handler(add_category="prohibited_category")
        assert res["success"] is False
        assert res["status"] == "FORBIDDEN"

        # Verify database was NOT modified
        mandate_after = mandate_store.get_mandate("CUST001")
        assert "prohibited_category" not in mandate_after.allowed_categories
    finally:
        authenticated_customer_id.reset(token)


def test_remote_mcp_never_returns_confirmation_token():
    """Verify that under no circumstance does the remote handler issue a confirmation token."""
    token = authenticated_customer_id.set("CUST001")
    try:
        for payload in [
            {"new_limit": 5000.0},
            {"add_merchant": "NEW_MERCH"},
            {"add_category": "new_cat"},
            {"confirmation_token": "some.token"},
            {},
        ]:
            res = modify_spending_mandate_remote_handler(**payload)
            assert res["success"] is False
            assert "confirmation_token" not in res
            assert res.get("status") == "FORBIDDEN"
    finally:
        authenticated_customer_id.reset(token)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Direct Handler Invocation Authorization Boundary Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_direct_handler_invocation_fails_closed():
    """
    Verify that even if a caller bypasses MCP and invokes modify_spending_mandate_handler
    directly in code or via an internal route, it fails closed with FORBIDDEN.
    """
    mandate_before = mandate_store.get_mandate("CUST001")
    initial_limit = mandate_before.max_transaction_amount

    res = modify_spending_mandate_handler(
        new_limit=30000.0,
        customer_id="CUST001",
    )
    assert res["success"] is False
    assert res["status"] == "FORBIDDEN"
    assert "disabled for security" in res["error"]
    assert "confirmation_token" not in res

    # Store must be unmodified
    mandate_after = mandate_store.get_mandate("CUST001")
    assert mandate_after.max_transaction_amount == initial_limit


def test_direct_handler_with_token_fails_closed():
    """Verify that calling modify_spending_mandate_handler with any token fails closed."""
    res = modify_spending_mandate_handler(
        confirmation_token="fake.token.attempt",
        customer_id="CUST001",
    )
    assert res["success"] is False
    assert res["status"] == "FORBIDDEN"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Legitimate Authenticated Channels Preserved Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_authenticated_admin_mandate_update_remains_functional(admin_headers):
    """
    Verify that the legitimate administrator API (PATCH /admin/customers/{id}/mandate)
    protected by verify_admin_key continues to function normally.
    """
    response = client.patch(
        "/admin/customers/CUST001/mandate",
        headers=admin_headers,
        json={"mandate_limit": 4500.0},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["max_transaction_amount"] == 4500.0

    # Verify store has the new limit
    mandate = mandate_store.get_mandate("CUST001")
    assert mandate.max_transaction_amount == 4500.0

    # Reset back to baseline ₹2,000.00
    client.patch(
        "/admin/customers/CUST001/mandate",
        headers=admin_headers,
        json={"mandate_limit": 2000.0},
    )


def test_authenticated_customer_self_service_remains_functional():
    """
    Verify that customer self-service mandate update (POST /customer/mandate/update)
    requiring customer password credentials continues to function normally.
    """
    response = client.post(
        "/customer/mandate/update",
        json={
            "username_or_email": "dinesh",
            "password": "password123",
            "new_limit": 3000.0,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["new_limit"] == 3000.0

    # Verify store has the new limit
    mandate = mandate_store.get_mandate("CUST001")
    assert mandate.max_transaction_amount == 3000.0

    # Reset back to ₹2,000.00
    client.post(
        "/customer/mandate/update",
        json={
            "username_or_email": "dinesh",
            "password": "password123",
            "new_limit": 2000.0,
        },
    )


# ══════════════════════════════════════════════════════════════════════════════
# 6. Purchase Proposal & Confirmation Continuity Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_purchase_proposal_and_confirmation_continue_working():
    """
    Verify that containing VULN-05 did not break or weaken the normal purchase proposal
    and confirmation lifecycle.
    """
    token_reset = authenticated_customer_id.set("CUST001")
    try:
        # Step 1: Propose gated purchase (KB001 is ₹1,499 >= ₹500 threshold)
        with patch(_CREATE_ORDER) as mock_create_1:
            prop = propose_purchase_remote_handler(
                product_id="KB001",
                quantity=1,
            )
        mock_create_1.assert_not_called()
        assert prop["decision"] == "PENDING_CONFIRMATION"
        assert prop["requires_confirmation"] is True
        assert prop["confirmation_token"] is not None

        # Step 2: Confirm purchase with token
        with patch(_CREATE_ORDER, return_value=_FAKE_ORDER) as mock_create_2:
            conf = confirm_purchase_remote_handler(
                confirmation_token=prop["confirmation_token"],
            )
        mock_create_2.assert_called_once()
        assert conf["decision"] == "APPROVED"
        assert conf["reference_code"].startswith("REF-")
    finally:
        authenticated_customer_id.reset(token_reset)
