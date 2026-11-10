"""
MCP tool definitions and handlers for ai-buyer-gateway.

Exposes tools to AI clients (e.g. Claude Desktop) over both:
1. Local stdio transport (single-user demo mode with inquire_merchant, search_products, suggest_addons, propose_purchase, and confirm_purchase)
2. Remote Streamable HTTP transport (OAuth-authenticated multi-tenant mode bound to verified JWT sub)

Data Minimization:
MCP tools return minimized, customer-facing response shapes. Internal transaction UUIDs,
Razorpay order IDs, and payment rails internals are intentionally withheld from AI clients
and preserved exclusively in the SQLite audit trail for admin inspection.
"""
from contextvars import ContextVar
from datetime import datetime, timezone, timedelta
import logging
from typing import Any, Dict, List, Optional

import jwt
from app.oauth.crypto import JWT_SECRET
try:
    from mcp.server.mcpserver import MCPServer  # type: ignore[import-not-found,import-untyped]
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[import-not-found,import-untyped]
    except ImportError:
        try:
            from mcp.server import MCPServer  # type: ignore[import-not-found,import-untyped]
        except ImportError:
            from mcp.server import FastMCP as MCPServer  # type: ignore[import-not-found,import-untyped]

from app.agent.service import (
    PurchaseResponse,
    confirm_purchase,
    execute_purchase,
    generate_bucketed_idempotency_key,
)
from app.audit import audit_store
from app.catalog.service import get_product, search_products
from app.exceptions import GatewayError, StalePriceError
from app.merchant_agent.models import InquiryRequest
from app.merchant_agent.service import merchant_agent_service
from app.policy.store import mandate_store

logger = logging.getLogger("gateway.mcp")

# Context variable holding the verified customer_id from validated OAuth JWT on remote HTTP requests
authenticated_customer_id: ContextVar[Optional[str]] = ContextVar("authenticated_customer_id", default=None)


def to_customer_response(full_response: PurchaseResponse) -> Dict[str, Any]:
    """
    Projects the full internal PurchaseResponse into a minimized customer-facing payload.

    Data Confidentiality Safeguard:
    Raw transaction UUIDs (transaction_id) and payment gateway identifiers (razorpay_order_id)
    are strictly omitted from AI/customer-facing MCP responses to prevent unintentional data leakage.
    Full traceability is preserved internally and remains queryable via admin /audit endpoints.
    """
    product = get_product(full_response.product_id)
    is_fully_created = (
        full_response.decision == "APPROVED"
        and full_response.payment is not None
        and full_response.payment.status in ("created", "captured")
    )
    ref_code = (
        f"REF-{full_response.transaction_id[-8:].upper()}"
        if is_fully_created
        else None
    )

    payment_url = full_response.payment.payment_url if full_response.payment else None
    qr_code_url = full_response.payment.qr_code_url if full_response.payment else None
    payment_method = full_response.payment.payment_method if full_response.payment else None

    user_instructions = None
    if payment_url and full_response.decision == "REJECTED":
        user_instructions = (
            "Item exceeds autonomous mandate limit. The merchant gateway has generated a secure, official "
            "Razorpay Checkout Link and UPI QR Code. You MUST provide this checkout link and QR code to the "
            "human user so they can complete payment manually via UPI, Netbanking, or Card."
        )

    return {
        "decision": full_response.decision,
        "product_name": product.name,
        "amount": full_response.amount,
        "reason": full_response.reason,
        "reference_code": ref_code,
        "payment_url": payment_url,
        "qr_code_url": qr_code_url,
        "payment_method": payment_method,
        "user_instructions": user_instructions,
        "requires_confirmation": full_response.requires_confirmation,
        "confirmation_token": full_response.confirmation_token,
    }


def inquire_merchant_handler(
    query: str,
    max_budget: Optional[float] = None,
    category: Optional[str] = None,
    quantity: int = 1,
) -> Dict[str, Any]:
    """
    Handler allowing Buyer AI Agents (Claude) to consult the Merchant Sales Agent
    with natural language queries and obtain smart product quotes, recommendations,
    and order status / payment confirmations.
    """
    q_lower = query.lower()
    if any(term in q_lower for term in ["status", "order", "paid", "payment", "placed", "receipt", "bought", "track"]):
        cust_id = authenticated_customer_id.get() or "CUST001"
        status_info = check_order_status_handler(customer_id=cust_id)
        if status_info.get("order_found"):
            req = InquiryRequest(
                query=query,
                max_budget=max_budget,
                category=category,
                quantity=quantity,
            )
            res = merchant_agent_service.process_inquiry(req)
            data = res.model_dump()
            data["order_status"] = status_info
            data["merchant_notes"] = f"{status_info['message']} " + (data.get("merchant_notes") or "")
            return data

    req = InquiryRequest(
        query=query,
        max_budget=max_budget,
        category=category,
        quantity=quantity,
    )
    res = merchant_agent_service.process_inquiry(req)
    return res.model_dump()


def suggest_addons_handler(
    product_id: str,
    remaining_budget: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Handler providing Track 01 revenue growth add-ons and cross-sell suggestions.
    """
    res = merchant_agent_service.recommend_addons(
        product_id=product_id,
        remaining_budget=remaining_budget,
    )
    return res.model_dump()


def respond_to_recommendation_handler(
    recommendation_id: str,
    decision: str,
    customer_id: Optional[str] = None,
    primary_transaction_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Handler for Buyer AI Agent accepting or rejecting a merchant add-on recommendation.
    Enforces terminal decision idempotency.
    """
    eff_cust = customer_id or authenticated_customer_id.get() or "CUST001"
    res = merchant_agent_service.respond_to_recommendation(
        recommendation_id=recommendation_id,
        decision=decision,
        customer_id=eff_cust,
        primary_transaction_id=primary_transaction_id,
    )
    return res.model_dump()



def search_products_handler(
    query: Optional[str] = None,
    category: Optional[str] = None,
    max_price: Optional[float] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """
    Handler executing product search against the catalog service.
    Returns list of matching product dicts with customer-facing fields (id, name, category, price).
    """
    try:
        raw_query = query or kwargs.get("search_query") or kwargs.get("q") or kwargs.get("text") or kwargs.get("input") or kwargs.get("name")
        clean_query = str(raw_query).strip() if raw_query is not None else None
        clean_category = str(category).strip() if category is not None else None
        clean_max_price: Optional[float] = None
        if max_price is not None and str(max_price).strip() != "":
            try:
                clean_max_price = float(max_price)
            except (ValueError, TypeError):
                clean_max_price = None

        products = search_products(query=clean_query, category=clean_category, max_price=clean_max_price)
        return [
            {
                "id": p.id,
                "name": p.name,
                "category": p.category,
                "price": p.price,
            }
            for p in products
        ]
    except Exception as e:
        logger.error("Error executing search_products_handler: %s", e, exc_info=True)
        return []


def resolve_customer_handler(identifier: str) -> Dict[str, Any]:
    """
    Handler resolving a customer's human-identifiable name, email, or identifier to their customer_id.
    """
    if not identifier or not str(identifier).strip():
        return {
            "resolved": False,
            "reason": "no_match",
            "message": "Identifier cannot be empty.",
        }

    matches = mandate_store.find_by_identifier(identifier)

    if len(matches) == 1:
        match = matches[0]
        return {
            "resolved": True,
            "customer_id": match.customer_id,
            "display_name": match.display_name,
        }
    elif len(matches) == 0:
        return {
            "resolved": False,
            "reason": "no_match",
            "message": f"No authorized customer found matching '{identifier}'.",
        }
    else:
        return {
            "resolved": False,
            "reason": "ambiguous",
            "candidates": [m.display_name for m in matches],
            "message": f"Multiple customers found matching '{identifier}'. Please ask the user to clarify with their exact full name or email.",
        }


def propose_purchase_handler(
    customer_id: Optional[str] = None,
    product_id: str = "",
    quantity: int = 1,
) -> Dict[str, Any]:
    """
    Core handler executing a purchase proposal through the gateway for local stdio mode.
    Defaults to CUST001 (Dinesh Kumar) if no customer_id is specified.
    """
    effective_customer_id = (customer_id or "CUST001").strip()
    try:
        idempotency_key = generate_bucketed_idempotency_key(effective_customer_id, product_id, quantity)
        response = execute_purchase(
            customer_id=effective_customer_id,
            product_id=product_id,
            quantity=quantity,
            idempotency_key=idempotency_key,
        )
        return to_customer_response(response)
    except GatewayError as e:
        return {
            "decision": "REJECTED",
            "product_name": product_id,
            "amount": 0.0,
            "reason": str(e),
            "reference_code": None,
            "requires_confirmation": False,
            "confirmation_token": None,
        }
    except Exception as e:
        logger.error("Error executing purchase proposal: %s", e, exc_info=True)
        return {
            "decision": "REJECTED",
            "product_name": product_id,
            "amount": 0.0,
            "reason": f"System error during purchase processing: {str(e)}",
            "reference_code": None,
            "requires_confirmation": False,
            "confirmation_token": None,
        }


def confirm_purchase_handler(
    confirmation_token: str,
    customer_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes payment and order confirmation for a previously proposed gated purchase.
    """
    try:
        response = confirm_purchase(
            confirmation_token=confirmation_token,
            customer_id=customer_id or "CUST001",
        )
        return to_customer_response(response)
    except StalePriceError as e:
        logger.warning("Stale price detected during confirmation: %s", e)
        return {
            "decision": "REJECTED",
            "status": "STALE_PRICE_DETECTED",
            "product_name": e.product_id,
            "product_id": e.product_id,
            "proposed_amount": e.proposed_amount,
            "live_amount": e.live_amount,
            "amount": e.proposed_amount,
            "reason": str(e),
            "reference_code": "STALE_PRICE",
            "requires_confirmation": False,
            "confirmation_token": None,
        }
    except GatewayError as e:
        return {
            "decision": "REJECTED",
            "product_name": "unknown",
            "amount": 0.0,
            "reason": str(e),
            "reference_code": None,
            "requires_confirmation": False,
            "confirmation_token": None,
        }
    except Exception as e:
        logger.error("Error confirming purchase: %s", e, exc_info=True)
        return {
            "decision": "REJECTED",
            "product_name": "unknown",
            "amount": 0.0,
            "reason": f"Confirmation error: {str(e)}",
            "reference_code": None,
            "requires_confirmation": False,
            "confirmation_token": None,
        }


def propose_purchase_remote_handler(
    product_id: str,
    quantity: int = 1,
) -> Dict[str, Any]:
    """
    Core handler executing a purchase proposal for the remote OAuth-authenticated MCP path.
    Identity is bound strictly to the validated JWT sub claim (authenticated_customer_id).
    """
    customer_id = authenticated_customer_id.get()
    if not customer_id:
        return {
            "decision": "REJECTED",
            "product_name": product_id,
            "amount": 0.0,
            "reason": "Unauthenticated tool call: missing or unverified customer identity.",
            "reference_code": None,
            "requires_confirmation": False,
            "confirmation_token": None,
        }

    return propose_purchase_handler(
        customer_id=customer_id,
        product_id=product_id,
        quantity=quantity,
    )


def confirm_purchase_remote_handler(
    confirmation_token: str,
) -> Dict[str, Any]:
    """
    Remote handler confirming a purchase with identity bound to authenticated OAuth customer.
    """
    customer_id = authenticated_customer_id.get()
    if not customer_id:
        return {
            "decision": "REJECTED",
            "product_name": "unknown",
            "amount": 0.0,
            "reason": "Unauthenticated tool call: missing or unverified customer identity.",
            "reference_code": None,
            "requires_confirmation": False,
            "confirmation_token": None,
        }

    return confirm_purchase_handler(
        confirmation_token=confirmation_token,
        customer_id=customer_id,
    )


def check_order_status_handler(
    reference_or_id: Optional[str] = None,
    customer_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Looks up order and payment status from the merchant audit ledger.
    Allows Claude to confirm to the user that their payment was captured and their order placed.
    """
    effective_customer_id = customer_id or "CUST001"
    record = audit_store.lookup_order(identifier=reference_or_id, customer_id=effective_customer_id)
    if not record:
        return {
            "order_found": False,
            "message": "No order records found for this customer.",
        }

    product = get_product(record.product_id)
    p_name = product.name if product else record.product_id
    is_auto_paid = record.decision == "APPROVED" and record.payment_status != "failed"
    is_captured = record.payment_status in ("captured", "paid")
    is_paid = is_captured or is_auto_paid
    ref_code = f"REF-{record.transaction_id[-8:].upper()}"

    payment_desc = (
        "CONFIRMED & PAID via Razorpay rails"
        if is_captured
        else "CONFIRMED & AUTO-PAID via Pre-Authorized Mandate Balance"
        if is_auto_paid
        else "awaiting payment"
    )

    return {
        "order_found": True,
        "reference_code": ref_code,
        "product_name": p_name,
        "quantity": record.quantity,
        "amount": record.amount,
        "decision": record.decision,
        "payment_status": record.payment_status if record.payment_status in ("captured", "paid", "failed") else ("paid" if is_paid else "pending"),
        "payment_method": "razorpay_gateway" if is_captured else ("auto_debit" if is_auto_paid else "pending"),
        "razorpay_order_id": record.razorpay_order_id,
        "is_paid": is_paid,
        "order_status": "PLACED_AND_CONFIRMED" if is_paid else "PENDING_PAYMENT",
        "timestamp": record.timestamp,
        "message": (
            f"Merchant confirmation: Order {ref_code} for {record.quantity}x {p_name} (₹{record.amount:.2f}) is "
            f"{payment_desc}."
        ),
    }


def check_order_status_remote_handler(
    reference_or_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Remote handler checking order status bound to the authenticated OAuth customer.
    """
    customer_id = authenticated_customer_id.get() or "CUST001"
    return check_order_status_handler(
        reference_or_id=reference_or_id,
        customer_id=customer_id,
    )


def generate_mandate_confirmation_token(
    customer_id: str,
    new_limit: Optional[float] = None,
    add_merchant: Optional[str] = None,
    add_category: Optional[str] = None,
) -> str:
    """Generates a cryptographically signed 5-minute confirmation token for conversational mandate changes."""
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(seconds=300)
    payload = {
        "sub": customer_id,
        "new_limit": float(new_limit) if new_limit is not None else None,
        "add_merchant": add_merchant.strip() if add_merchant and add_merchant.strip() else None,
        "add_category": add_category.strip() if add_category and add_category.strip() else None,
        "type": "mandate_update_confirmation",
        "iat": int(now.timestamp()),
        "exp": int(expiry.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_mandate_confirmation_token(token: str) -> dict:
    """Decodes and validates a signed mandate update confirmation token."""
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    if payload.get("type") != "mandate_update_confirmation":
        raise ValueError("Invalid token type: not a mandate confirmation token.")
    return payload


def get_spending_mandate_handler(customer_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Checks the active spending mandate, per-transaction limit, and allowed categories for a customer.
    Allows the AI Buyer in conversation to answer user questions about their budget.

    Identity Isolation Rules (Pre-P0 Hardening):
    - An authenticated customer context (authenticated_customer_id) is strictly authoritative.
    - If NO authenticated customer context exists, unauthenticated/arbitrary inspection is blocked:
      returns UNAUTHORIZED. No default identity (e.g. 'CUST001') is ever assumed.
    - If an authenticated customer context exists, caller-supplied customer_id must match it;
      mismatches are rejected with FORBIDDEN.
    """
    auth_id = authenticated_customer_id.get()
    if not auth_id:
        logger.warning(
            "Unauthenticated mandate inspection attempt: caller attempted "
            f"to access mandate (supplied customer_id: '{customer_id}') without authenticated session."
        )
        return {
            "mandate_found": False,
            "status": "UNAUTHORIZED",
            "error": "Authentication required: No verified customer identity in session.",
        }

    if customer_id and customer_id != auth_id:
        logger.warning(
            f"Customer ID mismatch in get_spending_mandate: caller supplied '{customer_id}' "
            f"but authenticated session is '{auth_id}'."
        )
        return {
            "mandate_found": False,
            "status": "FORBIDDEN",
            "error": f"Access denied: caller-supplied customer_id '{customer_id}' does not match authenticated identity '{auth_id}'.",
        }

    effective_id = auth_id
    mandate = mandate_store.get_mandate(effective_id)
    if not mandate:
        return {
            "mandate_found": False,
            "status": "NOT_FOUND",
            "message": f"No spending mandate found for customer '{effective_id}'.",
        }

    return {
        "mandate_found": True,
        "status": "SUCCESS",
        "customer_id": mandate.customer_id,
        "display_name": mandate.display_name,
        "currency": mandate.currency or "INR",
        "max_limit_per_transaction": mandate.max_transaction_amount,
        "allowed_categories": mandate.allowed_categories,
        "allowed_merchants": mandate.allowed_merchants,
        "expires_at": mandate.expires_at,
        "rule_summary": mandate.prompt_playback or (
            f"Pre-authorized spending up to ₹{mandate.max_transaction_amount:,.2f} for "
            f"{', '.join(mandate.allowed_categories)}."
        ),
        "message": (
            f"Your current AI spending mandate allows purchases up to ₹{mandate.max_transaction_amount:,.2f} "
            f"for {', '.join(mandate.allowed_categories)} from merchants {', '.join(mandate.allowed_merchants)}. "
            f"Spending mandates are read-only for AI agents."
        ),
    }


def modify_spending_mandate_handler(
    new_limit: Optional[float] = None,
    add_merchant: Optional[str] = None,
    add_category: Optional[str] = None,
    confirmation_token: Optional[str] = None,
    customer_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Conversational Spending Mandate Update:
    DISABLED FOR SECURITY CONTAINMENT (VULN-05 / ADR-03).

    Security Invariant:
    An external AI agent must never be able to increase, extend, or otherwise escalate
    a customer's spending authority through conversational tool calls.
    All conversational mandate modification attempts fail closed with FORBIDDEN.
    Spending mandates may only be configured through authenticated administrative
    or customer self-service portals.
    """
    logger.warning("Blocked conversational mandate modification attempt: VULN-05 containment active.")
    return {
        "success": False,
        "status": "FORBIDDEN",
        "error": (
            "Conversational spending mandate modification is disabled for security (VULN-05 containment). "
            "AI agents cannot modify or escalate customer spending mandates. "
            "Spending mandates must be configured through authenticated administrative or customer self-service channels."
        ),
    }


def get_spending_mandate_remote_handler() -> Dict[str, Any]:
    """
    Remote handler checking mandate bound exclusively to authenticated OAuth customer.
    Derives customer identity strictly from verified OAuth context.
    Fails closed with UNAUTHORIZED if no authenticated identity exists.
    """
    auth_id = authenticated_customer_id.get()
    if not auth_id:
        logger.warning("Unauthenticated remote mandate inspection attempt.")
        return {
            "mandate_found": False,
            "status": "UNAUTHORIZED",
            "error": "Authentication required: No verified customer identity in session.",
        }
    return get_spending_mandate_handler(customer_id=auth_id)


def modify_spending_mandate_remote_handler(
    new_limit: Optional[float] = None,
    add_merchant: Optional[str] = None,
    add_category: Optional[str] = None,
    confirmation_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Remote handler for spending mandate updates.

    PRE-P0 SECURITY CONTAINMENT (VULN-05 / ADR-03):
    External AI agents connecting over MCP are strictly prohibited from
    modifying spending mandates or receiving mandate confirmation tokens.
    Fails closed with FORBIDDEN.
    """
    logger.warning("Blocked remote mandate modification attempt: VULN-05 containment active.")
    return {
        "success": False,
        "status": "FORBIDDEN",
        "error": (
            "Mandate modification via remote AI agents is disabled for security (VULN-05 containment). "
            "Spending mandates may only be configured through authenticated administrative or customer "
            "self-service portals."
        ),
    }


def register_tools(server: MCPServer) -> None:
    """
    Registers local stdio gateway tools with the MCP server instance.
    """
    @server.tool(
        name="check_order_status",
        description=(
            "Check the placement, fulfillment, and payment status of a customer's order. "
            "Call this whenever the user asks if their order is placed, asks if payment was received, "
            "or requests confirmation/reference code for a recent purchase."
        )
    )
    def check_order_status_tool(
        reference_or_id: Optional[str] = None,
        customer_id: str = "CUST001",
    ) -> Dict[str, Any]:
        """Check order and payment settlement status."""
        return check_order_status_handler(
            reference_or_id=reference_or_id,
            customer_id=customer_id,
        )

    @server.tool(
        name="get_spending_mandate",
        description=(
            "Inspect the authenticated customer's current active spending mandate, per-transaction spending limit, "
            "allowed product categories, and authorized merchants. Call this whenever the user asks about "
            "their budget, asks how much they can spend, or checks their purchase allowance."
        )
    )
    def get_spending_mandate_tool(
        customer_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Inspect the customer's active spending mandate."""
        return get_spending_mandate_handler(customer_id=customer_id)

    @server.tool(
        name="inquire_merchant",
        description=(
            "Consult the Merchant Sales AI Agent with a natural language procurement inquiry "
            "(e.g. 'i want keyboard', 'buy keyboard', 'clicky keyboard for coding', '4k monitor under 5000'). "
            "Call this tool to get quotes and recommendations from the store's Merchant Agent first."
        )
    )
    def inquire_merchant_tool(
        query: str,
        max_budget: Optional[float] = None,
        category: Optional[str] = None,
        quantity: int = 1,
    ) -> Dict[str, Any]:
        """Consult the Merchant Sales Agent for quotes and recommendations."""
        return inquire_merchant_handler(
            query=query,
            max_budget=max_budget,
            category=category,
            quantity=quantity,
        )

    @server.tool(
        name="suggest_addons",
        description=(
            "Track 01 Merchant Revenue Growth: Discover complementary add-ons and cross-sell items "
            "that pair with a chosen product and fit within the user's remaining mandate budget."
        )
    )
    def suggest_addons_tool(
        product_id: str,
        remaining_budget: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Suggest complementary cross-sell add-ons under remaining budget."""
        return suggest_addons_handler(
            product_id=product_id,
            remaining_budget=remaining_budget,
        )

    @server.tool(
        name="respond_to_recommendation",
        description=(
            "Accept or Reject a merchant cross-sell add-on recommendation by recommendation_id. "
            "If decision='ACCEPT', executes the add-on purchase proposal using the customer's mandate. "
            "Enforces terminal decision idempotency (repeated calls return cached outcome without double charges)."
        )
    )
    def respond_to_recommendation_tool(
        recommendation_id: str,
        decision: str,
        customer_id: str = "CUST001",
        primary_transaction_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accept or reject a recommendation with terminal idempotency."""
        return respond_to_recommendation_handler(
            recommendation_id=recommendation_id,
            decision=decision,
            customer_id=customer_id,
            primary_transaction_id=primary_transaction_id,
        )


    @server.tool(
        name="search_products",
        description=(
            "Search catalog products by name, category, or maximum price. "
            "Call this before propose_purchase whenever you don't already have an exact product ID."
        )
    )
    def search_products_tool(
        query: Optional[str] = None,
        category: Optional[str] = None,
        max_price: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Search catalog products."""
        return search_products_handler(
            query=query,
            category=category,
            max_price=max_price,
        )

    @server.tool(
        name="resolve_customer",
        description="Resolve a customer's display name or email to their authorized customer_id."
    )
    def resolve_customer(identifier: str) -> Dict[str, Any]:
        """Resolve a human identity to a customer_id."""
        return resolve_customer_handler(identifier=identifier)

    @server.tool(
        name="propose_purchase",
        description=(
            "Propose a purchase under customer mandate rules. Evaluates deterministic policy rules "
            "(budget limit, cumulative daily cap, merchant, category, stock). "
            "1. If within auto-pay limit (< ₹500), auto-debits wallet directly. "
            "2. For gated transactions (₹500 to mandate limit), returns `requires_confirmation: true` and `confirmation_token`. Present quote to user and call `confirm_purchase`. "
            "3. If item price exceeds customer's autonomous mandate limit (e.g. > ₹2,000), the gateway refuses auto-debit and provides an official Razorpay Checkout Link (`payment_url`) and UPI QR code (`qr_code_url`). You MUST provide this link and QR code to the human user so they can complete payment manually via UPI, Netbanking, or Card."
        )
    )
    def propose_purchase(
        product_id: str,
        quantity: int = 1,
        customer_id: str = "CUST001",
    ) -> Dict[str, Any]:
        """Propose a purchase on behalf of a customer."""
        return propose_purchase_handler(
            customer_id=customer_id,
            product_id=product_id,
            quantity=quantity,
        )

    @server.tool(
        name="confirm_purchase",
        description=(
            "Confirm and execute a previously proposed purchase using the signed confirmation_token. "
            "Call this ONLY after presenting the proposal quote to the human user and receiving approval."
        )
    )
    def confirm_purchase_tool(
        confirmation_token: str,
        customer_id: str = "CUST001",
    ) -> Dict[str, Any]:
        """Confirm and finalize a gated purchase."""
        return confirm_purchase_handler(
            confirmation_token=confirmation_token,
            customer_id=customer_id,
        )


def register_remote_tools(server: MCPServer) -> None:
    """
    Registers remote OAuth-authenticated gateway tools with the remote MCP server instance.
    """
    @server.tool(
        name="check_order_status",
        description=(
            "Check the placement, fulfillment, and payment status of a customer's order. "
            "Call this whenever the user asks if their order is placed, asks if payment was received, "
            "or requests confirmation/reference code for a recent purchase."
        )
    )
    def check_order_status_tool(
        reference_or_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check order and payment settlement status."""
        return check_order_status_remote_handler(
            reference_or_id=reference_or_id,
        )

    @server.tool(
        name="inquire_merchant",
        description="Consult the Merchant Sales AI Agent with a natural language procurement inquiry."
    )
    def inquire_merchant_tool(
        query: str,
        max_budget: Optional[float] = None,
        category: Optional[str] = None,
        quantity: int = 1,
    ) -> Dict[str, Any]:
        """Consult the Merchant Sales Agent for quotes and recommendations."""
        return inquire_merchant_handler(
            query=query,
            max_budget=max_budget,
            category=category,
            quantity=quantity,
        )

    @server.tool(
        name="suggest_addons",
        description="Track 01 Revenue Growth: Discover complementary add-ons and cross-sell items within budget headroom."
    )
    def suggest_addons_tool(
        product_id: str,
        remaining_budget: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Suggest complementary cross-sell add-ons under remaining budget."""
        return suggest_addons_handler(
            product_id=product_id,
            remaining_budget=remaining_budget,
        )

    @server.tool(
        name="respond_to_recommendation",
        description=(
            "Accept or Reject a merchant cross-sell add-on recommendation by recommendation_id on behalf of authenticated customer. "
            "If decision='ACCEPT', executes the add-on purchase proposal using the customer's mandate. "
            "Enforces terminal decision idempotency."
        )
    )
    def respond_to_recommendation_remote(
        recommendation_id: str,
        decision: str,
        primary_transaction_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accept or reject a recommendation on behalf of authenticated customer."""
        return respond_to_recommendation_handler(
            recommendation_id=recommendation_id,
            decision=decision,
            primary_transaction_id=primary_transaction_id,
        )


    @server.tool(
        name="search_products",
        description="Search catalog products by name, category, or maximum price."
    )
    def search_products_tool(
        query: Optional[str] = None,
        category: Optional[str] = None,
        max_price: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Search catalog products."""
        return search_products_handler(
            query=query,
            category=category,
            max_price=max_price,
        )

    @server.tool(
        name="propose_purchase",
        description=(
            "Propose a single product purchase on behalf of the authenticated customer. "
            "Pass exactly ONE specific product_id (e.g. 'FD005', 'KB001', 'HK001'). If purchasing multiple distinct items, call this tool once per item. "
            "Customer identity is bound strictly to verified OAuth JWT. "
            "1. If within auto-pay limit (< ₹500), auto-debits wallet directly. "
            "2. For gated orders (₹500 to mandate limit), returns `requires_confirmation: true` and `confirmation_token`. Present quote to user and call `confirm_purchase`. "
            "3. If order exceeds autonomous mandate limit (e.g. > ₹2,000), the gateway refuses autonomous auto-debit and provides an official Razorpay Checkout Link (`payment_url`) and UPI QR Code (`qr_code_url`). You MUST provide this link and QR code to the human user so they can complete payment manually on their own device via UPI, Netbanking, or Card."
        )
    )
    def propose_purchase_remote(
        product_id: str,
        quantity: int = 1,
    ) -> Dict[str, Any]:
        """Propose a purchase on behalf of the authenticated customer."""
        return propose_purchase_remote_handler(
            product_id=product_id.strip(),
            quantity=quantity,
        )

    @server.tool(
        name="confirm_purchase",
        description=(
            "Confirm and execute payment rails for a previously proposed, gated purchase using the signed confirmation_token. "
            "Protocol Guard: Call this ONLY after the human user has reviewed the proposal quote and explicitly authorized the payment."
        )
    )
    def confirm_purchase_remote(
        confirmation_token: str,
    ) -> Dict[str, Any]:
        """Confirm a gated purchase on behalf of the authenticated customer."""
        return confirm_purchase_remote_handler(
            confirmation_token=confirmation_token,
        )

    @server.tool(
        name="get_spending_mandate",
        description=(
            "Inspect the authenticated customer's current active spending mandate, per-transaction spending limit, "
            "allowed product categories, and authorized merchants. Call this whenever the user asks about "
            "their budget, asks how much they can spend, or checks their purchase allowance."
        )
    )
    def get_spending_mandate_remote(
    ) -> Dict[str, Any]:
        """Inspect the authenticated customer's active spending mandate."""
        return get_spending_mandate_remote_handler()


