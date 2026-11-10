"""
Agent commerce service layer.

Provides transport-agnostic purchase proposal orchestration, confirmation gating,
deterministic policy mandate evaluation, inventory management, auto-debit wallet settlement,
and Razorpay payment links / UPI QR code generation.
"""
import hashlib
from datetime import datetime, timedelta, timezone
import sqlite3
import time
from typing import Optional
from uuid import uuid4

import jwt
from pydantic import BaseModel, Field

from app.audit import AuditRecord, audit_store
from app.catalog.service import decrement_stock, get_product, restore_stock
from app.exceptions import (
    InsufficientStockError,
    InvalidPurchaseError,
    MandateNotFoundError,
    ProductNotFoundError,
    StalePriceError,
)
import os
import urllib.parse
from app.oauth.crypto import JWT_SECRET
from app.payment import PaymentResult, create_order_for_approved
from app.payment.service import create_payment_link_for_manual, generate_checkout_token
from app.policy.engine import evaluate
from app.policy.requests import PurchaseRequest
from app.policy.store import mandate_store
from app.wallet.store import wallet_store

# Autonomous execution threshold: orders under ₹500 can auto-execute within mandate.
# Orders >= ₹500 require human confirmation token for safety and gating.
AUTO_CONFIRM_THRESHOLD = 500.0
CONFIRMATION_TOKEN_TTL_SECONDS = 300  # 5 minutes
CONFIRMATION_TOKEN_SECRET = os.environ.get("CONFIRMATION_TOKEN_SECRET", JWT_SECRET)


def generate_bucketed_idempotency_key(
    customer_id: str,
    product_id: str,
    quantity: int,
    timestamp: Optional[float] = None,
) -> str:
    """
    Generate a deterministic idempotency key bucketed to the nearest 60-second window.
    Format: sha256 of (customer_id:product_id:quantity:floor(current_unix_timestamp / 60))
    """
    ts = time.time() if timestamp is None else timestamp
    bucket = int(ts // 60)
    raw = f"{customer_id.strip()}:{product_id.strip()}:{quantity}:{bucket}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def generate_confirmation_token(
    customer_id: str,
    product_id: str,
    quantity: int,
    amount: float,
    transaction_id: str,
    idempotency_key: str,
    merchant_id: Optional[str] = None,
) -> str:
    """
    Generates a cryptographically signed, short-lived JWT confirmation token.
    Binds customer, SKU, quantity, authoritative amount, currency, and merchant.
    Uses dedicated CONFIRMATION_TOKEN_SECRET for token-purpose separation (VULN-06).
    """
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(seconds=CONFIRMATION_TOKEN_TTL_SECONDS)
    payload = {
        "sub": customer_id,
        "product_id": product_id,
        "quantity": quantity,
        "amount": amount,
        "currency": "INR",
        "merchant_id": merchant_id,
        "transaction_id": transaction_id,
        "idempotency_key": idempotency_key,
        "type": "purchase_confirmation",
        "purpose": "purchase_confirmation",
        "iat": int(now.timestamp()),
        "exp": int(expiry.timestamp()),
    }
    return jwt.encode(payload, CONFIRMATION_TOKEN_SECRET, algorithm="HS256")


def decode_confirmation_token(token: str) -> dict:
    """
    Decodes and validates a signed purchase confirmation token.
    Enforces dedicated secret and token-purpose validation.
    Raises jwt.PyJWTError on expiration or signature tampering.
    """
    payload = jwt.decode(
        token,
        CONFIRMATION_TOKEN_SECRET,
        algorithms=["HS256"],
    )
    token_type = payload.get("type") or payload.get("purpose")
    if token_type != "purchase_confirmation":
        raise InvalidPurchaseError("Invalid token type: not a purchase confirmation token")
    return payload


def _build_replayed_response(record: AuditRecord) -> "PurchaseResponse":
    """
    Constructs a PurchaseResponse from an existing audit trail record.
    Ensures consistent shape for cached/replayed responses.
    """
    mandate = mandate_store.get_mandate(record.customer_id)
    limit = mandate.max_transaction_amount if mandate else record.amount
    payment = None
    if record.payment_status is not None:
        base_url = os.environ.get("BASE_URL", "https://razorpay-c454.onrender.com").rstrip("/")
        effective_key = os.environ.get("RAZORPAY_KEY_ID") or "rzp_test_51tPkUG58N7Lkg"
        checkout_token = generate_checkout_token(record.transaction_id, record.amount, record.customer_id)
        query = urllib.parse.urlencode({
            "order_id": record.razorpay_order_id or f"order_{record.transaction_id.replace('-', '')[:16]}",
            "amount": f"{record.amount:.2f}",
            "product": record.product_id,
            "key": effective_key,
            "customer": record.customer_id,
            "receipt": record.transaction_id,
            "token": checkout_token,
            "auto_open": "1",
        })
        checkout_url = f"{base_url}/checkout?{query}"
        payment = PaymentResult(
            status=record.payment_status,
            razorpay_order_id=record.razorpay_order_id,
            razorpay_payment_id=record.razorpay_payment_id,
            payment_url=checkout_url,
            qr_code_url=f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={urllib.parse.quote(checkout_url)}",
            payment_method="auto_debit" if record.payment_status == "captured" else "razorpay_order",
        )
    return PurchaseResponse(
        decision=record.decision,
        reason=record.decision_reason,
        product_id=record.product_id,
        amount=record.amount,
        mandate_limit=limit,
        transaction_id=record.transaction_id,
        payment=payment,
        idempotency_key=record.idempotency_key,
    )


class AgentPurchaseRequest(BaseModel):
    """
    Request payload for an AI shopping agent proposing a purchase.
    """
    customer_id: str = Field(..., description="Unique customer identifier who authorized the mandate")
    product_id: str = Field(..., description="Unique identifier of the product being purchased")
    quantity: int = Field(default=1, ge=1, description="Quantity of items to purchase (must be >= 1)")
    idempotency_key: Optional[str] = Field(
        default=None,
        description="Optional client-supplied idempotency key to prevent duplicate orders on retry. Auto-generated if omitted."
    )
    logical_order_group_id: Optional[str] = Field(
        default=None,
        description="Shared logical order group UUID linking primary and add-on transactions for AOV/attach rate telemetry."
    )
    recommendation_id: Optional[str] = Field(
        default=None,
        description="Optional recommendation UUID if purchasing a recommended add-on."
    )


class ConfirmPurchaseRequest(BaseModel):
    """
    Request payload for confirming a previously proposed, gated purchase.
    """
    confirmation_token: str = Field(..., description="Signed confirmation token generated by propose_purchase")


class PurchaseResponse(BaseModel):
    """
    Response payload returned with the policy engine verdict, payment outcome, and confirmation gating.
    """
    decision: str = Field(..., description="Policy decision status: APPROVED, REJECTED, PENDING_CONFIRMATION, or PAYMENT_FAILED")
    reason: str = Field(..., description="Human-readable explanation of the policy decision")
    product_id: str = Field(..., description="Identifier of the requested product")
    amount: float = Field(..., description="Total computed transaction amount (price × quantity) in INR (₹)")
    mandate_limit: float = Field(..., description="Customer's maximum transaction limit from mandate in INR (₹)")
    transaction_id: str = Field(..., description="Gateway-minted UUID for this proposal, used as Razorpay receipt")
    payment: Optional[PaymentResult] = Field(
        default=None,
        description="Razorpay order or payment link result when decision is evaluated."
    )
    idempotency_key: Optional[str] = Field(
        default=None,
        description="Client-supplied or bucket-generated idempotency key associated with this transaction"
    )
    requires_confirmation: bool = Field(
        default=False,
        description="Indicates whether this purchase is gated and requires explicit human confirmation via confirm_purchase"
    )
    confirmation_token: Optional[str] = Field(
        default=None,
        description="Time-limited signed token required to execute confirm_purchase"
    )
    logical_order_group_id: Optional[str] = Field(
        default=None,
        description="Shared logical order group UUID linking primary and add-on transactions."
    )
    recommendation_id: Optional[str] = Field(
        default=None,
        description="Optional recommendation UUID associated with this purchase."
    )



def execute_purchase(
    customer_id: str,
    product_id: str,
    quantity: int = 1,
    idempotency_key: Optional[str] = None,
    logical_order_group_id: Optional[str] = None,
    recommendation_id: Optional[str] = None,
) -> PurchaseResponse:

    """
    Executes the purchase proposal orchestration:
    1. Validate input parameters (quantity >= 1 and integer).
    2. Resolve mandatory idempotency_key (override if provided, else deterministic 60s bucket).
    3. Check idempotency replay: return cached record if idempotency_key was already processed.
    4. Look up product in catalog (raises ProductNotFoundError if not found).
    5. Check inventory stock (raises InsufficientStockError if quantity > stock).
    6. Look up customer mandate in store (raises MandateNotFoundError if not found).
    7. Compute total amount (price * quantity).
    8. Check current daily spend against mandate daily limit.
    9. Evaluate proposal against customer mandate (deterministic, no side effects).
    10. Mint a unique transaction_id for cross-system tracing.
    11. Phase A Audit: Record proposal, verdict, and reasoning in SQLite audit store.
    12. Check Safety Confirmation Gate & Policy Execution:
        - If APPROVED and amount >= ₹500:
          Return PENDING_CONFIRMATION with confirmation_token (no payment yet).
        - If APPROVED and amount < ₹500:
          Execute Razorpay order & auto-debit customer pre-authorized balance, decrement inventory, update Phase B audit, return APPROVED.
        - If REJECTED (Out of Mandate / Exceeds Limit):
          Generate Razorpay Payment Link and dynamic UPI QR Code so user can pay via their own app.
    """
    # 1. Transport-agnostic input validation
    if not isinstance(quantity, int) or quantity < 1:
        raise InvalidPurchaseError(f"Quantity must be a positive integer (>= 1), got {quantity}")

    # 2. Mandatory internal idempotency key resolution
    if not idempotency_key or not idempotency_key.strip():
        idempotency_key = generate_bucketed_idempotency_key(customer_id, product_id, quantity)
    else:
        idempotency_key = idempotency_key.strip()

    # 3. Idempotency replay check
    existing_record = audit_store.get_by_idempotency_key(idempotency_key)
    if existing_record is not None:
        return _build_replayed_response(existing_record)

    # 4. Catalog lookup (raises ProductNotFoundError if not found)
    product = get_product(product_id)

    # 5. Inventory stock availability check
    if quantity > product.stock:
        raise InsufficientStockError(
            product_id=product.id,
            requested=quantity,
            available=product.stock,
        )

    # 6. Mandate lookup (raises MandateNotFoundError if not found)
    mandate = mandate_store.get_mandate(customer_id)
    if mandate is None:
        raise MandateNotFoundError(customer_id)

    # 7. Compute total transaction amount in authoritative integer paise and decimal INR
    from decimal import Decimal, ROUND_HALF_UP
    if getattr(product, "price_paise", None) is not None:
        amount_paise = product.price_paise * quantity
        amount = round(amount_paise / 100.0, 2)
    else:
        amount_paise = int((Decimal(str(product.price)) * Decimal("100") * quantity).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        amount = round(amount_paise / 100.0, 2)

    # 8. Query approved daily spend from audit store
    current_daily_spend = audit_store.get_daily_spend(customer_id)

    # 9. Build internal PurchaseRequest model & Evaluate via Policy Engine
    purchase_request = PurchaseRequest(
        customer_id=customer_id,
        product_id=product.id,
        category=product.category,
        amount=amount,
        amount_paise=amount_paise,
        merchant=product.merchant_id,
        quantity=quantity,
    )
    decision = evaluate(purchase_request, mandate, current_daily_spend=current_daily_spend)

    # 10. Mint a unique transaction ID for tracing across systems
    transaction_id = str(uuid4())

    # 11. Evaluate Gating vs Immediate Execution (Strict non-bypassable threshold)
    requires_confirmation = (
        decision.status == "APPROVED"
        and amount_paise >= 50000
    )

    initial_decision_status = "PENDING_CONFIRMATION" if requires_confirmation else decision.status
    decision_reason = (
        f"Proposal approved by policy (₹{amount:.2f} <= mandate limit of ₹{mandate.max_transaction_amount:.2f}). "
        f"Gating Rule: Transactions >= ₹{AUTO_CONFIRM_THRESHOLD:.2f} require explicit human confirmation before payment. "
        f"Present quote to customer and execute with confirm_purchase."
        if requires_confirmation
        else decision.reason
    )

    confirmation_token = None
    if requires_confirmation:
        confirmation_token = generate_confirmation_token(
            customer_id=customer_id,
            product_id=product.id,
            quantity=quantity,
            amount=amount,
            transaction_id=transaction_id,
            idempotency_key=idempotency_key,
            merchant_id=product.merchant_id,
        )

    # 12. Phase A Audit: Record the evaluated proposal and rule decision
    try:
        audit_store.write_proposal(
            transaction_id=transaction_id,
            customer_id=customer_id,
            product_id=product.id,
            merchant_id=product.merchant_id,
            quantity=quantity,
            amount=amount,
            decision=initial_decision_status,
            decision_reason=decision_reason,
            idempotency_key=idempotency_key,
            amount_paise=amount_paise,
        )
    except Exception:
        # Race condition & lock contention safeguard: check if concurrent request committed winning record
        existing_record = audit_store.get_by_idempotency_key(idempotency_key)
        if existing_record is not None:
            return _build_replayed_response(existing_record)
        raise

    # 13. Payment execution:
    # - If APPROVED (< ₹500): Order creation + Auto-debit
    # - If REJECTED (Out of Mandate): Generate Payment Link & UPI QR for manual user checkout
    payment_result = None
    final_decision = initial_decision_status

    if decision.status == "APPROVED" and not requires_confirmation:
        # 1. Create Razorpay Test Order
        payment_result = create_order_for_approved(
            amount_inr=amount,
            receipt=transaction_id,
            customer_id=customer_id,
            product_id=product.id,
        )
        if payment_result.status == "failed":
            final_decision = "PAYMENT_FAILED"
            decision_reason = f"Policy approved purchase of {product.name} (₹{amount:.2f}), but Razorpay payment rail failed: {payment_result.error}"
            audit_store.update_payment_outcome(
                transaction_id=transaction_id,
                payment_status="failed",
                razorpay_order_id=payment_result.razorpay_order_id,
            )
        elif payment_result.status == "status_unknown":
            final_decision = "PAYMENT_FAILED"
            decision_reason = f"Policy approved purchase of {product.name} (₹{amount:.2f}), but Razorpay returned unknown status: {payment_result.error}"
            audit_store.update_payment_outcome(
                transaction_id=transaction_id,
                payment_status="status_unknown",
                razorpay_order_id=payment_result.razorpay_order_id,
            )
        else:
            # 2. Atomic stock decrement (concurrency guard against overselling)
            if not decrement_stock(product.id, quantity):
                final_decision = "PAYMENT_FAILED"
                decision_reason = f"Stock was depleted before order settlement: insufficient inventory."
                payment_result.status = "failed"
                payment_result.error = "Insufficient inventory stock"
                audit_store.update_payment_outcome(
                    transaction_id=transaction_id,
                    payment_status="failed",
                    razorpay_order_id=payment_result.razorpay_order_id,
                )
            else:
                # 3. Auto-debit customer pre-authorized sandbox mandate balance
                debit_success, remaining_bal, debit_msg = wallet_store.debit(customer_id, amount)
                if not debit_success:
                    # Saga compensating rollback: restore decremented inventory stock
                    restore_stock(product.id, quantity)
                    final_decision = "PAYMENT_FAILED"
                    decision_reason = f"Policy approved purchase of {product.name} (₹{amount:.2f}), but sandbox mandate wallet debit failed: {debit_msg}"
                    payment_result.status = "failed"
                    payment_result.error = debit_msg
                    audit_store.update_payment_outcome(
                        transaction_id=transaction_id,
                        payment_status="failed",
                        razorpay_order_id=payment_result.razorpay_order_id,
                    )
                else:
                    # 4. Transparent simulated mandate settlement: mint authentic tracking ID & record capture
                    payment_id = f"pay_mandate_{uuid4().hex[:14]}"
                    payment_result.status = "captured"
                    payment_result.razorpay_payment_id = payment_id
                    payment_result.payment_method = "auto_debit"

                    # Phase B Audit: Update row with settled payment outcome & payment_id
                    audit_store.update_payment_outcome(
                        transaction_id=transaction_id,
                        payment_status="captured",
                        razorpay_order_id=payment_result.razorpay_order_id,
                        razorpay_payment_id=payment_id,
                    )
    elif decision.status == "REJECTED":
        # Out-of-mandate graceful escalation: generate Payment Link & UPI QR so customer can pay via their own app
        payment_result = create_payment_link_for_manual(
            amount_inr=amount,
            receipt=transaction_id,
            customer_id=customer_id,
            product_id=product.id,
            product_name=product.name,
        )

    effective_group_id = logical_order_group_id or f"GRP-{transaction_id[-8:]}"

    return PurchaseResponse(
        decision=final_decision,
        reason=decision_reason,
        product_id=product.id,
        amount=amount,
        mandate_limit=mandate.max_transaction_amount,
        transaction_id=transaction_id,
        payment=payment_result,
        idempotency_key=idempotency_key,
        requires_confirmation=requires_confirmation,
        confirmation_token=confirmation_token,
        logical_order_group_id=effective_group_id,
        recommendation_id=recommendation_id,
    )



def confirm_purchase(
    confirmation_token: str,
    customer_id: Optional[str] = None,
) -> PurchaseResponse:
    """
    Executes a previously proposed, gated purchase using the signed confirmation token:
    1. Decodes and verifies the confirmation token (checks signature & 5-minute expiry).
    2. Validates identity matches token 'sub' claim if customer_id is provided.
    3. Idempotency & Replay Guard: Checks if transaction_id has already been confirmed/finalized.
    4. Re-verifies catalog inventory stock availability.
    5. Re-evaluates deterministic policy engine mandate rules at confirmation time.
    6. Creates Razorpay Test Mode order and settles via auto-debit.
    7. Decrements inventory stock.
    8. Updates audit record from PENDING_CONFIRMATION to APPROVED and logs payment outcome.
    9. Returns shaped PurchaseResponse with confirmed reference code.
    """
    try:
        payload = decode_confirmation_token(confirmation_token)
    except jwt.ExpiredSignatureError:
        raise InvalidPurchaseError("Confirmation token has expired (valid for 5 minutes). Please propose the purchase again.")
    except Exception as exc:
        raise InvalidPurchaseError(f"Invalid confirmation token: {str(exc)}")

    token_customer_id = payload["sub"]
    if customer_id and customer_id.strip() != token_customer_id:
        raise InvalidPurchaseError(
            f"Confirmation token customer '{token_customer_id}' does not match caller '{customer_id}'"
        )

    product_id = payload["product_id"]
    quantity = payload["quantity"]
    amount = payload["amount"]
    transaction_id = payload["transaction_id"]
    idempotency_key = payload.get("idempotency_key")

    # 1. Idempotency & Replay Guard: Check if transaction has already been finalized
    existing_record = audit_store.get(transaction_id)
    if existing_record is not None and (
        existing_record.decision == "APPROVED"
        or existing_record.payment_status in ("created", "captured")
    ):
        return _build_replayed_response(existing_record)

    # Atomic single-use claim to prevent concurrent duplicate execution (ADR-02 §4.1 item 6)
    if not audit_store.claim_confirmation(transaction_id):
        import time
        for _ in range(25):
            time.sleep(0.04)
            rec = audit_store.get(transaction_id)
            if rec and (rec.decision == "APPROVED" or rec.payment_status in ("created", "captured")):
                return _build_replayed_response(rec)
        rec = audit_store.get(transaction_id)
        if rec and (rec.decision == "APPROVED" or rec.payment_status in ("created", "captured")):
            return _build_replayed_response(rec)
        raise InvalidPurchaseError("Confirmation token currently in-flight or already consumed")

    # 2. Re-verify stock & Live Catalog Pricing Parity (P0.1: STALE_PRICE_DETECTED)
    product = get_product(product_id)
    if product.stock < quantity:
        audit_store.release_confirmation_claim(transaction_id)
        raise InsufficientStockError(
            product_id=product.id,
            requested=quantity,
            available=product.stock,
        )

    # Authoritative integer paise price parity check
    from decimal import Decimal, ROUND_HALF_UP
    if getattr(product, "price_paise", None) is not None:
        expected_amount_paise = product.price_paise * quantity
    else:
        expected_amount_paise = int((Decimal(str(product.price)) * Decimal("100") * quantity).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

    token_amount_paise = int((Decimal(str(amount)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

    if expected_amount_paise != token_amount_paise:
        audit_store.release_confirmation_claim(transaction_id)
        raise StalePriceError(
            product_id=product.id,
            proposed_amount=amount,
            live_amount=round(expected_amount_paise / 100.0, 2),
        )

    # 3. Mandate Lookup & Deterministic Policy Re-Evaluation at Confirmation Time
    mandate = mandate_store.get_mandate(token_customer_id)
    if mandate is None:
        audit_store.release_confirmation_claim(transaction_id)
        raise MandateNotFoundError(token_customer_id)

    current_daily_spend = audit_store.get_daily_spend(token_customer_id)
    purchase_request = PurchaseRequest(
        customer_id=token_customer_id,
        product_id=product.id,
        category=product.category,
        amount=amount,
        amount_paise=expected_amount_paise,
        merchant=product.merchant_id,
        quantity=quantity,
    )
    decision = evaluate(purchase_request, mandate, current_daily_spend=current_daily_spend)
    if decision.status != "APPROVED":
        audit_store.release_confirmation_claim(transaction_id)
        raise InvalidPurchaseError(f"Policy evaluation rejected purchase at confirmation time: {decision.reason}")

    limit = mandate.max_transaction_amount

    # 4. Execute Razorpay payment order
    payment_result = create_order_for_approved(
        amount_inr=amount,
        receipt=transaction_id,
        customer_id=token_customer_id,
        product_id=product.id,
    )

    if payment_result.status == "failed":
        final_decision = "PAYMENT_FAILED"
        reason = f"Human confirmation verified, but Razorpay payment rail failed: {payment_result.error}"
        audit_store.update_payment_outcome(
            transaction_id=transaction_id,
            payment_status="failed",
            razorpay_order_id=payment_result.razorpay_order_id,
        )
    elif payment_result.status == "status_unknown":
        final_decision = "PAYMENT_FAILED"
        reason = f"Human confirmation verified, but Razorpay returned unknown status: {payment_result.error}"
        audit_store.update_payment_outcome(
            transaction_id=transaction_id,
            payment_status="status_unknown",
            razorpay_order_id=payment_result.razorpay_order_id,
        )
    else:
        # 1. Atomic inventory stock decrement (concurrency guard against overselling)
        if not decrement_stock(product.id, quantity):
            final_decision = "PAYMENT_FAILED"
            reason = f"Human confirmation verified, but stock was depleted: insufficient inventory."
            payment_result.status = "failed"
            payment_result.error = "Insufficient inventory stock"
            audit_store.update_payment_outcome(
                transaction_id=transaction_id,
                payment_status="failed",
                razorpay_order_id=payment_result.razorpay_order_id,
            )
        else:
            # 2. Auto-debit customer pre-authorized balance
            debit_success, remaining_bal, debit_msg = wallet_store.debit(token_customer_id, amount)
            if not debit_success:
                # Saga compensating rollback: restore decremented stock
                restore_stock(product.id, quantity)
                final_decision = "PAYMENT_FAILED"
                reason = f"Human confirmation verified, but sandbox mandate wallet debit failed: {debit_msg}"
                payment_result.status = "failed"
                payment_result.error = debit_msg
                audit_store.update_payment_outcome(
                    transaction_id=transaction_id,
                    payment_status="failed",
                    razorpay_order_id=payment_result.razorpay_order_id,
                )
            else:
                final_decision = "APPROVED"
                reason = f"Human confirmation verified. Transaction approved and settled via customer simulated mandate balance for ₹{amount:.2f} (Razorpay Order: {payment_result.razorpay_order_id})."

                payment_id = f"pay_mandate_{uuid4().hex[:14]}"
                payment_result.status = "captured"
                payment_result.razorpay_payment_id = payment_id
                payment_result.payment_method = "auto_debit"

                # 5. Update audit record to final approved state
                audit_store.update_payment_outcome(
                    transaction_id=transaction_id,
                    payment_status="captured",
                    razorpay_order_id=payment_result.razorpay_order_id,
                    razorpay_payment_id=payment_id,
                )

    return PurchaseResponse(
        decision=final_decision,
        reason=reason,
        product_id=product.id,
        amount=amount,
        mandate_limit=limit,
        transaction_id=transaction_id,
        payment=payment_result,
        idempotency_key=idempotency_key,
        requires_confirmation=False,
        confirmation_token=None,
    )
