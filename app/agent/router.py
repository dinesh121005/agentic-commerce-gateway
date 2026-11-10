"""
Agent commerce HTTP router.

Exposes POST /agent/purchase as a thin FastAPI wrapper around the core
purchase execution service in app.agent.service.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status

from app.agent.service import (
    AgentPurchaseRequest,
    ConfirmPurchaseRequest,
    PurchaseResponse,
    confirm_purchase,
    execute_purchase,
)
from app.auth import verify_agent_or_admin_auth
from app.exceptions import (
    InsufficientStockError,
    InvalidPurchaseError,
    MandateNotFoundError,
    ProductNotFoundError,
    StalePriceError,
)

router = APIRouter(prefix="/agent", tags=["agent"])


@router.post(
    "/purchase",
    response_model=PurchaseResponse,
    status_code=status.HTTP_200_OK,
    summary="Propose an agent purchase transaction",
    description="Secure endpoint evaluating policy mandate. Requires OAuth Bearer token or Admin API Key."
)
def propose_purchase(
    payload: AgentPurchaseRequest,
    auth: dict = Depends(verify_agent_or_admin_auth),
) -> PurchaseResponse:
    """
    HTTP handler delegating to the core purchase execution service.
    Binds customer identity strictly to OAuth JWT sub claim for agent callers,
    or allows explicit customer_id specification for authorized admin callers.
    """
    # If authenticated via OAuth token, bind strictly to verified sub claim
    if auth["auth_type"] == "oauth":
        effective_customer_id = auth["customer_id"]
    else:
        # Admin key authentication: permit explicit customer_id in request
        effective_customer_id = payload.customer_id

    try:
        return execute_purchase(
            customer_id=effective_customer_id,
            product_id=payload.product_id,
            quantity=payload.quantity,
            idempotency_key=payload.idempotency_key,
            logical_order_group_id=payload.logical_order_group_id,
            recommendation_id=payload.recommendation_id,
        )

    except (ProductNotFoundError, MandateNotFoundError) as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except InsufficientStockError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except InvalidPurchaseError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )


@router.post(
    "/confirm",
    response_model=PurchaseResponse,
    status_code=status.HTTP_200_OK,
    summary="Confirm a gated agent purchase proposal",
    description="Executes payment and order creation for a previously proposed purchase using a valid confirmation token."
)
def confirm_purchase_endpoint(
    payload: ConfirmPurchaseRequest,
    auth: dict = Depends(verify_agent_or_admin_auth),
) -> PurchaseResponse:
    """
    HTTP handler validating confirmation tokens and executing final Razorpay orders.
    """
    caller_customer_id = auth["customer_id"] if auth["auth_type"] == "oauth" else None

    try:
        return confirm_purchase(
            confirmation_token=payload.confirmation_token,
            customer_id=caller_customer_id,
        )
    except StalePriceError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "STALE_PRICE_DETECTED",
                "message": str(e),
                "product_id": e.product_id,
                "proposed_amount": e.proposed_amount,
                "live_amount": e.live_amount,
            }
        )
    except InsufficientStockError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except (InvalidPurchaseError, ProductNotFoundError, MandateNotFoundError) as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )

