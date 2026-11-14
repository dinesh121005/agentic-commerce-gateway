from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import verify_admin_key
from app.catalog.models import CreateProductRequest, Product, UpdateProductRequest
from app.catalog.service import (
    archive_product,
    create_product,
    get_product,
    list_products_admin,
    search_products,
    update_product,
)
from app.exceptions import ProductNotFoundError

router = APIRouter(prefix="/products", tags=["catalog"])


@router.get("", response_model=List[Product], summary="List and filter catalog products")
def list_products(
    query: Optional[str] = Query(
        default=None,
        description="Filter products by product name (case-insensitive substring)"
    ),
    category: Optional[str] = Query(
        default=None,
        description="Filter products by category name (case-insensitive exact match)"
    ),
    max_price: Optional[float] = Query(
        default=None,
        gt=0,
        description="Filter products with price less than or equal to this maximum amount in INR (₹)"
    ),
    include_all: Optional[bool] = Query(
        default=False,
        description="Include inactive/archived items (Admin view)"
    ),
    merchant_id: Optional[str] = Query(
        default=None,
        description="Filter products scoped to a specific merchant identifier"
    ),
) -> List[Product]:
    """
    Retrieve products from the catalog.
    Supports optional filtering by keyword query, category, maximum price, and merchant ID.
    """
    try:
        if include_all:
            return list_products_admin(merchant_id=merchant_id)
        return search_products(query=query, category=category, max_price=max_price, merchant_id=merchant_id)
    except Exception as e:
        import logging
        logging.getLogger("gateway.catalog").error("Error listing products from catalog: %s", e, exc_info=True)
        from app.catalog.data import PRODUCTS
        if include_all:
            return [p for p in PRODUCTS if not merchant_id or p.merchant_id == merchant_id]
        if query or category or max_price or merchant_id:
            from app.catalog.data import PRODUCTS
            res = PRODUCTS
            if merchant_id:
                res = [p for p in res if p.merchant_id == merchant_id]
            if category:
                res = [p for p in res if p.category.lower() == category.strip().lower()]
            if max_price:
                res = [p for p in res if p.price <= max_price]
            if query:
                q = query.strip().lower()
                res = [p for p in res if q in p.name.lower() or q in p.description.lower()]
            return res
        return PRODUCTS


@router.get("/{id}", response_model=Product, summary="Get product details by ID")
def get_product_endpoint(
    id: str,
    merchant_id: Optional[str] = Query(default=None, description="Optional merchant context"),
) -> Product:
    """
    Retrieve single product details by product ID.
    Returns 404 if the product is not found in the catalog.
    """
    try:
        return get_product(id, merchant_id=merchant_id)
    except ProductNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@router.post(
    "",
    response_model=Product,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new catalog product (Admin CRUD)",
    dependencies=[Depends(verify_admin_key)],
)
def create_product_endpoint(payload: CreateProductRequest) -> Product:
    """Admin endpoint to provision a new catalog product."""
    try:
        return create_product(payload)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )


@router.patch(
    "/{id}",
    response_model=Product,
    status_code=status.HTTP_200_OK,
    summary="Update catalog product details (Admin CRUD)",
    dependencies=[Depends(verify_admin_key)],
)
def update_product_endpoint(
    id: str,
    payload: UpdateProductRequest,
    merchant_id: Optional[str] = Query(default=None, description="Optional merchant filter"),
) -> Product:
    """Admin endpoint to update price, stock, description, or status of a catalog product."""
    try:
        return update_product(id, payload, merchant_id=merchant_id)
    except ProductNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.delete(
    "/{id}",
    status_code=status.HTTP_200_OK,
    summary="Archive a catalog product (Soft Delete)",
    dependencies=[Depends(verify_admin_key)],
)
def archive_product_endpoint(
    id: str,
    merchant_id: Optional[str] = Query(default=None, description="Optional merchant filter"),
) -> dict:
    """Admin endpoint to soft-delete a catalog product by setting status = 'ARCHIVED'."""
    success = archive_product(id, merchant_id=merchant_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product '{id}' not found or already archived.",
        )
    return {"status": "ok", "message": f"Product '{id}' archived successfully."}
