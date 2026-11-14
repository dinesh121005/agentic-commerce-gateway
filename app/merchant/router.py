"""
FastAPI REST Router for Multi-Tenant Merchant Identity, Authentication & RBAC.
Mounted at /api/v1.
"""
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, status

from app.audit.models import AuditRecord
from app.audit.store import audit_store
from app.catalog import service as catalog_service
from app.catalog.models import CreateProductRequest, Product, UpdateProductRequest
from app.core.context import (
    TenantContext,
    get_current_tenant_context,
    reset_current_tenant_context,
    set_current_tenant_context,
)
from app.exceptions import ProductNotFoundError
from app.merchant import crypto, rbac
from app.merchant.models import (
    AcceptInvitationRequest,
    AvailableMerchantOrganization,
    CreateInvitationRequest,
    CreateMemberRequest,
    CreateMerchantRequest,
    CurrentMerchantProfile,
    CurrentUserProfile,
    InvitationResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
    MerchantMembershipResponse,
    MerchantResponse,
    RegisterMerchantRequest,
    SwitchMerchantRequest,
    UpdateMemberRequest,
)
from app.merchant.rate_limit import login_rate_limiter
from app.merchant.service import merchant_service
from app.merchant.store import merchant_store

logger = logging.getLogger("gateway.merchant.router")
router = APIRouter(prefix="/api/v1", tags=["merchant-identity"])


# ══════════════════════════════════════════════════════════════════════════════
# Centralized Authentication & Tenant Context Dependencies
# ══════════════════════════════════════════════════════════════════════════════

def get_current_merchant_user(request: Request) -> Dict[str, Any]:
    """
    FastAPI dependency validating merchant employee JWT access token.
    Enforces strict token type ('merchant_employee'), audience ('merchant-platform'),
    and immediate revocation checking against merchant_users.token_version.
    """
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Bearer authorization token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:].strip()
    try:
        payload = crypto.verify_merchant_access_token(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    token_merchant_id = payload.get("merchant_id")
    token_version = payload.get("token_version", 1)

    # Validate against persistent database state
    user = merchant_store.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user["status"] != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated or disabled.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Immediate Revocation Guard: assert token_version matches DB
    if user["token_version"] != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked or expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "user_id": user_id,
        "email": user["email"],
        "status": user["status"],
        "token_merchant_id": token_merchant_id,
        "token_role": payload.get("role", "STAFF"),
    }


def require_tenant_context(
    request: Request,
    merchant_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_merchant_user),
) -> TenantContext:
    """
    Authoritative dependency establishing the active TenantContext.
    
    Tenant Isolation Safeguard:
    1. If merchant_id is present in the path parameters (e.g. /merchants/{merchant_id}/...),
       it validates that the authenticated user possesses an ACTIVE membership in that exact merchant.
    2. If merchant_id is not in path, defaults to the active merchant_id bound to the verified JWT token.
    3. Rejects cross-tenant access attempts immediately with 403 Forbidden.
    4. Binds the context to Python contextvars for safe downstream propagation.
    """
    target_merchant_id = merchant_id or current_user.get("token_merchant_id")
    if not target_merchant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not resolve active merchant organization context.",
        )

    user_id = current_user["user_id"]

    # Verify active membership in the target organization
    membership = merchant_store.get_membership(target_merchant_id, user_id)
    if not membership or membership["status"] != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not possess an active membership in this merchant organization.",
        )

    # Verify merchant organization itself is ACTIVE
    merchant = merchant_store.get_merchant(target_merchant_id)
    if not merchant or merchant["status"] != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Merchant organization is suspended or deactivated.",
        )

    effective_role = membership["role"]
    permissions = rbac.get_role_permissions(effective_role)

    ctx = TenantContext(
        user_id=user_id,
        merchant_id=target_merchant_id,
        membership_id=membership["id"],
        role=effective_role,
        permissions=permissions,
    )

    # Bind to async contextvar
    set_current_tenant_context(ctx)
    return ctx


# ══════════════════════════════════════════════════════════════════════════════
# Authentication & Registration Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/auth/register",
    response_model=LoginResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new merchant organization & owner employee",
)
def register_merchant(payload: RegisterMerchantRequest):
    """
    Registers a new corporate employee and creates their root merchant organization.
    The caller automatically becomes the organization OWNER.
    """
    try:
        result = merchant_service.register_merchant(
            email=payload.email,
            password=payload.password,
            full_name=payload.full_name,
            merchant_name=payload.merchant_name,
        )
        return LoginResponse(**result)
    except ValueError as e:
        msg = str(e)
        if "already registered" in msg:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=msg)


@router.post(
    "/auth/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Merchant employee authentication & JWT issuance",
)
def login(request: Request, payload: LoginRequest):
    """
    Authenticates a merchant employee using Argon2id password verification.
    Enforces brute-force rate limiting (5 failed attempts per 5 minutes -> 429).
    Returns an employee JWT bound strictly to their active merchant organization.
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{payload.email.strip().lower()}"

    login_rate_limiter.check_rate_limit(rate_key)
    try:
        result = merchant_service.authenticate_employee(
            email=payload.email,
            password=payload.password,
        )
        login_rate_limiter.record_success(rate_key)
        return LoginResponse(**result)
    except (ValueError, PermissionError) as e:
        login_rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password." if isinstance(e, ValueError) else str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post(
    "/auth/logout",
    status_code=status.HTTP_200_OK,
    summary="Merchant employee logout & immediate session revocation",
)
def logout(current_user: Dict[str, Any] = Depends(get_current_merchant_user)):
    """
    Revokes all active tokens for the employee immediately by incrementing their token_version.
    """
    merchant_service.logout_and_revoke(
        user_id=current_user["user_id"],
        merchant_id=current_user.get("token_merchant_id"),
    )
    return {"message": "Logged out successfully. All sessions have been revoked."}


# ══════════════════════════════════════════════════════════════════════════════
# Merchant Organization Profile & Switching Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/merchants/me",
    response_model=MeResponse,
    status_code=status.HTTP_200_OK,
    summary="Current authenticated employee profile and active tenant context",
)
def get_me(
    current_user: Dict[str, Any] = Depends(get_current_merchant_user),
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Returns the profile, active merchant organization, granted permissions,
    and all organizations the user belongs to.
    """
    merchant = merchant_store.get_merchant(ctx.merchant_id)
    all_memberships = merchant_store.list_user_memberships(ctx.user_id)

    available_orgs = [
        AvailableMerchantOrganization(
            merchant_id=m["merchant_id"],
            name=m.get("merchant_name", m["merchant_id"]),
            role=m["role"],
            status=m["status"],
        )
        for m in all_memberships
    ]

    return MeResponse(
        user=CurrentUserProfile(
            user_id=ctx.user_id,
            email=current_user["email"],
            status=current_user["status"],
        ),
        active_merchant=CurrentMerchantProfile(
            merchant_id=ctx.merchant_id,
            name=merchant["name"] if merchant else ctx.merchant_id,
            status=merchant["status"] if merchant else "ACTIVE",
            role=ctx.role,
            permissions=sorted(list(ctx.permissions)),
        ),
        available_organizations=available_orgs,
    )


@router.post(
    "/merchants",
    response_model=MerchantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an additional merchant organization",
)
def create_merchant_org(
    payload: CreateMerchantRequest,
    current_user: Dict[str, Any] = Depends(get_current_merchant_user),
):
    """
    Creates an additional merchant organization owned by the authenticated employee.
    """
    new_merchant = merchant_store.create_merchant(name=payload.name)
    # Assign user as OWNER
    merchant_store.create_membership(
        merchant_id=new_merchant["id"],
        user_id=current_user["user_id"],
        role=rbac.ROLE_OWNER,
        status="ACTIVE",
    )
    return MerchantResponse(**new_merchant)


@router.get(
    "/merchants",
    response_model=List[AvailableMerchantOrganization],
    status_code=status.HTTP_200_OK,
    summary="List all merchant organizations available to employee",
)
def list_my_merchants(current_user: Dict[str, Any] = Depends(get_current_merchant_user)):
    """
    Lists all organizations the current employee belongs to.
    """
    memberships = merchant_store.list_user_memberships(current_user["user_id"])
    return [
        AvailableMerchantOrganization(
            merchant_id=m["merchant_id"],
            name=m.get("merchant_name", m["merchant_id"]),
            role=m["role"],
            status=m["status"],
        )
        for m in memberships
    ]


@router.post(
    "/merchants/{merchant_id}/switch",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Switch active tenant organization context",
)
def switch_merchant_org(
    merchant_id: str = Path(..., description="Target merchant organization ID"),
    current_user: Dict[str, Any] = Depends(get_current_merchant_user),
):
    """
    Switches active tenant context to another organization where the user holds membership.
    Issues a new access token bound to the target organization.
    """
    try:
        result = merchant_service.switch_organization(
            user_id=current_user["user_id"],
            target_merchant_id=merchant_id,
        )
        return LoginResponse(**result)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Organization Members & RBAC Management Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/merchants/{merchant_id}/members",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List members of a merchant organization",
)
def list_members(
    merchant_id: str,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Lists all employee members in the active organization.
    Requires members:read permission.
    """
    if not ctx.has_permission(rbac.PERM_MEMBERS_READ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: Insufficient permissions.")
    return merchant_store.list_merchant_members(ctx.merchant_id)


@router.post(
    "/merchants/{merchant_id}/members",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Directly add or provision a member",
)
def add_member(
    merchant_id: str,
    payload: CreateMemberRequest,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Directly provisions a member under the merchant organization.
    Enforces that caller cannot grant a role higher than their authority.
    """
    if not ctx.has_permission(rbac.PERM_MEMBERS_MANAGE):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: Insufficient permissions.")

    clean_role = payload.role.strip().upper()
    if not rbac.can_assign_role(ctx.role, clean_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Privilege escalation prevented: Actor with role '{ctx.role}' cannot assign role '{clean_role}'.",
        )

    clean_email = payload.email.strip().lower()
    user = merchant_store.get_user_by_email(clean_email)
    if not user:
        if not payload.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required to provision a new user account directly.",
            )
        is_strong, err = crypto.validate_password_strength(payload.password)
        if not is_strong:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=err)
        p_hash = crypto.hash_password(payload.password)
        user = merchant_store.create_user(email=clean_email, password_hash=p_hash)

    # Check if already a member
    existing = merchant_store.get_membership(ctx.merchant_id, user["id"])
    if existing and existing["status"] == "ACTIVE":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User is already an active member.")

    if existing:
        mem = merchant_store.update_membership(existing["id"], role=clean_role, status="ACTIVE")
    else:
        mem = merchant_store.create_membership(
            merchant_id=ctx.merchant_id,
            user_id=user["id"],
            role=clean_role,
            status="ACTIVE",
        )
    return mem


@router.patch(
    "/merchants/{merchant_id}/members/{member_id}",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Update member role or status",
)
def update_member(
    merchant_id: str,
    member_id: str,
    payload: UpdateMemberRequest,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Updates role or status of a member.
    Enforces that:
    1. Caller cannot demote or remove the last active OWNER.
    2. Caller cannot grant a role higher than their own authority.
    3. Triggers immediate token revocation for target user.
    """
    try:
        updated = merchant_service.update_membership(
            tenant_context=ctx,
            membership_id=member_id,
            new_role=payload.role,
            new_status=payload.status,
        )
        return updated
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Merchant Invitations Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/merchants/{merchant_id}/invitations",
    response_model=InvitationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a single-use employee invitation",
)
def create_invitation(
    merchant_id: str,
    payload: CreateInvitationRequest,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Issues a single-use invitation token.
    Token is stored securely as SHA-256 hash.
    """
    try:
        result = merchant_service.create_invitation(
            tenant_context=ctx,
            recipient_email=payload.email,
            role=payload.role,
        )
        return InvitationResponse(**result)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post(
    "/merchants/invitations/accept",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Accept an invitation and join organization",
)
def accept_invitation(payload: AcceptInvitationRequest):
    """
    Accepts an invitation via single-use token and grants organization membership.
    """
    try:
        result = merchant_service.accept_invitation(
            raw_token=payload.token,
            password=payload.password,
            full_name=payload.full_name,
        )
        return LoginResponse(**result)
    except ValueError as e:
        msg = str(e)
        if "already holds an active membership" in msg:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


# ══════════════════════════════════════════════════════════════════════════════
# Merchant-Scoped Product Catalog Endpoints (/api/v1/merchants/{merchant_id}/products)
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/merchants/{merchant_id}/products",
    response_model=List[Product],
    status_code=status.HTTP_200_OK,
    summary="List merchant's own catalog products",
)
def list_merchant_products(
    merchant_id: str,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Returns products strictly belonging to the authenticated merchant.
    Cross-tenant queries are blocked by require_tenant_context.
    """
    return catalog_service.list_products_admin(merchant_id=ctx.merchant_id)


@router.post(
    "/merchants/{merchant_id}/products",
    response_model=Product,
    status_code=status.HTTP_201_CREATED,
    summary="Create a product in merchant's catalog",
)
def create_merchant_product(
    merchant_id: str,
    payload: CreateProductRequest,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Creates a new product scoped to the authenticated merchant.
    """
    if not (ctx.has_role("OWNER") or ctx.has_role("ADMIN") or ctx.has_role("MANAGER")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role to manage products.")
    try:
        payload.merchant_id = ctx.merchant_id
        return catalog_service.create_product(payload, merchant_id=ctx.merchant_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get(
    "/merchants/{merchant_id}/products/{product_id}",
    response_model=Product,
    status_code=status.HTTP_200_OK,
    summary="Get single merchant product details",
)
def get_merchant_product(
    merchant_id: str,
    product_id: str,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Retrieves a single product belonging to the authenticated merchant.
    """
    try:
        return catalog_service.get_product(product_id, merchant_id=ctx.merchant_id)
    except ProductNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch(
    "/merchants/{merchant_id}/products/{product_id}",
    response_model=Product,
    status_code=status.HTTP_200_OK,
    summary="Update a merchant product",
)
def update_merchant_product(
    merchant_id: str,
    product_id: str,
    payload: UpdateProductRequest,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Updates a product belonging to the authenticated merchant.
    """
    if not (ctx.has_role("OWNER") or ctx.has_role("ADMIN") or ctx.has_role("MANAGER")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role to manage products.")
    try:
        return catalog_service.update_product(product_id, payload, merchant_id=ctx.merchant_id)
    except ProductNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete(
    "/merchants/{merchant_id}/products/{product_id}",
    status_code=status.HTTP_200_OK,
    summary="Archive a merchant product",
)
def delete_merchant_product(
    merchant_id: str,
    product_id: str,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Archives a product belonging to the authenticated merchant.
    """
    if not (ctx.has_role("OWNER") or ctx.has_role("ADMIN")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only OWNER or ADMIN may archive products.")
    success = catalog_service.archive_product(product_id, merchant_id=ctx.merchant_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found or already archived.")
    return {"status": "ok", "message": f"Product '{product_id}' archived successfully."}


# ══════════════════════════════════════════════════════════════════════════════
# Merchant-Scoped Audit Trail Endpoints (/api/v1/merchants/{merchant_id}/audit)
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/merchants/{merchant_id}/audit",
    response_model=List[AuditRecord],
    status_code=status.HTTP_200_OK,
    summary="List merchant's own audit trail records",
)
def list_merchant_audit_records(
    merchant_id: str,
    customer_id: Optional[str] = Query(default=None),
    decision: Optional[str] = Query(default=None),
    payment_status: Optional[str] = Query(default=None),
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Retrieves audit trail records strictly scoped to the authenticated merchant.
    """
    return audit_store.list(
        customer_id=customer_id,
        decision=decision,
        payment_status=payment_status,
        merchant_id=ctx.merchant_id,
    )


@router.get(
    "/merchants/{merchant_id}/audit/{transaction_id}",
    response_model=AuditRecord,
    status_code=status.HTTP_200_OK,
    summary="Get single merchant audit record",
)
def get_merchant_audit_record(
    merchant_id: str,
    transaction_id: str,
    ctx: TenantContext = Depends(require_tenant_context),
):
    """
    Retrieves a single audit record strictly belonging to the authenticated merchant.
    """
    record = audit_store.get(transaction_id, merchant_id=ctx.merchant_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit record '{transaction_id}' not found.",
        )
    return record

