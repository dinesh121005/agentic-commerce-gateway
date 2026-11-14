"""
Authoritative Tenant Context Management for Multi-Tenant Isolation.

Provides thread-safe and async-safe request context via contextvars.
Enforces that active merchant identity and employee authorization
are server-derived from validated authentication credentials.
"""
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Optional, Set


@dataclass(frozen=True)
class TenantContext:
    """
    Immutable request-scoped tenant identity and authorization context.
    Derived strictly from verified JWT tokens and database membership records.
    """
    user_id: str
    merchant_id: str
    membership_id: str
    role: str
    permissions: Set[str] = field(default_factory=set)

    def has_permission(self, permission: str) -> bool:
        """Checks if the context possesses the requested permission."""
        if "*" in self.permissions:
            return True
        return permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Checks exact role match."""
        return self.role.upper() == role.upper()


# Async-safe context variable holding the active tenant context for the executing request
_current_tenant_context: ContextVar[Optional[TenantContext]] = ContextVar(
    "current_tenant_context",
    default=None,
)


def get_current_tenant_context() -> Optional[TenantContext]:
    """Retrieves the active tenant context for the current async task."""
    return _current_tenant_context.get()


def require_current_tenant_context() -> TenantContext:
    """
    Retrieves the active tenant context or raises a RuntimeError if uninitialized.
    Ensures that domain services never execute in a tenant vacuum.
    """
    ctx = _current_tenant_context.get()
    if ctx is None:
        raise RuntimeError(
            "Security violation: Operation attempted without an authoritative TenantContext."
        )
    return ctx


def set_current_tenant_context(ctx: Optional[TenantContext]) -> Token:
    """Binds an authoritative tenant context to the current async task."""
    return _current_tenant_context.set(ctx)


def reset_current_tenant_context(token: Token) -> None:
    """Resets the contextvar using the token returned by set_current_tenant_context."""
    _current_tenant_context.reset(token)


@dataclass(frozen=True)
class CustomerContext:
    """
    Immutable request-scoped buyer/customer identity context.
    Derived strictly from verified customer OAuth tokens / Ed25519 signatures.
    """
    customer_id: str


# Async-safe context variable holding the active customer context for the executing request
_current_customer_context: ContextVar[Optional[CustomerContext]] = ContextVar(
    "current_customer_context",
    default=None,
)


def get_current_customer_context() -> Optional[CustomerContext]:
    """Retrieves the active customer context for the current async task."""
    return _current_customer_context.get()


def require_current_customer_context() -> CustomerContext:
    """Retrieves the active customer context or raises a RuntimeError if uninitialized."""
    ctx = _current_customer_context.get()
    if ctx is None:
        raise RuntimeError(
            "Security violation: Operation attempted without an authoritative CustomerContext."
        )
    return ctx


def set_current_customer_context(ctx: Optional[CustomerContext]) -> Token:
    """Binds an authoritative customer context to the current async task."""
    return _current_customer_context.set(ctx)


def reset_current_customer_context(token: Token) -> None:
    """Resets the contextvar using the token returned by set_current_customer_context."""
    _current_customer_context.reset(token)


