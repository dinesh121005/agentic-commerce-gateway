"""
Role-Based Access Control (RBAC) definitions and hierarchy for Merchant Organizations.

Enforces principle of least privilege and strict server-side rules preventing privilege escalation.
"""
from typing import Dict, Set

# Role Constants
ROLE_OWNER = "OWNER"
ROLE_ADMIN = "ADMIN"
ROLE_MANAGER = "MANAGER"
ROLE_STAFF = "STAFF"

ALL_ROLES = {ROLE_OWNER, ROLE_ADMIN, ROLE_MANAGER, ROLE_STAFF}

# Standard Permissions
PERM_ALL = "*"
PERM_MERCHANT_READ = "merchant:read"
PERM_MERCHANT_UPDATE = "merchant:update"
PERM_MERCHANT_DELETE = "merchant:delete"
PERM_MERCHANT_TRANSFER_OWNERSHIP = "merchant:transfer_ownership"

PERM_MEMBERS_READ = "members:read"
PERM_MEMBERS_INVITE = "members:invite"
PERM_MEMBERS_MANAGE = "members:manage"
PERM_MEMBERS_REMOVE = "members:remove"

PERM_STORES_READ = "stores:read"
PERM_STORES_MANAGE = "stores:manage"

PERM_CATALOG_READ = "catalog:read"
PERM_CATALOG_WRITE = "catalog:write"

PERM_ORDERS_READ = "orders:read"
PERM_ORDERS_WRITE = "orders:write"

PERM_WORKFORCE_READ = "workforce:read"
PERM_WORKFORCE_MANAGE = "workforce:manage"

# Explicit role permission mappings
ROLE_PERMISSIONS_MAP: Dict[str, Set[str]] = {
    ROLE_OWNER: {PERM_ALL},
    ROLE_ADMIN: {
        PERM_MERCHANT_READ,
        PERM_MERCHANT_UPDATE,
        PERM_MEMBERS_READ,
        PERM_MEMBERS_INVITE,
        PERM_MEMBERS_MANAGE,
        PERM_MEMBERS_REMOVE,
        PERM_STORES_READ,
        PERM_STORES_MANAGE,
        PERM_CATALOG_READ,
        PERM_CATALOG_WRITE,
        PERM_ORDERS_READ,
        PERM_ORDERS_WRITE,
        PERM_WORKFORCE_READ,
        PERM_WORKFORCE_MANAGE,
    },
    ROLE_MANAGER: {
        PERM_MERCHANT_READ,
        PERM_MEMBERS_READ,
        PERM_STORES_READ,
        PERM_CATALOG_READ,
        PERM_CATALOG_WRITE,
        PERM_ORDERS_READ,
        PERM_ORDERS_WRITE,
        PERM_WORKFORCE_READ,
    },
    ROLE_STAFF: {
        PERM_MERCHANT_READ,
        PERM_CATALOG_READ,
        PERM_ORDERS_READ,
    },
}


def get_role_permissions(role: str) -> Set[str]:
    """Returns the set of permissions associated with a given role."""
    return ROLE_PERMISSIONS_MAP.get(role.upper(), set())


def can_assign_role(acting_role: str, target_role: str) -> bool:
    """
    Validates whether an actor with acting_role can assign or invite target_role.
    Prevents role escalation (e.g. ADMIN cannot grant OWNER).
    """
    acting = acting_role.upper()
    target = target_role.upper()

    if target not in ALL_ROLES:
        return False

    if acting == ROLE_OWNER:
        return True
    if acting == ROLE_ADMIN:
        # Admin can only assign MANAGER or STAFF, never OWNER or ADMIN
        return target in {ROLE_MANAGER, ROLE_STAFF}
    return False


def can_manage_member(acting_role: str, target_member_role: str) -> bool:
    """
    Validates whether an actor can edit, suspend, or remove a member with target_member_role.
    """
    acting = acting_role.upper()
    target = target_member_role.upper()

    if acting == ROLE_OWNER:
        return True
    if acting == ROLE_ADMIN:
        # Admin can only manage Manager or Staff, cannot demote/modify Owner or peer Admins
        return target in {ROLE_MANAGER, ROLE_STAFF}
    return False

