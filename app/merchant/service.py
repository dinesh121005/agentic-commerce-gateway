"""
Merchant Identity & RBAC Service Layer.

Orchestrates:
- Merchant organization creation and employee registration.
- Multi-organization membership switching.
- Invitation lifecycle with cryptographic tokens.
- Privilege escalation prevention and ownership integrity rules.
- Immediate token revocation.
- Security audit event logging.
"""
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from app.audit import audit_store
from app.core.context import TenantContext
from app.merchant import crypto, rbac
from app.merchant.store import merchant_store

logger = logging.getLogger("gateway.merchant.service")


class MerchantService:
    """Service handling merchant employee identity, memberships, and RBAC governance."""

    def register_merchant(
        self,
        email: str,
        password: str,
        full_name: str,
        merchant_name: str,
    ) -> Dict[str, Any]:
        """
        Registers a new merchant user and provisions their root merchant organization.
        The registering user automatically becomes the primary OWNER.
        """
        clean_email = email.strip().lower()
        clean_merch_name = merchant_name.strip()

        # 1. Validate password strength
        is_strong, err_msg = crypto.validate_password_strength(password)
        if not is_strong:
            raise ValueError(err_msg)

        # 2. Check if user already exists
        existing_user = merchant_store.get_user_by_email(clean_email)
        if existing_user is not None:
            raise ValueError(f"Email '{clean_email}' is already registered.")

        # 3. Hash password with Argon2id
        p_hash = crypto.hash_password(password)

        # 4. Atomically provision Merchant Organization, User, and Owner Membership
        user_id = f"usr_{uuid4().hex[:12]}"
        merchant_id = f"merch_{uuid4().hex[:12]}"
        membership_id = f"mem_{uuid4().hex[:12]}"

        user = merchant_store.create_user(
            email=clean_email,
            password_hash=p_hash,
            user_id=user_id,
            status="ACTIVE",
        )
        merchant = merchant_store.create_merchant(
            name=clean_merch_name,
            merchant_id=merchant_id,
            status="ACTIVE",
        )
        membership = merchant_store.create_membership(
            merchant_id=merchant_id,
            user_id=user_id,
            role=rbac.ROLE_OWNER,
            membership_id=membership_id,
            status="ACTIVE",
        )

        # 5. Log Security Audit Event
        self._log_security_event(
            merchant_id=merchant_id,
            actor_id=user_id,
            event_type="MERCHANT_ORGANIZATION_REGISTERED",
            payload={
                "merchant_id": merchant_id,
                "merchant_name": clean_merch_name,
                "owner_user_id": user_id,
                "email": clean_email,
            },
        )

        # 6. Issue Merchant Employee Access Token
        access_token = crypto.create_merchant_access_token(
            user_id=user_id,
            merchant_id=merchant_id,
            role=rbac.ROLE_OWNER,
            token_version=user["token_version"],
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": crypto.MERCHANT_TOKEN_EXPIRY_SECONDS,
            "user_id": user_id,
            "merchant_id": merchant_id,
            "role": rbac.ROLE_OWNER,
            "merchant_name": clean_merch_name,
        }

    def authenticate_employee(self, email: str, password: str) -> Dict[str, Any]:
        """
        Authenticates an employee using Argon2id password verification.
        Binds token to primary active merchant organization.
        """
        clean_email = email.strip().lower()

        # 1. Look up user
        user = merchant_store.get_user_by_email(clean_email)
        if not user:
            # Generic error preventing user enumeration
            raise ValueError("Invalid email or password.")

        # 2. Verify password
        if not crypto.verify_password(password, user["password_hash"]):
            raise ValueError("Invalid email or password.")

        # 3. Check user account status
        if user["status"] != "ACTIVE":
            raise PermissionError("Account is disabled or deactivated.")

        # 4. Resolve active merchant memberships
        memberships = merchant_store.list_user_memberships(user["id"])
        if not memberships:
            raise PermissionError("No active merchant organization memberships found for this user.")

        # Select primary (first) active organization
        primary = memberships[0]
        merchant_id = primary["merchant_id"]
        role = primary["role"]

        # 5. Log Security Audit Event
        self._log_security_event(
            merchant_id=merchant_id,
            actor_id=user["id"],
            event_type="MERCHANT_EMPLOYEE_LOGIN",
            payload={
                "user_id": user["id"],
                "merchant_id": merchant_id,
                "role": role,
            },
        )

        # 6. Issue Merchant Access Token
        access_token = crypto.create_merchant_access_token(
            user_id=user["id"],
            merchant_id=merchant_id,
            role=role,
            token_version=user["token_version"],
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": crypto.MERCHANT_TOKEN_EXPIRY_SECONDS,
            "user_id": user["id"],
            "merchant_id": merchant_id,
            "role": role,
        }

    def switch_organization(self, user_id: str, target_merchant_id: str) -> Dict[str, Any]:
        """
        Switches the active tenant context for a multi-tenant user to another organization
        in which they hold verified active membership.
        """
        clean_target = target_merchant_id.strip()

        # 1. Fetch user
        user = merchant_store.get_user_by_id(user_id)
        if not user or user["status"] != "ACTIVE":
            raise PermissionError("User account is invalid or inactive.")

        # 2. Verify active membership in target organization
        membership = merchant_store.get_membership(clean_target, user_id)
        if not membership or membership["status"] != "ACTIVE":
            raise PermissionError(f"User does not hold an active membership in merchant '{clean_target}'.")

        # 3. Verify target organization is active
        merchant = merchant_store.get_merchant(clean_target)
        if not merchant or merchant["status"] != "ACTIVE":
            raise PermissionError("Target merchant organization is suspended or deactivated.")

        # 4. Log Security Audit Event
        self._log_security_event(
            merchant_id=clean_target,
            actor_id=user_id,
            event_type="MERCHANT_ORGANIZATION_SWITCHED",
            payload={
                "user_id": user_id,
                "target_merchant_id": clean_target,
                "role": membership["role"],
            },
        )

        # 5. Mint new token bound to target organization
        access_token = crypto.create_merchant_access_token(
            user_id=user_id,
            merchant_id=clean_target,
            role=membership["role"],
            token_version=user["token_version"],
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": crypto.MERCHANT_TOKEN_EXPIRY_SECONDS,
            "user_id": user_id,
            "merchant_id": clean_target,
            "role": membership["role"],
        }

    def logout_and_revoke(self, user_id: str, merchant_id: Optional[str] = None) -> None:
        """
        Immediately revokes all active sessions for the user by incrementing token_version.
        """
        merchant_store.increment_user_token_version(user_id)
        if merchant_id:
            self._log_security_event(
                merchant_id=merchant_id,
                actor_id=user_id,
                event_type="MERCHANT_EMPLOYEE_LOGOUT",
                payload={"user_id": user_id},
            )

    def create_invitation(
        self,
        tenant_context: TenantContext,
        recipient_email: str,
        role: str,
    ) -> Dict[str, Any]:
        """
        Creates a single-use merchant employee invitation.
        Strictly prevents role escalation (e.g. Admin cannot invite Owner).
        """
        clean_email = recipient_email.strip().lower()
        target_role = role.strip().upper()

        # 1. Enforce RBAC permission
        if not tenant_context.has_permission(rbac.PERM_MEMBERS_INVITE):
            raise PermissionError("Forbidden: Insufficient permissions to invite members.")

        # 2. Prevent role escalation
        if not rbac.can_assign_role(tenant_context.role, target_role):
            raise PermissionError(
                f"Privilege escalation prevented: Actor with role '{tenant_context.role}' "
                f"cannot invite a member with role '{target_role}'."
            )

        # 3. Check if user is already an active member of this organization
        existing_user = merchant_store.get_user_by_email(clean_email)
        if existing_user:
            existing_mem = merchant_store.get_membership(tenant_context.merchant_id, existing_user["id"])
            if existing_mem and existing_mem["status"] == "ACTIVE":
                raise ValueError(f"User '{clean_email}' is already an active member of this organization.")

        # 4. Generate random invitation token and hash
        raw_token = crypto.generate_invitation_token()
        token_hash = crypto.hash_invitation_token(raw_token)
        expires_at = time.time() + (7 * 86400)  # 7 days TTL

        inv = merchant_store.create_invitation(
            merchant_id=tenant_context.merchant_id,
            email=clean_email,
            role=target_role,
            token_hash=token_hash,
            created_by=tenant_context.user_id,
            expires_at=expires_at,
        )

        # 5. Log Security Audit Event
        self._log_security_event(
            merchant_id=tenant_context.merchant_id,
            actor_id=tenant_context.user_id,
            event_type="MERCHANT_INVITATION_CREATED",
            payload={
                "invitation_id": inv["id"],
                "recipient_email": clean_email,
                "role": target_role,
            },
        )

        inv_copy = dict(inv)
        inv_copy["token"] = raw_token  # Return plaintext token strictly once for delivery
        return inv_copy

    def accept_invitation(
        self,
        raw_token: str,
        password: str,
        full_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Accepts a valid single-use invitation.
        Links user to the merchant organization under the specified role.
        """
        token_hash = crypto.hash_invitation_token(raw_token)
        inv = merchant_store.get_invitation_by_token_hash(token_hash)

        if not inv:
            raise ValueError("Invalid or expired invitation token.")

        if inv["status"] != "PENDING":
            raise ValueError(f"Invitation has already been {inv['status'].lower()}.")

        if time.time() > inv["expires_at"]:
            merchant_store.update_invitation_status(inv["id"], "EXPIRED")
            raise ValueError("Invitation has expired.")

        email = inv["email"]
        merchant_id = inv["merchant_id"]
        role = inv["role"]

        # Find or create user
        user = merchant_store.get_user_by_email(email)
        if user is None:
            is_strong, err_msg = crypto.validate_password_strength(password)
            if not is_strong:
                raise ValueError(err_msg)
            p_hash = crypto.hash_password(password)
            user_id = f"usr_{uuid4().hex[:12]}"
            user = merchant_store.create_user(
                email=email,
                password_hash=p_hash,
                user_id=user_id,
                status="ACTIVE",
            )
        else:
            # User exists; verify password
            if not crypto.verify_password(password, user["password_hash"]):
                raise ValueError("Incorrect password for existing user account.")

        # Check existing membership
        existing_mem = merchant_store.get_membership(merchant_id, user["id"])
        if existing_mem and existing_mem["status"] == "ACTIVE":
            raise ValueError("User already holds an active membership in this organization.")

        if existing_mem:
            merchant_store.update_membership(existing_mem["id"], role=role, status="ACTIVE")
        else:
            merchant_store.create_membership(
                merchant_id=merchant_id,
                user_id=user["id"],
                role=role,
                status="ACTIVE",
            )

        # Atomically burn invitation to prevent concurrent double-acceptance
        burned = merchant_store.update_invitation_status(inv["id"], "ACCEPTED", expected_status="PENDING")
        if not burned:
            raise ValueError("Invitation has already been accepted or is no longer pending.")

        # Log Security Audit Event
        self._log_security_event(
            merchant_id=merchant_id,
            actor_id=user["id"],
            event_type="MERCHANT_INVITATION_ACCEPTED",
            payload={
                "invitation_id": inv["id"],
                "user_id": user["id"],
                "role": role,
            },
        )

        access_token = crypto.create_merchant_access_token(
            user_id=user["id"],
            merchant_id=merchant_id,
            role=role,
            token_version=user["token_version"],
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": crypto.MERCHANT_TOKEN_EXPIRY_SECONDS,
            "user_id": user["id"],
            "merchant_id": merchant_id,
            "role": role,
        }

    def update_membership(
        self,
        tenant_context: TenantContext,
        membership_id: str,
        new_role: Optional[str] = None,
        new_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Updates a member's role or status within the tenant.
        Enforces:
        - Cross-tenant boundaries (member must belong to active tenant).
        - Prevents demoting or removing the final active OWNER.
        - Prevents role escalation (actor cannot grant role above their authority).
        - Triggers immediate token revocation if role or status changes.
        """
        # 1. Enforce permission
        if not tenant_context.has_permission(rbac.PERM_MEMBERS_MANAGE):
            raise PermissionError("Forbidden: Insufficient permissions to manage members.")

        # 2. Retrieve membership
        target_mem = merchant_store.get_membership_by_id(membership_id)
        if not target_mem or target_mem["merchant_id"] != tenant_context.merchant_id:
            raise KeyError("Membership not found in this organization.")

        current_role = target_mem["role"]
        current_status = target_mem["status"]

        # 3. Check management permissions over target role
        if not rbac.can_manage_member(tenant_context.role, current_role):
            raise PermissionError(
                f"Privilege escalation prevented: Actor with role '{tenant_context.role}' "
                f"cannot modify a member with role '{current_role}'."
            )

        # 4. Check role assignment permission if role is changing
        if new_role:
            clean_new_role = new_role.upper()
            if not rbac.can_assign_role(tenant_context.role, clean_new_role):
                raise PermissionError(
                    f"Privilege escalation prevented: Cannot assign role '{clean_new_role}'."
                )
        else:
            clean_new_role = current_role

        clean_new_status = new_status.upper() if new_status else current_status

        # 5. Invariant: Protect final active OWNER
        is_demoting_or_disabling_owner = (
            current_role == rbac.ROLE_OWNER
            and (clean_new_role != rbac.ROLE_OWNER or clean_new_status != "ACTIVE")
        )
        if is_demoting_or_disabling_owner:
            owner_count = merchant_store.count_active_owners(tenant_context.merchant_id)
            if owner_count <= 1:
                raise ValueError("Cannot demote, suspend, or remove the final active OWNER of an organization.")

        # 6. Apply update
        updated = merchant_store.update_membership(
            membership_id=membership_id,
            role=clean_new_role,
            status=clean_new_status,
        )

        # 7. Immediate Revocation: increment target user's token_version
        merchant_store.increment_user_token_version(target_mem["user_id"])

        # 8. Log Security Audit Event
        self._log_security_event(
            merchant_id=tenant_context.merchant_id,
            actor_id=tenant_context.user_id,
            event_type="MERCHANT_MEMBERSHIP_UPDATED",
            payload={
                "membership_id": membership_id,
                "target_user_id": target_mem["user_id"],
                "old_role": current_role,
                "new_role": clean_new_role,
                "old_status": current_status,
                "new_status": clean_new_status,
            },
        )

        return updated  # type: ignore

    def _log_security_event(
        self,
        merchant_id: str,
        actor_id: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """Appends a security-relevant event to the append-only audit ledger."""
        try:
            import json
            audit_store.append_event(
                transaction_id=f"sec_{uuid4().hex[:12]}",
                event_type=event_type,
                payload={
                    "merchant_id": merchant_id,
                    "actor_id": actor_id,
                    "actor_type": "MERCHANT_EMPLOYEE",
                    "details": payload,
                },
            )
        except Exception as e:
            logger.warning("Could not append audit event %s: %s", event_type, e)


# Singleton instance
merchant_service = MerchantService()

