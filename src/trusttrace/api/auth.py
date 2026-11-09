"""Authentication and Role-Based Authorization for TRUSTTRACE API."""

import os
import secrets
from dataclasses import dataclass
from typing import List, Optional, Dict
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security_bearer = HTTPBearer(auto_error=False)


@dataclass
class AuthenticatedUser:
    """Represents a verified, authenticated principal."""
    user_id: str
    username: str
    roles: List[str]

    def has_role(self, role: str) -> bool:
        return role in self.roles or "admin" in self.roles


# Server-managed token registry
# In production, tokens are loaded from secret store / environment variables
def get_token_registry() -> Dict[str, AuthenticatedUser]:
    """Retrieve the authoritative token-to-user registry."""
    mod_token = os.environ.get("TRUSTTRACE_MODERATOR_TOKEN", "mod-secret-token-key-2026")
    admin_token = os.environ.get("TRUSTTRACE_ADMIN_TOKEN", "admin-secret-token-key-2026")
    collector_token = os.environ.get("TRUSTTRACE_COLLECTOR_TOKEN", "collector-secret-token-key-2026")
    viewer_token = os.environ.get("TRUSTTRACE_VIEWER_TOKEN", "viewer-secret-token-key-2026")

    return {
        mod_token: AuthenticatedUser(
            user_id="usr-mod-001",
            username="security_moderator",
            roles=["moderator"],
        ),
        admin_token: AuthenticatedUser(
            user_id="usr-admin-001",
            username="security_admin",
            roles=["admin", "moderator"],
        ),
        collector_token: AuthenticatedUser(
            user_id="usr-collector-001",
            username="internal_collector_agent",
            roles=["collector"],
        ),
        viewer_token: AuthenticatedUser(
            user_id="usr-viewer-001",
            username="auditor_viewer",
            roles=["viewer"],
        ),
    }


def verify_bearer_token(token: str) -> Optional[AuthenticatedUser]:
    """Constant-time token verification against registered credentials."""
    registry = get_token_registry()
    for registered_token, user in registry.items():
        if secrets.compare_digest(registered_token, token):
            return user
    return None


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> AuthenticatedUser:
    """Dependency: Extract and verify Bearer token from request."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = verify_bearer_token(credentials.credentials)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_roles(required_roles: List[str]):
    """Dependency factory: Enforce role-based access control (RBAC)."""

    def role_checker(
        current_user: AuthenticatedUser = Security(get_current_user),
    ) -> AuthenticatedUser:
        if not any(current_user.has_role(r) for r in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient privileges. Required roles: {required_roles}",
            )
        return current_user

    return role_checker
