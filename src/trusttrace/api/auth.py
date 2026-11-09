"""Authentication and Role-Based Authorization for TRUSTTRACE API."""

import os
import secrets
from dataclasses import dataclass
from typing import List, Optional, Dict, Set
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security_bearer = HTTPBearer(auto_error=False)

# Known insecure/default tokens strictly forbidden in production
INSECURE_DEFAULT_TOKENS: Set[str] = {
    "mod-secret-token-key-2026",
    "admin-secret-token-key-2026",
    "collector-secret-token-key-2026",
    "viewer-secret-token-key-2026",
    "secret",
    "password",
    "admin",
    "123456",
    "changeme",
}

# Explicit development/test fallback tokens (ONLY valid when NOT in production)
DEV_TEST_TOKENS: Dict[str, str] = {
    "moderator": "mod-secret-token-key-2026",
    "admin": "admin-secret-token-key-2026",
    "collector": "collector-secret-token-key-2026",
    "viewer": "viewer-secret-token-key-2026",
}


def is_production_environment() -> bool:
    """Determine whether the application is running in production mode."""
    env = (
        os.environ.get("TRUSTTRACE_ENV")
        or os.environ.get("ENV")
        or os.environ.get("ENVIRONMENT")
        or ""
    ).strip().lower()
    return env == "production"


@dataclass
class AuthenticatedUser:
    """Represents a verified, authenticated principal."""
    user_id: str
    username: str
    roles: List[str]

    def has_role(self, role: str) -> bool:
        if "admin" in self.roles:
            return True
        return role in self.roles


def validate_token_configuration() -> Dict[str, AuthenticatedUser]:
    """Validate token credentials from environment and build the authoritative registry.
    
    Security rules enforced:
    - Production requires explicit, high-entropy tokens from environment.
    - Default/insecure credentials cause immediate failure in production.
    - Empty or whitespace-only tokens are rejected in all environments.
    - Duplicate tokens mapping to multiple roles are strictly rejected.
    - Token values are never logged or exposed.
    """
    is_prod = is_production_environment()

    env_mod = os.environ.get("TRUSTTRACE_MODERATOR_TOKEN")
    env_admin = os.environ.get("TRUSTTRACE_ADMIN_TOKEN")
    env_collector = os.environ.get("TRUSTTRACE_COLLECTOR_TOKEN")
    env_viewer = os.environ.get("TRUSTTRACE_VIEWER_TOKEN")

    raw_tokens = {
        "moderator": env_mod,
        "admin": env_admin,
        "collector": env_collector,
        "viewer": env_viewer,
    }

    resolved_tokens: Dict[str, str] = {}

    for role, token_val in raw_tokens.items():
        if token_val is not None:
            stripped = token_val.strip()
            if not stripped:
                raise ValueError(
                    f"Authentication token for role '{role}' cannot be empty or whitespace only."
                )
            if is_prod:
                if stripped in INSECURE_DEFAULT_TOKENS or len(stripped) < 32:
                    raise RuntimeError(
                        f"Production configuration error: Insecure or weak token detected for role '{role}'. "
                        f"Production requires high-entropy secrets of at least 32 characters."
                    )
            resolved_tokens[role] = stripped
        else:
            if is_prod:
                raise RuntimeError(
                    f"Production configuration error: Missing required authentication token for role '{role}'. "
                    f"Set environment variable TRUSTTRACE_{role.upper()}_TOKEN with a secure secret."
                )
            # In development/test mode, fall back to explicit dev/test token
            resolved_tokens[role] = DEV_TEST_TOKENS[role]

    # Validate against duplicate credentials mapping to multiple roles
    seen_tokens: Dict[str, str] = {}
    for role, token_val in resolved_tokens.items():
        if token_val in seen_tokens:
            raise ValueError(
                f"Duplicate credentials error: Role '{role}' shares the exact same token with '{seen_tokens[token_val]}'."
            )
        seen_tokens[token_val] = role

    return {
        resolved_tokens["moderator"]: AuthenticatedUser(
            user_id="usr-mod-001",
            username="security_moderator",
            roles=["moderator", "viewer"],
        ),
        resolved_tokens["admin"]: AuthenticatedUser(
            user_id="usr-admin-001",
            username="security_admin",
            roles=["admin", "moderator", "viewer"],
        ),
        resolved_tokens["collector"]: AuthenticatedUser(
            user_id="usr-collector-001",
            username="internal_collector_agent",
            roles=["collector"],
        ),
        resolved_tokens["viewer"]: AuthenticatedUser(
            user_id="usr-viewer-001",
            username="auditor_viewer",
            roles=["viewer"],
        ),
    }


def get_token_registry() -> Dict[str, AuthenticatedUser]:
    """Retrieve the authoritative token-to-user registry."""
    return validate_token_configuration()


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
