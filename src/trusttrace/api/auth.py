"""Authentication and Role-Based Authorization for TRUSTTRACE API."""

import os
import secrets
from dataclasses import dataclass, field
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
    "phishtank-secret-token-key-2026",
    "urlhaus-secret-token-key-2026",
    "openphish-secret-token-key-2026",
    "virustotal-secret-token-key-2026",
    "cert-feed-secret-token-key-2026",
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
    "phishtank": "phishtank-secret-token-key-2026",
    "urlhaus": "urlhaus-secret-token-key-2026",
    "openphish": "openphish-secret-token-key-2026",
    "virustotal": "virustotal-secret-token-key-2026",
    "cert_feed": "cert-feed-secret-token-key-2026",
}

# Authoritative list of verified external threat provider families
VERIFIED_PROVIDER_FAMILIES: Set[str] = {
    "phishtank",
    "openphish",
    "urlhaus",
    "virustotal",
    "cert_feed",
    "internal_collector",
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
    permitted_source_families: Set[str] = field(default_factory=set)

    def has_role(self, role: str) -> bool:
        if "admin" in self.roles:
            return True
        return role in self.roles

    def is_authorized_for_family(self, source_family: str) -> bool:
        """Check if principal is authorized to submit for a given source family."""
        if "admin" in self.roles:
            return True
        return source_family in self.permitted_source_families


def validate_token_configuration() -> Dict[str, AuthenticatedUser]:
    """Validate token credentials from environment and build the authoritative registry.
    
    Security rules enforced:
    - Production requires explicit, high-entropy tokens from environment.
    - Default/insecure credentials cause immediate failure in production.
    - Empty or whitespace-only tokens are rejected in all environments.
    - Duplicate tokens mapping to multiple roles are strictly rejected.
    - Token values are never logged or exposed in error messages.
    - Authenticated principals are strictly bound to permitted source families (TASK 4).
    """
    is_prod = is_production_environment()

    # Core system roles
    env_mod = os.environ.get("TRUSTTRACE_MODERATOR_TOKEN")
    env_admin = os.environ.get("TRUSTTRACE_ADMIN_TOKEN")
    env_collector = os.environ.get("TRUSTTRACE_COLLECTOR_TOKEN")
    env_viewer = os.environ.get("TRUSTTRACE_VIEWER_TOKEN")

    # Specific feed provider credentials (optional in dev, required if provider feed active)
    env_phishtank = os.environ.get("TRUSTTRACE_PHISHTANK_TOKEN")
    env_urlhaus = os.environ.get("TRUSTTRACE_URLHAUS_TOKEN")
    env_openphish = os.environ.get("TRUSTTRACE_OPENPHISH_TOKEN")
    env_virustotal = os.environ.get("TRUSTTRACE_VIRUSTOTAL_TOKEN")
    env_cert_feed = os.environ.get("TRUSTTRACE_CERT_FEED_TOKEN")

    raw_tokens = {
        "moderator": env_mod,
        "admin": env_admin,
        "collector": env_collector,
        "viewer": env_viewer,
        "phishtank": env_phishtank,
        "urlhaus": env_urlhaus,
        "openphish": env_openphish,
        "virustotal": env_virustotal,
        "cert_feed": env_cert_feed,
    }

    resolved_tokens: Dict[str, str] = {}
    required_roles = {"moderator", "admin", "collector", "viewer"}

    for key, token_val in raw_tokens.items():
        if token_val is not None:
            stripped = token_val.strip()
            if not stripped:
                raise ValueError(
                    f"Authentication token for '{key}' cannot be empty or whitespace only."
                )
            if is_prod:
                if stripped in INSECURE_DEFAULT_TOKENS or len(stripped) < 32:
                    raise RuntimeError(
                        f"Production configuration error: Insecure or weak token detected for role '{key}'. "
                        f"Production requires high-entropy secrets of at least 32 characters."
                    )
            resolved_tokens[key] = stripped
        else:
            if is_prod and key in required_roles:
                raise RuntimeError(
                    f"Production configuration error: Missing required authentication token for role '{key}'. "
                    f"Set environment variable TRUSTTRACE_{key.upper()}_TOKEN with a secure secret."
                )
            if not is_prod:
                # In development/test mode, fall back to explicit dev/test token
                resolved_tokens[key] = DEV_TEST_TOKENS[key]

    # Validate against duplicate credentials mapping to multiple roles/principals
    seen_tokens: Dict[str, str] = {}
    for role_or_provider, token_val in resolved_tokens.items():
        if token_val in seen_tokens:
            raise ValueError(
                f"Duplicate credentials error: '{role_or_provider}' shares the exact same token with '{seen_tokens[token_val]}'."
            )
        seen_tokens[token_val] = role_or_provider

    # Check if collector permitted families are explicitly configured via env
    collector_families_env = os.environ.get("TRUSTTRACE_COLLECTOR_FAMILIES")
    if collector_families_env:
        collector_families = {f.strip() for f in collector_families_env.split(",") if f.strip()}
    else:
        # In production, default strictly to internal_collector unless configured;
        # in dev/test, allow verified provider families for generic test collector
        collector_families = {"internal_collector"} if is_prod else VERIFIED_PROVIDER_FAMILIES.copy()

    registry: Dict[str, AuthenticatedUser] = {
        resolved_tokens["moderator"]: AuthenticatedUser(
            user_id="usr-mod-001",
            username="security_moderator",
            roles=["moderator", "viewer"],
            permitted_source_families=set(),
        ),
        resolved_tokens["admin"]: AuthenticatedUser(
            user_id="usr-admin-001",
            username="security_admin",
            roles=["admin", "moderator", "viewer"],
            permitted_source_families=VERIFIED_PROVIDER_FAMILIES.copy(),
        ),
        resolved_tokens["collector"]: AuthenticatedUser(
            user_id="usr-collector-001",
            username="internal_collector_agent",
            roles=["collector"],
            permitted_source_families=collector_families,
        ),
        resolved_tokens["viewer"]: AuthenticatedUser(
            user_id="usr-viewer-001",
            username="auditor_viewer",
            roles=["viewer"],
            permitted_source_families=set(),
        ),
    }

    # Register specialized provider collector principals
    if "phishtank" in resolved_tokens:
        registry[resolved_tokens["phishtank"]] = AuthenticatedUser(
            user_id="usr-provider-phishtank",
            username="phishtank_feed_agent",
            roles=["collector"],
            permitted_source_families={"phishtank"},
        )
    if "urlhaus" in resolved_tokens:
        registry[resolved_tokens["urlhaus"]] = AuthenticatedUser(
            user_id="usr-provider-urlhaus",
            username="urlhaus_feed_agent",
            roles=["collector"],
            permitted_source_families={"urlhaus"},
        )
    if "openphish" in resolved_tokens:
        registry[resolved_tokens["openphish"]] = AuthenticatedUser(
            user_id="usr-provider-openphish",
            username="openphish_feed_agent",
            roles=["collector"],
            permitted_source_families={"openphish"},
        )
    if "virustotal" in resolved_tokens:
        registry[resolved_tokens["virustotal"]] = AuthenticatedUser(
            user_id="usr-provider-virustotal",
            username="virustotal_feed_agent",
            roles=["collector"],
            permitted_source_families={"virustotal"},
        )
    if "cert_feed" in resolved_tokens:
        registry[resolved_tokens["cert_feed"]] = AuthenticatedUser(
            user_id="usr-provider-cert-feed",
            username="cert_feed_agent",
            roles=["collector"],
            permitted_source_families={"cert_feed"},
        )

    return registry


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
