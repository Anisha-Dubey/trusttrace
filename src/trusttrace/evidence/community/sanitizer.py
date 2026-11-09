"""Input validation, text sanitization, and secure privacy hashing for community reports."""

import re
import html
import hashlib
import hmac
import os
from typing import Optional

# Regex to strip entire script and style blocks including inner contents
_SCRIPT_RE = re.compile(r"<script[\s\S]*?</script>", re.IGNORECASE)
_STYLE_RE = re.compile(r"<style[\s\S]*?</style>", re.IGNORECASE)
# Regex to strip any remaining HTML tags
_TAG_RE = re.compile(r"<[^>]+>")


def get_reporter_salt() -> bytes:
    """Retrieve the authoritative cryptographic salt used for reporter pseudonymization.
    
    In production mode (ENVIRONMENT=production or TRUSTTRACE_ENV=production),
    a secure, high-entropy secret MUST be supplied via the REPORTER_SALT environment variable.
    Hardcoded fallbacks in production are strictly prohibited.
    """
    env = os.environ.get("TRUSTTRACE_ENV") or os.environ.get("ENVIRONMENT", "development")
    salt = os.environ.get("REPORTER_SALT")

    if env.lower() == "production":
        if not salt or salt == "trusttrace-salt-hackmatrix26" or len(salt) < 16:
            raise RuntimeError(
                "FATAL CONFIGURATION ERROR: REPORTER_SALT must be configured with a high-entropy "
                "secret (at least 16 characters) in production mode."
            )
        return salt.encode("utf-8")

    # In development or testing mode
    if salt:
        return salt.encode("utf-8")
    # Deterministic development salt for predictable tests if not set
    return b"trusttrace-dev-salt-local-testing-only"


def sanitize_text(text: Optional[str], max_length: int = 1000) -> str:
    """Sanitize user-submitted text by stripping scripts, styles, HTML tags, and capping length.
    
    Protects against stored XSS (COMM-004) and unbounded memory allocation.
    """
    if not text:
        return ""
    # Strip script blocks completely
    clean = _SCRIPT_RE.sub("", text)
    # Strip style blocks completely
    clean = _STYLE_RE.sub("", clean)
    # Strip any remaining HTML tags
    clean = _TAG_RE.sub("", clean)
    # Escape remaining entities
    clean = html.escape(clean.strip())
    # Truncate to max length
    return clean[:max_length]


def hash_reporter_identity(raw_identifier: str) -> str:
    """Compute a non-reversible HMAC-SHA256 hash of reporter identifier using server salt.
    
    Ensures raw IP addresses, user IDs, or email addresses are NEVER stored or exposed.
    """
    salt = get_reporter_salt()
    if not raw_identifier:
        raw_identifier = "anonymous_client"
    return hmac.new(salt, raw_identifier.encode("utf-8"), hashlib.sha256).hexdigest()
