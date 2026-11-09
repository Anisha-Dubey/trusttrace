"""Input validation, text sanitization, and privacy hashing for community reports."""

import re
import html
import hashlib
import hmac
import os
from typing import Optional

# Salt for reporter pseudonymization (server-side secret, fallback to deterministic salt in dev)
_REPORTER_SALT = os.environ.get("REPORTER_SALT", "trusttrace-salt-hackmatrix26").encode("utf-8")

# Regex to strip HTML/script tags
_TAG_RE = re.compile(r"<[^>]+>")


def sanitize_text(text: Optional[str], max_length: int = 1000) -> str:
    """Sanitize user-submitted text by stripping HTML tags, escaping entities, and capping length.
    
    Protects against XSS (COMM-004) and unbounded memory allocation.
    """
    if not text:
        return ""
    # Strip HTML tags
    clean = _TAG_RE.sub("", text)
    # Escape remaining HTML entities
    clean = html.escape(clean.strip())
    # Truncate to max length
    return clean[:max_length]


def hash_reporter_identity(raw_identifier: str) -> str:
    """Compute a non-reversible HMAC-SHA256 hash of reporter identifier.
    
    Ensures raw IP addresses, user IDs, or email addresses are NEVER stored or exposed.
    """
    if not raw_identifier:
        raw_identifier = "anonymous_client"
    return hmac.new(_REPORTER_SALT, raw_identifier.encode("utf-8"), hashlib.sha256).hexdigest()
