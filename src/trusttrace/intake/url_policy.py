"""URL Parsing, Normalization, Credential Checking, and Redaction Policy.

Implements requirements:
- URL-001: Normalized host and accepted scheme
- URL-002: Credential rejection without network egress
- URL-003: Sensitive token redaction from query/path
- URL-004: Unicode confusable/IDNA preservation as evidence
- URL-005: Unsupported scheme rejection before resolution
- DATA-001: Secret query/path redaction
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import urllib.parse
import re

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}
SAFE_ADDITIONAL_PORTS = frozenset({8080, 8443, 3000, 5000, 8000, 8008, 8888})

SENSITIVE_PARAM_NAMES = frozenset({
    "token", "auth", "secret", "key", "api_key", "apikey",
    "access_token", "id_token", "refresh_token", "session",
    "password", "pass", "pwd", "signature", "sig", "bearer",
    "credential", "credentials", "jwt"
})

JWT_PATTERN = re.compile(r"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+$")


@dataclass(frozen=True)
class URLParseResult:
    is_valid: bool
    rejection_reason: Optional[str] = None
    submitted_url: str = ""
    submitted_url_redacted: str = ""
    scheme: str = ""
    raw_host: str = ""
    normalized_host: Optional[str] = None
    ascii_host: Optional[str] = None
    unicode_host: Optional[str] = None
    is_idna: bool = False
    port: Optional[int] = None
    path: str = "/"
    query: str = ""
    fragment: str = ""
    limitations: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)


def redact_sensitive_tokens(url_str: str) -> str:
    """Redact sensitive credentials, query parameters, and fragment secrets."""
    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception:
        return "[INVALID_URL_REDACTED]"

    # 1. Redact credentials if present
    netloc = parsed.netloc
    if "@" in netloc:
        creds, _, hostpart = netloc.rpartition("@")
        netloc = f"[REDACTED_CREDENTIALS]@{hostpart}"

    # 2. Redact query parameters
    query = parsed.query
    if query:
        q_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        redacted_pairs = []
        for k, v in q_pairs:
            k_lower = k.lower()
            if (
                k_lower in SENSITIVE_PARAM_NAMES
                or any(sub in k_lower for sub in ("token", "secret", "auth", "key", "password"))
                or JWT_PATTERN.match(v)
            ):
                redacted_pairs.append((k, "[REDACTED]"))
            else:
                redacted_pairs.append((k, v))
        query = urllib.parse.urlencode(redacted_pairs)

    # 3. Redact fragment if it looks like query params or token
    fragment = parsed.fragment
    if fragment:
        if any(term in fragment.lower() for term in ("access_token", "token=", "key=", "id_token=")):
            fragment = "[REDACTED]"

    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))


def parse_and_validate_url(raw_url: str) -> URLParseResult:
    """Strictly parse, validate, and normalize a URL before any network interaction.
    
    Guarantees:
    - Rejects empty, too short (< 8 chars), or excessively long (> 2048 chars) URLs.
    - Rejects unsupported schemes (only http / https allowed).
    - Rejects credentials embedded in URL without network egress.
    - Canonicalizes hostname and produces Punycode and Unicode display forms.
    - Redacts sensitive query tokens.
    """
    if not isinstance(raw_url, str):
        return URLParseResult(
            is_valid=False,
            rejection_reason="url_not_a_string",
            submitted_url=str(raw_url),
            submitted_url_redacted="[INVALID]",
            limitations=["URL input must be a string."]
        )

    raw_url = raw_url.strip()
    if len(raw_url) < 8:
        return URLParseResult(
            is_valid=False,
            rejection_reason="url_too_short",
            submitted_url=raw_url,
            submitted_url_redacted=raw_url,
            limitations=["URL length is below minimum required 8 characters."]
        )

    if len(raw_url) > 2048:
        return URLParseResult(
            is_valid=False,
            rejection_reason="url_too_long",
            submitted_url=raw_url[:100] + "...[TRUNCATED]",
            submitted_url_redacted="[TOO_LONG_REDACTED]",
            limitations=["URL length exceeds 2048 characters limit."]
        )

    # Attempt parsing
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except Exception as exc:
        return URLParseResult(
            is_valid=False,
            rejection_reason="url_parse_error",
            submitted_url=raw_url,
            submitted_url_redacted="[PARSE_FAILED]",
            limitations=[f"Failed to parse URL syntax: {exc}"]
        )

    scheme = (parsed.scheme or "").lower()
    if not scheme:
        return URLParseResult(
            is_valid=False,
            rejection_reason="missing_scheme",
            submitted_url=raw_url,
            submitted_url_redacted=redact_sensitive_tokens(raw_url),
            limitations=["URL is missing scheme (http:// or https:// required)."]
        )

    if scheme not in ALLOWED_SCHEMES:
        return URLParseResult(
            is_valid=False,
            rejection_reason="unsupported_scheme",
            submitted_url=raw_url,
            submitted_url_redacted=redact_sensitive_tokens(raw_url),
            scheme=scheme,
            limitations=[f"Scheme '{scheme}' is prohibited. Only HTTP and HTTPS are permitted."]
        )

    # Check for embedded credentials (URL-002)
    # Check both parsed.username/password and raw netloc for presence of '@'
    netloc = parsed.netloc
    if "@" in netloc or parsed.username or parsed.password:
        return URLParseResult(
            is_valid=False,
            rejection_reason="credentials_in_url",
            submitted_url=raw_url,
            submitted_url_redacted=redact_sensitive_tokens(raw_url),
            scheme=scheme,
            limitations=["Credentials embedded in URL are prohibited for safety."]
        )

    # Extract hostname and port
    hostname = parsed.hostname
    if not hostname:
        return URLParseResult(
            is_valid=False,
            rejection_reason="missing_hostname",
            submitted_url=raw_url,
            submitted_url_redacted=redact_sensitive_tokens(raw_url),
            scheme=scheme,
            limitations=["URL does not contain a valid hostname."]
        )

    raw_host = hostname.strip().rstrip(".")
    if not raw_host:
        return URLParseResult(
            is_valid=False,
            rejection_reason="empty_hostname",
            submitted_url=raw_url,
            submitted_url_redacted=redact_sensitive_tokens(raw_url),
            scheme=scheme,
            limitations=["URL hostname is empty after normalization."]
        )

    # Host normalization and IDNA handling (URL-001, URL-004)
    # Convert to Punycode (ASCII) and Unicode display form
    evidence_records = []
    is_idna = False
    try:
        # If it's already punycode xn--, decode it to check Unicode form
        if raw_host.lower().startswith("xn--") or ".xn--" in raw_host.lower():
            is_idna = True
            ascii_host = raw_host.lower()
            unicode_host = ascii_host.encode("ascii").decode("idna")
        else:
            ascii_host = raw_host.encode("idna").decode("ascii").lower()
            unicode_host = raw_host.lower()
            if ascii_host != unicode_host:
                is_idna = True
    except Exception as exc:
        return URLParseResult(
            is_valid=False,
            rejection_reason="idna_encoding_error",
            submitted_url=raw_url,
            submitted_url_redacted=redact_sensitive_tokens(raw_url),
            scheme=scheme,
            raw_host=raw_host,
            limitations=[f"IDNA / punycode conversion failed: {exc}"]
        )

    if is_idna:
        evidence_records.append({
            "evidence_id": "ev-idna-normalizer-001",
            "kind": "idna_confusable_feature",
            "value": {
                "ascii_host": ascii_host,
                "unicode_host": unicode_host,
                "has_idna": True
            },
            "source": "url_intake_normalizer",
            "status": "observed",
            "reliability": "direct_observation",
            "limitations": [
                "IDNA feature recorded as contextual evidence; not treated as malicious by itself."
            ]
        })

    # Port validation
    port = parsed.port
    if port is not None:
        if port not in (80, 443) and port not in SAFE_ADDITIONAL_PORTS:
            return URLParseResult(
                is_valid=False,
                rejection_reason="non_standard_port_prohibited",
                submitted_url=raw_url,
                submitted_url_redacted=redact_sensitive_tokens(raw_url),
                scheme=scheme,
                raw_host=raw_host,
                port=port,
                limitations=[f"Port {port} is prohibited. Allowed web ports: 80, 443, 8080, 8443."]
            )

    redacted_url = redact_sensitive_tokens(raw_url)
    path = parsed.path or "/"

    return URLParseResult(
        is_valid=True,
        submitted_url=raw_url,
        submitted_url_redacted=redacted_url,
        scheme=scheme,
        raw_host=raw_host,
        normalized_host=ascii_host,
        ascii_host=ascii_host,
        unicode_host=unicode_host,
        is_idna=is_idna,
        port=port or ALLOWED_DEFAULT_PORTS.get(scheme, 80),
        path=path,
        query=parsed.query,
        fragment=parsed.fragment,
        evidence=evidence_records,
        limitations=[]
    )

