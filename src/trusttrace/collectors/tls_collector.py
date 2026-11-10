"""Bounded TLS Certificate Collector for Worker 01 Phase 02.

Extracts certificate metadata, validity window, SANs, and issuer.
Enforces:
- TLS-001: Valid certificate marks certificate=valid, but identity remains unverified
- TLS-002: Expired or hostname-mismatched certificate is technical warning; not sole proof of phishing
- LIMIT-001: Timeout budget enforcement and graceful degradation
"""

import ssl
import socket
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Callable, List
from .base import CollectorResult

try:
    import cryptography.x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


def parse_der_certificate(cert_bin: bytes) -> Dict[str, Any]:
    """Parse raw DER X.509 certificate bytes into structured metadata.

    Reliably extracts SANs, subject, issuer, and validity window even when
    ssl.CERT_NONE is used and Python's ssock.getpeercert(False) is empty.
    """
    if not _HAS_CRYPTOGRAPHY or not cert_bin:
        return {}

    cert = cryptography.x509.load_der_x509_certificate(cert_bin)

    # Subject attributes
    subject: Dict[str, str] = {}
    for attr in cert.subject:
        attr_name = getattr(attr.oid, "_name", str(attr.oid.dotted_string))
        subject[attr_name] = str(attr.value)

    # Issuer attributes
    issuer: Dict[str, str] = {}
    for attr in cert.issuer:
        attr_name = getattr(attr.oid, "_name", str(attr.oid.dotted_string))
        issuer[attr_name] = str(attr.value)

    # Dates
    if hasattr(cert, "not_valid_after_utc"):
        not_before_dt = cert.not_valid_before_utc
        not_after_dt = cert.not_valid_after_utc
    else:
        not_before_dt = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after_dt = cert.not_valid_after.replace(tzinfo=timezone.utc)

    not_before_str = not_before_dt.strftime("%b %d %H:%M:%S %Y GMT")
    not_after_str = not_after_dt.strftime("%b %d %H:%M:%S %Y GMT")
    is_expired = datetime.now(timezone.utc) > not_after_dt

    # SANs
    sans: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            sans.append(str(name.value).lower())
    except Exception:
        pass

    # Fallback to commonName if no SANs present
    if not sans and "commonName" in subject:
        sans.append(subject["commonName"].lower())

    return {
        "sans": sans,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before_str,
        "not_after": not_after_str,
        "is_expired": is_expired,
        "serial_number": str(cert.serial_number)
    }


class TLSCollector:
    """Bounded TLS certificate collector."""

    def __init__(
        self,
        timeout: float = 3.0,
        mock_cert_fn: Optional[Callable[[str, int], Dict[str, Any]]] = None
    ):
        self.timeout = timeout
        self.mock_cert_fn = mock_cert_fn

    def collect(
        self,
        hostname: str,
        port: int = 443,
        pinned_ip: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> CollectorResult:
        """Collect TLS certificate metadata under timeout and error shielding."""
        start_time = time.time()
        effective_timeout = timeout if timeout is not None else self.timeout

        if self.mock_cert_fn:
            try:
                mock_data = self.mock_cert_fn(hostname, port)
                if mock_data.get("simulate_timeout"):
                    return CollectorResult(
                        kind="tls_certificate",
                        value={"error": "tls_handshake_timeout", "elapsed_sec": effective_timeout},
                        source="bounded_tls_collector",
                        status="failed",
                        reliability="direct_observation",
                        limitations=[f"TLS handshake timed out after {effective_timeout}s."]
                    )
                if mock_data.get("simulate_error"):
                    return CollectorResult(
                        kind="tls_certificate",
                        value={"error": mock_data.get("error", "ssl_error")},
                        source="bounded_tls_collector",
                        status="failed",
                        reliability="direct_observation",
                        limitations=[mock_data.get("limitation", "TLS connection failed.")]
                    )

                # Return mock certificate details
                return CollectorResult(
                    kind="tls_certificate",
                    value=mock_data["value"],
                    source="bounded_tls_collector",
                    status="observed",
                    reliability="direct_observation",
                    limitations=mock_data.get("limitations", [])
                )
            except Exception as exc:
                return CollectorResult(
                    kind="tls_certificate",
                    value={"error": str(exc)},
                    source="bounded_tls_collector",
                    status="failed",
                    reliability="direct_observation",
                    limitations=[f"TLS mock exception: {exc}"]
                )

        # Real TLS handshake
        target_host = pinned_ip or hostname
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False  # We inspect hostname match explicitly for TLS-001/TLS-002
            ctx.verify_mode = ssl.CERT_NONE  # Grab peer cert even if untrusted/expired to observe truth

            with socket.create_connection((target_host, port), timeout=effective_timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    elapsed = time.time() - start_time

            # Parse certificate details reliably from DER binary or cert_dict
            sans: List[str] = []
            subject: Dict[str, Any] = {}
            issuer: Dict[str, Any] = {}
            not_after_str = ""
            not_before_str = ""
            is_expired = False
            cert_found = False

            if cert_bin:
                der_meta = parse_der_certificate(cert_bin)
                if der_meta:
                    cert_found = True
                    sans = der_meta["sans"]
                    subject = der_meta["subject"]
                    issuer = der_meta["issuer"]
                    not_before_str = der_meta["not_before"]
                    not_after_str = der_meta["not_after"]
                    is_expired = der_meta["is_expired"]

            if not cert_found and cert_dict:
                cert_found = True
                if "subjectAltName" in cert_dict:
                    for typ, name in cert_dict["subjectAltName"]:
                        if typ == "DNS":
                            sans.append(name.lower())
                subject = dict(x[0] for x in cert_dict.get("subject", []))
                issuer = dict(x[0] for x in cert_dict.get("issuer", []))
                not_after_str = cert_dict.get("notAfter", "")
                not_before_str = cert_dict.get("notBefore", "")
                if not_after_str:
                    try:
                        expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        if datetime.now(timezone.utc) > expiry_dt:
                            is_expired = True
                    except Exception:
                        pass

            # Hostname matching check
            hostname_lower = hostname.lower()
            hostname_match = (
                hostname_lower in sans
                or any(
                    san.startswith("*.") and (hostname_lower == san[2:] or hostname_lower.endswith(san[1:]))
                    for san in sans
                )
            )

            is_valid = bool(hostname_match and not is_expired and cert_found)

            limitations = []
            if is_valid:
                # Invariant TLS-001: Valid TLS certificate is technical encryption only; not identity authorization
                limitations.append(
                    "Valid TLS certificate verifies channel encryption only; it does not prove organizational legitimacy."
                )
            else:
                # Invariant TLS-002: Technical failure is not proof of phishing
                reasons = []
                if is_expired:
                    reasons.append("certificate is expired")
                if not hostname_match:
                    reasons.append(f"hostname '{hostname}' does not match SANs {sans}")
                limitations.append(
                    f"TLS technical anomaly ({', '.join(reasons)}); technical failure is not sole proof of malicious activity."
                )

            return CollectorResult(
                kind="tls_certificate",
                value={
                    "is_valid": is_valid,
                    "hostname_match": hostname_match,
                    "is_expired": is_expired,
                    "subject": subject,
                    "issuer": issuer,
                    "sans": sans,
                    "version": version,
                    "cipher": cipher[0] if cipher else None,
                    "not_after": not_after_str,
                    "not_before": not_before_str,
                    "elapsed_sec": round(elapsed, 4)
                },
                source="bounded_tls_collector",
                status="observed",
                reliability="direct_observation",
                limitations=limitations
            )

        except (socket.timeout, TimeoutError) as exc:
            return CollectorResult(
                kind="tls_certificate",
                value={"error": "timeout", "elapsed_sec": round(time.time() - start_time, 4)},
                source="bounded_tls_collector",
                status="failed",
                reliability="direct_observation",
                limitations=[f"TLS handshake exceeded timeout budget of {effective_timeout}s: {exc}"]
            )
        except Exception as exc:
            return CollectorResult(
                kind="tls_certificate",
                value={"error": str(exc), "elapsed_sec": round(time.time() - start_time, 4)},
                source="bounded_tls_collector",
                status="failed",
                reliability="direct_observation",
                limitations=[f"TLS inspection failed: {exc}"]
            )

