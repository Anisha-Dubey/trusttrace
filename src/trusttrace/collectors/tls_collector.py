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


class TLSCollector:
    """Bounded TLS certificate collector."""

    def __init__(
        self,
        timeout: float = 3.0,
        mock_cert_fn: Optional[Callable[[str, int], Dict[str, Any]]] = None
    ):
        self.timeout = timeout
        self.mock_cert_fn = mock_cert_fn

    def collect(self, hostname: str, port: int = 443, pinned_ip: Optional[str] = None) -> CollectorResult:
        """Collect TLS certificate metadata under timeout and error shielding."""
        start_time = time.time()

        if self.mock_cert_fn:
            try:
                mock_data = self.mock_cert_fn(hostname, port)
                if mock_data.get("simulate_timeout"):
                    return CollectorResult(
                        kind="tls_certificate",
                        value={"error": "tls_handshake_timeout", "elapsed_sec": self.timeout},
                        source="bounded_tls_collector",
                        status="failed",
                        reliability="direct_observation",
                        limitations=[f"TLS handshake timed out after {self.timeout}s."]
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

            with socket.create_connection((target_host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    elapsed = time.time() - start_time

            # Parse subject and SANs
            sans: List[str] = []
            if cert_dict and "subjectAltName" in cert_dict:
                for typ, name in cert_dict["subjectAltName"]:
                    if typ == "DNS":
                        sans.append(name.lower())

            # Hostname matching check
            hostname_lower = hostname.lower()
            hostname_match = (
                hostname_lower in sans
                or any(
                    san.startswith("*.") and hostname_lower.endswith(san[1:])
                    for san in sans
                )
            )

            # Dates
            not_after_str = cert_dict.get("notAfter", "") if cert_dict else ""
            not_before_str = cert_dict.get("notBefore", "") if cert_dict else ""
            is_expired = False
            if not_after_str:
                try:
                    # format: 'May  4 12:00:00 2027 GMT'
                    expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > expiry_dt:
                        is_expired = True
                except Exception:
                    pass

            is_valid = bool(hostname_match and not is_expired and cert_dict)

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
                    "subject": dict(x[0] for x in cert_dict.get("subject", [])) if cert_dict else {},
                    "issuer": dict(x[0] for x in cert_dict.get("issuer", [])) if cert_dict else {},
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
                limitations=[f"TLS handshake exceeded timeout budget of {self.timeout}s: {exc}"]
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
