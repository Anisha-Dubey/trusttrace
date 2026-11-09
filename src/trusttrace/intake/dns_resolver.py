"""Safe DNS Resolution & Rebinding Defense.

Implements requirements:
- SSRF-004: Hostname resolving to prohibited IP blocked after resolution before connect
- SSRF-005: DNS rebinding defense: connection-time validation blocks prohibited second resolution
"""

import socket
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict
from .ip_classifier import classify_ip, IPClassificationResult


@dataclass(frozen=True)
class DNSResolutionResult:
    hostname: str
    is_safe: bool
    rejection_reason: Optional[str] = None
    resolved_ips: List[str] = field(default_factory=list)
    classified_ips: List[IPClassificationResult] = field(default_factory=list)
    pinned_ip: Optional[str] = None
    limitations: List[str] = field(default_factory=list)


class SafeDNSResolver:
    """DNS Resolver that enforces SSRF policy and protects against DNS rebinding."""

    def __init__(self, custom_lookup_fn: Optional[Callable[[str, int], List[str]]] = None):
        """
        Args:
            custom_lookup_fn: Optional hook for test mocks (hostname, port -> list of ip strings).
        """
        self._custom_lookup_fn = custom_lookup_fn

    def resolve(self, hostname: str, port: int = 443) -> DNSResolutionResult:
        """Resolve a hostname and classify every returned address.
        
        If ANY returned IP address violates the SSRF safety policy, the resolution
        is rejected and no connection should be made.
        """
        clean_host = hostname.strip().rstrip(".")
        resolved_ips: List[str] = []

        # Check if the hostname itself is directly a numeric IP literal
        direct_ip_res = classify_ip(clean_host)
        if direct_ip_res.rejection_reason != "invalid_ip_format":
            # Hostname is an IP literal
            if not direct_ip_res.is_safe:
                return DNSResolutionResult(
                    hostname=clean_host,
                    is_safe=False,
                    rejection_reason=direct_ip_res.rejection_reason,
                    resolved_ips=[clean_host],
                    classified_ips=[direct_ip_res],
                    limitations=[f"Direct IP target '{clean_host}' is prohibited: {direct_ip_res.rejection_reason}."]
                )
            return DNSResolutionResult(
                hostname=clean_host,
                is_safe=True,
                resolved_ips=[clean_host],
                classified_ips=[direct_ip_res],
                pinned_ip=clean_host
            )

        # Resolve via custom lookup or socket.getaddrinfo
        try:
            if self._custom_lookup_fn is not None:
                resolved_ips = self._custom_lookup_fn(clean_host, port)
            else:
                addr_info = socket.getaddrinfo(clean_host, port, proto=socket.IPPROTO_TCP)
                seen = set()
                for item in addr_info:
                    sockaddr = item[4]
                    ip = sockaddr[0]
                    if ip not in seen:
                        seen.add(ip)
                        resolved_ips.append(ip)
        except socket.gaierror as exc:
            return DNSResolutionResult(
                hostname=clean_host,
                is_safe=False,
                rejection_reason="dns_resolution_failed",
                limitations=[f"DNS resolution failed for '{clean_host}': {exc}"]
            )
        except Exception as exc:
            return DNSResolutionResult(
                hostname=clean_host,
                is_safe=False,
                rejection_reason="resolver_exception",
                limitations=[f"Unexpected error resolving '{clean_host}': {exc}"]
            )

        if not resolved_ips:
            return DNSResolutionResult(
                hostname=clean_host,
                is_safe=False,
                rejection_reason="no_dns_records",
                limitations=[f"No IP addresses returned for '{clean_host}'."]
            )

        # Classify every returned IP
        classified: List[IPClassificationResult] = []
        for ip in resolved_ips:
            cls_res = classify_ip(ip)
            classified.append(cls_res)
            if not cls_res.is_safe:
                # SSRF-004: Prohibited IP in resolution blocks the entire target
                return DNSResolutionResult(
                    hostname=clean_host,
                    is_safe=False,
                    rejection_reason=cls_res.rejection_reason,
                    resolved_ips=resolved_ips,
                    classified_ips=classified,
                    limitations=[
                        f"Hostname '{clean_host}' resolved to prohibited IP '{ip}': {cls_res.rejection_reason}."
                    ]
                )

        # All resolved IPs are safe public addresses; pin the first one for connection
        pinned_ip = resolved_ips[0]
        return DNSResolutionResult(
            hostname=clean_host,
            is_safe=True,
            resolved_ips=resolved_ips,
            classified_ips=classified,
            pinned_ip=pinned_ip
        )

    def validate_connection_ip(self, original_result: DNSResolutionResult, current_ip: str) -> bool:
        """SSRF-005: Re-validate IP at connection time to defeat DNS rebinding attacks.
        
        Verifies that the current destination IP is among the previously validated safe IPs,
        or verifies that current_ip itself is classified as safe.
        """
        if current_ip in original_result.resolved_ips:
            return True
        cls = classify_ip(current_ip)
        return cls.is_safe
