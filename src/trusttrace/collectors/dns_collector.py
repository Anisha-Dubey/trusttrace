"""Passive Bounded DNS Collector for Worker 01 Phase 02.

Collects A and AAAA records, canonical names, and passive infrastructure observations
under bounded timeout and error shielding.
"""

import socket
import time
from typing import Optional, List, Dict, Any, Callable
from .base import CollectorResult
from trusttrace.intake.dns_resolver import SafeDNSResolver, DNSResolutionResult


class DNSCollector:
    """Bounded DNS metadata collector."""

    def __init__(
        self,
        resolver: Optional[SafeDNSResolver] = None,
        timeout: float = 3.0,
        mock_lookup_fn: Optional[Callable[[str], Dict[str, Any]]] = None
    ):
        self.resolver = resolver or SafeDNSResolver()
        self.timeout = timeout
        self.mock_lookup_fn = mock_lookup_fn

    def collect(self, hostname: str, port: int = 443) -> CollectorResult:
        """Collect DNS observation for a hostname under timeout and error shielding."""
        start_time = time.time()

        if self.mock_lookup_fn:
            try:
                mock_data = self.mock_lookup_fn(hostname)
                if mock_data.get("simulate_failure"):
                    return CollectorResult(
                        kind="dns_resolution",
                        value={"error": mock_data.get("error_message", "simulated_dns_timeout")},
                        source="passive_dns_collector",
                        status="failed",
                        reliability="direct_observation",
                        limitations=[mock_data.get("limitation", "DNS lookup timed out within configured budget.")]
                    )
                return CollectorResult(
                    kind="dns_resolution",
                    value=mock_data.get("value", {"resolved_ips": ["93.184.216.34"], "record_types": ["A"]}),
                    source="passive_dns_collector",
                    status="observed",
                    reliability="direct_observation",
                    limitations=[]
                )
            except Exception as exc:
                return CollectorResult(
                    kind="dns_resolution",
                    value={"error": str(exc)},
                    source="passive_dns_collector",
                    status="failed",
                    reliability="direct_observation",
                    limitations=[f"DNS collector exception: {exc}"]
                )

        # Real lookup using SafeDNSResolver
        try:
            socket.setdefaulttimeout(self.timeout)
            dns_res = self.resolver.resolve(hostname, port)
            elapsed = time.time() - start_time

            if not dns_res.is_safe:
                return CollectorResult(
                    kind="dns_resolution",
                    value={
                        "rejection_reason": dns_res.rejection_reason,
                        "resolved_ips": dns_res.resolved_ips
                    },
                    source="passive_dns_collector",
                    status="blocked",
                    reliability="direct_observation",
                    limitations=dns_res.limitations
                )

            return CollectorResult(
                kind="dns_resolution",
                value={
                    "hostname": hostname,
                    "resolved_ips": dns_res.resolved_ips,
                    "pinned_ip": dns_res.pinned_ip,
                    "elapsed_sec": round(elapsed, 4)
                },
                source="passive_dns_collector",
                status="observed",
                reliability="direct_observation",
                limitations=[]
            )
        except (socket.timeout, TimeoutError) as exc:
            return CollectorResult(
                kind="dns_resolution",
                value={"error": "timeout", "elapsed_sec": round(time.time() - start_time, 4)},
                source="passive_dns_collector",
                status="failed",
                reliability="direct_observation",
                limitations=[f"DNS resolution exceeded timeout budget of {self.timeout}s: {exc}"]
            )
        except Exception as exc:
            return CollectorResult(
                kind="dns_resolution",
                value={"error": str(exc), "elapsed_sec": round(time.time() - start_time, 4)},
                source="passive_dns_collector",
                status="failed",
                reliability="direct_observation",
                limitations=[f"Passive DNS lookup failed: {exc}"]
            )
