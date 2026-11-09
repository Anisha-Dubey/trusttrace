"""Safe Redirect Handling Policy.

Implements requirements:
- REDIR-001: Redirect to prohibited IP/domain blocked and scan rejected/partial
- REDIR-002: Redirect loop / excessive hops capped with explicit limit reason
- REDIR-003: Redirect to unsupported scheme blocked with explicit limitation
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import urllib.parse
from .url_policy import parse_and_validate_url, URLParseResult
from .dns_resolver import SafeDNSResolver, DNSResolutionResult


@dataclass(frozen=True)
class RedirectHopResult:
    is_safe: bool
    rejection_reason: Optional[str] = None
    target_url: str = ""
    parsed_url: Optional[URLParseResult] = None
    dns_result: Optional[DNSResolutionResult] = None
    hop_count: int = 0
    limitations: List[str] = field(default_factory=list)


class RedirectPolicy:
    """Evaluates redirect hops for safety before subsequent network requests are made."""

    def __init__(self, max_hops: int = 5, resolver: Optional[SafeDNSResolver] = None):
        self.max_hops = max_hops
        self.resolver = resolver or SafeDNSResolver()

    def evaluate_hop(
        self,
        current_url: str,
        redirect_target: str,
        current_hop_count: int
    ) -> RedirectHopResult:
        """Evaluate a single redirect hop for safety."""
        next_hop_count = current_hop_count + 1

        # 1. Enforce max hop count (REDIR-002)
        if next_hop_count > self.max_hops:
            return RedirectHopResult(
                is_safe=False,
                rejection_reason="excessive_redirect_hops",
                target_url=redirect_target,
                hop_count=next_hop_count,
                limitations=[
                    f"Redirect limit exceeded ({self.max_hops} max hops). Possible redirect loop."
                ]
            )

        # Resolve relative URLs against the current URL
        full_target_url = urllib.parse.urljoin(current_url, redirect_target)

        # 2. Parse and validate URL structure (REDIR-003: Scheme check)
        url_res = parse_and_validate_url(full_target_url)
        if not url_res.is_valid:
            return RedirectHopResult(
                is_safe=False,
                rejection_reason=f"redirect_{url_res.rejection_reason}",
                target_url=full_target_url,
                parsed_url=url_res,
                hop_count=next_hop_count,
                limitations=[
                    f"Redirect to invalid destination: {url_res.rejection_reason}. "
                    f"Details: {url_res.limitations}"
                ]
            )

        # 3. Resolve and classify destination IP (REDIR-001)
        dns_res = self.resolver.resolve(url_res.ascii_host, url_res.port)
        if not dns_res.is_safe:
            return RedirectHopResult(
                is_safe=False,
                rejection_reason=f"redirect_{dns_res.rejection_reason}",
                target_url=full_target_url,
                parsed_url=url_res,
                dns_result=dns_res,
                hop_count=next_hop_count,
                limitations=[
                    f"Redirect destination resolved to prohibited target: {dns_res.rejection_reason}."
                ]
            )

        return RedirectHopResult(
            is_safe=True,
            target_url=full_target_url,
            parsed_url=url_res,
            dns_result=dns_res,
            hop_count=next_hop_count
        )

    def filter_headers_for_redirect(
        self,
        source_url: str,
        destination_url: str,
        headers: Dict[str, str]
    ) -> Dict[str, str]:
        """Strip sensitive authorization and cookie headers when crossing origins."""
        src_parsed = urllib.parse.urlsplit(source_url)
        dst_parsed = urllib.parse.urlsplit(destination_url)

        is_same_origin = (
            src_parsed.scheme.lower() == dst_parsed.scheme.lower()
            and src_parsed.netloc.lower() == dst_parsed.netloc.lower()
        )

        filtered = dict(headers)
        if not is_same_origin:
            for sensitive_header in ("Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key"):
                filtered.pop(sensitive_header, None)
                filtered.pop(sensitive_header.lower(), None)
        return filtered
