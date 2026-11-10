"""Bounded HTTP Metadata & Header Collector for Worker 01 Phase 02.

Enforces:
- LIMIT-001: Timeout budget enforcement
- LIMIT-002: Bounded body and header response cap (no unbounded allocations)
- Safe redirect following using RedirectPolicy
- Zero script execution and zero browser rendering
"""

import http.client
import ssl
import socket
import urllib.request
import urllib.parse
import time
from typing import Optional, Dict, Any, Callable, List, Tuple
from .base import CollectorResult
from trusttrace.intake.redirect_policy import RedirectPolicy


class BoundedHTTPCollector:
    """Bounded HTTP metadata collector with IP connection pinning for SSRF/TOCTOU defense."""

    def __init__(
        self,
        timeout: float = 3.0,
        max_bytes: int = 65536,  # 64 KB cap (LIMIT-002)
        redirect_policy: Optional[RedirectPolicy] = None,
        mock_http_fn: Optional[Callable[[str], Dict[str, Any]]] = None
    ):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.redirect_policy = redirect_policy or RedirectPolicy()
        self.mock_http_fn = mock_http_fn

    def _execute_pinned_request(
        self,
        current_url: str,
        pinned_ip: Optional[str],
        headers: Dict[str, str],
        timeout: float
    ) -> Tuple[int, Dict[str, str], bytes, bool]:
        """Execute a single HTTP/HTTPS request directly to pinned_ip.

        Defeats DNS rebinding TOCTOU attacks while preserving the virtual
        Host header and TLS SNI server_hostname.
        """
        parsed = urllib.parse.urlsplit(current_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if scheme == "https" else 80)
        target_host = pinned_ip or hostname
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query += f"?{parsed.query}"

        host_header = hostname
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            host_header = f"{hostname}:{port}"

        conn: Optional[http.client.HTTPConnection] = None
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    host=target_host,
                    port=port,
                    timeout=timeout,
                    context=ctx
                )
                conn._server_hostname = hostname
            else:
                conn = http.client.HTTPConnection(
                    host=target_host,
                    port=port,
                    timeout=timeout
                )

            conn.putrequest("GET", path_and_query, skip_host=True)
            conn.putheader("Host", host_header)
            for k, v in headers.items():
                if k.lower() != "host":
                    conn.putheader(k, v)
            conn.endheaders()

            resp = conn.getresponse()
            code = resp.status
            resp_headers = {k: v for k, v in resp.getheaders()}

            raw_body = resp.read(self.max_bytes + 1)
            truncated = False
            if len(raw_body) > self.max_bytes:
                raw_body = raw_body[:self.max_bytes]
                truncated = True

            return code, resp_headers, raw_body, truncated
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def collect(
        self,
        url: str,
        pinned_ip: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> List[CollectorResult]:
        """Collect HTTP headers and redirect chain evidence with connection IP pinning."""
        start_time = time.time()
        effective_timeout = timeout if timeout is not None else self.timeout

        if self.mock_http_fn:
            try:
                mock_data = self.mock_http_fn(url)
                if mock_data.get("simulate_timeout"):
                    return [
                        CollectorResult(
                            kind="http_headers",
                            value={"error": "http_request_timeout", "elapsed_sec": effective_timeout},
                            source="bounded_http_collector",
                            status="failed",
                            reliability="direct_observation",
                            limitations=[f"HTTP request exceeded timeout budget of {effective_timeout}s."]
                        )
                    ]
                if mock_data.get("simulate_oversized"):
                    return [
                        CollectorResult(
                            kind="http_headers",
                            value={
                                "status_code": 200,
                                "bytes_read": self.max_bytes,
                                "body_truncated": True,
                                "headers": mock_data.get("headers", {})
                            },
                            source="bounded_http_collector",
                            status="observed",
                            reliability="direct_observation",
                            limitations=[f"Response body truncated at {self.max_bytes} bytes ceiling (LIMIT-002)."]
                        )
                    ]
                if mock_data.get("simulate_error"):
                    return [
                        CollectorResult(
                            kind="http_headers",
                            value={"error": mock_data.get("error", "http_error")},
                            source="bounded_http_collector",
                            status="failed",
                            reliability="direct_observation",
                            limitations=[mock_data.get("limitation", "HTTP connection failed.")]
                        )
                    ]

                results = []
                if "headers_value" in mock_data:
                    results.append(CollectorResult(
                        kind="http_headers",
                        value=mock_data["headers_value"],
                        source="bounded_http_collector",
                        status="observed",
                        reliability="direct_observation",
                        limitations=[]
                    ))
                if "redirect_value" in mock_data:
                    results.append(CollectorResult(
                        kind="redirect_chain",
                        value=mock_data["redirect_value"],
                        source="bounded_redirect_collector",
                        status="observed",
                        reliability="direct_observation",
                        limitations=mock_data.get("redirect_limitations", [])
                    ))
                return results
            except Exception as exc:
                return [
                    CollectorResult(
                        kind="http_headers",
                        value={"error": str(exc)},
                        source="bounded_http_collector",
                        status="failed",
                        reliability="direct_observation",
                        limitations=[f"HTTP mock exception: {exc}"]
                    )
                ]

        # Real low-impact bounded GET request with IP pinning across hops
        results: List[CollectorResult] = []
        current_url = url
        current_pinned_ip = pinned_ip
        hop_count = 0
        redirect_chain: List[str] = [current_url]
        redirect_blocked = False
        redirect_block_reason = None

        headers = {
            "User-Agent": "TrustTrace-Metadata-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        final_resp = None
        bytes_read = 0
        truncated = False

        while hop_count <= self.redirect_policy.max_hops:
            remaining_time = effective_timeout - (time.time() - start_time)
            if remaining_time <= 0:
                return [
                    CollectorResult(
                        kind="http_headers",
                        value={"error": "timeout", "elapsed_sec": round(time.time() - start_time, 4)},
                        source="bounded_http_collector",
                        status="failed",
                        reliability="direct_observation",
                        limitations=[f"HTTP request exceeded timeout budget of {effective_timeout}s."]
                    )
                ]

            try:
                code, resp_headers, raw_body, truncated = self._execute_pinned_request(
                    current_url=current_url,
                    pinned_ip=current_pinned_ip,
                    headers=headers,
                    timeout=remaining_time
                )

                # Check for redirect status
                if code in (301, 302, 303, 307, 308):
                    location = resp_headers.get("Location") or resp_headers.get("location")
                    if not location:
                        break
                    hop_res = self.redirect_policy.evaluate_hop(
                        current_url=current_url,
                        redirect_target=location,
                        current_hop_count=hop_count
                    )
                    if not hop_res.is_safe:
                        redirect_blocked = True
                        redirect_block_reason = hop_res.rejection_reason
                        break

                    # Update headers for next hop (strip sensitive headers on cross-origin)
                    headers = self.redirect_policy.filter_headers_for_redirect(
                        source_url=current_url,
                        destination_url=hop_res.target_url,
                        headers=headers
                    )
                    current_url = hop_res.target_url
                    current_pinned_ip = (
                        hop_res.dns_result.pinned_ip
                        if (hop_res.dns_result and hop_res.dns_result.pinned_ip)
                        else None
                    )
                    redirect_chain.append(current_url)
                    hop_count = hop_res.hop_count
                    continue
                else:
                    bytes_read = len(raw_body)
                    final_resp = {
                        "status_code": code,
                        "headers": {k: v for k, v in resp_headers.items() if len(str(v)) < 512},
                        "bytes_read": bytes_read,
                        "body_truncated": truncated,
                        "pinned_ip": current_pinned_ip,
                        "elapsed_sec": round(time.time() - start_time, 4)
                    }
                    break

            except (socket.timeout, TimeoutError):
                return [
                    CollectorResult(
                        kind="http_headers",
                        value={"error": "timeout", "elapsed_sec": round(time.time() - start_time, 4)},
                        source="bounded_http_collector",
                        status="failed",
                        reliability="direct_observation",
                        limitations=[f"HTTP request exceeded timeout budget of {effective_timeout}s."]
                    )
                ]
            except Exception as exc:
                return [
                    CollectorResult(
                        kind="http_headers",
                        value={"error": str(exc), "elapsed_sec": round(time.time() - start_time, 4)},
                        source="bounded_http_collector",
                        status="failed",
                        reliability="direct_observation",
                        limitations=[f"HTTP request failed: {exc}"]
                    )
                ]

        # 1. HTTP Headers evidence
        if final_resp:
            limitations = []
            if final_resp.get("body_truncated"):
                limitations.append(f"Response capped at {self.max_bytes} bytes ceiling (LIMIT-002).")

            # Extract security header signals
            resp_h = final_resp.get("headers", {})
            hsts = any(k.lower() == "strict-transport-security" for k in resp_h)
            csp = any(k.lower() == "content-security-policy" for k in resp_h)
            xfo = any(k.lower() == "x-frame-options" for k in resp_h)

            final_resp["security_headers"] = {
                "has_hsts": hsts,
                "has_csp": csp,
                "has_x_frame_options": xfo
            }

            results.append(CollectorResult(
                kind="http_headers",
                value=final_resp,
                source="bounded_http_collector",
                status="observed",
                reliability="direct_observation",
                limitations=limitations
            ))

        # 2. Redirect chain evidence
        if len(redirect_chain) > 1 or redirect_blocked:
            r_limitations = []
            r_status = "observed"
            if redirect_blocked:
                r_status = "blocked"
                r_limitations.append(f"Redirect hop blocked by security policy: {redirect_block_reason}.")

            results.append(CollectorResult(
                kind="redirect_chain",
                value={
                    "chain": redirect_chain,
                    "hop_count": len(redirect_chain) - 1,
                    "redirect_blocked": redirect_blocked,
                    "rejection_reason": redirect_block_reason
                },
                source="bounded_redirect_collector",
                status=r_status,
                reliability="direct_observation",
                limitations=r_limitations
            ))

        return results

