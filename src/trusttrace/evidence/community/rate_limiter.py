"""In-memory sliding window rate limiter and replay protection for community submissions."""

import time
from typing import Dict, List, Tuple
from collections import defaultdict


class RateLimitExceededError(ValueError):
    """Raised when request frequency exceeds allowed thresholds."""
    pass


class ReplaySubmissionError(ValueError):
    """Raised when an identical submission is replayed within a burst window."""
    pass


class CommunityRateLimiter:
    """Sliding-window rate limiter tracking client IP, domain velocity, and replay bursts."""

    def __init__(
        self,
        ip_limit_per_minute: int = 10,
        domain_limit_per_minute: int = 5,
        replay_burst_seconds: int = 5,
    ):
        self.ip_limit_per_minute = ip_limit_per_minute
        self.domain_limit_per_minute = domain_limit_per_minute
        self.replay_burst_seconds = replay_burst_seconds

        # IP -> list of timestamps
        self._ip_history: Dict[str, List[float]] = defaultdict(list)
        # Domain -> list of timestamps
        self._domain_history: Dict[str, List[float]] = defaultdict(list)
        # (IP, Domain, Claim) -> last timestamp
        self._last_submissions: Dict[Tuple[str, str, str], float] = {}

    def check_and_record(self, client_ip: str, normalized_domain: str, claim_type: str):
        """Check all rate boundaries and record submission if within limits.
        
        Raises:
            ReplaySubmissionError: If identical claim replayed within burst window.
            RateLimitExceededError: If IP or domain rate exceeded.
        """
        now = time.time()
        window_start = now - 60.0

        # 1. Replay check
        replay_key = (client_ip, normalized_domain.lower(), claim_type.lower())
        last_time = self._last_submissions.get(replay_key)
        if last_time and (now - last_time) < self.replay_burst_seconds:
            raise ReplaySubmissionError(
                f"Duplicate claim replayed too rapidly. Please wait {self.replay_burst_seconds}s before resubmitting."
            )

        # 2. Prune old timestamps
        self._ip_history[client_ip] = [t for t in self._ip_history[client_ip] if t > window_start]
        self._domain_history[normalized_domain] = [
            t for t in self._domain_history[normalized_domain] if t > window_start
        ]

        # 3. Check IP rate limit
        if len(self._ip_history[client_ip]) >= self.ip_limit_per_minute:
            raise RateLimitExceededError(
                f"Rate limit exceeded: Maximum {self.ip_limit_per_minute} submissions per minute per IP."
            )

        # 4. Check domain velocity limit
        if len(self._domain_history[normalized_domain]) >= self.domain_limit_per_minute:
            raise RateLimitExceededError(
                f"Domain submission rate exceeded: Maximum {self.domain_limit_per_minute} reports per minute for '{normalized_domain}'."
            )

        # 5. Record submission
        self._ip_history[client_ip].append(now)
        self._domain_history[normalized_domain].append(now)
        self._last_submissions[replay_key] = now

    def reset(self):
        """Reset all rate tracking history (useful for test isolation)."""
        self._ip_history.clear()
        self._domain_history.clear()
        self._last_submissions.clear()


default_rate_limiter = CommunityRateLimiter()
