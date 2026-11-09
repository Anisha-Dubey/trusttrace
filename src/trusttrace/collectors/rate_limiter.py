"""Concurrency & Rate Limiting Guard for Worker 01 Phase 02.

Implements requirement:
- LIMIT-003: Rate and concurrency limits enforced on burst submissions
"""

import time
import threading
from collections import deque
from typing import Dict, Tuple


class RateLimiter:
    """Sliding-window rate limiter and concurrency gate."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0, max_concurrency: int = 4):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_concurrency = max_concurrency
        self._requests: Dict[str, deque] = {}
        self._active_concurrency: Dict[str, int] = {}
        self._lock = threading.Lock()

    def acquire(self, client_id: str = "default") -> Tuple[bool, str]:
        """Attempt to acquire a scan slot under rate and concurrency limits.
        
        Returns:
            (allowed: bool, reason: str)
        """
        with self._lock:
            now = time.time()

            # Clean expired timestamps in sliding window
            if client_id not in self._requests:
                self._requests[client_id] = deque()
            q = self._requests[client_id]

            while q and q[0] <= now - self.window_seconds:
                q.popleft()

            # 1. Check rate limit
            if len(q) >= self.max_requests:
                retry_after = round(self.window_seconds - (now - q[0]), 1)
                return False, f"rate_limit_exceeded (max {self.max_requests} reqs/{self.window_seconds}s, retry after {retry_after}s)"

            # 2. Check concurrency
            current_conc = self._active_concurrency.get(client_id, 0)
            if current_conc >= self.max_concurrency:
                return False, f"concurrency_limit_exceeded (max {self.max_concurrency} concurrent scans)"

            # Approved
            q.append(now)
            self._active_concurrency[client_id] = current_conc + 1
            return True, "ok"

    def release(self, client_id: str = "default"):
        """Release active concurrency slot upon scan completion."""
        with self._lock:
            current = self._active_concurrency.get(client_id, 0)
            if current > 0:
                self._active_concurrency[client_id] = current - 1
