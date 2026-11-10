"""Concurrency & Rate Limiting Guard for Worker 01 Phase 02.

Implements requirements:
- LIMIT-003: Rate and concurrency limits enforced on burst submissions
- Bounded memory storage and TTL eviction for client state tracking
"""

import time
import threading
from collections import deque
from typing import Dict, Tuple


class RateLimiter:
    """Sliding-window rate limiter and concurrency gate with bounded memory."""

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: float = 60.0,
        max_concurrency: int = 4,
        max_tracked_clients: int = 10000
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_concurrency = max_concurrency
        self.max_tracked_clients = max_tracked_clients
        self._requests: Dict[str, deque] = {}
        self._active_concurrency: Dict[str, int] = {}
        self._last_access: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _cleanup_stale_entries(self, now: float):
        """Purge expired client deques and bound memory usage."""
        stale_clients = []
        for cid, q in self._requests.items():
            while q and q[0] <= now - self.window_seconds:
                q.popleft()
            if not q and self._active_concurrency.get(cid, 0) == 0:
                stale_clients.append(cid)

        for cid in stale_clients:
            self._requests.pop(cid, None)
            self._active_concurrency.pop(cid, None)
            self._last_access.pop(cid, None)

        # Capacity ceiling enforcement
        if len(self._requests) >= self.max_tracked_clients:
            sorted_entries = sorted(self._last_access.items(), key=lambda kv: kv[1])
            excess = len(self._requests) - self.max_tracked_clients + 1
            for cid, _ in sorted_entries[:excess]:
                if self._active_concurrency.get(cid, 0) == 0:
                    self._requests.pop(cid, None)
                    self._active_concurrency.pop(cid, None)
                    self._last_access.pop(cid, None)

    def acquire(self, client_id: str = "default") -> Tuple[bool, str]:
        """Attempt to acquire a scan slot under rate and concurrency limits.

        Returns:
            (allowed: bool, reason: str)
        """
        with self._lock:
            now = time.time()
            self._cleanup_stale_entries(now)
            self._last_access[client_id] = now

            # Clean expired timestamps in sliding window for this client
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
        """Release active concurrency slot upon scan completion and prune idle records."""
        with self._lock:
            current = self._active_concurrency.get(client_id, 0)
            if current > 0:
                new_conc = current - 1
                if new_conc == 0:
                    self._active_concurrency.pop(client_id, None)
                    # If requests deque is also empty, clean up client record immediately
                    q = self._requests.get(client_id)
                    if q is not None and len(q) == 0:
                        self._requests.pop(client_id, None)
                        self._last_access.pop(client_id, None)
                else:
                    self._active_concurrency[client_id] = new_conc

