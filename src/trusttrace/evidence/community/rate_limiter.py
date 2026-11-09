"""Pluggable, production-ready sliding window rate limiter and replay protection."""

import os
import time
import threading
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional
from collections import defaultdict


class RateLimitExceededError(ValueError):
    """Raised when request frequency exceeds allowed thresholds."""
    pass


class ReplaySubmissionError(ValueError):
    """Raised when an identical submission is replayed within a burst window."""
    pass


class RateLimiterBackendError(RuntimeError):
    """Raised when the rate limiter backend infrastructure encounters an unrecoverable failure."""
    pass


class BaseRateLimiterBackend(ABC):
    """Abstract interface for rate limiting backends."""

    @abstractmethod
    def check_and_record(
        self,
        client_ip: str,
        normalized_domain: str,
        claim_type: str,
        ip_limit_per_minute: int,
        domain_limit_per_minute: int,
        replay_burst_seconds: int,
    ) -> None:
        pass

    @abstractmethod
    def reset(self) -> None:
        pass


class InMemoryRateLimiterBackend(BaseRateLimiterBackend):
    """Thread-safe, bounded in-memory sliding window backend for local and test use."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ip_history: Dict[str, List[float]] = defaultdict(list)
        self._domain_history: Dict[str, List[float]] = defaultdict(list)
        self._last_submissions: Dict[Tuple[str, str, str], float] = {}

    def check_and_record(
        self,
        client_ip: str,
        normalized_domain: str,
        claim_type: str,
        ip_limit_per_minute: int,
        domain_limit_per_minute: int,
        replay_burst_seconds: int,
    ) -> None:
        now = time.time()
        window_start = now - 60.0

        with self._lock:
            # 1. Replay check
            replay_key = (client_ip, normalized_domain.lower(), claim_type.lower())
            last_time = self._last_submissions.get(replay_key)
            if last_time and (now - last_time) < replay_burst_seconds:
                raise ReplaySubmissionError(
                    f"Duplicate claim replayed too rapidly. Please wait {replay_burst_seconds}s before resubmitting."
                )

            # 2. Prune old timestamps and purge stale keys across all history to prevent unbounded memory growth
            stale_ips = [ip for ip, times in self._ip_history.items() if not any(t > window_start for t in times)]
            for ip in stale_ips:
                del self._ip_history[ip]

            stale_domains = [d for d, times in self._domain_history.items() if not any(t > window_start for t in times)]
            for d in stale_domains:
                del self._domain_history[d]

            # Prune stale replay entries older than 2x burst window
            stale_replays = [k for k, t in self._last_submissions.items() if (now - t) > (replay_burst_seconds * 2)]
            for k in stale_replays:
                del self._last_submissions[k]

            # 3. Check IP rate limit
            ip_history = [t for t in self._ip_history.get(client_ip, []) if t > window_start]
            if len(ip_history) >= ip_limit_per_minute:
                raise RateLimitExceededError(
                    f"Rate limit exceeded: Maximum {ip_limit_per_minute} submissions per minute per IP."
                )

            # 4. Check domain velocity limit
            domain_history = [t for t in self._domain_history.get(normalized_domain, []) if t > window_start]
            if len(domain_history) >= domain_limit_per_minute:
                raise RateLimitExceededError(
                    f"Domain submission rate exceeded: Maximum {domain_limit_per_minute} reports per minute for '{normalized_domain}'."
                )

            # 5. Record submission
            self._ip_history[client_ip].append(now)
            self._domain_history[normalized_domain].append(now)
            self._last_submissions[replay_key] = now

    def reset(self) -> None:
        with self._lock:
            self._ip_history.clear()
            self._domain_history.clear()
            self._last_submissions.clear()


class RedisRateLimiterBackend(BaseRateLimiterBackend):
    """Distributed Redis-backed sliding window rate limiter using atomic pipeline operations."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        try:
            import redis
            self.client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=2.0)
        except Exception as e:
            raise RateLimiterBackendError(f"Failed to initialize Redis client: {e}")

    def check_and_record(
        self,
        client_ip: str,
        normalized_domain: str,
        claim_type: str,
        ip_limit_per_minute: int,
        domain_limit_per_minute: int,
        replay_burst_seconds: int,
    ) -> None:
        try:
            now = time.time()
            window_start = now - 60.0

            ip_key = f"rate:ip:{client_ip}"
            domain_key = f"rate:domain:{normalized_domain.lower()}"
            replay_key = f"rate:replay:{client_ip}:{normalized_domain.lower()}:{claim_type.lower()}"

            # 1. Atomic Replay check using SET NX EX
            # If the key already exists, SET with NX returns None
            was_set = self.client.set(replay_key, "1", ex=replay_burst_seconds, nx=True)
            if not was_set:
                raise ReplaySubmissionError(
                    f"Duplicate claim replayed too rapidly. Please wait {replay_burst_seconds}s before resubmitting."
                )

            # 2. Sliding window evaluation for IP and Domain via pipeline
            pipe = self.client.pipeline()
            pipe.zremrangebyscore(ip_key, "-inf", window_start)
            pipe.zcard(ip_key)
            pipe.zremrangebyscore(domain_key, "-inf", window_start)
            pipe.zcard(domain_key)
            results = pipe.execute()

            ip_count = results[1]
            domain_count = results[3]

            if ip_count >= ip_limit_per_minute:
                raise RateLimitExceededError(
                    f"Rate limit exceeded: Maximum {ip_limit_per_minute} submissions per minute per IP."
                )

            if domain_count >= domain_limit_per_minute:
                raise RateLimitExceededError(
                    f"Domain submission rate exceeded: Maximum {domain_limit_per_minute} reports per minute for '{normalized_domain}'."
                )

            # 3. Record timestamp into sorted sets with 120s TTL
            pipe = self.client.pipeline()
            item_val = f"{now}"
            pipe.zadd(ip_key, {item_val: now})
            pipe.expire(ip_key, 120)
            pipe.zadd(domain_key, {item_val: now})
            pipe.expire(domain_key, 120)
            pipe.execute()

        except (RateLimitExceededError, ReplaySubmissionError):
            raise
        except Exception as e:
            # Under production policy, never silently bypass rate limiting
            raise RateLimiterBackendError(f"Redis rate limiting failure: {e}")

    def reset(self) -> None:
        try:
            keys = self.client.keys("rate:*")
            if keys:
                self.client.delete(*keys)
        except Exception as e:
            raise RateLimiterBackendError(f"Redis reset failure: {e}")


def get_default_backend() -> BaseRateLimiterBackend:
    """Factory selecting backend from environment configuration."""
    redis_url = os.environ.get("TRUSTTRACE_REDIS_URL") or os.environ.get("REDIS_URL")
    if redis_url:
        return RedisRateLimiterBackend(redis_url=redis_url)
    return InMemoryRateLimiterBackend()


class CommunityRateLimiter:
    """Sliding-window rate limiter tracking client IP, domain velocity, and replay bursts."""

    def __init__(
        self,
        backend: Optional[BaseRateLimiterBackend] = None,
        ip_limit_per_minute: int = 10,
        domain_limit_per_minute: int = 5,
        replay_burst_seconds: int = 5,
    ):
        self.backend = backend or get_default_backend()
        self.ip_limit_per_minute = ip_limit_per_minute
        self.domain_limit_per_minute = domain_limit_per_minute
        self.replay_burst_seconds = replay_burst_seconds

    def check_and_record(self, client_ip: str, normalized_domain: str, claim_type: str) -> None:
        """Check all rate boundaries and record submission if within limits."""
        self.backend.check_and_record(
            client_ip=client_ip,
            normalized_domain=normalized_domain,
            claim_type=claim_type,
            ip_limit_per_minute=self.ip_limit_per_minute,
            domain_limit_per_minute=self.domain_limit_per_minute,
            replay_burst_seconds=self.replay_burst_seconds,
        )

    def reset(self) -> None:
        """Reset all rate tracking history (useful for test isolation)."""
        self.backend.reset()


default_rate_limiter = CommunityRateLimiter()
