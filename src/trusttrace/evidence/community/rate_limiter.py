"""Pluggable, production-ready sliding window rate limiter and replay protection."""

import os
import time
import uuid
import threading
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict


def is_production_environment() -> bool:
    """Determine whether the application is running in production mode."""
    env = (
        os.environ.get("TRUSTTRACE_ENV")
        or os.environ.get("ENV")
        or os.environ.get("ENVIRONMENT")
        or ""
    ).strip().lower()
    return env == "production"


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

    def ping(self) -> bool:
        """Verify backend connectivity."""
        return True


class InMemoryRateLimiterBackend(BaseRateLimiterBackend):
    """Thread-safe, bounded in-memory sliding window backend for local and test use."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ip_history: Dict[str, List[float]] = defaultdict(list)
        self._domain_history: Dict[str, List[float]] = defaultdict(list)
        self._last_submissions: Dict[Tuple[str, str, str], float] = {}

    def ping(self) -> bool:
        return True

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

            # 5. Record submission (atomic under lock)
            self._ip_history[client_ip].append(now)
            self._domain_history[normalized_domain].append(now)
            self._last_submissions[replay_key] = now

    def reset(self) -> None:
        with self._lock:
            self._ip_history.clear()
            self._domain_history.clear()
            self._last_submissions.clear()


# Atomic Lua script for Redis rate limiting and replay defense (TASK 3)
# Checks replay, ip limit, and domain limit atomically in a single Redis evaluation.
# Only updates state when all checks succeed. Rejected requests do not contaminate state.
ATOMIC_RATE_LIMIT_LUA = """
local replay_key = KEYS[1]
local ip_key = KEYS[2]
local domain_key = KEYS[3]

local now = tonumber(ARGV[1])
local window_start = tonumber(ARGV[2])
local ip_limit = tonumber(ARGV[3])
local domain_limit = tonumber(ARGV[4])
local burst_ttl = tonumber(ARGV[5])
local unique_member = ARGV[6]
local key_ttl = tonumber(ARGV[7])

-- 1. Check replay burst key
if redis.call('EXISTS', replay_key) == 1 then
    return {0, 'replay'}
end

-- 2. Prune sliding window
redis.call('ZREMRANGEBYSCORE', ip_key, '-inf', window_start)
redis.call('ZREMRANGEBYSCORE', domain_key, '-inf', window_start)

-- 3. Check IP rate limit
local ip_count = redis.call('ZCARD', ip_key)
if ip_count >= ip_limit then
    return {0, 'ip_limit'}
end

-- 4. Check domain rate limit
local domain_count = redis.call('ZCARD', domain_key)
if domain_count >= domain_limit then
    return {0, 'domain_limit'}
end

-- 5. All checks passed: Atomically record accepted request
redis.call('SET', replay_key, '1', 'EX', burst_ttl)
redis.call('ZADD', ip_key, now, unique_member)
redis.call('EXPIRE', ip_key, key_ttl)
redis.call('ZADD', domain_key, now, unique_member)
redis.call('EXPIRE', domain_key, key_ttl)

return {1, 'ok'}
"""


class RedisRateLimiterBackend(BaseRateLimiterBackend):
    """Distributed Redis-backed sliding window rate limiter using an atomic Lua script (TASK 3)."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        try:
            import redis
            self.client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=3.0)
            self._script = self.client.register_script(ATOMIC_RATE_LIMIT_LUA)
        except Exception as e:
            raise RateLimiterBackendError(f"Failed to initialize Redis client: {e}")

    def ping(self) -> bool:
        """Verify Redis connectivity."""
        try:
            return bool(self.client.ping())
        except Exception as e:
            raise RateLimiterBackendError(f"Redis ping failure at '{self.redis_url}': {e}")

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

            # Member string contains unique nonce so simultaneous requests don't overwrite
            unique_member = f"{now}:{uuid.uuid4().hex[:10]}"

            # Execute single atomic operation
            res = self._script(
                keys=[replay_key, ip_key, domain_key],
                args=[
                    now,
                    window_start,
                    ip_limit_per_minute,
                    domain_limit_per_minute,
                    replay_burst_seconds,
                    unique_member,
                    120,  # 120s TTL for keys
                ],
            )

            success_code = res[0]
            reason = res[1]

            if success_code == 0:
                if reason == "replay":
                    raise ReplaySubmissionError(
                        f"Duplicate claim replayed too rapidly. Please wait {replay_burst_seconds}s before resubmitting."
                    )
                elif reason == "ip_limit":
                    raise RateLimitExceededError(
                        f"Rate limit exceeded: Maximum {ip_limit_per_minute} submissions per minute per IP."
                    )
                elif reason == "domain_limit":
                    raise RateLimitExceededError(
                        f"Domain submission rate exceeded: Maximum {domain_limit_per_minute} reports per minute for '{normalized_domain}'."
                    )
                else:
                    raise RateLimitExceededError(f"Rate boundary triggered: {reason}")

        except (RateLimitExceededError, ReplaySubmissionError):
            raise
        except Exception as e:
            # Under production policy, never silently bypass rate limiting (fail-closed)
            raise RateLimiterBackendError(f"Redis rate limiting failure: {e}")

    def reset(self) -> None:
        """Clean all rate limit keys using iterative scan to prevent blocking production Redis."""
        try:
            keys_to_delete = []
            for k in self.client.scan_iter(match="rate:*", count=100):
                keys_to_delete.append(k)
                if len(keys_to_delete) >= 500:
                    self.client.delete(*keys_to_delete)
                    keys_to_delete.clear()
            if keys_to_delete:
                self.client.delete(*keys_to_delete)
        except Exception as e:
            raise RateLimiterBackendError(f"Redis reset failure: {e}")


def get_default_backend() -> BaseRateLimiterBackend:
    """Factory selecting backend from environment configuration.
    
    Production Requirements (TASK 2):
    - When TRUSTTRACE_ENV=production, Redis MUST be configured.
    - If Redis is missing or unavailable, fail startup safely (fail-closed).
    - Never silently fall back to process-local memory in production.
    - In-memory backend may remain available for local development and isolated tests.
    """
    is_prod = is_production_environment()
    redis_url = os.environ.get("TRUSTTRACE_REDIS_URL") or os.environ.get("REDIS_URL")

    if is_prod:
        if not redis_url:
            raise RateLimiterBackendError(
                "Production configuration error: Redis is strictly required in production mode. "
                "Set environment variable TRUSTTRACE_REDIS_URL with a valid Redis connection string."
            )
        backend = RedisRateLimiterBackend(redis_url=redis_url)
        backend.ping()
        return backend

    # Non-production (development or test)
    if redis_url:
        try:
            backend = RedisRateLimiterBackend(redis_url=redis_url)
            backend.ping()
            return backend
        except Exception:
            # Development fallback to memory when local Redis is not running
            return InMemoryRateLimiterBackend()

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
