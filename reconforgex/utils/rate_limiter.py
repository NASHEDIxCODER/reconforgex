"""
Intelligent Rate Limiter.

Supports per-host and global limits with:
- requests/sec rate limiting (token bucket algorithm)
- Burst support
- Adaptive slowdown based on response latency
- Per-host limits for polite scanning
- Global limits to avoid overwhelming targets

Usage::

    limiter = RateLimiter(
        global_rps=100,
        burst=10,
        per_host_rps=5,
    )
    async with limiter.limit("example.com"):
        response = await client.get(url)
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class HostState:
    """Rate limit state for a single host."""
    tokens: float = 0.0
    last_refill: float = 0.0
    last_request_time: float = 0.0
    recent_latencies: list = field(default_factory=list)
    slowdown_factor: float = 1.0


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded and no retry possible."""


class RateLimiter:
    """Intelligent rate limiter with per-host and global limits.

    Uses a token bucket algorithm with adaptive slowdown based on
    observed response latency.

    Parameters
    ----------
    global_rps:
        Maximum requests per second globally.
    burst:
        Maximum burst size (extra tokens for short bursts).
    per_host_rps:
        Maximum requests per second per unique host.
    enable_adaptive:
        If True, slows down when hosts return slow responses.
    """

    def __init__(
        self,
        global_rps: int = 100,
        burst: int = 10,
        per_host_rps: int = 5,
        enable_adaptive: bool = True,
    ):
        self._global_rps = global_rps
        self._global_burst = burst
        self._per_host_rps = per_host_rps
        self._enable_adaptive = enable_adaptive

        # Global token bucket
        self._global_tokens = float(burst)
        self._global_last_refill = time.monotonic()

        # Per-host token buckets
        self._host_states: Dict[str, HostState] = defaultdict(HostState)

        # Concurrency control
        self._semaphore = asyncio.Semaphore(global_rps)

        # Statistics
        self._total_delayed = 0
        self._total_throttled = 0

    @property
    def stats(self) -> dict:
        """Return rate limiter statistics."""
        return {
            "total_delayed": self._total_delayed,
            "total_throttled": self._total_throttled,
            "active_hosts": len(self._host_states),
        }

    def _refill_global(self) -> None:
        """Refill global token bucket."""
        now = time.monotonic()
        elapsed = now - self._global_last_refill
        new_tokens = elapsed * self._global_rps
        self._global_tokens = min(
            self._global_tokens + new_tokens,
            self._global_burst,
        )
        self._global_last_refill = now

    def _refill_host(self, host: str) -> None:
        """Refill per-host token bucket."""
        state = self._host_states[host]
        now = time.monotonic()
        elapsed = now - state.last_refill
        effective_rps = self._per_host_rps / state.slowdown_factor
        new_tokens = elapsed * effective_rps
        state.tokens = min(state.tokens + new_tokens, self._per_host_rps + 2)
        state.last_refill = now

    def _calculate_slowdown(self, host: str, latency: float) -> None:
        """Update slowdown factor based on observed latency."""
        if not self._enable_adaptive:
            return

        state = self._host_states[host]
        state.recent_latencies.append(latency)
        if len(state.recent_latencies) > 10:
            state.recent_latencies.pop(0)

        if len(state.recent_latencies) >= 3:
            avg_latency = sum(state.recent_latencies) / len(state.recent_latencies)
            if avg_latency > 10.0:
                state.slowdown_factor = min(10.0, state.slowdown_factor * 1.5)
            elif avg_latency < 2.0:
                state.slowdown_factor = max(1.0, state.slowdown_factor / 1.2)
            else:
                state.slowdown_factor = max(
                    1.0, min(
                        state.slowdown_factor,
                        avg_latency / 3.0,
                    )
                )

    async def acquire(self, host: str) -> float:
        """Acquire permission to send a request.

        Parameters
        ----------
        host:
            The target host for per-host limiting.

        Returns
        -------
        float
            The wait time before the request should be sent.
        """
        self._refill_global()
        self._refill_host(host)

        # Calculate wait time
        wait_time = 0.0

        # Global limit
        if self._global_tokens < 1.0:
            wait_time = max(wait_time, (1.0 - self._global_tokens) / self._global_rps)
            self._total_throttled += 1

        # Host limit
        host_state = self._host_states[host]
        if host_state.tokens < 1.0:
            effective_rps = self._per_host_rps / host_state.slowdown_factor
            host_wait = (1.0 - host_state.tokens) / max(effective_rps, 0.1)
            wait_time = max(wait_time, host_wait)
            self._total_throttled += 1

        # Ensure minimum spacing between requests to same host
        if host_state.last_request_time > 0:
            elapsed_since_last = time.monotonic() - host_state.last_request_time
            min_spacing = 1.0 / max(self._per_host_rps, 1)
            if elapsed_since_last < min_spacing:
                spacing_wait = min_spacing - elapsed_since_last
                wait_time = max(wait_time, spacing_wait)

        # Consume tokens
        self._global_tokens -= 1.0
        host_state.tokens -= 1.0
        host_state.last_request_time = time.monotonic()

        if wait_time > 0:
            self._total_delayed += 1

        return wait_time

    async def __aenter__(self) -> "RateLimiter":
        return self

    async def __aexit__(self, *args: object) -> None:
        pass

    def record_latency(self, host: str, latency: float) -> None:
        """Record observed latency for adaptive slowdown."""
        self._calculate_slowdown(host, latency)

    def reset_host(self, host: str) -> None:
        """Reset rate limit state for a host."""
        self._host_states.pop(host, None)
