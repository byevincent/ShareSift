"""Per-service token bucket rate limiter.

Verifiers share a global default cap; individual services may also
acquire from a per-service bucket (e.g., GitHub /user is 60/hour
unauthenticated, 5000/hour authenticated — we don't want a ShareSift
verification run to exhaust the operator's API budget).

Thread-safe via a per-bucket lock so a parallel verifier driver can
share a rate limiter across worker threads.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    capacity: float
    tokens: float
    refill_per_sec: float
    last_refill: float
    lock: threading.Lock


class RateLimiter:
    """Token-bucket limiter keyed by service name.

    Services that haven't been registered fall back to the default
    bucket (one global rate cap). Use ``register(name, rate, burst)``
    to give a service its own bucket.
    """

    def __init__(self, default_rate_per_sec: float = 1.0, default_burst: int = 3):
        self._buckets: dict[str, _Bucket] = {}
        self._default_rate = default_rate_per_sec
        self._default_burst = default_burst

    def register(self, service: str, rate_per_sec: float, burst: int) -> None:
        now = time.monotonic()
        self._buckets[service] = _Bucket(
            capacity=float(burst),
            tokens=float(burst),
            refill_per_sec=float(rate_per_sec),
            last_refill=now,
            lock=threading.Lock(),
        )

    def _bucket_for(self, service: str) -> _Bucket:
        if service not in self._buckets:
            self.register(service, self._default_rate, self._default_burst)
        return self._buckets[service]

    def acquire(self, service: str, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available for ``service``.

        Returns the wait time (seconds) spent blocked. 0 if granted
        immediately. Designed for synchronous callers; switch to an
        async variant if/when verification gets a thread pool.
        """
        bucket = self._bucket_for(service)
        waited = 0.0
        while True:
            with bucket.lock:
                now = time.monotonic()
                elapsed = now - bucket.last_refill
                bucket.tokens = min(
                    bucket.capacity,
                    bucket.tokens + elapsed * bucket.refill_per_sec,
                )
                bucket.last_refill = now
                if bucket.tokens >= tokens:
                    bucket.tokens -= tokens
                    return waited
                deficit = tokens - bucket.tokens
                sleep_for = deficit / bucket.refill_per_sec
            time.sleep(sleep_for)
            waited += sleep_for
