"""Token-bucket rate limiter timing behavior."""

from __future__ import annotations

import time

from sharesift.verify.rate_limiter import RateLimiter


def test_acquire_within_burst_does_not_block():
    rl = RateLimiter(default_rate_per_sec=1.0, default_burst=3)
    t0 = time.monotonic()
    for _ in range(3):
        rl.acquire("svc")
    elapsed = time.monotonic() - t0
    assert elapsed < 0.05, f"burst should be instant, took {elapsed}s"


def test_acquire_beyond_burst_blocks_for_refill():
    rl = RateLimiter(default_rate_per_sec=10.0, default_burst=2)
    rl.acquire("svc")
    rl.acquire("svc")
    t0 = time.monotonic()
    rl.acquire("svc")
    elapsed = time.monotonic() - t0
    # Third call should wait ~100ms for one token at 10 tokens/sec
    assert 0.05 < elapsed < 0.25, f"expected ~0.1s wait, got {elapsed}s"


def test_per_service_buckets_are_independent():
    rl = RateLimiter(default_rate_per_sec=10.0, default_burst=1)
    rl.acquire("svc_a")
    t0 = time.monotonic()
    # svc_b is a new service with its own full bucket; should not block
    rl.acquire("svc_b")
    elapsed = time.monotonic() - t0
    assert elapsed < 0.05


def test_register_custom_rate():
    rl = RateLimiter(default_rate_per_sec=1.0, default_burst=1)
    rl.register("fast", rate_per_sec=100.0, burst=5)
    t0 = time.monotonic()
    for _ in range(5):
        rl.acquire("fast")
    elapsed = time.monotonic() - t0
    assert elapsed < 0.05, "5-token burst should be instant on custom-rate bucket"
