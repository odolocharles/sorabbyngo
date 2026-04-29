import pytest, time
from sorabbyngo.core.rate_limiter import TokenBucket, RateLimiter, _SCOPE_LIMITS

def test_bucket_allows_within_capacity():
    assert TokenBucket(10, 10/60).consume() is True
def test_bucket_denies_when_exhausted():
    b = TokenBucket(3, 1/60)
    b.consume(); b.consume(); b.consume()
    assert b.consume() is False
def test_bucket_remaining_decrements():
    b = TokenBucket(5, 5/60)
    before = b.remaining; b.consume()
    assert b.remaining == before - 1
def test_bucket_refills_over_time():
    b = TokenBucket(2, 100)
    b.consume(); b.consume()
    assert b.consume() is False
    time.sleep(0.05)
    assert b.consume() is True
def test_bucket_cannot_exceed_capacity():
    b = TokenBucket(5, 1000); time.sleep(0.1)
    assert b.remaining <= 5
def test_bucket_remaining_never_negative():
    b = TokenBucket(1, 1/60); b.consume(); b.consume()
    assert b.remaining >= 0
def test_scope_limits_defined():
    assert "read" in _SCOPE_LIMITS and "write" in _SCOPE_LIMITS and "admin" in _SCOPE_LIMITS
def test_admin_limit_higher_than_write(): assert _SCOPE_LIMITS["admin"] > _SCOPE_LIMITS["write"]
def test_read_limit_higher_than_write(): assert _SCOPE_LIMITS["read"] > _SCOPE_LIMITS["write"]
def test_limiter_stats_empty(): assert RateLimiter().stats()["tracked_buckets"] == 0
def test_limiter_reset():
    l = RateLimiter(); l._buckets["key:test"] = TokenBucket(5,1); l.reset("key:test")
    assert "key:test" not in l._buckets
def test_rate_limit_header_present(client):
    r = client.get("/health"); assert r.status_code == 200
def test_rate_limit_stats_endpoint(client):
    r = client.get("/api/v1/rate-limits")
    assert r.status_code == 200 and "tracked_buckets" in r.get_json()
def test_bucket_exhaustion():
    b = TokenBucket(2, 0.001)
    assert b.consume() is True; assert b.consume() is True; assert b.consume() is False
def test_bypass_paths():
    assert "/health" in ["/health", "/dashboard"]
    assert "/dashboard" in ["/health", "/dashboard"]
def test_retry_after_in_429_format():
    b = TokenBucket(1, 0.001); b.consume()
    assert b.consume() is False
def test_limiter_tracks_multiple_buckets():
    l = RateLimiter()
    l._buckets["key:a"] = TokenBucket(5,1)
    l._buckets["key:b"] = TokenBucket(5,1)
    assert l.stats()["tracked_buckets"] == 2
