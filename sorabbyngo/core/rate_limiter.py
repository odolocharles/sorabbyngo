from __future__ import annotations
import time
from threading import Lock
from flask import request, jsonify, g

_SCOPE_LIMITS = {"read": 60, "write": 30, "admin": 120}
_DEFAULT_LIMIT = 30

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = refill_rate
        self._last = time.monotonic()
        self._lock = Lock()
    def consume(self, tokens=1):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    @property
    def remaining(self):
        return max(0, int(self.tokens))

class RateLimiter:
    def __init__(self):
        self._buckets = {}
        self._lock = Lock()
    def _key(self):
        api_key = getattr(g, "api_key", None)
        if api_key:
            scopes = api_key.scopes
            if "admin" in scopes: limit = _SCOPE_LIMITS["admin"]
            elif "write" in scopes: limit = _SCOPE_LIMITS["write"]
            else: limit = _SCOPE_LIMITS["read"]
            return f"key:{api_key.name}", limit
        return f"ip:{request.remote_addr or 'unknown'}", _DEFAULT_LIMIT
    def _get_bucket(self, key, limit):
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(capacity=limit, refill_rate=limit/60.0)
            return self._buckets[key]
    def check(self):
        key, limit = self._key()
        bucket = self._get_bucket(key, limit)
        allowed = bucket.consume()
        return allowed, bucket.remaining, limit
    def reset(self, identifier):
        with self._lock:
            self._buckets.pop(identifier, None)
    def stats(self):
        with self._lock:
            return {"tracked_buckets": len(self._buckets),
                    "buckets": {k: {"remaining": b.remaining, "capacity": b.capacity}
                                for k, b in self._buckets.items()}}

def register_rate_limiter(app, limiter):
    @app.before_request
    def _rate_limit():
        if request.path in ("/health", "/dashboard"): return None
        allowed, remaining, limit = limiter.check()
        g.rl_remaining = remaining
        g.rl_limit = limit
        if not allowed:
            return jsonify({"error": "Rate limit exceeded", "limit": limit, "retry_after_seconds": 60}), 429
    @app.after_request
    def _add_headers(response):
        response.headers["X-RateLimit-Limit"] = getattr(g, "rl_limit", _DEFAULT_LIMIT)
        response.headers["X-RateLimit-Remaining"] = getattr(g, "rl_remaining", 0)
        return response
