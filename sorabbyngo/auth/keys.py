from __future__ import annotations
import hashlib, secrets
from datetime import datetime, timezone
from functools import wraps
from flask import request, jsonify, g

class ApiKey:
    def __init__(self, name, scopes, key=None):
        self.key = key or f"sora_{secrets.token_urlsafe(32)}"
        self.name = name
        self.scopes = scopes
        self.created_at = datetime.now(timezone.utc)
        self.last_used = None
        self.enabled = True
        self._hash = hashlib.sha256(self.key.encode()).hexdigest()
    def has_scope(self, scope):
        return scope in self.scopes or "admin" in self.scopes
    def to_dict(self, reveal=False):
        return {"name": self.name, "scopes": self.scopes,
                "created_at": self.created_at.isoformat(),
                "last_used": self.last_used.isoformat() if self.last_used else None,
                "enabled": self.enabled,
                **({"key": self.key} if reveal else {"key_prefix": self.key[:12] + "..."})}

class ApiKeyStore:
    def __init__(self):
        self._keys = {}
    def create(self, name, scopes):
        key = ApiKey(name=name, scopes=scopes)
        self._keys[key._hash] = key
        return key
    def validate(self, raw_key):
        h = hashlib.sha256(raw_key.encode()).hexdigest()
        key = self._keys.get(h)
        if key and key.enabled:
            key.last_used = datetime.now(timezone.utc)
            return key
        return None
    def revoke(self, name):
        for key in self._keys.values():
            if key.name == name:
                key.enabled = False
                return True
        return False
    def list_keys(self):
        return list(self._keys.values())
    def seed_default(self):
        key = ApiKey(name="default-admin", scopes=["admin"], key="sora_dev_key_insecure_change_me")
        self._keys[key._hash] = key
        return key

def require_scope(scope):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            raw_key = request.headers.get("X-API-Key", "")
            if not raw_key:
                return jsonify({"error": "Missing X-API-Key header"}), 401
            api_key = g.key_store.validate(raw_key)
            if not api_key:
                return jsonify({"error": "Invalid or disabled API key"}), 401
            if not api_key.has_scope(scope):
                return jsonify({"error": f"Scope '{scope}' required"}), 403
            g.api_key = api_key
            return fn(*args, **kwargs)
        return wrapper
    return decorator
