import pytest
from sorabbyngo.auth.keys import ApiKeyStore, ApiKey

@pytest.fixture
def store(): return ApiKeyStore()

def test_create_key_returns_api_key(store): assert isinstance(store.create("test",["read"]), ApiKey)
def test_created_key_has_sora_prefix(store): assert store.create("test",["read"]).key.startswith("sora_")
def test_created_key_has_correct_name(store): assert store.create("mykey",["write"]).name == "mykey"
def test_created_key_has_correct_scopes(store):
    key = store.create("test",["read","write"])
    assert "read" in key.scopes and "write" in key.scopes
def test_created_key_is_enabled(store): assert store.create("test",["read"]).enabled is True
def test_to_dict_hides_key_by_default(store):
    d = store.create("test",["read"]).to_dict()
    assert "key_prefix" in d and "key" not in d
def test_to_dict_reveals_key_on_create(store):
    key = store.create("test",["read"])
    d = key.to_dict(reveal=True)
    assert d["key"] == key.key
def test_validate_correct_key(store):
    key = store.create("test",["read"])
    assert store.validate(key.key).name == "test"
def test_validate_wrong_key_returns_none(store): assert store.validate("sora_wrongkey") is None
def test_validate_updates_last_used(store):
    key = store.create("test",["read"])
    assert key.last_used is None
    store.validate(key.key)
    assert key.last_used is not None
def test_validate_disabled_key_returns_none(store):
    key = store.create("test",["read"])
    key.enabled = False
    assert store.validate(key.key) is None
def test_admin_scope_passes_all(store):
    key = store.create("admin",["admin"])
    assert key.has_scope("read") and key.has_scope("write") and key.has_scope("admin")
def test_read_scope_fails_write(store): assert store.create("r",["read"]).has_scope("write") is False
def test_write_scope_fails_admin(store): assert store.create("w",["write"]).has_scope("admin") is False
def test_revoke_disables_key(store):
    key = store.create("test",["read"])
    store.revoke("test")
    assert store.validate(key.key) is None
def test_revoke_returns_true(store): store.create("test",["read"]); assert store.revoke("test") is True
def test_revoke_returns_false_missing(store): assert store.revoke("nonexistent") is False
def test_list_keys(store):
    store.create("k1",["read"]); store.create("k2",["write"])
    assert len(store.list_keys()) == 2
def test_seed_default(store):
    key = store.seed_default()
    assert key.has_scope("admin") and store.validate(key.key) is not None

@pytest.fixture
def auth_client():
    from sorabbyngo.api.app import create_app
    app = create_app(dry_run=True, testing=False, require_auth=True)
    app.config["TESTING"] = True
    return app.test_client()

def test_events_without_key_returns_401(auth_client):
    assert auth_client.get("/api/v1/events").status_code == 401
def test_events_with_wrong_key_returns_401(auth_client):
    assert auth_client.get("/api/v1/events", headers={"X-API-Key":"bad"}).status_code == 401
def test_events_with_valid_key_returns_200(auth_client):
    assert auth_client.get("/api/v1/events", headers={"X-API-Key":"sora_dev_key_insecure_change_me"}).status_code == 200
def test_create_key_requires_admin(auth_client):
    admin = "sora_dev_key_insecure_change_me"
    r = auth_client.post("/api/v1/keys", json={"name":"ro","scopes":["read"]}, headers={"X-API-Key":admin})
    read_key = r.get_json()["key"]
    r2 = auth_client.post("/api/v1/keys", json={"name":"x","scopes":["read"]}, headers={"X-API-Key":read_key})
    assert r2.status_code == 403
def test_revoke_key_via_api(auth_client):
    admin = "sora_dev_key_insecure_change_me"
    auth_client.post("/api/v1/keys", json={"name":"temp","scopes":["read"]}, headers={"X-API-Key":admin})
    r = auth_client.post("/api/v1/keys/temp/revoke", headers={"X-API-Key":admin})
    assert r.status_code == 200 and r.get_json()["revoked"] is True
def test_health_no_auth(auth_client):
    assert auth_client.get("/health").status_code == 200
