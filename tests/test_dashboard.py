import pytest

@pytest.fixture
def client_with_data(client, critical_payload, low_payload):
    r1 = client.post("/api/v1/events", json=critical_payload)
    event_id = r1.get_json()["id"]
    client.post(f"/api/v1/events/{event_id}/investigate")
    client.post("/api/v1/events", json=low_payload)
    return client

def test_dashboard_returns_200(client): assert client.get("/dashboard").status_code == 200
def test_dashboard_content_type_html(client): assert "text/html" in client.get("/dashboard").content_type
def test_dashboard_has_platform_name(client): assert b"Sorabbyngo" in client.get("/dashboard").data
def test_dashboard_shows_stats_cards(client):
    r = client.get("/dashboard").data
    assert b"Total Events" in r and b"Incident Reports" in r
def test_dashboard_shows_empty_state(client): assert b"No events yet" in client.get("/dashboard").data
def test_dashboard_shows_events_after_ingest(client_with_data):
    r = client_with_data.get("/dashboard").data
    assert b"CRITICAL" in r or b"INTRUSION" in r or b"SSH" in r
def test_dashboard_shows_reports(client_with_data): assert b"No reports yet" not in client_with_data.get("/dashboard").data
def test_dashboard_has_auto_refresh(client):
    r = client.get("/dashboard").data
    assert b"http-equiv" in r and b"refresh" in r
def test_dashboard_has_health_link(client): assert b"/health" in client.get("/dashboard").data
def test_dashboard_execution_mode(client): assert b"DRY" in client.get("/dashboard").data or b"LIVE" in client.get("/dashboard").data
def test_dashboard_no_auth_required(client): assert client.get("/dashboard").status_code == 200
def test_dashboard_has_metrics_link(client): assert b"/metrics" in client.get("/dashboard").data
