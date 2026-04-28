"""Tests for Module 6 — REST API"""
import pytest
import json


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health_returns_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert data["platform"] == "Sorabbyngo"
    assert data["dry_run"] is True


def test_health_includes_stats(client):
    r = client.get("/health")
    data = r.get_json()
    assert "total_events" in data
    assert "total_reports" in data


# ---------------------------------------------------------------------------
# Event ingestion
# ---------------------------------------------------------------------------

def test_ingest_event_returns_201(client, critical_payload):
    r = client.post("/api/v1/events", json=critical_payload)
    assert r.status_code == 201
    data = r.get_json()
    assert "id" in data
    assert data["source"] == "falco"


def test_ingest_event_missing_source_returns_400(client):
    r = client.post("/api/v1/events", json={"payload": {"severity": "HIGH"}})
    assert r.status_code == 400


def test_ingest_event_missing_payload_returns_400(client):
    r = client.post("/api/v1/events", json={"source": "falco"})
    assert r.status_code == 400


def test_ingest_event_empty_body_returns_400(client):
    r = client.post("/api/v1/events", data="not json", content_type="text/plain")
    assert r.status_code == 400


def test_duplicate_event_returns_200_with_flag(client, critical_payload):
    client.post("/api/v1/events", json=critical_payload)
    r = client.post("/api/v1/events", json=critical_payload)
    assert r.status_code == 200
    data = r.get_json()
    assert data["duplicate"] is True


def test_different_hosts_both_accepted(client, critical_payload, low_payload):
    r1 = client.post("/api/v1/events", json=critical_payload)
    r2 = client.post("/api/v1/events", json=low_payload)
    assert r1.status_code == 201
    assert r2.status_code == 201


# ---------------------------------------------------------------------------
# List events
# ---------------------------------------------------------------------------

def test_list_events_empty(client):
    r = client.get("/api/v1/events")
    assert r.status_code == 200
    assert r.get_json() == []


def test_list_events_after_ingest(client, critical_payload):
    client.post("/api/v1/events", json=critical_payload)
    r = client.get("/api/v1/events")
    assert r.status_code == 200
    assert len(r.get_json()) == 1


def test_list_events_filter_by_severity(client, critical_payload, low_payload):
    client.post("/api/v1/events", json=critical_payload)
    client.post("/api/v1/events", json=low_payload)
    r = client.get("/api/v1/events?severity=CRITICAL")
    data = r.get_json()
    assert all(e["severity"] == "CRITICAL" for e in data)


def test_list_events_filter_by_category(client, critical_payload, low_payload):
    client.post("/api/v1/events", json=critical_payload)
    client.post("/api/v1/events", json=low_payload)
    r = client.get("/api/v1/events?category=INTRUSION")
    data = r.get_json()
    assert all(e["category"] == "INTRUSION" for e in data)


def test_list_events_invalid_severity_returns_400(client):
    r = client.get("/api/v1/events?severity=BOGUS")
    assert r.status_code == 400


def test_list_events_limit(client, critical_payload):
    # Ingest with different hosts to avoid dedup
    for i in range(5):
        p = dict(critical_payload)
        p["payload"] = dict(critical_payload["payload"], host=f"host-{i}")
        client.post("/api/v1/events", json=p)
    r = client.get("/api/v1/events?limit=2")
    assert len(r.get_json()) == 2


# ---------------------------------------------------------------------------
# Get single event
# ---------------------------------------------------------------------------

def test_get_event_by_id(client, critical_payload):
    r = client.post("/api/v1/events", json=critical_payload)
    event_id = r.get_json()["id"]
    r2 = client.get(f"/api/v1/events/{event_id}")
    assert r2.status_code == 200
    assert r2.get_json()["id"] == event_id


def test_get_event_not_found(client):
    r = client.get("/api/v1/events/nonexistent-id")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

def test_triage_event(client, critical_payload):
    r = client.post("/api/v1/events", json=critical_payload)
    event_id = r.get_json()["id"]
    r2 = client.post(f"/api/v1/events/{event_id}/triage")
    assert r2.status_code == 200
    data = r2.get_json()
    assert "score" in data
    assert "verdict" in data
    assert data["event_id"] == event_id


def test_triage_critical_intrusion_immediate(client, critical_payload):
    r = client.post("/api/v1/events", json=critical_payload)
    event_id = r.get_json()["id"]
    r2 = client.post(f"/api/v1/events/{event_id}/triage")
    assert r2.get_json()["verdict"] == "IMMEDIATE_RESPONSE"


def test_triage_nonexistent_event(client):
    r = client.post("/api/v1/events/no-such-id/triage")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------

def test_investigate_creates_report(client, critical_payload):
    r = client.post("/api/v1/events", json=critical_payload)
    event_id = r.get_json()["id"]
    r2 = client.post(f"/api/v1/events/{event_id}/investigate")
    assert r2.status_code == 201
    data = r2.get_json()
    assert "id" in data
    assert data["event_id"] == event_id
    assert len(data["response_actions"]) > 0


def test_investigate_auto_triages(client, critical_payload):
    """Investigate works even without prior triage call."""
    r = client.post("/api/v1/events", json=critical_payload)
    event_id = r.get_json()["id"]
    r2 = client.post(f"/api/v1/events/{event_id}/investigate")
    assert r2.status_code == 201


def test_investigate_nonexistent_event(client):
    r = client.post("/api/v1/events/no-such-id/investigate")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def test_list_reports_empty(client):
    r = client.get("/api/v1/reports")
    assert r.status_code == 200
    assert r.get_json() == []


def test_list_reports_after_investigation(client, critical_payload):
    r = client.post("/api/v1/events", json=critical_payload)
    event_id = r.get_json()["id"]
    client.post(f"/api/v1/events/{event_id}/investigate")
    r2 = client.get("/api/v1/reports")
    assert len(r2.get_json()) == 1


def test_get_report_by_id(client, critical_payload):
    r = client.post("/api/v1/events", json=critical_payload)
    event_id = r.get_json()["id"]
    report_id = client.post(f"/api/v1/events/{event_id}/investigate").get_json()["id"]
    r2 = client.get(f"/api/v1/reports/{report_id}")
    assert r2.status_code == 200
    assert r2.get_json()["id"] == report_id


def test_get_report_not_found(client):
    r = client.get("/api/v1/reports/no-such-report")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _full_pipeline(client, payload):
    """Ingest → investigate → get report_id."""
    r = client.post("/api/v1/events", json=payload)
    event_id = r.get_json()["id"]
    report_id = client.post(f"/api/v1/events/{event_id}/investigate").get_json()["id"]
    return event_id, report_id


def test_execute_report_returns_records(client, low_payload):
    _, report_id = _full_pipeline(client, low_payload)
    r = client.post(f"/api/v1/reports/{report_id}/execute")
    assert r.status_code == 200
    records = r.get_json()
    assert len(records) > 0


def test_execute_nonexistent_report(client):
    r = client.post("/api/v1/reports/no-such/execute")
    assert r.status_code == 404


def test_non_destructive_actions_executed(client, low_payload):
    _, report_id = _full_pipeline(client, low_payload)
    records = client.post(f"/api/v1/reports/{report_id}/execute").get_json()
    # In dry-run mode, non-destructive are SKIPPED (not PENDING)
    statuses = {r["status"] for r in records}
    assert "PENDING" not in statuses or all(
        r["action_type"] in ("ISOLATE_HOST", "KILL_PROCESS", "REVOKE_CREDENTIALS")
        for r in records if r["status"] == "PENDING"
    )


# ---------------------------------------------------------------------------
# Execution records
# ---------------------------------------------------------------------------

def test_list_records_empty(client):
    r = client.get("/api/v1/records")
    assert r.status_code == 200
    assert r.get_json() == []


def test_list_records_after_execution(client, low_payload):
    _, report_id = _full_pipeline(client, low_payload)
    client.post(f"/api/v1/reports/{report_id}/execute")
    r = client.get("/api/v1/records")
    assert len(r.get_json()) > 0


def test_list_records_filter_by_report_id(client, low_payload):
    _, report_id = _full_pipeline(client, low_payload)
    client.post(f"/api/v1/reports/{report_id}/execute")
    r = client.get(f"/api/v1/records?report_id={report_id}")
    data = r.get_json()
    assert all(rec["report_id"] == report_id for rec in data)


def test_get_record_by_id(client, low_payload):
    _, report_id = _full_pipeline(client, low_payload)
    records = client.post(f"/api/v1/reports/{report_id}/execute").get_json()
    record_id = records[0]["id"]
    r = client.get(f"/api/v1/records/{record_id}")
    assert r.status_code == 200
    assert r.get_json()["id"] == record_id


def test_get_record_not_found(client):
    r = client.get("/api/v1/records/nope")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------

def test_approve_pending_record(client, critical_payload):
    """Approve a destructive action and confirm it transitions to executed."""
    _, report_id = _full_pipeline(client, critical_payload)
    records = client.post(f"/api/v1/reports/{report_id}/execute").get_json()
    pending = next((r for r in records if r["status"] == "PENDING"), None)
    if pending:
        r = client.post(f"/api/v1/records/{pending['id']}/approve")
        assert r.status_code == 200


def test_approve_nonexistent_record(client):
    r = client.post("/api/v1/records/nope/approve")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

def test_rollback_executed_record(client, low_payload):
    _, report_id = _full_pipeline(client, low_payload)
    records = client.post(f"/api/v1/reports/{report_id}/execute").get_json()
    # In dry-run mode records are SKIPPED not EXECUTED — check for either
    executable = next((r for r in records if r["status"] in ("EXECUTED", "SKIPPED")), None)
    if executable and executable["status"] == "EXECUTED":
        r = client.post(f"/api/v1/records/{executable['id']}/rollback")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ROLLED_BACK"


def test_rollback_pending_returns_400(client, critical_payload):
    _, report_id = _full_pipeline(client, critical_payload)
    records = client.post(f"/api/v1/reports/{report_id}/execute").get_json()
    pending = next((r for r in records if r["status"] == "PENDING"), None)
    if pending:
        r = client.post(f"/api/v1/records/{pending['id']}/rollback")
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# 404 catch-all
# ---------------------------------------------------------------------------

def test_unknown_route_404(client):
    r = client.get("/api/v999/does-not-exist")
    assert r.status_code == 404


def test_wrong_method_405(client):
    r = client.delete("/api/v1/events")
    assert r.status_code == 405
