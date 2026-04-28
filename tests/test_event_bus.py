"""Tests for Module 1 — Event Bus"""
import pytest
from sorabbyngo.core.event_bus import EventBus
from sorabbyngo.core.models import RawSignal, Severity, EventCategory


@pytest.fixture
def bus():
    return EventBus()


def _signal(severity="MEDIUM", category="ANOMALY", title="Test", host="host-01", source="falco"):
    return RawSignal(
        source=source,
        payload={
            "severity": severity,
            "category": category,
            "title": title,
            "description": "Test event",
            "host": host,
        },
    )


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def test_ingest_returns_event(bus):
    event = bus.ingest(_signal())
    assert event is not None
    assert event.title == "Test"


def test_ingest_increments_count(bus):
    bus.ingest(_signal(host="a"))
    bus.ingest(_signal(host="b"))
    assert bus.event_count == 2


def test_ingest_normalises_severity(bus):
    event = bus.ingest(_signal(severity="high"))
    assert event.severity == Severity.HIGH


def test_ingest_normalises_category(bus):
    event = bus.ingest(_signal(category="malware"))
    assert event.category == EventCategory.MALWARE


def test_ingest_unknown_severity_defaults_to_medium(bus):
    event = bus.ingest(_signal(severity="BOGUS"))
    assert event.severity == Severity.MEDIUM


def test_ingest_unknown_category_defaults_to_unknown(bus):
    event = bus.ingest(_signal(category="BOGUS"))
    assert event.category == EventCategory.UNKNOWN


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_duplicate_event_rejected(bus):
    sig = _signal()
    bus.ingest(sig)
    result = bus.ingest(sig)      # same signal → same fingerprint
    assert result is None
    assert bus.event_count == 1


def test_different_hosts_not_deduplicated(bus):
    bus.ingest(_signal(host="a"))
    bus.ingest(_signal(host="b"))
    assert bus.event_count == 2


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def test_handler_called_on_matching_severity(bus):
    received = []
    bus.subscribe(Severity.CRITICAL, received.append)
    bus.ingest(_signal(severity="CRITICAL"))
    assert len(received) == 1


def test_wildcard_handler_called_for_all(bus):
    received = []
    bus.subscribe_all(received.append)
    bus.ingest(_signal(severity="LOW", host="x"))
    bus.ingest(_signal(severity="HIGH", host="y"))
    assert len(received) == 2


def test_handler_not_called_for_wrong_severity(bus):
    received = []
    bus.subscribe(Severity.CRITICAL, received.append)
    bus.ingest(_signal(severity="LOW"))
    assert len(received) == 0


# ---------------------------------------------------------------------------
# Querying
# ---------------------------------------------------------------------------

def test_get_events_by_severity(bus):
    bus.ingest(_signal(severity="HIGH", host="a"))
    bus.ingest(_signal(severity="LOW", host="b"))
    highs = bus.get_events(severity=Severity.HIGH)
    assert len(highs) == 1
    assert highs[0].severity == Severity.HIGH


def test_get_event_by_id(bus):
    event = bus.ingest(_signal())
    found = bus.get_event_by_id(event.id)
    assert found is not None
    assert found.id == event.id


def test_get_event_by_id_missing(bus):
    assert bus.get_event_by_id("nonexistent") is None


def test_get_events_limit(bus):
    for i in range(10):
        bus.ingest(_signal(host=f"host-{i}"))
    assert len(bus.get_events(limit=3)) == 3
