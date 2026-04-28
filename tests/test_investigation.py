"""Tests for Module 3 — Investigation Crew"""
import pytest
from sorabbyngo.agents.investigation import InvestigationCrew
from sorabbyngo.agents.triage import TriageAgent
from sorabbyngo.core.models import SecurityEvent, Severity, EventCategory, ActionType


@pytest.fixture
def crew():
    return InvestigationCrew()


@pytest.fixture
def triage():
    return TriageAgent()


def _event(severity=Severity.HIGH, category=EventCategory.INTRUSION,
           process="sshd", user="root"):
    return SecurityEvent(
        source="falco",
        category=category,
        severity=severity,
        title="SSH brute-force",
        description="Repeated failed auth attempts",
        host="prod-01",
        process=process,
        user=user,
    )


def _investigate(crew, triage, event):
    tr = triage.triage(event)
    return crew.investigate(event, tr)


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

def test_report_has_title(crew, triage):
    report = _investigate(crew, triage, _event())
    assert report.title
    assert "HIGH" in report.title or "SSH" in report.title


def test_report_event_id_matches(crew, triage):
    event = _event()
    report = _investigate(crew, triage, event)
    assert report.report_id if hasattr(report, "report_id") else report.event_id == event.id


def test_report_has_summary(crew, triage):
    report = _investigate(crew, triage, _event())
    assert len(report.summary) > 10


def test_report_has_attack_timeline(crew, triage):
    report = _investigate(crew, triage, _event())
    assert len(report.attack_timeline) >= 2


def test_report_has_root_cause(crew, triage):
    report = _investigate(crew, triage, _event())
    assert report.root_cause


def test_report_affected_assets_includes_host(crew, triage):
    event = _event()
    report = _investigate(crew, triage, event)
    assert event.host in report.affected_assets


def test_report_affected_assets_includes_user(crew, triage):
    event = _event()
    report = _investigate(crew, triage, event)
    assert any("root" in a for a in report.affected_assets)


def test_report_affected_assets_includes_process(crew, triage):
    event = _event()
    report = _investigate(crew, triage, event)
    assert any("sshd" in a for a in report.affected_assets)


# ---------------------------------------------------------------------------
# Response actions
# ---------------------------------------------------------------------------

def test_report_always_has_notify_action(crew, triage):
    report = _investigate(crew, triage, _event())
    types = [a.action_type for a in report.response_actions]
    assert ActionType.NOTIFY_TEAM in types


def test_report_always_has_ticket_action(crew, triage):
    report = _investigate(crew, triage, _event())
    types = [a.action_type for a in report.response_actions]
    assert ActionType.CREATE_TICKET in types


def test_critical_includes_isolate_host(crew, triage):
    event = _event(severity=Severity.CRITICAL)
    report = _investigate(crew, triage, event)
    types = [a.action_type for a in report.response_actions]
    assert ActionType.ISOLATE_HOST in types


def test_critical_isolate_requires_approval(crew, triage):
    event = _event(severity=Severity.CRITICAL)
    report = _investigate(crew, triage, event)
    isolate = next(a for a in report.response_actions if a.action_type == ActionType.ISOLATE_HOST)
    assert isolate.requires_approval is True


def test_low_severity_no_isolate(crew, triage):
    event = _event(severity=Severity.LOW)
    report = _investigate(crew, triage, event)
    types = [a.action_type for a in report.response_actions]
    assert ActionType.ISOLATE_HOST not in types


def test_actions_sorted_by_priority(crew, triage):
    report = _investigate(crew, triage, _event())
    priorities = [a.priority for a in report.response_actions]
    assert priorities == sorted(priorities)


def test_mitre_tactics_passed_through(crew, triage):
    event = _event()
    tr = triage.triage(event)
    report = crew.investigate(event, tr)
    assert report.mitre_tactics == tr.mitre_techniques
