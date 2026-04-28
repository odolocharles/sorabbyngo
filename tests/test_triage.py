"""Tests for Module 2 — Triage Agent"""
import pytest
from sorabbyngo.agents.triage import TriageAgent
from sorabbyngo.core.models import SecurityEvent, Severity, EventCategory, TriageVerdict


@pytest.fixture
def agent():
    return TriageAgent()


def _event(severity=Severity.MEDIUM, category=EventCategory.ANOMALY,
           title="Test", description="", host="host-01"):
    return SecurityEvent(
        source="test",
        category=category,
        severity=severity,
        title=title,
        description=description,
        host=host,
    )


# ---------------------------------------------------------------------------
# Score range
# ---------------------------------------------------------------------------

def test_score_is_between_0_and_1(agent):
    event = _event()
    result = agent.triage(event)
    assert 0.0 <= result.score <= 1.0


def test_critical_intrusion_scores_max(agent):
    event = _event(severity=Severity.CRITICAL, category=EventCategory.INTRUSION)
    result = agent.triage(event)
    assert result.score == 1.0


def test_info_policy_scores_low(agent):
    event = _event(severity=Severity.INFO, category=EventCategory.POLICY_VIOLATION)
    result = agent.triage(event)
    assert result.score < 0.20


def test_high_severity_scores_above_medium(agent):
    high = agent.triage(_event(severity=Severity.HIGH)).score
    medium = agent.triage(_event(severity=Severity.MEDIUM)).score
    assert high > medium


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def test_critical_intrusion_immediate_response(agent):
    event = _event(severity=Severity.CRITICAL, category=EventCategory.INTRUSION)
    result = agent.triage(event)
    assert result.verdict == TriageVerdict.IMMEDIATE_RESPONSE


def test_medium_anomaly_escalates(agent):
    event = _event(severity=Severity.MEDIUM, category=EventCategory.ANOMALY)
    result = agent.triage(event)
    assert result.verdict == TriageVerdict.ESCALATE


def test_low_policy_auto_closes(agent):
    event = _event(severity=Severity.LOW, category=EventCategory.POLICY_VIOLATION)
    result = agent.triage(event)
    assert result.verdict == TriageVerdict.AUTO_CLOSE


def test_info_auto_closes(agent):
    event = _event(severity=Severity.INFO)
    result = agent.triage(event)
    assert result.verdict == TriageVerdict.AUTO_CLOSE


# ---------------------------------------------------------------------------
# MITRE mapping
# ---------------------------------------------------------------------------

def test_ssh_keyword_maps_technique(agent):
    event = _event(title="SSH brute force", description="ssh attack")
    result = agent.triage(event)
    assert any("SSH" in t or "Brute" in t for t in result.mitre_techniques)


def test_existing_mitre_technique_preserved(agent):
    event = _event()
    event.mitre_technique = "T1234 – Custom Technique"
    result = agent.triage(event)
    assert "T1234 – Custom Technique" in result.mitre_techniques


def test_no_duplicate_techniques(agent):
    event = _event(title="ssh scan", description="ssh scan recon")
    result = agent.triage(event)
    assert len(result.mitre_techniques) == len(set(result.mitre_techniques))


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

def test_result_has_event_id(agent):
    event = _event()
    result = agent.triage(event)
    assert result.event_id == event.id


def test_llm_not_used_for_rule_based(agent):
    event = _event()
    result = agent.triage(event)
    assert result.llm_used is False


def test_reasoning_non_empty(agent):
    event = _event()
    result = agent.triage(event)
    assert len(result.reasoning) > 0
