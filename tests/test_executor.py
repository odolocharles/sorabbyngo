"""Tests for Module 4 — Response Executor"""
import pytest
from sorabbyngo.agents.executor import ResponseExecutor, ApprovalGate, _DESTRUCTIVE_ACTIONS
from sorabbyngo.agents.investigation import InvestigationCrew
from sorabbyngo.agents.triage import TriageAgent
from sorabbyngo.core.models import (
    SecurityEvent, Severity, EventCategory, ActionStatus, ActionType,
)


@pytest.fixture
def executor():
    return ResponseExecutor(dry_run=False)


@pytest.fixture
def dry_executor():
    return ResponseExecutor(dry_run=True)


def _critical_event():
    return SecurityEvent(
        source="falco",
        category=EventCategory.INTRUSION,
        severity=Severity.CRITICAL,
        title="Rootkit installed",
        description="Kernel module rootkit detected",
        host="prod-01",
        process="insmod",
        user="root",
    )


def _report(severity=Severity.CRITICAL):
    event = _critical_event()
    event.severity = severity
    agent = TriageAgent()
    crew = InvestigationCrew()
    tr = agent.triage(event)
    return crew.investigate(event, tr)


# ---------------------------------------------------------------------------
# ApprovalGate
# ---------------------------------------------------------------------------

def test_non_destructive_auto_approved():
    gate = ApprovalGate()
    from sorabbyngo.core.models import ResponseAction
    action = ResponseAction(action_type=ActionType.NOTIFY_TEAM, target="team@x.com")
    assert gate.is_approved(action) is True


def test_destructive_not_approved_by_default():
    gate = ApprovalGate()
    from sorabbyngo.core.models import ResponseAction
    action = ResponseAction(action_type=ActionType.ISOLATE_HOST, target="host-01")
    assert gate.is_approved(action) is False


def test_destructive_approved_after_approval():
    gate = ApprovalGate()
    from sorabbyngo.core.models import ResponseAction
    action = ResponseAction(action_type=ActionType.ISOLATE_HOST, target="host-01")
    gate.approve(action.id)
    assert gate.is_approved(action) is True


def test_revoke_removes_approval():
    gate = ApprovalGate()
    from sorabbyngo.core.models import ResponseAction
    action = ResponseAction(action_type=ActionType.ISOLATE_HOST, target="host-01")
    gate.approve(action.id)
    gate.revoke(action.id)
    assert gate.is_approved(action) is False


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def test_execute_report_returns_records(executor):
    report = _report()
    records = executor.execute_report(report)
    assert len(records) > 0


def test_non_destructive_actions_execute(executor):
    report = _report()
    records = executor.execute_report(report)
    executed = [r for r in records if r.action_type == ActionType.NOTIFY_TEAM]
    assert all(r.status == ActionStatus.EXECUTED for r in executed)


def test_destructive_actions_pending_without_approval(executor):
    report = _report(severity=Severity.CRITICAL)
    records = executor.execute_report(report)
    pending = [r for r in records if r.action_type == ActionType.ISOLATE_HOST]
    assert all(r.status == ActionStatus.PENDING for r in pending)


def test_approved_destructive_executes(executor):
    report = _report(severity=Severity.CRITICAL)
    isolate_action = next(
        a for a in report.response_actions if a.action_type == ActionType.ISOLATE_HOST
    )
    executor.gate.approve(isolate_action.id)
    records = executor.execute_report(report)
    isolate_records = [r for r in records if r.action_type == ActionType.ISOLATE_HOST]
    assert all(r.status == ActionStatus.EXECUTED for r in isolate_records)


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------

def test_dry_run_marks_records_skipped(dry_executor):
    report = _report(severity=Severity.LOW)  # no destructive actions
    records = dry_executor.execute_report(report)
    non_pending = [r for r in records if r.status != ActionStatus.PENDING]
    assert all(r.status == ActionStatus.SKIPPED for r in non_pending)


def test_dry_run_output_prefixed(dry_executor):
    report = _report(severity=Severity.LOW)
    records = dry_executor.execute_report(report)
    executed = [r for r in records if r.output.startswith("[DRY-RUN]")]
    assert len(executed) > 0


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

def test_rollback_executed_record(executor):
    report = _report(severity=Severity.LOW)
    records = executor.execute_report(report)
    executed = next(r for r in records if r.status == ActionStatus.EXECUTED)
    rolled = executor.rollback(executed.id)
    assert rolled is not None
    assert rolled.status == ActionStatus.ROLLED_BACK
    assert rolled.rolled_back_at is not None


def test_rollback_pending_returns_none(executor):
    report = _report(severity=Severity.CRITICAL)
    records = executor.execute_report(report)
    pending = next((r for r in records if r.status == ActionStatus.PENDING), None)
    if pending:
        result = executor.rollback(pending.id)
        assert result is None


def test_rollback_nonexistent_returns_none(executor):
    assert executor.rollback("nonexistent-id") is None


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

def test_ledger_grows_with_each_execution(executor):
    report = _report(severity=Severity.LOW)
    executor.execute_report(report)
    assert len(executor.ledger) > 0


def test_get_record_returns_correct_record(executor):
    report = _report(severity=Severity.LOW)
    records = executor.execute_report(report)
    rec = records[0]
    found = executor.get_record(rec.id)
    assert found is not None
    assert found.id == rec.id
