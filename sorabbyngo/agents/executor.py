"""
Module 4 — Response Executor
Executes response actions safely. ApprovalGate blocks destructive actions.
Full audit ledger with rollback commands. Dry-run mode.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sorabbyngo.core.models import (
    IncidentReport, ResponseAction, ExecutionRecord,
    ActionStatus, ActionType,
)

# Actions that require explicit approval before execution
_DESTRUCTIVE_ACTIONS: frozenset[ActionType] = frozenset({
    ActionType.ISOLATE_HOST,
    ActionType.KILL_PROCESS,
    ActionType.REVOKE_CREDENTIALS,
})


class ApprovalGate:
    def __init__(self) -> None:
        self._approved: set[str] = set()   # action IDs

    def approve(self, action_id: str) -> None:
        self._approved.add(action_id)

    def is_approved(self, action: ResponseAction) -> bool:
        if action.action_type not in _DESTRUCTIVE_ACTIONS:
            return True          # non-destructive: auto-approved
        return action.id in self._approved

    def revoke(self, action_id: str) -> None:
        self._approved.discard(action_id)


class ResponseExecutor:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.gate = ApprovalGate()
        self._ledger: list[ExecutionRecord] = []

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def execute_report(self, report: IncidentReport) -> list[ExecutionRecord]:
        records: list[ExecutionRecord] = []
        for action in sorted(report.response_actions, key=lambda a: a.priority):
            record = self._execute_action(report.id, action)
            self._ledger.append(record)
            records.append(record)
        return records

    def _execute_action(self, report_id: str, action: ResponseAction) -> ExecutionRecord:
        record = ExecutionRecord(
            report_id=report_id,
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            dry_run=self.dry_run,
        )

        if not self.gate.is_approved(action):
            record.status = ActionStatus.PENDING
            record.output = f"Awaiting approval for {action.action_type.value} on {action.target}"
            return record

        try:
            output = self._dispatch(action)
            record.status = ActionStatus.EXECUTED if not self.dry_run else ActionStatus.SKIPPED
            record.output = f"[DRY-RUN] {output}" if self.dry_run else output
            record.executed_at = datetime.now(timezone.utc)
        except Exception as exc:
            record.status = ActionStatus.FAILED
            record.error = str(exc)

        return record

    def _dispatch(self, action: ResponseAction) -> str:
        """Simulated dispatch — wire to real effectors in production."""
        handlers: dict[ActionType, Any] = {
            ActionType.ISOLATE_HOST:       lambda a: f"Host {a.target} isolated via network ACL",
            ActionType.KILL_PROCESS:       lambda a: f"Process {a.target} killed on {a.parameters.get('host', 'unknown')}",
            ActionType.REVOKE_CREDENTIALS: lambda a: f"Credentials revoked for {a.target}",
            ActionType.BLOCK_IP:           lambda a: f"IP {a.target} blocked at perimeter firewall",
            ActionType.QUARANTINE_FILE:    lambda a: f"File {a.target} quarantined",
            ActionType.COLLECT_FORENSICS:  lambda a: f"Forensics collected from {a.target} (depth={a.parameters.get('depth', 'standard')})",
            ActionType.NOTIFY_TEAM:        lambda a: f"Team notified via {a.parameters.get('channel', 'email')}",
            ActionType.CREATE_TICKET:      lambda a: f"Ticket created in {a.target} project {a.parameters.get('project', 'SEC')}",
        }
        handler = handlers.get(action.action_type)
        if handler:
            return handler(action)
        return f"Action {action.action_type.value} dispatched to {action.target}"

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------
    def rollback(self, record_id: str) -> ExecutionRecord | None:
        record = next((r for r in self._ledger if r.id == record_id), None)
        if not record or record.status != ActionStatus.EXECUTED:
            return None
        record.status = ActionStatus.ROLLED_BACK
        record.rolled_back_at = datetime.now(timezone.utc)
        return record

    # ------------------------------------------------------------------
    # Ledger access
    # ------------------------------------------------------------------
    @property
    def ledger(self) -> list[ExecutionRecord]:
        return list(self._ledger)

    def get_record(self, record_id: str) -> ExecutionRecord | None:
        return next((r for r in self._ledger if r.id == record_id), None)
