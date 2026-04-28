"""
Module 3 — Investigation Crew
Three-agent crew: Correlation Analyst, Threat Intel, Incident Commander.
Produces a structured IncidentReport for escalated events.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sorabbyngo.core.models import (
    SecurityEvent, TriageResult, IncidentReport, ResponseAction,
    ActionType, Severity,
)


class InvestigationCrew:
    """
    Synchronous stub crew — production version wires crewai agents here.
    Generates a deterministic IncidentReport from event + triage data.
    """

    def investigate(self, event: SecurityEvent, triage: TriageResult) -> IncidentReport:
        timeline = self._build_timeline(event)
        root_cause = self._root_cause(event)
        assets = self._affected_assets(event)
        actions = self._response_actions(event, triage)

        return IncidentReport(
            event_id=event.id,
            title=f"[{event.severity.value}] {event.title}",
            severity=event.severity,
            summary=(
                f"Security event detected from {event.source} on host {event.host}. "
                f"Triage score: {triage.score:.2f} ({triage.verdict.value}). "
                f"{event.description}"
            ),
            attack_timeline=timeline,
            root_cause=root_cause,
            affected_assets=assets,
            mitre_tactics=triage.mitre_techniques,
            response_actions=actions,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _build_timeline(self, event: SecurityEvent) -> list[str]:
        ts = event.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        entries = [
            f"{ts} — Event detected: {event.title}",
            f"{ts} — Source: {event.source}, Host: {event.host}",
        ]
        if event.process:
            entries.append(f"{ts} — Involved process: {event.process}")
        if event.user:
            entries.append(f"{ts} — Involved user: {event.user}")
        return entries

    def _root_cause(self, event: SecurityEvent) -> str:
        return (
            f"Event '{event.title}' originated from {event.source} "
            f"on {event.host}. Category: {event.category.value}. "
            f"Full investigation required to confirm root cause."
        )

    def _affected_assets(self, event: SecurityEvent) -> list[str]:
        assets = [event.host]
        if event.user:
            assets.append(f"user:{event.user}")
        if event.process:
            assets.append(f"process:{event.process}")
        return assets

    def _response_actions(self, event: SecurityEvent, triage: TriageResult) -> list[ResponseAction]:
        actions: list[ResponseAction] = []
        severity_val = event.severity

        # Always notify
        actions.append(ResponseAction(
            action_type=ActionType.NOTIFY_TEAM,
            target="security-team@sorabbyngo.internal",
            parameters={"channel": "slack", "urgency": severity_val.value},
            priority=1,
            requires_approval=False,
        ))

        # Always create ticket
        actions.append(ResponseAction(
            action_type=ActionType.CREATE_TICKET,
            target="jira",
            parameters={"project": "SEC", "priority": severity_val.value},
            priority=2,
            requires_approval=False,
        ))

        # Forensics collection
        actions.append(ResponseAction(
            action_type=ActionType.COLLECT_FORENSICS,
            target=event.host,
            parameters={"depth": "full"},
            priority=3,
            requires_approval=False,
        ))

        # Destructive actions only for high/critical
        if severity_val in (Severity.HIGH, Severity.CRITICAL):
            if event.process:
                actions.append(ResponseAction(
                    action_type=ActionType.KILL_PROCESS,
                    target=event.process,
                    parameters={"host": event.host},
                    priority=4,
                    requires_approval=True,
                    rollback_command=f"# Process {event.process} was killed — restart manually",
                ))

            if severity_val == Severity.CRITICAL:
                actions.append(ResponseAction(
                    action_type=ActionType.ISOLATE_HOST,
                    target=event.host,
                    parameters={"method": "network_acl"},
                    priority=5,
                    requires_approval=True,
                    rollback_command=f"# Remove isolation ACL on {event.host}",
                ))

        return actions
