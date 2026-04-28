"""
Module 5 — Storage Layer
In-memory store for API layer. Production version uses PostgreSQL + SQLAlchemy 2.0 async.
"""
from __future__ import annotations

from sorabbyngo.core.models import SecurityEvent, IncidentReport, ExecutionRecord


class Store:
    """Thread-safe in-memory store. Replace with DB backend in production."""

    def __init__(self) -> None:
        self._events: dict[str, SecurityEvent] = {}
        self._reports: dict[str, IncidentReport] = {}
        self._records: dict[str, ExecutionRecord] = {}

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def save_event(self, event: SecurityEvent) -> None:
        self._events[event.id] = event

    def get_event(self, event_id: str) -> SecurityEvent | None:
        return self._events.get(event_id)

    def list_events(self, limit: int = 100) -> list[SecurityEvent]:
        events = list(self._events.values())
        return events[-limit:]

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def save_report(self, report: IncidentReport) -> None:
        self._reports[report.id] = report

    def get_report(self, report_id: str) -> IncidentReport | None:
        return self._reports.get(report_id)

    def list_reports(self, limit: int = 100) -> list[IncidentReport]:
        return list(self._reports.values())[-limit:]

    def get_report_by_event(self, event_id: str) -> IncidentReport | None:
        return next((r for r in self._reports.values() if r.event_id == event_id), None)

    # ------------------------------------------------------------------
    # Execution records
    # ------------------------------------------------------------------
    def save_record(self, record: ExecutionRecord) -> None:
        self._records[record.id] = record

    def get_record(self, record_id: str) -> ExecutionRecord | None:
        return self._records.get(record_id)

    def list_records_for_report(self, report_id: str) -> list[ExecutionRecord]:
        return [r for r in self._records.values() if r.report_id == report_id]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        return {
            "total_events": len(self._events),
            "total_reports": len(self._reports),
            "total_execution_records": len(self._records),
        }
