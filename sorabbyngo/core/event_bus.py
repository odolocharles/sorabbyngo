"""
Module 1 — Event Bus
Central nervous system: ingest, normalise, deduplicate, route.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Any

from sorabbyngo.core.models import (
    RawSignal, SecurityEvent, Severity, EventCategory
)


class NormalisationError(Exception):
    pass


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable]] = defaultdict(list)
        self._seen_fingerprints: set[str] = set()
        self._event_log: list[SecurityEvent] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def subscribe(self, severity: Severity | str, handler: Callable) -> None:
        key = severity.value if isinstance(severity, Severity) else severity
        self._handlers[key].append(handler)

    def subscribe_all(self, handler: Callable) -> None:
        self._handlers["*"].append(handler)

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def ingest(self, signal: RawSignal) -> SecurityEvent | None:
        event = self._normalise(signal)
        if self._is_duplicate(event):
            return None
        self._event_log.append(event)
        self._route(event)
        return event

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------
    def _normalise(self, signal: RawSignal) -> SecurityEvent:
        p = signal.payload
        try:
            severity = Severity(p.get("severity", "MEDIUM").upper())
        except ValueError:
            severity = Severity.MEDIUM

        try:
            category = EventCategory(p.get("category", "UNKNOWN").upper())
        except ValueError:
            category = EventCategory.UNKNOWN

        return SecurityEvent(
            source=signal.source,
            category=category,
            severity=severity,
            title=p.get("title", "Untitled Event"),
            description=p.get("description", ""),
            host=p.get("host", "unknown"),
            process=p.get("process"),
            user=p.get("user"),
            mitre_technique=p.get("mitre_technique"),
            raw_payload=p,
            timestamp=signal.received_at,
        )

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------
    def _is_duplicate(self, event: SecurityEvent) -> bool:
        if event.fingerprint in self._seen_fingerprints:
            return True
        self._seen_fingerprints.add(event.fingerprint)  # type: ignore[arg-type]
        return False

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def _route(self, event: SecurityEvent) -> None:
        key = event.severity.value
        for handler in self._handlers.get(key, []):
            handler(event)
        for handler in self._handlers.get("*", []):
            handler(event)

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------
    def get_events(
        self,
        severity: Severity | None = None,
        category: EventCategory | None = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        events = self._event_log
        if severity:
            events = [e for e in events if e.severity == severity]
        if category:
            events = [e for e in events if e.category == category]
        return events[-limit:]

    def get_event_by_id(self, event_id: str) -> SecurityEvent | None:
        for event in self._event_log:
            if event.id == event_id:
                return event
        return None

    @property
    def event_count(self) -> int:
        return len(self._event_log)
