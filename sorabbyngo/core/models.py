"""
Core data models for Sorabbyngo — the canonical schemas used across all modules.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventCategory(str, Enum):
    INTRUSION = "INTRUSION"
    MALWARE = "MALWARE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PERSISTENCE = "PERSISTENCE"
    RECONNAISSANCE = "RECONNAISSANCE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ANOMALY = "ANOMALY"
    UNKNOWN = "UNKNOWN"


class TriageVerdict(str, Enum):
    AUTO_CLOSE = "AUTO_CLOSE"
    ESCALATE = "ESCALATE"
    IMMEDIATE_RESPONSE = "IMMEDIATE_RESPONSE"


class ActionStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SKIPPED = "SKIPPED"


class ActionType(str, Enum):
    ISOLATE_HOST = "ISOLATE_HOST"
    KILL_PROCESS = "KILL_PROCESS"
    REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
    BLOCK_IP = "BLOCK_IP"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    COLLECT_FORENSICS = "COLLECT_FORENSICS"
    NOTIFY_TEAM = "NOTIFY_TEAM"
    CREATE_TICKET = "CREATE_TICKET"


# ---------------------------------------------------------------------------
# Module 1 — Event Bus models
# ---------------------------------------------------------------------------

class RawSignal(BaseModel):
    """Incoming signal before normalisation."""
    source: str
    payload: dict[str, Any]
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecurityEvent(BaseModel):
    """Canonical, normalised security event."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    category: EventCategory
    severity: Severity
    title: str
    description: str
    host: str = "unknown"
    process: str | None = None
    user: str | None = None
    mitre_technique: str | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    fingerprint: str | None = None  # for dedup

    def model_post_init(self, __context: Any) -> None:
        if self.fingerprint is None:
            import hashlib
            blob = f"{self.source}:{self.category}:{self.title}:{self.host}"
            self.fingerprint = hashlib.sha256(blob.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Module 2 — Triage models
# ---------------------------------------------------------------------------

class TriageResult(BaseModel):
    event_id: str
    score: float = Field(ge=0.0, le=1.0)
    verdict: TriageVerdict
    mitre_techniques: list[str] = Field(default_factory=list)
    reasoning: str = ""
    llm_used: bool = False
    triaged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Module 3 — Investigation models
# ---------------------------------------------------------------------------

class ResponseAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ActionType
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    priority: int = 1
    requires_approval: bool = False
    rollback_command: str | None = None


class IncidentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str
    title: str
    severity: Severity
    summary: str
    attack_timeline: list[str] = Field(default_factory=list)
    root_cause: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    response_actions: list[ResponseAction] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Module 4 — Execution models
# ---------------------------------------------------------------------------

class ExecutionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_id: str
    action_id: str
    action_type: ActionType
    target: str
    status: ActionStatus = ActionStatus.PENDING
    dry_run: bool = False
    output: str = ""
    error: str | None = None
    executed_at: datetime | None = None
    rolled_back_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
