"""
Module 2 — Triage Agent
Rule-based scoring engine: scores events 0.0–1.0, maps MITRE techniques,
issues AUTO_CLOSE / ESCALATE / IMMEDIATE_RESPONSE verdicts.
"""
from __future__ import annotations

from sorabbyngo.core.models import (
    SecurityEvent, TriageResult, TriageVerdict,
    Severity, EventCategory,
)

# ---------------------------------------------------------------------------
# Severity weight table
# ---------------------------------------------------------------------------
_SEVERITY_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH:     0.75,
    Severity.MEDIUM:   0.50,
    Severity.LOW:      0.25,
    Severity.INFO:     0.05,
}

# ---------------------------------------------------------------------------
# Category risk modifier
# ---------------------------------------------------------------------------
_CATEGORY_MODIFIER: dict[EventCategory, float] = {
    EventCategory.INTRUSION:            0.20,
    EventCategory.MALWARE:              0.20,
    EventCategory.PRIVILEGE_ESCALATION: 0.15,
    EventCategory.DATA_EXFILTRATION:    0.15,
    EventCategory.LATERAL_MOVEMENT:     0.10,
    EventCategory.PERSISTENCE:          0.10,
    EventCategory.RECONNAISSANCE:       0.05,
    EventCategory.POLICY_VIOLATION:     0.00,
    EventCategory.ANOMALY:              0.05,
    EventCategory.UNKNOWN:              0.00,
}

# ---------------------------------------------------------------------------
# Keyword → MITRE technique mapping
# ---------------------------------------------------------------------------
_KEYWORD_MITRE: list[tuple[str, str]] = [
    ("ssh",            "T1021.004 – Remote Services: SSH"),
    ("brute",          "T1110 – Brute Force"),
    ("privilege",      "T1068 – Exploitation for Privilege Escalation"),
    ("sudo",           "T1548.003 – Abuse Elevation Control: Sudo"),
    ("exfil",          "T1041 – Exfiltration Over C2 Channel"),
    ("lateral",        "T1021 – Remote Services"),
    ("persistence",    "T1053 – Scheduled Task/Job"),
    ("cron",           "T1053.003 – Scheduled Task/Job: Cron"),
    ("recon",          "T1595 – Active Scanning"),
    ("scan",           "T1046 – Network Service Discovery"),
    ("malware",        "T1204 – User Execution"),
    ("ransomware",     "T1486 – Data Encrypted for Impact"),
    ("credential",     "T1078 – Valid Accounts"),
    ("token",          "T1134 – Access Token Manipulation"),
    ("inject",         "T1055 – Process Injection"),
    ("shell",          "T1059 – Command and Scripting Interpreter"),
]


class TriageAgent:
    def __init__(self, escalate_threshold: float = 0.5, immediate_threshold: float = 0.85) -> None:
        self.escalate_threshold = escalate_threshold
        self.immediate_threshold = immediate_threshold

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def triage(self, event: SecurityEvent) -> TriageResult:
        score = self._score(event)
        verdict = self._verdict(score)
        techniques = self._map_mitre(event)
        reasoning = self._explain(event, score, verdict)

        return TriageResult(
            event_id=event.id,
            score=round(score, 4),
            verdict=verdict,
            mitre_techniques=techniques,
            reasoning=reasoning,
            llm_used=False,
        )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    def _score(self, event: SecurityEvent) -> float:
        base = _SEVERITY_SCORE.get(event.severity, 0.5)
        modifier = _CATEGORY_MODIFIER.get(event.category, 0.0)
        score = min(base + modifier, 1.0)
        return score

    # ------------------------------------------------------------------
    # Verdict
    # ------------------------------------------------------------------
    def _verdict(self, score: float) -> TriageVerdict:
        if score >= self.immediate_threshold:
            return TriageVerdict.IMMEDIATE_RESPONSE
        if score >= self.escalate_threshold:
            return TriageVerdict.ESCALATE
        return TriageVerdict.AUTO_CLOSE

    # ------------------------------------------------------------------
    # MITRE mapping
    # ------------------------------------------------------------------
    def _map_mitre(self, event: SecurityEvent) -> list[str]:
        techniques: list[str] = []
        text = f"{event.title} {event.description}".lower()
        for keyword, technique in _KEYWORD_MITRE:
            if keyword in text:
                techniques.append(technique)
        if event.mitre_technique and event.mitre_technique not in techniques:
            techniques.insert(0, event.mitre_technique)
        return techniques

    # ------------------------------------------------------------------
    # Reasoning
    # ------------------------------------------------------------------
    def _explain(self, event: SecurityEvent, score: float, verdict: TriageVerdict) -> str:
        return (
            f"Severity={event.severity.value} base score mapped to {_SEVERITY_SCORE.get(event.severity, 0.5):.2f}. "
            f"Category={event.category.value} added modifier {_CATEGORY_MODIFIER.get(event.category, 0.0):.2f}. "
            f"Final score={score:.4f} → verdict={verdict.value}."
        )
