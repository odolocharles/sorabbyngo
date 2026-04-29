from __future__ import annotations
import json, smtplib, urllib.request, urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from sorabbyngo.core.models import SecurityEvent, TriageResult, TriageVerdict, Severity

@dataclass
class Alert:
    event_id: str
    title: str
    severity: str
    verdict: str
    score: float
    host: str
    source: str
    mitre_techniques: list
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    def to_dict(self):
        return {"platform": "Sorabbyngo", "event_id": self.event_id, "title": self.title,
                "severity": self.severity, "verdict": self.verdict, "score": self.score,
                "host": self.host, "source": self.source,
                "mitre_techniques": self.mitre_techniques, "timestamp": self.timestamp}
    def to_text(self):
        return (f"[Sorabbyngo Alert] {self.severity} — {self.title}\n"
                f"Host: {self.host} | Source: {self.source}\n"
                f"Verdict: {self.verdict} | Score: {self.score:.2f}\n"
                f"MITRE: {', '.join(self.mitre_techniques) or 'N/A'}\nTime: {self.timestamp}")
    def to_slack(self):
        color = {"CRITICAL": "#ff0000", "HIGH": "#ff7b00", "MEDIUM": "#ffcc00", "LOW": "#36a64f"}.get(self.severity, "#cccccc")
        return {"text": f":rotating_light: *Sorabbyngo Alert* — {self.severity}",
                "attachments": [{"color": color, "title": self.title,
                                 "fields": [{"title": "Host", "value": self.host, "short": True},
                                            {"title": "Verdict", "value": self.verdict, "short": True}],
                                 "footer": "Sorabbyngo"}]}

@dataclass
class AlertResult:
    channel: str
    success: bool
    error: str = None

class AlertChannel(ABC):
    @property
    @abstractmethod
    def name(self): ...
    @abstractmethod
    def send(self, alert): ...

class ConsoleChannel(AlertChannel):
    @property
    def name(self): return "console"
    def send(self, alert):
        print(f"\n{'='*60}\n{alert.to_text()}\n{'='*60}")
        return AlertResult(channel=self.name, success=True)

class WebhookChannel(AlertChannel):
    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout
    @property
    def name(self): return "webhook"
    def send(self, alert):
        try:
            data = json.dumps(alert.to_dict()).encode()
            req = urllib.request.Request(self.url, data=data, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout): pass
            return AlertResult(channel=self.name, success=True)
        except Exception as e:
            return AlertResult(channel=self.name, success=False, error=str(e))

class SlackChannel(AlertChannel):
    def __init__(self, webhook_url, timeout=5):
        self.webhook_url = webhook_url
        self.timeout = timeout
    @property
    def name(self): return "slack"
    def send(self, alert):
        try:
            data = json.dumps(alert.to_slack()).encode()
            req = urllib.request.Request(self.webhook_url, data=data, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout): pass
            return AlertResult(channel=self.name, success=True)
        except Exception as e:
            return AlertResult(channel=self.name, success=False, error=str(e))

class EmailChannel(AlertChannel):
    def __init__(self, smtp_host, smtp_port, sender, recipients, username=None, password=None, use_tls=True):
        self.smtp_host = smtp_host; self.smtp_port = smtp_port
        self.sender = sender; self.recipients = recipients
        self.username = username; self.password = password; self.use_tls = use_tls
    @property
    def name(self): return "email"
    def send(self, alert):
        try:
            msg = MIMEText(alert.to_text())
            msg["Subject"] = f"[Sorabbyngo] {alert.severity} Alert: {alert.title}"
            msg["From"] = self.sender; msg["To"] = ", ".join(self.recipients)
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=5) as smtp:
                if self.use_tls: smtp.starttls()
                if self.username: smtp.login(self.username, self.password)
                smtp.sendmail(self.sender, self.recipients, msg.as_string())
            return AlertResult(channel=self.name, success=True)
        except Exception as e:
            return AlertResult(channel=self.name, success=False, error=str(e))

_ALERT_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}

class AlertManager:
    def __init__(self, channels=None, min_verdict=TriageVerdict.ESCALATE):
        self.channels = channels or [ConsoleChannel()]
        self.min_verdict = min_verdict
        self._history = []
    def add_channel(self, channel):
        self.channels.append(channel)
    def should_alert(self, event, triage):
        if event.severity not in _ALERT_SEVERITIES: return False
        order = [TriageVerdict.AUTO_CLOSE, TriageVerdict.ESCALATE, TriageVerdict.IMMEDIATE_RESPONSE]
        return order.index(triage.verdict) >= order.index(self.min_verdict)
    def fire(self, event, triage):
        if not self.should_alert(event, triage): return []
        alert = Alert(event_id=event.id, title=event.title, severity=event.severity.value,
                      verdict=triage.verdict.value, score=triage.score, host=event.host,
                      source=event.source, mitre_techniques=triage.mitre_techniques)
        results = []
        for channel in self.channels:
            result = channel.send(alert)
            results.append(result)
            self._history.append({"alert": alert.to_dict(), "channel": result.channel,
                                  "success": result.success, "error": result.error})
        return results
    @property
    def history(self): return list(self._history)
    def stats(self):
        total = len(self._history)
        success = sum(1 for h in self._history if h["success"])
        return {"total_alerts_fired": total, "successful": success,
                "failed": total - success, "channels": [c.name for c in self.channels]}
