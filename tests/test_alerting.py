import pytest
from unittest.mock import patch, MagicMock
from sorabbyngo.core.alerting import Alert, AlertManager, AlertResult, ConsoleChannel, WebhookChannel, SlackChannel, EmailChannel
from sorabbyngo.core.models import SecurityEvent, Severity, EventCategory, TriageVerdict
from sorabbyngo.agents.triage import TriageAgent

def _event(severity=Severity.CRITICAL, category=EventCategory.INTRUSION):
    return SecurityEvent(source="falco", category=category, severity=severity,
                        title="SSH brute-force", description="Failed SSH logins",
                        host="prod-01", process="sshd", user="root")

def _triage(event): return TriageAgent().triage(event)

def _alert(event=None, tr=None):
    e = event or _event(); t = tr or _triage(e)
    return Alert(event_id=e.id, title=e.title, severity=e.severity.value,
                 verdict=t.verdict.value, score=t.score, host=e.host,
                 source=e.source, mitre_techniques=t.mitre_techniques)

def test_alert_to_dict_has_platform(): assert _alert().to_dict()["platform"] == "Sorabbyngo"
def test_alert_to_dict_has_severity(): assert _alert().to_dict()["severity"] == "CRITICAL"
def test_alert_to_text_contains_host(): assert "prod-01" in _alert().to_text()
def test_alert_to_slack_has_attachments(): assert "attachments" in _alert().to_slack()
def test_alert_to_slack_critical_red(): assert _alert().to_slack()["attachments"][0]["color"] == "#ff0000"
def test_console_returns_success(capsys):
    assert ConsoleChannel().send(_alert()).success is True
def test_console_prints_output(capsys):
    ConsoleChannel().send(_alert()); assert "Sorabbyngo" in capsys.readouterr().out
def test_webhook_sends_post():
    with patch("urllib.request.urlopen") as m:
        m.return_value.__enter__ = lambda s: s; m.return_value.__exit__ = MagicMock(return_value=False)
        assert WebhookChannel("http://fake/hook").send(_alert()).channel == "webhook"
def test_webhook_failure_on_error():
    with patch("urllib.request.urlopen", side_effect=Exception("refused")):
        r = WebhookChannel("http://x").send(_alert())
        assert r.success is False and r.error is not None
def test_slack_sends_formatted():
    captured = {}
    def fake_open(req, timeout=None):
        captured["data"] = req.data; m = MagicMock(); m.__enter__ = lambda s: s; m.__exit__ = MagicMock(return_value=False); return m
    with patch("urllib.request.urlopen", fake_open):
        import json; r = SlackChannel("http://fake/hook").send(_alert())
        assert "attachments" in json.loads(captured["data"])
def test_email_fails_gracefully():
    r = EmailChannel("smtp.fake",587,"from@x",["to@x"]).send(_alert())
    assert r.success is False and r.channel == "email"
def test_critical_triggers_alert():
    assert AlertManager().should_alert(_event(Severity.CRITICAL), _triage(_event(Severity.CRITICAL))) is True
def test_high_triggers_alert():
    e = _event(Severity.HIGH, EventCategory.MALWARE)
    assert AlertManager().should_alert(e, _triage(e)) is True
def test_low_no_alert():
    e = _event(Severity.LOW)
    assert AlertManager().should_alert(e, _triage(e)) is False
def test_medium_no_alert():
    e = _event(Severity.MEDIUM)
    assert AlertManager().should_alert(e, _triage(e)) is False
def test_fire_records_history(capsys):
    m = AlertManager(); e = _event(); m.fire(e, _triage(e)); assert len(m.history) == 1
def test_stats_correct(capsys):
    m = AlertManager(); e = _event(); m.fire(e, _triage(e))
    s = m.stats(); assert s["total_alerts_fired"]==1 and s["successful"]==1 and s["failed"]==0
def test_multiple_channels(capsys):
    m = AlertManager(channels=[ConsoleChannel(),ConsoleChannel()])
    assert len(m.fire(_event(), _triage(_event()))) == 2
def test_add_channel():
    m = AlertManager(channels=[ConsoleChannel()]); m.add_channel(ConsoleChannel())
    assert len(m.channels) == 2
def test_no_alert_low(capsys):
    m = AlertManager(); e = _event(Severity.LOW)
    assert m.fire(e, _triage(e)) == [] and len(m.history) == 0
