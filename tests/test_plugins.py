import pytest
from sorabbyngo.plugins import PluginRegistry, BasePlugin, TriagePlugin, AlertPlugin, EnrichmentPlugin, SourcePlugin
from sorabbyngo.core.models import SecurityEvent, Severity, EventCategory


class HighScorePlugin(TriagePlugin):
    name = "high-scorer"
    description = "Always 0.9"
    def score(self, e): return 0.9
    def mitre_techniques(self, e): return ["T1059 - Command Scripting"]

class LowScorePlugin(TriagePlugin):
    name = "low-scorer"
    def score(self, e): return 0.1

class PassThroughPlugin(TriagePlugin):
    name = "pass-through"
    def score(self, e): return None

class KeywordPlugin(TriagePlugin):
    name = "keyword-plugin"
    def score(self, e):
        return 0.99 if "ransomware" in e.title.lower() else None

class MockAlertPlugin(AlertPlugin):
    name = "mock-alert"
    def __init__(self):
        super().__init__()
        self.received = []
    def send(self, d):
        self.received.append(d)
        return True

class FailingAlertPlugin(AlertPlugin):
    name = "failing-alert"
    def send(self, d): raise RuntimeError("boom")

class TagEnrichmentPlugin(EnrichmentPlugin):
    name = "tag-enricher"
    def enrich(self, e):
        e.description = "[ENRICHED] " + e.description
        return e

class MockSourcePlugin(SourcePlugin):
    name = "mock-source"
    def poll(self): return [{"source":"mock","payload":{"title":"T","host":"h"}}]


def _event(title="Test", severity=Severity.HIGH, category=EventCategory.INTRUSION):
    return SecurityEvent(source="f", category=category, severity=severity,
                         title=title, description="D", host="h")


def test_register():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    assert reg.count() == 1

def test_register_wrong_type():
    with pytest.raises(TypeError):
        PluginRegistry().register("bad")

def test_register_duplicate():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    with pytest.raises(ValueError):
        reg.register(HighScorePlugin())

def test_unregister():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    assert reg.unregister("high-scorer") is True
    assert reg.count() == 0

def test_unregister_missing():
    assert PluginRegistry().unregister("x") is False

def test_get():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    assert reg.get("high-scorer") is not None

def test_get_missing():
    assert PluginRegistry().get("x") is None

def test_all():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.register(LowScorePlugin())
    assert len(reg.all()) == 2

def test_disable():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.disable("high-scorer")
    assert not reg.get("high-scorer").enabled

def test_enable():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.disable("high-scorer")
    reg.enable("high-scorer")
    assert reg.get("high-scorer").enabled

def test_disable_missing():
    assert PluginRegistry().disable("x") is False

def test_disabled_excluded():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.disable("high-scorer")
    assert len(reg.triage_plugins()) == 0

def test_triage_only():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.register(MockAlertPlugin())
    assert len(reg.triage_plugins()) == 1

def test_alert_only():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.register(MockAlertPlugin())
    assert len(reg.alert_plugins()) == 1

def test_enrichment():
    reg = PluginRegistry()
    reg.register(TagEnrichmentPlugin())
    assert len(reg.enrichment_plugins()) == 1

def test_source():
    reg = PluginRegistry()
    reg.register(MockSourcePlugin())
    assert len(reg.source_plugins()) == 1

def test_run_triage_highest():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.register(LowScorePlugin())
    assert reg.run_triage(_event()) == 0.9

def test_run_triage_pass_through():
    reg = PluginRegistry()
    reg.register(PassThroughPlugin())
    assert reg.run_triage(_event()) is None

def test_run_triage_no_plugins():
    assert PluginRegistry().run_triage(_event()) is None

def test_run_triage_keyword():
    reg = PluginRegistry()
    reg.register(KeywordPlugin())
    assert reg.run_triage(_event("Ransomware detected")) == 0.99

def test_run_triage_clamp_high():
    class O(TriagePlugin):
        name = "o"
        def score(self, e): return 999.0
    reg = PluginRegistry()
    reg.register(O())
    assert reg.run_triage(_event()) == 1.0

def test_run_triage_clamp_low():
    class U(TriagePlugin):
        name = "u"
        def score(self, e): return -5.0
    reg = PluginRegistry()
    reg.register(U())
    assert reg.run_triage(_event()) == 0.0

def test_run_triage_exception():
    class B(TriagePlugin):
        name = "b"
        def score(self, e): raise RuntimeError("boom")
    reg = PluginRegistry()
    reg.register(B())
    assert reg.run_triage(_event()) is None

def test_run_enrichment():
    reg = PluginRegistry()
    reg.register(TagEnrichmentPlugin())
    assert "[ENRICHED]" in reg.run_enrichment(_event()).description

def test_run_enrichment_no_plugins():
    e = _event()
    orig = e.description
    assert PluginRegistry().run_enrichment(e).description == orig

def test_run_enrichment_chained():
    class A(EnrichmentPlugin):
        name = "a"
        def enrich(self, e):
            e.description = "A:" + e.description
            return e
    class B(EnrichmentPlugin):
        name = "b"
        def enrich(self, e):
            e.description = "B:" + e.description
            return e
    reg = PluginRegistry()
    reg.register(A())
    reg.register(B())
    assert reg.run_enrichment(_event()).description.startswith("B:A:")

def test_run_alert():
    reg = PluginRegistry()
    p = MockAlertPlugin()
    reg.register(p)
    reg.run_alert({"sev": "CRITICAL"})
    assert len(p.received) == 1

def test_run_alert_results():
    reg = PluginRegistry()
    reg.register(MockAlertPlugin())
    assert reg.run_alert({})["mock-alert"] is True

def test_run_alert_failure():
    reg = PluginRegistry()
    reg.register(FailingAlertPlugin())
    assert reg.run_alert({})["failing-alert"] is False

def test_run_alert_no_plugins():
    assert PluginRegistry().run_alert({}) == {}

def test_collect_mitre():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    assert "T1059 - Command Scripting" in reg.collect_mitre(_event())

def test_collect_mitre_dedup():
    class D(TriagePlugin):
        name = "d"
        def score(self, e): return None
        def mitre_techniques(self, e): return ["T1059 - Command Scripting"]
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.register(D())
    assert reg.collect_mitre(_event()).count("T1059 - Command Scripting") == 1

def test_collect_mitre_empty():
    assert PluginRegistry().collect_mitre(_event()) == []

def test_stats_total():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.register(MockAlertPlugin())
    assert reg.stats()["total"] == 2

def test_stats_enabled_disabled():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    reg.register(LowScorePlugin())
    reg.disable("low-scorer")
    s = reg.stats()
    assert s["enabled"] == 1 and s["disabled"] == 1

def test_stats_list():
    reg = PluginRegistry()
    reg.register(HighScorePlugin())
    assert reg.stats()["plugins"][0]["name"] == "high-scorer"

def test_setup_called():
    called = []
    class S(TriagePlugin):
        name = "s"
        def setup(self, c): called.append(c)
        def score(self, e): return None
    reg = PluginRegistry()
    reg.register(S(), config={"k": "v"})
    assert called[0] == {"k": "v"}

def test_teardown_called():
    torn = []
    class T(TriagePlugin):
        name = "t"
        def teardown(self): torn.append(True)
        def score(self, e): return None
    reg = PluginRegistry()
    reg.register(T())
    reg.unregister("t")
    assert torn == [True]

def test_to_dict():
    d = HighScorePlugin().to_dict()
    assert d["name"] == "high-scorer" and d["enabled"] and "type" in d

def test_list_plugins_empty(client):
    r = client.get("/api/v1/plugins")
    assert r.status_code == 200 and r.get_json()["total"] == 0

def test_enable_missing(client):
    assert client.post("/api/v1/plugins/x/enable").status_code == 404

def test_disable_missing(client):
    assert client.post("/api/v1/plugins/x/disable").status_code == 404

def test_unregister_missing(client):
    assert client.delete("/api/v1/plugins/x").status_code == 404
