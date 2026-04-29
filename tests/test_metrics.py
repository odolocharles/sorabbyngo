import pytest, time
from sorabbyngo.core.metrics import Counter, Gauge, SoraMetrics

def test_counter_starts_zero(): assert Counter("t","h").get() == 0.0
def test_counter_increments(): c=Counter("t","h"); c.inc(); assert c.get()==1.0
def test_counter_by_amount(): c=Counter("t","h"); c.inc(5.0); assert c.get()==5.0
def test_counter_labels():
    c=Counter("t","h",labels=["sev"]); c.inc(sev="CRITICAL"); c.inc(sev="HIGH")
    assert c.get(sev="CRITICAL")==1.0 and c.get(sev="HIGH")==1.0
def test_counter_render_help(): assert "# HELP" in Counter("sora_t","A test").render()
def test_counter_render_type(): assert "# TYPE" in Counter("sora_t","A test").render()
def test_counter_render_labels():
    c=Counter("sora_e","E",labels=["sev"]); c.inc(sev="CRITICAL")
    assert 'sev="CRITICAL"' in c.render()
def test_counter_render_zero(): assert "sora_e 0" in Counter("sora_e","E").render()
def test_gauge_starts_zero(): assert Gauge("t","h").get()==0.0
def test_gauge_set(): g=Gauge("t","h"); g.set(42.0); assert g.get()==42.0
def test_gauge_inc(): g=Gauge("t","h"); g.inc(3.0); assert g.get()==3.0
def test_gauge_dec(): g=Gauge("t","h"); g.set(10.0); g.dec(3.0); assert g.get()==7.0
def test_gauge_floors_zero(): g=Gauge("t","h"); g.dec(100.0); assert g.get()==0.0
def test_gauge_render(): g=Gauge("sora_a","A"); g.set(5.0); assert "sora_a 5.0" in g.render()
def test_metrics_render_string(): assert isinstance(SoraMetrics().render(), str)
def test_metrics_has_events(): assert "sora_events_ingested_total" in SoraMetrics().render()
def test_metrics_has_triage(): assert "sora_triage_verdicts_total" in SoraMetrics().render()
def test_metrics_has_uptime(): assert "sora_uptime_seconds" in SoraMetrics().render()
def test_metrics_has_requests(): assert "sora_api_requests_total" in SoraMetrics().render()
def test_metrics_uptime_nonzero():
    m=SoraMetrics(); time.sleep(0.05); output=m.render()
    val=float([l for l in output.split("\n") if l.startswith("sora_uptime_seconds ")][0].split()[-1])
    assert val > 0
def test_metrics_events_inc():
    m=SoraMetrics(); m.events_ingested.inc(severity="CRITICAL",category="INTRUSION")
    assert m.events_ingested.get(severity="CRITICAL",category="INTRUSION")==1.0
def test_metrics_rate_limit_hits():
    m=SoraMetrics(); m.rate_limit_hits.inc(); m.rate_limit_hits.inc()
    assert m.rate_limit_hits.get()==2.0
def test_metrics_endpoint_200(client): assert client.get("/metrics").status_code==200
def test_metrics_content_type(client): assert "text/plain" in client.get("/metrics").content_type
def test_metrics_has_help(client): assert b"# HELP" in client.get("/metrics").data
def test_metrics_tracks_requests(client):
    client.get("/health"); client.get("/api/v1/events")
    assert b"sora_api_requests_total" in client.get("/metrics").data
