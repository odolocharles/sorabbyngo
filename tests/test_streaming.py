import pytest, queue, time
from sorabbyngo.core.streaming import (
    StreamBroker, StreamClient, _sse_message,
    STREAM_EVENT_INGESTED, STREAM_EVENT_TRIAGED,
    STREAM_EVENT_INVESTIGATED, STREAM_EVENT_ALERT, STREAM_HEARTBEAT,
)
from sorabbyngo.core.models import SecurityEvent, Severity, EventCategory

def test_sse_has_event_field(): assert "event: test.event" in _sse_message("test.event", {})
def test_sse_has_data_field(): assert "data:" in _sse_message("test.event", {"k":"v"})
def test_sse_ends_double_newline(): assert _sse_message("t", {}).endswith("\n\n")
def test_sse_with_id(): assert "id: abc" in _sse_message("t", {}, id="abc")
def test_sse_without_id(): assert "id:" not in _sse_message("t", {})
def test_sse_data_is_json():
    import json; msg=_sse_message("t",{"count":42})
    data=[l for l in msg.split("\n") if l.startswith("data:")][0]
    assert json.loads(data[5:].strip())["count"]==42
def test_client_matches_no_filter():
    c=StreamClient("c1"); assert c.matches("CRITICAL") and c.matches("LOW") and c.matches(None)
def test_client_matches_filter():
    c=StreamClient("c1","CRITICAL"); assert c.matches("CRITICAL") and not c.matches("LOW")
def test_client_filter_case_insensitive():
    assert StreamClient("c1","critical").matches("CRITICAL")
def test_client_enqueue_success(): assert StreamClient("c1").enqueue("msg") is True
def test_client_enqueue_full():
    c=StreamClient("c1"); c.queue=queue.Queue(maxsize=1); c.enqueue("a")
    assert c.enqueue("b") is False
def test_client_to_dict():
    d=StreamClient("c1","HIGH").to_dict()
    assert d["client_id"]=="c1" and d["severity_filter"]=="HIGH" and "connected_at" in d
def test_client_starts_active(): assert StreamClient("c1").active is True
def test_client_messages_zero(): assert StreamClient("c1").messages_sent==0

@pytest.fixture
def broker():
    b=StreamBroker(heartbeat_interval=9999); yield b; b.stop()

def test_connect_returns_client(broker): assert isinstance(broker.connect("c1"), StreamClient)
def test_connect_increments_count(broker):
    broker.connect("c1"); broker.connect("c2"); assert broker.client_count()==2
def test_disconnect_removes(broker):
    broker.connect("c1"); broker.disconnect("c1"); assert broker.client_count()==0
def test_disconnect_nonexistent_ok(broker): broker.disconnect("x")
def test_connect_sends_welcome(broker):
    c=broker.connect("c1"); assert "connected" in c.queue.get_nowait()
def test_connect_with_filter(broker):
    assert broker.connect("c1","CRITICAL").severity_filter=="CRITICAL"
def test_broadcast_delivers(broker):
    c=broker.connect("c1"); c.queue.get_nowait()
    broker.broadcast("t",{"msg":"hi"}); assert "hi" in c.queue.get_nowait()
def test_broadcast_respects_filter(broker):
    ca=broker.connect("ca"); cc=broker.connect("cc","CRITICAL")
    ca.queue.get_nowait(); cc.queue.get_nowait()
    broker.broadcast("t",{},severity="LOW")
    assert not ca.queue.empty() and cc.queue.empty()
def test_broadcast_no_clients_zero(broker): assert broker.broadcast("t",{})==0
def test_broadcast_event(broker):
    c=broker.connect("c1"); c.queue.get_nowait()
    e=SecurityEvent(source="f",category=EventCategory.INTRUSION,severity=Severity.CRITICAL,
                   title="SSH",description="d",host="h")
    broker.broadcast_event(e); msg=c.queue.get_nowait()
    assert "SSH" in msg and STREAM_EVENT_INGESTED in msg
def test_broadcast_triage(broker):
    c=broker.connect("c1"); c.queue.get_nowait()
    broker.broadcast_triage("eid","IMMEDIATE_RESPONSE",1.0,"CRITICAL")
    assert STREAM_EVENT_TRIAGED in c.queue.get_nowait()
def test_broadcast_alert(broker):
    c=broker.connect("c1"); c.queue.get_nowait()
    broker.broadcast_alert("slack","CRITICAL","SSH Attack")
    assert STREAM_EVENT_ALERT in c.queue.get_nowait()
def test_broadcast_report(broker):
    from sorabbyngo.agents.triage import TriageAgent
    from sorabbyngo.agents.investigation import InvestigationCrew
    e=SecurityEvent(source="f",category=EventCategory.INTRUSION,severity=Severity.HIGH,title="T",description="D",host="h")
    r=InvestigationCrew().investigate(e,TriageAgent().triage(e))
    c=broker.connect("c1"); c.queue.get_nowait()
    broker.broadcast_report(r); assert STREAM_EVENT_INVESTIGATED in c.queue.get_nowait()
def test_stats_fields(broker):
    s=broker.stats()
    assert "connected_clients" in s and "total_messages_broadcast" in s and "clients" in s
def test_stats_client_count(broker):
    broker.connect("c1"); broker.connect("c2"); assert broker.stats()["connected_clients"]==2
def test_stats_empty(broker):
    s=broker.stats(); assert s["connected_clients"]==0 and s["clients"]==[]
def test_stream_stats_endpoint(client):
    r=client.get("/api/v1/stream/stats")
    assert r.status_code==200 and "connected_clients" in r.get_json()
def test_stream_stats_zero(client):
    assert client.get("/api/v1/stream/stats").get_json()["connected_clients"]==0
def test_stream_stats_int(client):
    assert isinstance(client.get("/api/v1/stream/stats").get_json()["total_messages_broadcast"],int)
def test_stream_route_registered(client):
    assert client.get("/api/v1/stream/stats").status_code==200
