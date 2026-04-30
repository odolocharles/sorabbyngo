from __future__ import annotations
import json, queue, threading, uuid
from datetime import datetime, timezone
from typing import Any

STREAM_EVENT_INGESTED    = "event.ingested"
STREAM_EVENT_TRIAGED     = "event.triaged"
STREAM_EVENT_INVESTIGATED = "event.investigated"
STREAM_EVENT_EXECUTED    = "action.executed"
STREAM_EVENT_ALERT       = "alert.fired"
STREAM_HEARTBEAT         = "heartbeat"

def _sse_message(event_type, data, id=None):
    payload = json.dumps(data, default=str)
    lines = []
    if id: lines.append(f"id: {id}")
    lines.append(f"event: {event_type}")
    lines.append(f"data: {payload}")
    lines.append("")
    return "\n".join(lines) + "\n"

class StreamClient:
    def __init__(self, client_id, severity_filter=None):
        self.client_id = client_id
        self.severity_filter = severity_filter.upper() if severity_filter else None
        self.queue = queue.Queue(maxsize=100)
        self.connected_at = datetime.now(timezone.utc)
        self.messages_sent = 0
        self.active = True
    def matches(self, severity):
        if self.severity_filter is None: return True
        return severity == self.severity_filter
    def enqueue(self, message):
        try: self.queue.put_nowait(message); return True
        except queue.Full: return False
    def to_dict(self):
        return {"client_id": self.client_id, "severity_filter": self.severity_filter,
                "connected_at": self.connected_at.isoformat(),
                "messages_sent": self.messages_sent, "active": self.active}

class StreamBroker:
    def __init__(self, heartbeat_interval=15):
        self._clients = {}; self._lock = threading.Lock()
        self._message_count = 0; self._heartbeat_interval = heartbeat_interval
        self._running = False
    def start(self):
        self._running = True
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
    def stop(self): self._running = False
    def _heartbeat_loop(self):
        import time
        while self._running:
            time.sleep(self._heartbeat_interval)
            self.broadcast(STREAM_HEARTBEAT, {"ts": datetime.now(timezone.utc).isoformat()})
    def connect(self, client_id, severity_filter=None):
        client = StreamClient(client_id=client_id, severity_filter=severity_filter)
        with self._lock: self._clients[client_id] = client
        client.enqueue(_sse_message("connected", {"client_id": client_id, "filter": severity_filter,
                                                   "ts": datetime.now(timezone.utc).isoformat()}))
        return client
    def disconnect(self, client_id):
        with self._lock:
            client = self._clients.pop(client_id, None)
            if client: client.active = False
    def client_count(self):
        with self._lock: return len(self._clients)
    def broadcast(self, event_type, data, severity=None, message_id=None):
        message = _sse_message(event_type, data, id=message_id)
        delivered = 0
        with self._lock:
            dead = []
            for cid, client in self._clients.items():
                if not client.active: dead.append(cid); continue
                if client.matches(severity):
                    if client.enqueue(message): client.messages_sent += 1; delivered += 1
            for cid in dead: self._clients.pop(cid, None)
        self._message_count += 1
        return delivered
    def broadcast_event(self, event):
        return self.broadcast(STREAM_EVENT_INGESTED,
            {"id": event.id, "title": event.title, "severity": event.severity.value,
             "category": event.category.value, "host": event.host, "source": event.source,
             "timestamp": event.timestamp.isoformat()},
            severity=event.severity.value, message_id=event.id)
    def broadcast_triage(self, event_id, verdict, score, severity):
        return self.broadcast(STREAM_EVENT_TRIAGED,
            {"event_id": event_id, "verdict": verdict, "score": score}, severity=severity)
    def broadcast_report(self, report):
        return self.broadcast(STREAM_EVENT_INVESTIGATED,
            {"id": report.id, "event_id": report.event_id, "title": report.title,
             "severity": report.severity.value, "action_count": len(report.response_actions)},
            severity=report.severity.value, message_id=report.id)
    def broadcast_alert(self, channel, severity, title):
        return self.broadcast(STREAM_EVENT_ALERT,
            {"channel": channel, "severity": severity, "title": title,
             "ts": datetime.now(timezone.utc).isoformat()}, severity=severity)
    def stats(self):
        with self._lock: clients = [c.to_dict() for c in self._clients.values()]
        return {"connected_clients": len(clients),
                "total_messages_broadcast": self._message_count,
                "clients": clients,
                "heartbeat_interval_seconds": self._heartbeat_interval}

def register_stream(app, broker):
    import uuid as _uuid
    from flask import request, Response, jsonify
    broker.start()

    @app.get("/stream")
    def sse_stream():
        severity_filter = request.args.get("severity")
        client_id = str(_uuid.uuid4())
        client = broker.connect(client_id, severity_filter)
        def generate():
            try:
                while client.active:
                    try: yield client.queue.get(timeout=1.0)
                    except queue.Empty: yield ": keepalive\n\n"
            finally: broker.disconnect(client_id)
        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Connection":"keep-alive"})

    @app.get("/api/v1/stream/stats")
    def stream_stats():
        return jsonify(broker.stats()), 200
