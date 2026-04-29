from __future__ import annotations
import time
from threading import Lock

class Counter:
    def __init__(self, name, help_text, labels=None):
        self.name = name; self.help_text = help_text
        self.labels = labels or []; self._values = {}; self._lock = Lock()
    def inc(self, amount=1.0, **label_values):
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock: self._values[key] = self._values.get(key, 0.0) + amount
    def render(self):
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} counter"]
        with self._lock:
            for key, value in self._values.items():
                label_str = ""
                if self.labels:
                    pairs = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, key))
                    label_str = f"{{{pairs}}}"
                lines.append(f"{self.name}{label_str} {value}")
            if not self._values: lines.append(f"{self.name} 0")
        return "\n".join(lines)
    def get(self, **label_values):
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock: return self._values.get(key, 0.0)

class Gauge:
    def __init__(self, name, help_text):
        self.name = name; self.help_text = help_text; self._value = 0.0; self._lock = Lock()
    def set(self, value):
        with self._lock: self._value = value
    def inc(self, amount=1.0):
        with self._lock: self._value += amount
    def dec(self, amount=1.0):
        with self._lock: self._value = max(0.0, self._value - amount)
    def render(self):
        with self._lock:
            return "\n".join([f"# HELP {self.name} {self.help_text}",
                              f"# TYPE {self.name} gauge", f"{self.name} {self._value}"])
    def get(self):
        with self._lock: return self._value

class SoraMetrics:
    def __init__(self):
        self.events_ingested = Counter("sora_events_ingested_total", "Total security events ingested", labels=["severity", "category"])
        self.events_deduplicated = Counter("sora_events_deduplicated_total", "Total duplicate events rejected")
        self.triage_verdicts = Counter("sora_triage_verdicts_total", "Triage verdicts issued", labels=["verdict"])
        self.reports_created = Counter("sora_reports_created_total", "Incident reports created", labels=["severity"])
        self.actions_executed = Counter("sora_actions_executed_total", "Response actions executed", labels=["action_type", "status"])
        self.alerts_fired = Counter("sora_alerts_fired_total", "Alerts fired by channel", labels=["channel", "success"])
        self.rate_limit_hits = Counter("sora_rate_limit_hits_total", "Rate limit rejections")
        self.api_requests = Counter("sora_api_requests_total", "Total API requests", labels=["method", "path", "status"])
        self.active_events = Gauge("sora_active_events", "Current number of stored events")
        self.active_reports = Gauge("sora_active_reports", "Current number of incident reports")
        self.uptime_seconds = Gauge("sora_uptime_seconds", "Seconds since platform started")
        self._start_time = time.monotonic()
    def render(self):
        self.uptime_seconds.set(time.monotonic() - self._start_time)
        metrics = [self.events_ingested, self.events_deduplicated, self.triage_verdicts,
                   self.reports_created, self.actions_executed, self.alerts_fired,
                   self.rate_limit_hits, self.api_requests, self.active_events,
                   self.active_reports, self.uptime_seconds]
        return "\n\n".join(m.render() for m in metrics) + "\n"

def register_metrics(app, metrics):
    from flask import request, Response
    @app.get("/metrics")
    def prometheus_metrics():
        return Response(metrics.render(), mimetype="text/plain; version=0.0.4")
    @app.after_request
    def _track_request(response):
        path = request.path
        for segment in ["events", "reports", "records", "keys"]:
            if f"/api/v1/{segment}/" in path:
                path = f"/api/v1/{segment}/:id"; break
        metrics.api_requests.inc(method=request.method, path=path, status=str(response.status_code))
        if response.status_code == 429: metrics.rate_limit_hits.inc()
        return response
