from __future__ import annotations
import uuid
from flask import Flask, jsonify, request, g, Response
from flask_cors import CORS
from sorabbyngo.core.event_bus import EventBus
from sorabbyngo.core.models import RawSignal, Severity, EventCategory
from sorabbyngo.agents.triage import TriageAgent
from sorabbyngo.agents.investigation import InvestigationCrew
from sorabbyngo.agents.executor import ResponseExecutor
from sorabbyngo.storage.store import Store
from sorabbyngo.auth.keys import ApiKeyStore, require_scope
from sorabbyngo.core.rate_limiter import RateLimiter, register_rate_limiter
from sorabbyngo.core.metrics import SoraMetrics
from sorabbyngo.core.streaming import StreamBroker, register_stream
from sorabbyngo.plugins import PluginRegistry

def create_app(dry_run=False, testing=False, require_auth=True):
    app = Flask(f"{__name__}.{uuid.uuid4().hex[:8]}")
    app.config["TESTING"] = testing
    CORS(app)
    bus = EventBus()
    triage_agent = TriageAgent()
    investigation_crew = InvestigationCrew()
    executor = ResponseExecutor(dry_run=dry_run)
    store = Store()
    key_store = ApiKeyStore()
    key_store.seed_default()
    rate_limiter = RateLimiter()
    metrics = SoraMetrics()
    broker = StreamBroker()
    plugin_registry = PluginRegistry()
    register_stream(app, broker)
    _triage_results = {}

    if not testing:
        register_rate_limiter(app, rate_limiter)

    @app.before_request
    def _inject():
        g.key_store = key_store

    def _auth(scope):
        if not require_auth or testing:
            return lambda fn: fn
        return require_scope(scope)

    def _err(msg, code=400): return jsonify({"error": msg}), code
    def _404(r, i): return _err(f"{r} '{i}' not found", 404)

    @app.get("/health")
    def health():
        return jsonify({"status":"ok","platform":"Sorabbyngo","dry_run":dry_run,**store.stats()}), 200

    @app.get("/metrics")
    def prometheus_metrics():
        return Response(metrics.render(), mimetype="text/plain; version=0.0.4")

    @app.post("/api/v1/keys")
    @_auth("admin")
    def create_key():
        body = request.get_json(silent=True) or {}
        name = body.get("name")
        scopes = body.get("scopes", ["read"])
        if not name: return _err("Field 'name' is required")
        if not all(s in {"read","write","admin"} for s in scopes):
            return _err("Valid scopes: read, write, admin")
        key = key_store.create(name=name, scopes=scopes)
        return jsonify(key.to_dict(reveal=True)), 201

    @app.get("/api/v1/keys")
    @_auth("admin")
    def list_keys():
        return jsonify([k.to_dict() for k in key_store.list_keys()]), 200

    @app.post("/api/v1/keys/<name>/revoke")
    @_auth("admin")
    def revoke_key(name):
        if not key_store.revoke(name): return _err(f"Key '{name}' not found", 404)
        return jsonify({"revoked":True,"name":name}), 200

    @app.post("/api/v1/events")
    @_auth("write")
    def ingest_event():
        body = request.get_json(silent=True)
        if not body: return _err("Request body must be JSON")
        source = body.get("source")
        payload = body.get("payload")
        if not source or not isinstance(payload, dict):
            return _err("Fields 'source' (str) and 'payload' (object) are required")
        event = bus.ingest(RawSignal(source=source, payload=payload))
        if event is None:
            return jsonify({"duplicate":True,"message":"Event deduplicated"}), 200
        store.save_event(event)
        broker.broadcast_event(event)
        return jsonify(event.model_dump(mode="json")), 201

    @app.get("/api/v1/events")
    @_auth("read")
    def list_events():
        limit = min(int(request.args.get("limit",100)), 500)
        sev = cat = None
        if s := request.args.get("severity"):
            try: sev = Severity(s.upper())
            except ValueError: return _err(f"Unknown severity '{s}'")
        if c := request.args.get("category"):
            try: cat = EventCategory(c.upper())
            except ValueError: return _err(f"Unknown category '{c}'")
        return jsonify([e.model_dump(mode="json") for e in bus.get_events(sev,cat,limit)]), 200

    @app.get("/api/v1/events/<event_id>")
    @_auth("read")
    def get_event(event_id):
        e = bus.get_event_by_id(event_id)
        return (jsonify(e.model_dump(mode="json")), 200) if e else _404("Event", event_id)

    @app.post("/api/v1/events/<event_id>/triage")
    @_auth("write")
    def triage_event(event_id):
        e = bus.get_event_by_id(event_id)
        if not e: return _404("Event", event_id)
        result = triage_agent.triage(e)
        _triage_results[event_id] = result.model_dump(mode="json")
        return jsonify(_triage_results[event_id]), 200

    @app.post("/api/v1/events/<event_id>/investigate")
    @_auth("write")
    def investigate_event(event_id):
        e = bus.get_event_by_id(event_id)
        if not e: return _404("Event", event_id)
        if event_id not in _triage_results:
            tr = triage_agent.triage(e)
            _triage_results[event_id] = tr.model_dump(mode="json")
        else:
            from sorabbyngo.core.models import TriageResult
            tr = TriageResult(**_triage_results[event_id])
        report = investigation_crew.investigate(e, tr)
        store.save_report(report)
        return jsonify(report.model_dump(mode="json")), 201

    @app.get("/api/v1/reports")
    @_auth("read")
    def list_reports():
        limit = min(int(request.args.get("limit",100)), 500)
        return jsonify([r.model_dump(mode="json") for r in store.list_reports(limit)]), 200

    @app.get("/api/v1/reports/<report_id>")
    @_auth("read")
    def get_report(report_id):
        r = store.get_report(report_id)
        return (jsonify(r.model_dump(mode="json")), 200) if r else _404("Report", report_id)

    @app.post("/api/v1/reports/<report_id>/execute")
    @_auth("write")
    def execute_report(report_id):
        r = store.get_report(report_id)
        if not r: return _404("Report", report_id)
        records = executor.execute_report(r)
        for rec in records: store.save_record(rec)
        return jsonify([rec.model_dump(mode="json") for rec in records]), 200

    @app.get("/api/v1/records")
    @_auth("read")
    def list_records():
        rid = request.args.get("report_id")
        recs = store.list_records_for_report(rid) if rid else executor.ledger
        return jsonify([r.model_dump(mode="json") for r in recs]), 200

    @app.get("/api/v1/records/<record_id>")
    @_auth("read")
    def get_record(record_id):
        r = store.get_record(record_id)
        return (jsonify(r.model_dump(mode="json")), 200) if r else _404("Record", record_id)

    @app.post("/api/v1/records/<record_id>/approve")
    @_auth("write")
    def approve_record(record_id):
        rec = store.get_record(record_id)
        if not rec: return _404("Record", record_id)
        executor.gate.approve(rec.action_id)
        report = store.get_report(rec.report_id)
        if report:
            action = next((a for a in report.response_actions if a.id == rec.action_id), None)
            if action:
                updated = executor._execute_action(rec.report_id, action)
                updated.id = rec.id
                store.save_record(updated)
                return jsonify(updated.model_dump(mode="json")), 200
        return jsonify({"approved":True,"record_id":record_id}), 200

    @app.post("/api/v1/records/<record_id>/rollback")
    @_auth("write")
    def rollback_record(record_id):
        updated = executor.rollback(record_id)
        if not updated: return _err(f"Cannot rollback '{record_id}'", 400)
        store.save_record(updated)
        return jsonify(updated.model_dump(mode="json")), 200

    @app.get("/api/v1/rate-limits")
    @_auth("admin")
    def rate_limit_stats():
        return jsonify(rate_limiter.stats()), 200

    @app.get("/dashboard")
    def dashboard():
        stats = store.stats()
        events = bus.get_events(limit=10)
        reports = store.list_reports(limit=5)
        event_rows = "".join(
            f'<tr><td class="{e.severity.value}">{e.severity.value}</td><td>{e.category.value}</td><td>{e.title}</td><td>{e.host}</td><td>{e.timestamp.strftime("%H:%M:%S")}</td></tr>'
            for e in reversed(events)
        ) or '<tr><td colspan="5" class="empty">No events yet</td></tr>'
        report_rows = "".join(
            f'<tr><td class="{r.severity.value}">{r.severity.value}</td><td>{r.title}</td><td>{len(r.response_actions)}</td><td>{r.created_at.strftime("%H:%M:%S")}</td></tr>'
            for r in reversed(reports)
        ) or '<tr><td colspan="4" class="empty">No reports yet</td></tr>'
        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="10"><title>Sorabbyngo Dashboard</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9}}
header{{background:#161b22;padding:20px 32px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:12px}}
header h1{{font-size:1.4rem;color:#58a6ff}}header span{{font-size:.8rem;color:#8b949e}}
.stats{{display:flex;gap:16px;padding:24px 32px;flex-wrap:wrap}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px 28px;min-width:150px;flex:1}}
.card .num{{font-size:2.4rem;font-weight:700;color:#58a6ff}}.card .lbl{{font-size:.8rem;color:#8b949e;margin-top:4px}}
section{{padding:0 32px 32px}}section h2{{font-size:.85rem;color:#8b949e;margin-bottom:12px;text-transform:uppercase;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}}
th{{background:#21262d;color:#8b949e;font-size:.75rem;text-transform:uppercase;padding:10px 14px;text-align:left}}
td{{padding:10px 14px;border-top:1px solid #30363d;font-size:.875rem}}tr:hover td{{background:#1c2128}}
.CRITICAL{{color:#ff7b72;font-weight:600}}.HIGH{{color:#ffa657;font-weight:600}}.MEDIUM{{color:#e3b341}}.LOW{{color:#58a6ff}}.INFO{{color:#8b949e}}
.empty{{color:#8b949e;text-align:center;padding:20px}}footer{{padding:16px 32px;color:#8b949e;font-size:.75rem;border-top:1px solid #30363d}}
</style></head><body>
<header><h1>⚡ Sorabbyngo</h1><span>Enterprise AI Security Platform · auto-refreshes every 10s</span></header>
<div class="stats">
<div class="card"><div class="num">{stats['total_events']}</div><div class="lbl">Total Events</div></div>
<div class="card"><div class="num">{stats['total_reports']}</div><div class="lbl">Incident Reports</div></div>
<div class="card"><div class="num">{stats['total_execution_records']}</div><div class="lbl">Actions Executed</div></div>
<div class="card"><div class="num">{'LIVE' if not dry_run else 'DRY'}</div><div class="lbl">Execution Mode</div></div>
</div>
<section><h2>Recent Events</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Host</th><th>Time</th></tr></thead>
<tbody>{event_rows}</tbody></table></section>
<section><h2>Recent Incident Reports</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Actions</th><th>Time</th></tr></thead>
<tbody>{report_rows}</tbody></table></section>
<footer>Sorabbyngo v0.13.0 · <a href="/health" style="color:#58a6ff">/health</a> · <a href="/metrics" style="color:#58a6ff">/metrics</a></footer>
</body></html>"""
        return html, 200, {"Content-Type": "text/html"}


    @app.get("/api/v1/plugins")
    @_auth("admin")
    def list_plugins():
        return jsonify(plugin_registry.stats()), 200

    @app.post("/api/v1/plugins/<name>/enable")
    @_auth("admin")
    def enable_plugin(name):
        if not plugin_registry.enable(name): return _err(f"Plugin '{name}' not found", 404)
        return jsonify({"enabled": True, "name": name}), 200

    @app.post("/api/v1/plugins/<name>/disable")
    @_auth("admin")
    def disable_plugin(name):
        if not plugin_registry.disable(name): return _err(f"Plugin '{name}' not found", 404)
        return jsonify({"enabled": False, "name": name}), 200

    @app.delete("/api/v1/plugins/<name>")
    @_auth("admin")
    def unregister_plugin(name):
        if not plugin_registry.unregister(name): return _err(f"Plugin '{name}' not found", 404)
        return jsonify({"unregistered": True, "name": name}), 200

    @app.errorhandler(404)
    def not_found(e): return jsonify({"error":"Route not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e): return jsonify({"error":"Method not allowed"}), 405

    return app
