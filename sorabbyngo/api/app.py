"""
Module 6 — REST API
Flask application exposing all Sorabbyngo capabilities over HTTP.

Routes
------
GET  /health                          — Health check + system stats
POST /api/v1/events                   — Ingest a raw signal
GET  /api/v1/events                   — List events  (?limit=N&severity=X&category=Y)
GET  /api/v1/events/<id>              — Get event
POST /api/v1/events/<id>/triage       — Triage an event
GET  /api/v1/reports                  — List incident reports
GET  /api/v1/reports/<id>             — Get report
POST /api/v1/events/<id>/investigate  — Investigate event → IncidentReport
POST /api/v1/reports/<id>/execute     — Execute a report's response actions
POST /api/v1/records/<id>/approve     — Approve a pending action
POST /api/v1/records/<id>/rollback    — Roll back an executed action
GET  /api/v1/records                  — List execution records (?report_id=X)
"""
from __future__ import annotations

from flask import Flask, jsonify, request, Response
from flask_cors import CORS

from sorabbyngo.core.event_bus import EventBus
from sorabbyngo.core.models import RawSignal, Severity, EventCategory
from sorabbyngo.agents.triage import TriageAgent
from sorabbyngo.agents.investigation import InvestigationCrew
from sorabbyngo.agents.executor import ResponseExecutor
from sorabbyngo.storage.store import Store


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(
    dry_run: bool = False,
    testing: bool = False,
) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = testing
    CORS(app)

    # -- Shared singletons injected into app context
    bus = EventBus()
    triage_agent = TriageAgent()
    investigation_crew = InvestigationCrew()
    executor = ResponseExecutor(dry_run=dry_run)
    store = Store()

    # Store triage results in memory keyed by event_id
    _triage_results: dict[str, dict] = {}

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def _err(msg: str, code: int = 400) -> tuple[Response, int]:
        return jsonify({"error": msg}), code

    def _not_found(resource: str, id_: str) -> tuple[Response, int]:
        return _err(f"{resource} '{id_}' not found", 404)

    # -----------------------------------------------------------------------
    # Health
    # -----------------------------------------------------------------------
    @app.get("/health")
    def health() -> tuple[Response, int]:
        return jsonify({
            "status": "ok",
            "platform": "Sorabbyngo",
            "dry_run": dry_run,
            **store.stats(),
        }), 200

    # -----------------------------------------------------------------------
    # Events
    # -----------------------------------------------------------------------
    @app.post("/api/v1/events")
    def ingest_event() -> tuple[Response, int]:
        body = request.get_json(silent=True)
        if not body:
            return _err("Request body must be JSON")

        source = body.get("source")
        payload = body.get("payload")
        if not source or not isinstance(payload, dict):
            return _err("Fields 'source' (str) and 'payload' (object) are required")

        signal = RawSignal(source=source, payload=payload)
        event = bus.ingest(signal)

        if event is None:
            return jsonify({"duplicate": True, "message": "Event deduplicated — already seen"}), 200

        store.save_event(event)
        return jsonify(event.model_dump(mode="json")), 201

    @app.get("/api/v1/events")
    def list_events() -> tuple[Response, int]:
        limit = min(int(request.args.get("limit", 100)), 500)
        severity_str = request.args.get("severity")
        category_str = request.args.get("category")

        severity = None
        if severity_str:
            try:
                severity = Severity(severity_str.upper())
            except ValueError:
                return _err(f"Unknown severity '{severity_str}'")

        category = None
        if category_str:
            try:
                category = EventCategory(category_str.upper())
            except ValueError:
                return _err(f"Unknown category '{category_str}'")

        events = bus.get_events(severity=severity, category=category, limit=limit)
        return jsonify([e.model_dump(mode="json") for e in events]), 200

    @app.get("/api/v1/events/<event_id>")
    def get_event(event_id: str) -> tuple[Response, int]:
        event = bus.get_event_by_id(event_id)
        if not event:
            return _not_found("Event", event_id)
        return jsonify(event.model_dump(mode="json")), 200

    # -----------------------------------------------------------------------
    # Triage
    # -----------------------------------------------------------------------
    @app.post("/api/v1/events/<event_id>/triage")
    def triage_event(event_id: str) -> tuple[Response, int]:
        event = bus.get_event_by_id(event_id)
        if not event:
            return _not_found("Event", event_id)

        result = triage_agent.triage(event)
        _triage_results[event_id] = result.model_dump(mode="json")
        return jsonify(_triage_results[event_id]), 200

    # -----------------------------------------------------------------------
    # Investigation → IncidentReport
    # -----------------------------------------------------------------------
    @app.post("/api/v1/events/<event_id>/investigate")
    def investigate_event(event_id: str) -> tuple[Response, int]:
        event = bus.get_event_by_id(event_id)
        if not event:
            return _not_found("Event", event_id)

        # Auto-triage if not already done
        if event_id not in _triage_results:
            triage_result = triage_agent.triage(event)
            _triage_results[event_id] = triage_result.model_dump(mode="json")
        else:
            from sorabbyngo.core.models import TriageResult
            triage_result = TriageResult(**_triage_results[event_id])

        report = investigation_crew.investigate(event, triage_result)
        store.save_report(report)
        return jsonify(report.model_dump(mode="json")), 201

    # -----------------------------------------------------------------------
    # Incident Reports
    # -----------------------------------------------------------------------
    @app.get("/api/v1/reports")
    def list_reports() -> tuple[Response, int]:
        limit = min(int(request.args.get("limit", 100)), 500)
        reports = store.list_reports(limit=limit)
        return jsonify([r.model_dump(mode="json") for r in reports]), 200

    @app.get("/api/v1/reports/<report_id>")
    def get_report(report_id: str) -> tuple[Response, int]:
        report = store.get_report(report_id)
        if not report:
            return _not_found("Report", report_id)
        return jsonify(report.model_dump(mode="json")), 200

    # -----------------------------------------------------------------------
    # Execution
    # -----------------------------------------------------------------------
    @app.post("/api/v1/reports/<report_id>/execute")
    def execute_report(report_id: str) -> tuple[Response, int]:
        report = store.get_report(report_id)
        if not report:
            return _not_found("Report", report_id)

        records = executor.execute_report(report)
        for rec in records:
            store.save_record(rec)

        return jsonify([r.model_dump(mode="json") for r in records]), 200

    # -----------------------------------------------------------------------
    # Execution Records
    # -----------------------------------------------------------------------
    @app.get("/api/v1/records")
    def list_records() -> tuple[Response, int]:
        report_id = request.args.get("report_id")
        if report_id:
            records = store.list_records_for_report(report_id)
        else:
            records = executor.ledger
        return jsonify([r.model_dump(mode="json") for r in records]), 200

    @app.get("/api/v1/records/<record_id>")
    def get_record(record_id: str) -> tuple[Response, int]:
        record = store.get_record(record_id)
        if not record:
            return _not_found("Record", record_id)
        return jsonify(record.model_dump(mode="json")), 200

    @app.post("/api/v1/records/<record_id>/approve")
    def approve_record(record_id: str) -> tuple[Response, int]:
        record = store.get_record(record_id)
        if not record:
            return _not_found("Record", record_id)

        executor.gate.approve(record.action_id)

        # Re-execute the action now that it's approved
        report = store.get_report(record.report_id)
        if report:
            action = next((a for a in report.response_actions if a.id == record.action_id), None)
            if action:
                updated = executor._execute_action(record.report_id, action)
                updated.id = record.id  # keep same record ID
                store.save_record(updated)
                return jsonify(updated.model_dump(mode="json")), 200

        return jsonify({"approved": True, "record_id": record_id}), 200

    @app.post("/api/v1/records/<record_id>/rollback")
    def rollback_record(record_id: str) -> tuple[Response, int]:
        updated = executor.rollback(record_id)
        if not updated:
            return _err(f"Cannot rollback record '{record_id}' — not found or not in EXECUTED state", 400)
        store.save_record(updated)
        return jsonify(updated.model_dump(mode="json")), 200

    # -----------------------------------------------------------------------
    # 404 catch-all
    # -----------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found_handler(e):
        return jsonify({"error": "Route not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    return app
