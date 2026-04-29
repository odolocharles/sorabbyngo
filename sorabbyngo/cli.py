from __future__ import annotations
import argparse, json, os, sys, urllib.request, urllib.error
from typing import Any

class SoraClient:
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("SORA_API_KEY", "sora_dev_key_insecure_change_me")
    def _request(self, method, path, body=None):
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body else None
        headers = {"Content-Type": "application/json", "X-API-Key": self.api_key}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read())
            raise CLIError(f"HTTP {e.code}: {body.get('error', str(body))}")
        except urllib.error.URLError as e:
            raise CLIError(f"Cannot reach {self.base_url}: {e.reason}")
    def get(self, path): return self._request("GET", path)
    def post(self, path, body=None): return self._request("POST", path, body)

class CLIError(Exception): pass

def _print_json(data): print(json.dumps(data, indent=2, default=str))

def _print_table(rows, columns):
    if not rows: print("  (no results)"); return
    widths = {col: max(len(col), max(len(str(r.get(col, ""))) for r in rows)) for col in columns}
    header = "  ".join(col.upper().ljust(widths[col]) for col in columns)
    print(header); print("-" * len(header))
    for row in rows:
        print("  ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns))

def cmd_health(client, args):
    data = client.get("/health")
    print(f"Status:  {data.get('status','?').upper()}")
    print(f"Platform: {data.get('platform','?')}")
    print(f"Events:  {data.get('total_events',0)}")
    print(f"Reports: {data.get('total_reports',0)}")
    print(f"Records: {data.get('total_execution_records',0)}")
    print(f"Dry-run: {data.get('dry_run',False)}")

def cmd_events(client, args):
    path = f"/api/v1/events?limit={args.limit}"
    if args.severity: path += f"&severity={args.severity}"
    if args.category: path += f"&category={args.category}"
    events = client.get(path)
    if args.json: _print_json(events)
    else: _print_table(events, ["id","severity","category","title","host"])

def cmd_ingest(client, args):
    payload = {"severity": args.severity, "category": args.category,
               "title": args.title, "description": args.description or args.title, "host": args.host}
    if args.process: payload["process"] = args.process
    if args.user: payload["user"] = args.user
    result = client.post("/api/v1/events", {"source": args.source, "payload": payload})
    if result.get("duplicate"): print("⚠  Duplicate event — already seen.")
    else:
        print(f"✅ Event ingested: {result['id']}")
        if args.triage:
            tr = client.post(f"/api/v1/events/{result['id']}/triage")
            print(f"   Score: {tr['score']:.2f} | Verdict: {tr['verdict']}")

def cmd_triage(client, args):
    result = client.post(f"/api/v1/events/{args.event_id}/triage")
    if args.json: _print_json(result)
    else:
        print(f"Score:   {result['score']:.4f}")
        print(f"Verdict: {result['verdict']}")
        print(f"MITRE:   {', '.join(result['mitre_techniques']) or 'None'}")

def cmd_investigate(client, args):
    result = client.post(f"/api/v1/events/{args.event_id}/investigate")
    if args.json: _print_json(result)
    else:
        print(f"Report ID: {result['id']}")
        print(f"Title:     {result['title']}")
        print(f"Actions:   {len(result['response_actions'])}")
        if args.execute:
            records = client.post(f"/api/v1/reports/{result['id']}/execute")
            for r in records:
                icon = "✅" if r["status"]=="EXECUTED" else "⏳" if r["status"]=="PENDING" else "⏭"
                print(f"  {icon} [{r['status']}] {r['action_type']} → {r['target']}")

def cmd_reports(client, args):
    reports = client.get(f"/api/v1/reports?limit={args.limit}")
    if args.json: _print_json(reports)
    else: _print_table(reports, ["id","severity","title","event_id"])

def cmd_execute(client, args):
    records = client.post(f"/api/v1/reports/{args.report_id}/execute")
    if args.json: _print_json(records)
    else:
        for r in records:
            icon = "✅" if r["status"]=="EXECUTED" else "⏳" if r["status"]=="PENDING" else "⏭"
            print(f"  {icon} [{r['status']}] {r['action_type']} → {r['target']}")

def cmd_approve(client, args):
    result = client.post(f"/api/v1/records/{args.record_id}/approve")
    if args.json: _print_json(result)
    else: print(f"✅ Record {args.record_id}: {result.get('status','approved')}")

def cmd_records(client, args):
    path = "/api/v1/records"
    if args.report_id: path += f"?report_id={args.report_id}"
    records = client.get(path)
    if args.json: _print_json(records)
    else: _print_table(records, ["id","action_type","target","status"])

def cmd_keys(client, args):
    if args.create:
        scopes = args.scopes.split(",") if args.scopes else ["read"]
        result = client.post("/api/v1/keys", {"name": args.create, "scopes": scopes})
        print(f"✅ Key created: {result['key']}")
    elif args.revoke:
        client.post(f"/api/v1/keys/{args.revoke}/revoke")
        print(f"✅ Key '{args.revoke}' revoked.")
    else:
        keys = client.get("/api/v1/keys")
        _print_table(keys, ["name","scopes","enabled","last_used"])

def cmd_dashboard(client, args):
    print(f"Dashboard: {client.base_url}/dashboard")
    print(f"Health:    {client.base_url}/health")

def build_parser():
    parser = argparse.ArgumentParser(prog="sora", description="Sorabbyngo CLI")
    parser.add_argument("--url", default=os.environ.get("SORA_URL","http://localhost:8002"))
    parser.add_argument("--key", default=None)
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health"); sub.add_parser("dashboard")
    p = sub.add_parser("events"); p.add_argument("--limit",type=int,default=20); p.add_argument("--severity"); p.add_argument("--category")
    p = sub.add_parser("ingest"); p.add_argument("--source",default="cli"); p.add_argument("--severity",default="MEDIUM")
    p.add_argument("--category",default="ANOMALY"); p.add_argument("--title",required=True); p.add_argument("--description")
    p.add_argument("--host",required=True); p.add_argument("--process"); p.add_argument("--user"); p.add_argument("--triage",action="store_true")
    sub.add_parser("triage").add_argument("event_id")
    p = sub.add_parser("investigate"); p.add_argument("event_id"); p.add_argument("--execute",action="store_true")
    p = sub.add_parser("reports"); p.add_argument("--limit",type=int,default=20)
    sub.add_parser("execute").add_argument("report_id")
    sub.add_parser("approve").add_argument("record_id")
    p = sub.add_parser("records"); p.add_argument("--report-id",dest="report_id")
    p = sub.add_parser("keys"); p.add_argument("--create",metavar="NAME"); p.add_argument("--scopes",default="read"); p.add_argument("--revoke",metavar="NAME")
    return parser

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    client = SoraClient(base_url=args.url, api_key=args.key)
    handlers = {"health":cmd_health,"dashboard":cmd_dashboard,"events":cmd_events,
                "ingest":cmd_ingest,"triage":cmd_triage,"investigate":cmd_investigate,
                "reports":cmd_reports,"execute":cmd_execute,"approve":cmd_approve,
                "records":cmd_records,"keys":cmd_keys}
    try: handlers[args.command](client, args); return 0
    except CLIError as e: print(f"Error: {e}", file=sys.stderr); return 1

if __name__ == "__main__":
    sys.exit(main())
