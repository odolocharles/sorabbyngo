import pytest
from unittest.mock import patch, MagicMock
from sorabbyngo.cli import build_parser, SoraClient, CLIError, main, _print_table

def test_parser_health(): assert build_parser().parse_args(["health"]).command == "health"
def test_parser_events_default_limit(): assert build_parser().parse_args(["events"]).limit == 20
def test_parser_events_custom_limit(): assert build_parser().parse_args(["events","--limit","50"]).limit == 50
def test_parser_severity_filter(): assert build_parser().parse_args(["events","--severity","CRITICAL"]).severity == "CRITICAL"
def test_parser_ingest_args():
    a = build_parser().parse_args(["ingest","--title","T","--host","h"])
    assert a.title=="T" and a.host=="h"
def test_parser_ingest_defaults():
    a = build_parser().parse_args(["ingest","--title","T","--host","h"])
    assert a.severity=="MEDIUM" and a.source=="cli"
def test_parser_triage_event_id(): assert build_parser().parse_args(["triage","eid"]).event_id=="eid"
def test_parser_investigate_execute(): assert build_parser().parse_args(["investigate","eid","--execute"]).execute is True
def test_parser_keys_create():
    a = build_parser().parse_args(["keys","--create","k","--scopes","read,write"])
    assert a.create=="k" and a.scopes=="read,write"
def test_parser_json_flag(): assert build_parser().parse_args(["--json","health"]).json is True
def test_parser_custom_url(): assert build_parser().parse_args(["--url","http://x:9000","health"]).url=="http://x:9000"
def test_client_default_key(): assert SoraClient("http://x").api_key=="sora_dev_key_insecure_change_me"
def test_client_custom_key(): assert SoraClient("http://x",api_key="k").api_key=="k"
def test_client_http_error():
    import urllib.error
    with patch("urllib.request.urlopen") as m:
        m.side_effect = urllib.error.HTTPError("",404,"NF",None,MagicMock(read=lambda:b'{"error":"nf"}'))
        with pytest.raises(CLIError): SoraClient("http://x").get("/")
def test_client_url_error():
    import urllib.error
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        with pytest.raises(CLIError): SoraClient("http://x:9999").get("/health")
def test_print_table_empty(capsys): _print_table([],"id title".split()); assert "no results" in capsys.readouterr().out
def test_print_table_data(capsys):
    _print_table([{"id":"abc","title":"T"}],["id","title"]); o=capsys.readouterr().out
    assert "abc" in o and "T" in o
def test_cmd_health(capsys):
    from sorabbyngo.cli import cmd_health
    c=MagicMock(); c.get.return_value={"status":"ok","platform":"Sorabbyngo","total_events":5,"total_reports":2,"total_execution_records":10,"dry_run":True}
    cmd_health(c, build_parser().parse_args(["health"])); o=capsys.readouterr().out
    assert "OK" in o and "Sorabbyngo" in o
def test_cmd_events(capsys):
    from sorabbyngo.cli import cmd_events
    c=MagicMock(); c.get.return_value=[{"id":"abc","severity":"HIGH","category":"INTRUSION","title":"SSH","host":"h"}]
    cmd_events(c, build_parser().parse_args(["events"])); assert "SSH" in capsys.readouterr().out
def test_cmd_ingest_success(capsys):
    from sorabbyngo.cli import cmd_ingest
    c=MagicMock(); c.post.return_value={"id":"new-id"}
    cmd_ingest(c, build_parser().parse_args(["ingest","--title","T","--host","h","--severity","HIGH","--category","INTRUSION"]))
    assert "new-id" in capsys.readouterr().out
def test_cmd_ingest_duplicate(capsys):
    from sorabbyngo.cli import cmd_ingest
    c=MagicMock(); c.post.return_value={"duplicate":True}
    cmd_ingest(c, build_parser().parse_args(["ingest","--title","T","--host","h"]))
    assert "Duplicate" in capsys.readouterr().out
def test_cmd_dashboard(capsys):
    from sorabbyngo.cli import cmd_dashboard
    c=MagicMock(); c.base_url="http://localhost:8002"
    cmd_dashboard(c, build_parser().parse_args(["dashboard"])); o=capsys.readouterr().out
    assert "dashboard" in o and "8002" in o
def test_main_success():
    with patch("sorabbyngo.cli.SoraClient") as M:
        M.return_value.get.return_value={"status":"ok","platform":"Sorabbyngo","total_events":0,"total_reports":0,"total_execution_records":0,"dry_run":True}
        assert main(["health"])==0
def test_main_error():
    with patch("sorabbyngo.cli.SoraClient") as M:
        M.return_value.get.side_effect=CLIError("refused")
        assert main(["health"])==1
