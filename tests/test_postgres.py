import pytest
import pytest_asyncio
from sorabbyngo.storage.postgres import PostgresStore, HAS_SQLALCHEMY
from sorabbyngo.core.models import SecurityEvent, Severity, EventCategory
from sorabbyngo.agents.triage import TriageAgent
from sorabbyngo.agents.investigation import InvestigationCrew

pytestmark = pytest.mark.asyncio

def _event(host="h",severity=Severity.HIGH,category=EventCategory.INTRUSION):
    return SecurityEvent(source="falco",category=category,severity=severity,
                        title="Test",description="Desc",host=host,process="sshd",user="root")

def _report(event=None):
    e=event or _event(); tr=TriageAgent().triage(e); return InvestigationCrew().investigate(e,tr)

@pytest_asyncio.fixture
async def pg():
    if not HAS_SQLALCHEMY: pytest.skip("SQLAlchemy not installed")
    return await PostgresStore.create("sqlite+aiosqlite:///:memory:")

async def test_save_get_event(pg):
    e=_event(); await pg.save_event(e); f=await pg.get_event(e.id)
    assert f is not None and f.id==e.id
async def test_get_missing_event(pg): assert await pg.get_event("x") is None
async def test_list_events(pg):
    await pg.save_event(_event("a")); await pg.save_event(_event("b"))
    assert len(await pg.list_events())==2
async def test_list_events_limit(pg):
    for i in range(5): await pg.save_event(_event(f"h{i}"))
    assert len(await pg.list_events(limit=3))==3
async def test_save_event_idempotent(pg):
    e=_event(); await pg.save_event(e); await pg.save_event(e)
    assert len(await pg.list_events())==1
async def test_event_severity_preserved(pg):
    e=_event(severity=Severity.CRITICAL); await pg.save_event(e)
    assert (await pg.get_event(e.id)).severity==Severity.CRITICAL
async def test_save_get_report(pg):
    r=_report(); await pg.save_report(r); f=await pg.get_report(r.id)
    assert f is not None and f.id==r.id
async def test_get_missing_report(pg): assert await pg.get_report("x") is None
async def test_list_reports(pg):
    await pg.save_report(_report(_event("a"))); await pg.save_report(_report(_event("b")))
    assert len(await pg.list_reports())==2
async def test_report_actions_preserved(pg):
    r=_report(_event(severity=Severity.CRITICAL)); await pg.save_report(r)
    f=await pg.get_report(r.id); assert len(f.response_actions)==len(r.response_actions)
async def test_save_get_record(pg):
    from sorabbyngo.agents.executor import ResponseExecutor
    r=_report(); await pg.save_report(r)
    rec=ResponseExecutor(dry_run=True).execute_report(r)[0]
    await pg.save_record(rec); f=await pg.get_record(rec.id)
    assert f is not None and f.id==rec.id
async def test_list_records_for_report(pg):
    from sorabbyngo.agents.executor import ResponseExecutor
    r=_report(); await pg.save_report(r)
    recs=ResponseExecutor(dry_run=True).execute_report(r)
    for rec in recs: await pg.save_record(rec)
    assert len(await pg.list_records_for_report(r.id))==len(recs)
async def test_stats_empty(pg):
    s=await pg.stats(); assert s["total_events"]==0 and s["total_reports"]==0
async def test_stats_counts(pg):
    await pg.save_event(_event()); await pg.save_report(_report())
    s=await pg.stats(); assert s["total_events"]==1 and s["total_reports"]==1
