from __future__ import annotations
import json, os
from sorabbyngo.storage.store import Store

try:
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
    from sqlalchemy import String, Boolean, DateTime, Text, select
    import sqlalchemy as sa
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

if HAS_SQLALCHEMY:
    class Base(DeclarativeBase): pass
    class EventRow(Base):
        __tablename__ = "security_events"
        id: Mapped[str] = mapped_column(String(36), primary_key=True)
        source: Mapped[str] = mapped_column(String(64))
        severity: Mapped[str] = mapped_column(String(16))
        category: Mapped[str] = mapped_column(String(32))
        title: Mapped[str] = mapped_column(String(256))
        description: Mapped[str] = mapped_column(Text)
        host: Mapped[str] = mapped_column(String(128))
        timestamp: Mapped[object] = mapped_column(DateTime(timezone=True))
        payload_json: Mapped[str] = mapped_column(Text, default="{}")
    class ReportRow(Base):
        __tablename__ = "incident_reports"
        id: Mapped[str] = mapped_column(String(36), primary_key=True)
        event_id: Mapped[str] = mapped_column(String(36))
        title: Mapped[str] = mapped_column(String(256))
        severity: Mapped[str] = mapped_column(String(16))
        summary: Mapped[str] = mapped_column(Text)
        payload_json: Mapped[str] = mapped_column(Text, default="{}")
        created_at: Mapped[object] = mapped_column(DateTime(timezone=True))
    class RecordRow(Base):
        __tablename__ = "execution_records"
        id: Mapped[str] = mapped_column(String(36), primary_key=True)
        report_id: Mapped[str] = mapped_column(String(36))
        action_type: Mapped[str] = mapped_column(String(32))
        target: Mapped[str] = mapped_column(String(256))
        status: Mapped[str] = mapped_column(String(16))
        dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
        payload_json: Mapped[str] = mapped_column(Text, default="{}")
        executed_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=True)

class PostgresStore:
    def __init__(self, engine): self._engine = engine

    @classmethod
    async def create(cls, db_url):
        if not HAS_SQLALCHEMY: raise RuntimeError("SQLAlchemy not installed")
        engine = create_async_engine(db_url, echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return cls(engine)

    async def save_event(self, event):
        from sorabbyngo.core.models import SecurityEvent
        async with AsyncSession(self._engine) as s:
            async with s.begin():
                await s.merge(EventRow(id=event.id, source=event.source,
                    severity=event.severity.value, category=event.category.value,
                    title=event.title, description=event.description,
                    host=event.host, timestamp=event.timestamp,
                    payload_json=json.dumps(event.model_dump(mode="json"))))

    async def get_event(self, event_id):
        from sorabbyngo.core.models import SecurityEvent
        async with AsyncSession(self._engine) as s:
            row = await s.get(EventRow, event_id)
            return SecurityEvent(**json.loads(row.payload_json)) if row else None

    async def list_events(self, limit=100):
        from sorabbyngo.core.models import SecurityEvent
        async with AsyncSession(self._engine) as s:
            result = await s.execute(select(EventRow).order_by(EventRow.timestamp.desc()).limit(limit))
            return [SecurityEvent(**json.loads(r.payload_json)) for r in result.scalars()]

    async def save_report(self, report):
        from sorabbyngo.core.models import IncidentReport
        async with AsyncSession(self._engine) as s:
            async with s.begin():
                await s.merge(ReportRow(id=report.id, event_id=report.event_id,
                    title=report.title, severity=report.severity.value,
                    summary=report.summary, created_at=report.created_at,
                    payload_json=json.dumps(report.model_dump(mode="json"))))

    async def get_report(self, report_id):
        from sorabbyngo.core.models import IncidentReport
        async with AsyncSession(self._engine) as s:
            row = await s.get(ReportRow, report_id)
            return IncidentReport(**json.loads(row.payload_json)) if row else None

    async def list_reports(self, limit=100):
        from sorabbyngo.core.models import IncidentReport
        async with AsyncSession(self._engine) as s:
            result = await s.execute(select(ReportRow).order_by(ReportRow.created_at.desc()).limit(limit))
            return [IncidentReport(**json.loads(r.payload_json)) for r in result.scalars()]

    async def save_record(self, record):
        async with AsyncSession(self._engine) as s:
            async with s.begin():
                await s.merge(RecordRow(id=record.id, report_id=record.report_id,
                    action_type=record.action_type.value, target=record.target,
                    status=record.status.value, dry_run=record.dry_run,
                    executed_at=record.executed_at,
                    payload_json=json.dumps(record.model_dump(mode="json"))))

    async def get_record(self, record_id):
        from sorabbyngo.core.models import ExecutionRecord
        async with AsyncSession(self._engine) as s:
            row = await s.get(RecordRow, record_id)
            return ExecutionRecord(**json.loads(row.payload_json)) if row else None

    async def list_records_for_report(self, report_id):
        from sorabbyngo.core.models import ExecutionRecord
        async with AsyncSession(self._engine) as s:
            result = await s.execute(select(RecordRow).where(RecordRow.report_id==report_id))
            return [ExecutionRecord(**json.loads(r.payload_json)) for r in result.scalars()]

    async def stats(self):
        async with AsyncSession(self._engine) as s:
            events = await s.scalar(select(sa.func.count()).select_from(EventRow))
            reports = await s.scalar(select(sa.func.count()).select_from(ReportRow))
            records = await s.scalar(select(sa.func.count()).select_from(RecordRow))
        return {"total_events": events or 0, "total_reports": reports or 0, "total_execution_records": records or 0}

def get_store(db_url=None):
    url = db_url or os.environ.get("SORABBYNGO_DB_URL")
    return url if url else Store()
