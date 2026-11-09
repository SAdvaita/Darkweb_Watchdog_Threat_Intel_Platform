"""
Milestone M3 Acceptance Tests:
1. Scorer calculates explainable severity and confidence
2. High/Critical findings auto-create an SLA-tracked Case
3. Case findings junction links the case and finding
4. Audit hash chain records finding and case events with valid integrity
5. Telegram and Slack alerts receive formatted alert payload
"""
import pytest
import json
from unittest.mock import patch, AsyncMock
from sqlmodel import SQLModel, create_engine, Session, select
from sqlmodel.pool import StaticPool

from app.collectors.base import RawItemData
from app.models import RawItem, Finding, Case, CaseFinding, AuditLog
from app.pipeline.processor import process_raw_item
from app.cases.audit import verify_chain
from app.config import settings


@pytest.fixture(name="db_session")
def db_session_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.mark.asyncio
async def test_m3_critical_finding_creates_case_and_alert(db_session: Session):
    """M3 Acceptance: Ransomware victim on watched domain scores Critical, creates Case, and sends alert."""
    settings.watched_domains = "acme.example"

    raw = RawItemData(
        source="ransomware_live",
        url="https://ransomware.live/#victim=acme.example",
        text="Ransomware victim: acme.example\nGroup: lockbit\nPublished: 2026-11-06T10:00:00Z\nSector: Finance",
        data_origin="live",
    )

    with patch("app.cases.manager.send_telegram", new_callable=AsyncMock) as mock_tg, \
         patch("app.cases.manager.send_slack", new_callable=AsyncMock) as mock_slack:

        await process_raw_item(db_session, raw)

        # 1. Verify finding exists and is Critical (base 80 + domain match 10 = 90)
        findings = db_session.exec(select(Finding)).all()
        assert len(findings) >= 1
        finding = findings[0]
        assert finding.severity == "critical"
        assert finding.score >= 80

        # 2. Verify Case was created
        cases = db_session.exec(select(Case)).all()
        assert len(cases) == 1
        case = cases[0]
        assert case.severity == "critical"
        assert "INC-CRITICAL" in case.title
        assert case.sla_ack_due is not None
        assert case.sla_contain_due is not None
        assert case.sla_contain_due > case.sla_ack_due

        # 3. Verify CaseFinding association
        cf = db_session.exec(select(CaseFinding).where(CaseFinding.case_id == case.id)).first()
        assert cf is not None
        assert cf.finding_id == finding.id

        # 4. Verify Alert was dispatched to both channels
        assert mock_tg.called
        assert mock_slack.called

        tg_msg = mock_tg.call_args[0][0]
        assert "CRITICAL" in tg_msg
        assert str(finding.score) in tg_msg
        assert "category_base" in tg_msg

        # 5. Verify Audit Log hash chain validity
        audit_res = verify_chain(db_session)
        assert audit_res["valid"] is True
        assert audit_res["broken_at"] is None

        # Verify audit logs contain case_created and finding_created
        logs = db_session.exec(select(AuditLog)).all()
        actions = [l.action for l in logs]
        assert "finding_created" in actions
        assert "case_created" in actions
