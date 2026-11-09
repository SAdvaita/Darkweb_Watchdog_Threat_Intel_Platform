"""
Milestone M7 Acceptance Tests:
1. STIX 2.1 bundle export format and fields
2. ATT&CK Navigator layer JSON export format and scores
3. PDF report generation and byte delivery
"""
import pytest
import json
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine, Session
from sqlmodel.pool import StaticPool

from app.models import Finding
from app.main import app
from app.database import get_session


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


def test_m7_exports_stix_navigator_pdf(db_session: Session):
    finding = Finding(
        title="Sample Leaked AWS Credentials",
        description="Found in public gist",
        category="secret_in_code",
        severity="high",
        score=75,
        confidence=0.85,
        rule_id="DWW-SECRET-002",
        attack_techniques=json.dumps(["T1552.001"]),
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    def get_session_override():
        yield db_session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)

    # 1. Test STIX 2.1 export
    stix_resp = client.get("/export/stix")
    assert stix_resp.status_code == 200
    bundle = stix_resp.json()
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) >= 1
    assert bundle["objects"][0]["type"] == "indicator"
    assert bundle["objects"][0]["name"] == finding.title

    # 2. Test ATT&CK Navigator layer export
    nav_resp = client.get("/export/navigator")
    assert nav_resp.status_code == 200
    nav = nav_resp.json()
    assert "techniques" in nav
    assert nav["domain"] == "enterprise-attack"
    techniques = [t["techniqueID"] for t in nav["techniques"]]
    assert "T1552.001" in techniques

    # 3. Test PDF report export
    pdf_resp = client.get("/export/report.pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF")

    # 4. Root report.pdf alias
    root_pdf_resp = client.get("/report.pdf")
    assert root_pdf_resp.status_code == 200
    assert root_pdf_resp.content.startswith(b"%PDF")

    app.dependency_overrides.clear()
