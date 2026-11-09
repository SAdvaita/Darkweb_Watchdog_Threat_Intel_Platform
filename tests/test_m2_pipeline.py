"""
Milestone M2 Acceptance Tests:
1. RawItem normalization and secret redaction before storage
2. Deduplication drops exact repeated fingerprints
3. RuleEngine evaluates items and generates Finding records
4. Finding scores are populated with explainable score breakdowns
5. Watchlist domain matching links findings to Asset entities
6. Canary markers are detected and recorded
"""
import pytest
import json
from datetime import datetime, timezone
from sqlmodel import SQLModel, create_engine, Session, select
from sqlmodel.pool import StaticPool

from app.collectors.base import RawItemData
from app.models import RawItem, Finding, Asset, Canary
from app.pipeline.processor import process_raw_item
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
async def test_m2_pipeline_creates_finding_and_redacts(db_session: Session):
    """M2 Acceptance: Pipeline processes raw item, redacts secret, matches rule, and saves finding."""
    # Ensure test domain is in watchlist
    settings.watched_domains = "acme.example,example.com"

    # Input containing corporate credential pair
    raw = RawItemData(
        source="github_gist",
        url="https://gist.github.com/leaker/secret123",
        text="Employee leak: alice@acme.example:SuperSecretPassword123! in production",
        data_origin="live",
    )

    result = await process_raw_item(db_session, raw)
    assert result is not None
    assert result.id is not None

    # Verify secret is redacted in raw_items table
    assert "SuperSecretPassword123!" not in result.redacted_text
    assert "[REDACTED:" in result.redacted_text

    # Verify finding was created
    findings = db_session.exec(select(Finding).where(Finding.raw_item_id == result.id)).all()
    assert len(findings) >= 1

    finding = findings[0]
    assert finding.rule_id == "DWW-CRED-001"
    assert finding.category == "credential_leak"
    assert finding.score >= 40
    assert finding.confidence > 0
    assert finding.status == "new"

    # Verify explainable breakdown is valid JSON with category_base
    breakdown = json.loads(finding.score_breakdown)
    assert "category_base" in breakdown
    assert breakdown["category_base"] == 40


@pytest.mark.asyncio
async def test_m2_pipeline_deduplication(db_session: Session):
    """M2 Acceptance: Processing the exact same item twice drops the duplicate."""
    raw = RawItemData(
        source="github_gist",
        url="https://gist.github.com/leaker/dup_test",
        text="Normal content with alice@acme.example:PasswordOne!",
        data_origin="live",
    )

    first = await process_raw_item(db_session, raw)
    assert first is not None

    # Second pass must be detected as duplicate and return None
    second = await process_raw_item(db_session, raw)
    assert second is None

    # Count of raw_items should remain 1
    items = db_session.exec(select(RawItem)).all()
    assert len(items) == 1


@pytest.mark.asyncio
async def test_m2_pipeline_asset_correlation(db_session: Session):
    """M2 Acceptance: Findings mentioning a watched domain create or link to an Asset."""
    settings.watched_domains = "acme.example"

    raw = RawItemData(
        source="github_gist",
        url="https://gist.github.com/leaker/asset_test",
        text="Found credentials for bob@acme.example:Winter2025!",
        data_origin="live",
    )

    await process_raw_item(db_session, raw)

    assets = db_session.exec(select(Asset).where(Asset.value == "acme.example")).all()
    assert len(assets) == 1
    assert assets[0].type == "domain"

    findings = db_session.exec(select(Finding)).all()
    assert len(findings) >= 1
    assert findings[0].asset_id == assets[0].id


@pytest.mark.asyncio
async def test_m2_pipeline_canary_detection(db_session: Session):
    """M2 Acceptance: Planted canary marker is detected and its latency measured."""
    marker = "CNRY-TEST1234"
    planted_time = datetime(2026, 11, 6, 10, 0, 0, tzinfo=timezone.utc)

    # Pre-plant a canary
    canary = Canary(
        type="gist",
        marker=marker,
        location_url="https://gist.github.com/myaccount/123",
        planted_at=planted_time,
    )
    db_session.add(canary)
    db_session.commit()
    db_session.refresh(canary)

    # Pipeline ingests a gist containing the canary marker
    raw = RawItemData(
        source="github_gist",
        url="https://gist.github.com/myaccount/123",
        text=f"# Config\nAPI_TOKEN={marker}\nDEBUG=true",
        data_origin="canary",
    )

    await process_raw_item(db_session, raw)

    # Verify canary is marked as detected
    db_session.refresh(canary)
    assert canary.first_detected_at is not None
    assert canary.detected_source == "github_gist"
    assert canary.time_to_detect_seconds is not None
    assert canary.time_to_detect_seconds > 0
