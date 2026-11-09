"""
Pipeline integration test — verify the full normalize → redact → dedup flow.
"""
import pytest
from datetime import datetime
from sqlmodel import SQLModel, create_engine, Session

from app.collectors.base import RawItemData
from app.pipeline.normalize import normalize
from app.pipeline.redact import redact_item
from app.pipeline.dedup import is_duplicate
from app.models import RawItem


@pytest.fixture(name="mem_session")
def mem_session_fixture():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_normalize_produces_fingerprint():
    item = RawItemData(source="test", url="http://example.com", text="Hello world")
    result = normalize(item)
    assert result["fingerprint"]
    assert len(result["fingerprint"]) == 64  # SHA-256 hex


def test_normalize_caps_text_at_4000():
    long_text = "A" * 10000
    item = RawItemData(source="test", url="http://example.com", text=long_text)
    result = normalize(item)
    assert len(result["redacted_text"]) <= 4000


def test_normalize_sets_data_origin():
    item = RawItemData(source="test", url="", text="x", data_origin="canary")
    result = normalize(item)
    assert result["data_origin"] == "canary"


def test_dedup_detects_duplicate(mem_session: Session):
    item = RawItem(
        source="test", url="http://a.com",
        fingerprint="abc123", redacted_text="text", data_origin="live"
    )
    mem_session.add(item)
    mem_session.commit()
    assert is_duplicate(mem_session, "abc123") is True


def test_dedup_allows_new_item(mem_session: Session):
    assert is_duplicate(mem_session, "new_fingerprint_xyz") is False


def test_full_pipeline_stores_item(mem_session: Session):
    """Simulate the full: collect → normalize → dedup → store flow."""
    raw = RawItemData(
        source="github_gist",
        url="https://gist.github.com/test/123",
        text="Some normal gist content",
        data_origin="live",
    )
    normalized = normalize(raw)
    assert not is_duplicate(mem_session, normalized["fingerprint"])

    db_item = RawItem(
        source=normalized["source"],
        url=normalized["url"],
        fingerprint=normalized["fingerprint"],
        redacted_text=normalized["redacted_text"],
        data_origin=normalized["data_origin"],
    )
    mem_session.add(db_item)
    mem_session.commit()

    # Second time should be detected as duplicate
    assert is_duplicate(mem_session, normalized["fingerprint"]) is True
