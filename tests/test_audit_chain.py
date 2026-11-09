import pytest
from sqlmodel import SQLModel, create_engine, Session
from sqlmodel.pool import StaticPool
from app.cases.audit import log_action, verify_chain


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_audit_chain_valid(db_session):
    log_action(db_session, "user1", "finding_created", {"id": 1})
    log_action(db_session, "user2", "case_created", {"id": 1})
    log_action(db_session, "system", "status_changed", {"from": "new", "to": "triage"})

    result = verify_chain(db_session)
    assert result["valid"] is True
    assert result["broken_at"] is None


def test_audit_chain_empty(db_session):
    result = verify_chain(db_session)
    assert result["valid"] is True


def test_audit_chain_tamper_detected(db_session):
    from app.models import AuditLog
    from sqlmodel import select

    log_action(db_session, "user1", "action_a", {"x": 1})
    log_action(db_session, "user2", "action_b", {"x": 2})

    # Tamper with the first entry
    stmt = select(AuditLog).order_by(AuditLog.id.asc()).limit(1)
    first = db_session.exec(stmt).first()
    first.detail = '{"x": 999}'  # tampered
    db_session.add(first)
    db_session.commit()

    result = verify_chain(db_session)
    assert result["valid"] is False
    assert result["broken_at"] is not None


def test_audit_prev_hash_chain(db_session):
    from app.models import AuditLog
    from sqlmodel import select

    e1 = log_action(db_session, "sys", "event_1", {})
    e2 = log_action(db_session, "sys", "event_2", {})

    assert e2.prev_hash == e1.hash
    assert e1.prev_hash == ""
