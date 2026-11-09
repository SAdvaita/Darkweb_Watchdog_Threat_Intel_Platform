import json
from sqlmodel import Session, select
from app.models import AuditLog


def log_action(session: Session, actor: str, action: str, detail: dict) -> AuditLog:
    # Get the last row's hash
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    last = session.exec(stmt).first()
    prev_hash = last.hash if last else ""

    entry = AuditLog(
        actor=actor,
        action=action,
        detail=json.dumps(detail),
        prev_hash=prev_hash,
    )
    entry.hash = entry.compute_hash()
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry


def verify_chain(session: Session) -> dict:
    """Verify the integrity of the audit chain. Returns {valid: bool, broken_at: int|None}"""
    stmt = select(AuditLog).order_by(AuditLog.id.asc())
    rows = session.exec(stmt).all()

    prev_hash = ""
    for row in rows:
        expected_hash = row.compute_hash()
        if row.prev_hash != prev_hash or row.hash != expected_hash:
            return {"valid": False, "broken_at": row.id}
        prev_hash = row.hash

    return {"valid": True, "broken_at": None}
