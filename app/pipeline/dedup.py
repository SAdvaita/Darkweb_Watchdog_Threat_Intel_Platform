from sqlmodel import Session, select
from app.models import RawItem


def is_duplicate(session: Session, fingerprint: str) -> bool:
    """Check if a fingerprint already exists in the database."""
    stmt = select(RawItem).where(RawItem.fingerprint == fingerprint)
    existing = session.exec(stmt).first()
    return existing is not None
