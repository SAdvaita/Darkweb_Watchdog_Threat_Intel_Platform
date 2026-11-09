from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from app.database import get_session
from app.models import AuditLog
from app.cases.audit import verify_chain

router = APIRouter()


@router.get("/")
async def list_audit(
    limit: int = 100,
    offset: int = 0,
    session: Session = Depends(get_session),
):
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).offset(offset).limit(limit)
    rows = session.exec(stmt).all()
    return rows


@router.get("/verify")
async def verify_audit_chain(session: Session = Depends(get_session)):
    return verify_chain(session)
