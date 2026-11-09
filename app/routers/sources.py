from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from app.database import get_session
from app.models import SourceHealth

router = APIRouter()


@router.get("/")
@router.get("/health")
async def list_sources(session: Session = Depends(get_session)):
    sources = session.exec(select(SourceHealth)).all()
    return sources
