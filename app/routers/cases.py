from typing import List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select
from app.database import get_session
from app.models import Case
from app.cases.manager import create_case

router = APIRouter()


class CaseCreate(BaseModel):
    title: str
    severity: str = "medium"
    finding_ids: List[int] = []


@router.get("/")
async def list_cases(session: Session = Depends(get_session)):
    cases = session.exec(select(Case).order_by(Case.created_at.desc())).all()
    return cases


@router.post("/", response_model=Case)
async def new_case(body: CaseCreate, session: Session = Depends(get_session)):
    return create_case(session, body.title, body.severity, body.finding_ids)


@router.patch("/{case_id}", response_model=Case)
async def update_case(case_id: int, update: dict, session: Session = Depends(get_session)):
    case = session.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    allowed = {"status", "assignee", "severity"}
    for k, v in update.items():
        if k in allowed:
            setattr(case, k, v)
    session.add(case)
    session.commit()
    session.refresh(case)
    return case
