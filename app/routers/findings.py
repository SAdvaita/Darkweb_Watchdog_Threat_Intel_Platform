import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select
from app.database import get_session
from app.models import Finding

router = APIRouter()


@router.get("/")
async def list_findings(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    session: Session = Depends(get_session),
):
    stmt = select(Finding)
    if status:
        stmt = stmt.where(Finding.status == status)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    stmt = stmt.offset(offset).limit(limit).order_by(Finding.first_seen.desc())
    findings = session.exec(stmt).all()
    return [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "score": f.score,
            "confidence": f.confidence,
            "status": f.status,
            "first_seen": f.first_seen,
            "last_seen": f.last_seen,
            "sightings": f.sightings,
            "score_breakdown": json.loads(f.score_breakdown or "{}"),
            "attack_techniques": json.loads(f.attack_techniques or "[]"),
        }
        for f in findings
    ]


@router.get("/{finding_id}")
async def get_finding(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    data = finding.model_dump()
    data["score_breakdown"] = json.loads(finding.score_breakdown or "{}")
    data["attack_techniques"] = json.loads(finding.attack_techniques or "[]")
    return data


@router.patch("/{finding_id}")
async def update_finding(
    finding_id: int, update: dict, session: Session = Depends(get_session)
):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    allowed = {"status", "assignee"}
    for k, v in update.items():
        if k in allowed:
            setattr(finding, k, v)
    session.add(finding)
    session.commit()
    session.refresh(finding)
    data = finding.model_dump()
    data["score_breakdown"] = json.loads(finding.score_breakdown or "{}")
    data["attack_techniques"] = json.loads(finding.attack_techniques or "[]")
    return data
