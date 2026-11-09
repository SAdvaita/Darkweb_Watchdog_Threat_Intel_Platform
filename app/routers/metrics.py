from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from app.database import get_session
from app.models import Finding, Case

router = APIRouter()


@router.get("/")
@router.get("/summary")
async def get_metrics_summary(session: Session = Depends(get_session)):
    findings = session.exec(select(Finding)).all()
    cases = session.exec(select(Case)).all()

    severity_counts = {
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
    }

    open_cases = sum(1 for c in cases if c.status not in ("closed", "resolved", "false_positive"))
    open_findings = sum(1 for f in findings if f.status == "new")

    return {
        "total_findings": len(findings),
        "findings_total": len(findings),
        "findings_open": open_findings,
        "total_cases": len(cases),
        "cases_total": len(cases),
        "open_cases": open_cases,
        "severity_counts": severity_counts,
    }
