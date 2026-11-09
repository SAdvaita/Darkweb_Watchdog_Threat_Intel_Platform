from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response
from sqlmodel import Session, select
from app.database import get_session
from app.models import Finding
from app.export.stix import findings_to_stix
from app.export.navigator import findings_to_navigator
from app.export.report import generate_pdf_report

router = APIRouter()


@router.get("/stix")
async def export_stix(session: Session = Depends(get_session)):
    findings = session.exec(select(Finding)).all()
    bundle = findings_to_stix(list(findings))
    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": "attachment; filename=watchdog-stix-bundle.json"},
    )


@router.get("/navigator")
async def export_navigator(session: Session = Depends(get_session)):
    findings = session.exec(select(Finding)).all()
    layer = findings_to_navigator(list(findings))
    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": "attachment; filename=watchdog-navigator-layer.json"},
    )


@router.get("/pdf")
@router.get("/report.pdf")
async def export_pdf(session: Session = Depends(get_session)):
    findings = session.exec(select(Finding)).all()
    findings_data = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "score": f.score,
            "status": f.status,
        }
        for f in findings
    ]
    metrics = {
        "total_findings": len(findings_data),
    }
    pdf_bytes = generate_pdf_report(findings_data, metrics)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=watchdog-report.pdf"},
    )
