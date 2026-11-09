from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select
from app.database import get_session
from app.models import Canary
from app.canary.planter import plant_gist_canary, plant_snippet_canary
from app.canary.tracker import calculate_latency_metrics

router = APIRouter()


class PlantCanaryRequest(BaseModel):
    type: str = "gist"  # gist, snippet, cert
    description: Optional[str] = "DarkWeb Watchdog Canary Tracer"
    location_url: Optional[str] = None


@router.get("/")
async def list_canaries(session: Session = Depends(get_session)):
    canaries = session.exec(select(Canary).order_by(Canary.planted_at.desc())).all()
    return canaries


@router.get("/metrics")
async def canary_metrics(session: Session = Depends(get_session)):
    """Returns Canary Lab metrics including median and p95 latency per source."""
    return calculate_latency_metrics(session)


@router.post("/plant")
@router.post("/plant/gist")
async def plant_canary(
    body: Optional[PlantCanaryRequest] = None,
    session: Session = Depends(get_session),
):
    canary_type = body.type if body else "gist"
    desc = body.description if body else "DarkWeb Watchdog Canary"
    loc = body.location_url if body and body.location_url else "local://snippet"

    try:
        if canary_type == "gist":
            canary = await plant_gist_canary(session, description=desc)
        else:
            canary = plant_snippet_canary(session, canary_type=canary_type, location_url=loc)
        return canary
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to plant canary: {e}")


@router.get("/{canary_id}")
async def get_canary(canary_id: int, session: Session = Depends(get_session)):
    canary = session.get(Canary, canary_id)
    if not canary:
        raise HTTPException(status_code=404, detail="Canary not found")
    return canary
