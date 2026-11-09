import random
import string
import httpx
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Session
from app.models import Canary
from app.config import settings


def generate_marker() -> str:
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"CNRY-{suffix}"


def plant_snippet_canary(
    session: Session,
    canary_type: str = "snippet",
    location_url: str = "local://planted",
) -> Canary:
    """Plant a local/manual canary snippet or decoy credential."""
    marker = generate_marker()
    canary = Canary(
        type=canary_type,
        marker=marker,
        location_url=location_url,
        planted_at=datetime.now(timezone.utc),
    )
    session.add(canary)
    session.commit()
    session.refresh(canary)
    return canary


async def plant_gist_canary(
    session: Session, description: str = "config backup"
) -> Canary:
    """Plant a canary gist on GitHub. Requires CANARY_GITHUB_GIST_TOKEN or generates simulation."""
    marker = generate_marker()
    token = settings.canary_github_gist_token

    now_iso = datetime.now(timezone.utc).isoformat()
    content = f"""# System Configuration
# Marker: {marker}
# Planted: {now_iso}
CANARY_TOKEN={marker}
SECRET_KEY=cnf_{marker[::-1]}
"""
    location_url = f"https://gist.github.com/simulation/{marker}"

    if token:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    "https://api.github.com/gists",
                    headers={
                        "Authorization": f"token {token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                    json={
                        "description": description,
                        "public": True,
                        "files": {"config.env": {"content": content}},
                    },
                )
                if resp.status_code in (200, 201):
                    location_url = resp.json().get("html_url", location_url)
        except Exception:
            pass

    canary = Canary(
        type="gist",
        marker=marker,
        location_url=location_url,
        planted_at=datetime.now(timezone.utc),
    )
    session.add(canary)
    session.commit()
    session.refresh(canary)
    return canary
