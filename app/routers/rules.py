from typing import List
from fastapi import APIRouter
from pydantic import BaseModel
from app.rules.loader import load_rules
from app.rules.engine import RuleEngine

router = APIRouter()


class RuleTestRequest(BaseModel):
    text: str
    source: str = "github_gist"
    watched_domains: List[str] = []


@router.get("/")
async def list_rules():
    rules = load_rules()
    return [
        {
            "id": r["id"],
            "title": r["title"],
            "status": r.get("status"),
            "category": r.get("category"),
            "applies_to": r.get("applies_to", []),
            "severity_base": r.get("severity_base"),
            "attack": r.get("attack", []),
        }
        for r in rules
    ]


@router.post("/test")
async def test_rule(body: RuleTestRequest):
    engine = RuleEngine(watched_domains=body.watched_domains)
    matches = engine.evaluate(body.text, body.source)
    return [
        {
            "rule_id": m.rule_id,
            "title": m.title,
            "category": m.category,
            "severity_base": m.severity_base,
            "confidence_base": m.confidence_base,
            "attack": m.attack,
        }
        for m in matches
    ]
