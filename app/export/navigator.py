import json
from typing import List
from app.models import Finding


def findings_to_navigator(findings: List[Finding]) -> dict:
    """Export findings as an ATT&CK Navigator layer."""
    techniques: dict = {}
    for finding in findings:
        attack = json.loads(finding.attack_techniques or "[]")
        for tech in attack:
            if tech not in techniques:
                techniques[tech] = {"score": 0, "count": 0}
            techniques[tech]["score"] += finding.score
            techniques[tech]["count"] += 1

    layer_techniques = []
    for tid, data in techniques.items():
        layer_techniques.append(
            {
                "techniqueID": tid,
                "score": min(100, int(data["score"] / max(data["count"], 1))),
                "color": "",
                "comment": f"Seen {data['count']} time(s)",
                "enabled": True,
            }
        )

    return {
        "name": "DarkWeb Watchdog Coverage",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques detected by DarkWeb Watchdog rules",
        "techniques": layer_techniques,
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
    }
