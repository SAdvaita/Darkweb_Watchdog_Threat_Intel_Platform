from typing import List
from app.models import Finding


def findings_to_stix(findings: List[Finding]) -> dict:
    """Export findings as a STIX 2.1 bundle (simplified)."""
    objects = []
    for finding in findings:
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{finding.id:08x}-0000-0000-0000-000000000000",
            "created": finding.first_seen.isoformat() + "Z",
            "modified": finding.last_seen.isoformat() + "Z",
            "name": finding.title,
            "description": finding.description,
            "pattern": f"[url:value = '{finding.id}']",
            "pattern_type": "stix",
            "valid_from": finding.first_seen.isoformat() + "Z",
            "labels": [finding.category],
            "confidence": int(finding.confidence * 100),
            "external_references": [],
        }
        objects.append(obj)

    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000000",
        "spec_version": "2.1",
        "objects": objects,
    }
