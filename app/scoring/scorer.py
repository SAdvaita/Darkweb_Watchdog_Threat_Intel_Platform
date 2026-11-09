from app.rules.engine import RuleMatch

SEVERITY_BANDS = {
    "critical": 80,
    "high": 60,
    "medium": 35,
    "low": 0,
}

SOURCE_RELIABILITY = {
    "live": 1.0,
    "replay": 0.5,
    "canary": 1.0,
}

AGGREGATOR_SOURCES = {"ransomware_live", "hudson_rock", "otx_pulses", "threatfox"}


def score_finding(
    match: RuleMatch,
    data_origin: str = "live",
    source: str = "",
    was_redacted: bool = False,
    domain_match: bool = False,
    fresh_hours: float = 999,
    sightings: int = 1,
    blast_radius: float = 0.0,
) -> dict:
    """
    Score a finding. Returns a breakdown dict and total score.
    """
    breakdown = {}

    # Base score from rule
    base = match.severity_base
    breakdown["category_base"] = base

    # Plaintext secret visible
    if was_redacted:
        breakdown["plaintext_secret"] = 15
    else:
        breakdown["plaintext_secret"] = 0

    # Domain match
    if domain_match:
        breakdown["domain_match"] = 10
    else:
        breakdown["domain_match"] = 0

    # Freshness
    if fresh_hours <= 24:
        breakdown["freshness"] = 10
    elif fresh_hours <= 168:
        breakdown["freshness"] = 5
    else:
        breakdown["freshness"] = 0

    # Graph blast radius (0-20)
    breakdown["blast_radius"] = min(blast_radius * 4, 20)

    # Sightings (0-10)
    breakdown["sightings"] = min((sightings - 1) * 2, 10)

    total_score = sum(breakdown.values())
    total_score = min(100, total_score)

    # Confidence
    reliability = SOURCE_RELIABILITY.get(data_origin, 0.8)
    if source in AGGREGATOR_SOURCES:
        reliability = min(reliability, 0.8)
    confidence = match.confidence_base * reliability
    if match.rule_id.startswith("DWW-CANARY"):
        confidence = 1.0

    # Determine severity band
    severity = "low"
    for band, threshold in sorted(SEVERITY_BANDS.items(), key=lambda x: -x[1]):
        if total_score >= threshold:
            severity = band
            break

    return {
        "score": total_score,
        "confidence": round(confidence, 3),
        "severity": severity,
        "breakdown": breakdown,
    }
