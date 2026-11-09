"""
Scoring engine tests — verify the explainable scoring formula.
"""
import pytest
from app.rules.engine import RuleMatch
from app.scoring.scorer import score_finding


def make_match(rule_id="DWW-CRED-001", severity_base=40, confidence_base=0.7):
    return RuleMatch(
        rule_id=rule_id,
        title="Test rule",
        severity_base=severity_base,
        confidence_base=confidence_base,
        attack=["T1589.001"],
        category="credential_leak",
        playbook="credential_leak",
    )


def test_score_basic():
    match = make_match()
    result = score_finding(match, data_origin="live")
    assert result["score"] >= 40
    assert result["severity"] in ("low", "medium", "high", "critical")
    assert 0 < result["confidence"] <= 1.0


def test_plaintext_secret_adds_15():
    match = make_match()
    base = score_finding(match, data_origin="live", was_redacted=False)
    with_secret = score_finding(match, data_origin="live", was_redacted=True)
    assert with_secret["score"] == base["score"] + 15


def test_domain_match_adds_10():
    match = make_match()
    base = score_finding(match, data_origin="live", domain_match=False)
    with_domain = score_finding(match, data_origin="live", domain_match=True)
    assert with_domain["score"] == base["score"] + 10


def test_fresh_24h_adds_10():
    match = make_match()
    base = score_finding(match, data_origin="live", fresh_hours=200)
    fresh = score_finding(match, data_origin="live", fresh_hours=12)
    assert fresh["score"] == base["score"] + 10


def test_replay_lowers_confidence():
    match = make_match(confidence_base=1.0)
    live_result = score_finding(match, data_origin="live")
    replay_result = score_finding(match, data_origin="replay")
    assert replay_result["confidence"] < live_result["confidence"]


def test_canary_always_100_confidence():
    match = make_match(rule_id="DWW-CANARY-001", confidence_base=1.0)
    result = score_finding(match, data_origin="live")
    assert result["confidence"] == 1.0


def test_critical_band():
    match = make_match(severity_base=80)
    result = score_finding(match, data_origin="live")
    assert result["severity"] == "critical"


def test_score_never_exceeds_100():
    match = make_match(severity_base=80)
    result = score_finding(
        match, data_origin="live", was_redacted=True,
        domain_match=True, fresh_hours=1, blast_radius=5.0, sightings=10
    )
    assert result["score"] <= 100


def test_score_breakdown_keys():
    match = make_match()
    result = score_finding(match)
    bd = result["breakdown"]
    assert "category_base" in bd
    assert "plaintext_secret" in bd
    assert "domain_match" in bd
    assert "freshness" in bd
