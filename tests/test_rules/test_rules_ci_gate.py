"""
CI Rule-test Gate:
Every rule YAML must have at least one positive and one negative test,
and must pass both against the RuleEngine.
"""
import os
import yaml
import pytest
from app.rules.engine import RuleEngine
from app.rules.loader import RULES_DIR

WATCHED_DOMAINS = ["acme.example", "example.com"]


def test_every_rule_has_positive_and_negative_tests():
    rule_files = [f for f in os.listdir(RULES_DIR) if f.endswith(".yaml") or f.endswith(".yml")]
    assert len(rule_files) >= 12, f"Expected at least 12 rules, found {len(rule_files)}"

    for fname in rule_files:
        fpath = os.path.join(RULES_DIR, fname)
        with open(fpath) as fp:
            rule_def = yaml.safe_load(fp)
            assert "id" in rule_def, f"{fname} missing id"
            tests = rule_def.get("tests", {})
            positives = tests.get("positive", [])
            negatives = tests.get("negative", [])

            assert len(positives) > 0, f"Rule {rule_def['id']} ({fname}) has no positive test cases"
            assert len(negatives) > 0, f"Rule {rule_def['id']} ({fname}) has no negative test cases"


def test_every_rule_passes_its_own_tests():
    engine = RuleEngine(watched_domains=WATCHED_DOMAINS)
    rule_files = [f for f in os.listdir(RULES_DIR) if f.endswith(".yaml") or f.endswith(".yml")]

    for fname in sorted(rule_files):
        fpath = os.path.join(RULES_DIR, fname)
        with open(fpath) as fp:
            rule_def = yaml.safe_load(fp)
            rule_id = rule_def["id"]
            applies_to = rule_def.get("applies_to", ["github_gist"])
            source = applies_to[0] if applies_to else "github_gist"

            tests = rule_def.get("tests", {})
            positives = tests.get("positive", [])
            negatives = tests.get("negative", [])

            for pos in positives:
                matches = engine.evaluate(pos, source)
                matched_ids = [m.rule_id for m in matches]
                assert rule_id in matched_ids, (
                    f"Rule {rule_id} did not match positive test '{pos}' from source '{source}'"
                )

            for neg in negatives:
                matches = engine.evaluate(neg, source)
                matched_ids = [m.rule_id for m in matches]
                assert rule_id not in matched_ids, (
                    f"Rule {rule_id} erroneously matched negative test '{neg}' from source '{source}'"
                )
