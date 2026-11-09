import re
import logging
from typing import List
from app.rules.loader import load_rules

logger = logging.getLogger(__name__)


class RuleMatch:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity_base: int,
        confidence_base: float,
        attack: List[str],
        category: str,
        playbook: str,
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity_base = severity_base
        self.confidence_base = confidence_base
        self.attack = attack
        self.category = category
        self.playbook = playbook


class RuleEngine:
    def __init__(self, watched_domains: List[str] = None):
        self.rules = load_rules()
        self.watched_domains = watched_domains or []

    def evaluate(self, text: str, source: str) -> List[RuleMatch]:
        """Evaluate all rules against a text. Returns list of matches."""
        matches = []
        for rule in self.rules:
            # Check source filter
            applies_to = rule.get("applies_to", [])
            if applies_to and source not in applies_to:
                continue

            if self._match_rule(rule, text):
                matches.append(
                    RuleMatch(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity_base=rule.get("severity_base", 10),
                        confidence_base=rule.get("confidence_base", 0.5),
                        attack=rule.get("attack", []),
                        category=rule.get("category", "general"),
                        playbook=rule.get("playbook", ""),
                    )
                )
        return matches

    def _match_rule(self, rule: dict, text: str) -> bool:
        detection = rule.get("detection", {})
        condition = detection.get("condition", "selection")

        selections = {}
        for key, val in detection.items():
            if key == "condition":
                continue
            selections[key] = self._evaluate_selection(val, text)

        return self._evaluate_condition(condition, selections)

    def _evaluate_selection(self, selection: dict, text: str) -> bool:
        if "regex" in selection:
            pattern = selection["regex"]
            # Substitute watchlist placeholder
            if "{{watchlist.domains}}" in pattern and self.watched_domains:
                domain_pattern = "|".join(re.escape(d) for d in self.watched_domains)
                pattern = pattern.replace("{{watchlist.domains}}", f"({domain_pattern})")
            elif "{{watchlist.domains}}" in pattern:
                return False
            try:
                return bool(re.search(pattern, text, re.IGNORECASE))
            except re.error:
                return False
        elif "wordlist" in selection:
            words = selection["wordlist"]
            # Handle watchlist substitution in wordlists
            expanded = []
            for w in words:
                if w == "{{watchlist.domains}}":
                    expanded.extend(self.watched_domains)
                else:
                    expanded.append(w)
            return any(w.lower() in text.lower() for w in expanded)
        elif "canary_marker" in selection:
            return bool(re.search(r"CNRY-[A-Z0-9]{8}", text))
        return False

    def _evaluate_condition(self, condition: str, selections: dict) -> bool:
        # Simple parser: "selection", "sel1 and sel2", "sel1 or sel2", "not sel1"
        condition = condition.strip()
        if " or " in condition:
            parts = condition.split(" or ")
            return any(self._evaluate_condition(p.strip(), selections) for p in parts)
        if " and " in condition:
            parts = condition.split(" and ")
            return all(self._evaluate_condition(p.strip(), selections) for p in parts)
        if condition.startswith("not "):
            return not self._evaluate_condition(condition[4:].strip(), selections)
        return selections.get(condition, False)
