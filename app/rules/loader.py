import os
import yaml
from typing import List

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def load_rules() -> List[dict]:
    rules = []
    if not os.path.isdir(RULES_DIR):
        return rules
    for fname in sorted(os.listdir(RULES_DIR)):
        if fname.endswith(".yaml") or fname.endswith(".yml"):
            fpath = os.path.join(RULES_DIR, fname)
            with open(fpath) as f:
                rule = yaml.safe_load(f)
                if rule and "id" in rule:
                    rules.append(rule)
    return rules
