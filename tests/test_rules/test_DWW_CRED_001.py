import pytest
from app.rules.engine import RuleEngine


WATCHED_DOMAINS = ["acme.example", "example.com"]


@pytest.fixture
def engine():
    return RuleEngine(watched_domains=WATCHED_DOMAINS)


# ── DWW-CRED-001 ──────────────────────────────────────────────────────────────

def test_rule_dww_cred_001_positive(engine):
    """Email:password pair with watched domain should match."""
    text = "alice@acme.example:Winter2024!"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-CRED-001" in rule_ids


def test_rule_dww_cred_001_negative(engine):
    """Email from non-watched domain should NOT match DWW-CRED-001."""
    text = "user@other.example:password123"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-CRED-001" not in rule_ids


def test_rule_dww_cred_001_wrong_source(engine):
    """DWW-CRED-001 does not apply to ransomware_live source."""
    text = "alice@acme.example:Winter2024!"
    matches = engine.evaluate(text, "ransomware_live")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-CRED-001" not in rule_ids


# ── DWW-SECRET-001 ────────────────────────────────────────────────────────────

def test_rule_dww_secret_001_positive(engine):
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-SECRET-001" in rule_ids


def test_rule_dww_secret_001_negative(engine):
    text = "-----BEGIN CERTIFICATE-----\nMIIE"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-SECRET-001" not in rule_ids


# ── DWW-SECRET-002 ────────────────────────────────────────────────────────────

def test_rule_dww_secret_002_positive(engine):
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-SECRET-002" in rule_ids


def test_rule_dww_secret_002_negative(engine):
    text = "aws_access_key_id = YOUR_KEY_HERE"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-SECRET-002" not in rule_ids


# ── DWW-CRED-003 ──────────────────────────────────────────────────────────────

def test_rule_dww_cred_003_positive(engine):
    text = "DB_PASS=SuperSecret123!"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-CRED-003" in rule_ids


def test_rule_dww_cred_003_negative(engine):
    # Only 7 chars — rule requires 8+
    text = "DB_PASS=1234567"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    # 7 chars should not match (regex requires \S{8,})
    # We test with a genuinely short value
    text2 = "DB_PASS=short"
    matches2 = engine.evaluate(text2, "github_gist")
    rule_ids2 = [m.rule_id for m in matches2]
    assert "DWW-CRED-003" not in rule_ids2


# ── DWW-CANARY-001 ────────────────────────────────────────────────────────────

def test_rule_dww_canary_001_positive(engine):
    text = "token=CNRY-ABCD1234 found in public gist"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-CANARY-001" in rule_ids


def test_rule_dww_canary_001_negative(engine):
    text = "normal content without marker"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-CANARY-001" not in rule_ids


# ── DWW-INFRA-001 ────────────────────────────────────────────────────────────

def test_rule_dww_infra_001_positive(engine):
    text = "server at 192.168.1.100 exposed"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-INFRA-001" in rule_ids


def test_rule_dww_infra_001_negative(engine):
    text = "example server at 203.0.113.1"
    matches = engine.evaluate(text, "github_gist")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-INFRA-001" not in rule_ids


# ── DWW-RANSOM-001 ───────────────────────────────────────────────────────────

def test_rule_dww_ransom_001_positive(engine):
    text = "victim: acme.example posted by lockbit"
    matches = engine.evaluate(text, "ransomware_live")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-RANSOM-001" in rule_ids


def test_rule_dww_ransom_001_negative(engine):
    text = "victim: other-company.com posted by lockbit"
    matches = engine.evaluate(text, "ransomware_live")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-RANSOM-001" not in rule_ids


# ── DWW-IOC-001 ──────────────────────────────────────────────────────────────

def test_rule_dww_ioc_001_positive(engine):
    text = "malicious indicator 1.2.3.4 detected"
    matches = engine.evaluate(text, "otx_pulses")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-IOC-001" in rule_ids


def test_rule_dww_ioc_001_negative(engine):
    text = "safe domain example.com"
    matches = engine.evaluate(text, "otx_pulses")
    rule_ids = [m.rule_id for m in matches]
    assert "DWW-IOC-001" not in rule_ids
