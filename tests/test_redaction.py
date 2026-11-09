import pytest
from app.pipeline.redact import redact_item


def test_redact_aws_key():
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    redacted, was_redacted = redact_item(text)
    assert was_redacted is True
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED:" in redacted


def test_redact_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    redacted, was_redacted = redact_item(text)
    assert was_redacted is True
    assert "MIIEpAIBAAKCAQEA" not in redacted


def test_redact_password_pattern():
    text = "password=SuperSecret123"
    redacted, was_redacted = redact_item(text)
    assert was_redacted is True
    assert "SuperSecret123" not in redacted


def test_no_redact_safe_text():
    text = "This is a normal sentence with no secrets."
    redacted, was_redacted = redact_item(text)
    assert was_redacted is False
    assert redacted == text


def test_redact_connection_string():
    text = "postgresql://admin:password123@db.example.com/mydb"
    redacted, was_redacted = redact_item(text)
    assert was_redacted is True
    assert "password123" not in redacted


def test_redact_github_token():
    text = "token = ghp_abcdefghijklmnopqrstuvwxyz123456789012"
    redacted, was_redacted = redact_item(text)
    assert was_redacted is True
    assert "ghp_" not in redacted


def test_redact_email_password_pair():
    text = "alice@example.com:Winter2024!"
    redacted, was_redacted = redact_item(text)
    assert was_redacted is True
    assert "Winter2024!" not in redacted


def test_redact_deterministic():
    """Same input always produces same redacted hash."""
    text = "AKIAIOSFODNN7EXAMPLE"
    r1, _ = redact_item(text)
    r2, _ = redact_item(text)
    assert r1 == r2
