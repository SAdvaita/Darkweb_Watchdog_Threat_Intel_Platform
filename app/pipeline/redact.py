import re
import hashlib
import os
from typing import Tuple

SALT = os.environ.get("APP_SECRET_KEY", "watchdog-salt")


def _hash(secret: str) -> str:
    return hashlib.sha256((SALT + secret).encode()).hexdigest()[:12]


# Targeted redactions with group capture so identifiers (email/usernames/hosts) remain intact
TARGETED_REPLACEMENTS = [
    # Email:password pairs -> preserve email, redact password
    (
        re.compile(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\s*[:;,]\s*)(\S{6,})"),
        lambda m: f"{m.group(1)}[REDACTED:{_hash(m.group(2))}]",
    ),
    # Password variables -> preserve key, redact password
    (
        re.compile(r"((?:password|passwd|pwd)\s*[:=]\s*['\"]?)(\S{6,})(['\"]?)", re.IGNORECASE),
        lambda m: f"{m.group(1)}[REDACTED:{_hash(m.group(2))}]{m.group(3)}",
    ),
    # Connection strings -> preserve db/user/host, redact password
    (
        re.compile(r"((?:postgresql|mysql|mongodb|redis):\/\/[^:]+:)([^@]+)(@[^\s]+)", re.IGNORECASE),
        lambda m: f"{m.group(1)}[REDACTED:{_hash(m.group(2))}]{m.group(3)}",
    ),
]

# Full-match secrets -> replace full token
FULL_SECRET_PATTERNS = [
    # Private key headers and body
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    # AWS-style keys
    re.compile(r"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}", re.IGNORECASE),
    # Generic API key patterns
    re.compile(r"(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", re.IGNORECASE),
    # GitHub tokens
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    # Generic bearer tokens
    re.compile(r"bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
]


def redact_text(text: str) -> Tuple[str, bool]:
    """
    Redact secrets from text while preserving usernames and corporate domains.
    Returns (redacted_text, was_redacted).
    """
    was_redacted = False

    # 1. Apply targeted replacements (email:password, password=, conn strings)
    for pattern, repl_fn in TARGETED_REPLACEMENTS:
        new_text, count = pattern.subn(repl_fn, text)
        if count > 0:
            was_redacted = True
            text = new_text

    # 2. Apply full secret replacements
    for pattern in FULL_SECRET_PATTERNS:
        def replace_match(m):
            secret = m.group(0)
            return f"[REDACTED:{_hash(secret)}]"

        new_text, count = pattern.subn(replace_match, text)
        if count > 0:
            was_redacted = True
            text = new_text

    return text, was_redacted


def redact_item(text: str) -> Tuple[str, bool]:
    """Public API: redact a single text item."""
    return redact_text(text)
