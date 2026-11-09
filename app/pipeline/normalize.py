import hashlib
from datetime import datetime, timezone
from app.collectors.base import RawItemData
from app.pipeline.redact import redact_item


def normalize(item: RawItemData) -> dict:
    """Normalize a raw item into the common schema."""
    redacted_text, was_redacted = redact_item(item.text)

    fingerprint = hashlib.sha256(
        f"{item.source}|{item.url}|{redacted_text}".encode()
    ).hexdigest()

    return {
        "source": item.source,
        "url": item.url,
        "redacted_text": redacted_text[:4000],  # hard cap
        "fetched_at": item.fetched_at or datetime.now(timezone.utc),
        "fingerprint": fingerprint,
        "data_origin": item.data_origin,
        "was_redacted": was_redacted,
    }
