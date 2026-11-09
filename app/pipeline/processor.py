"""
Pipeline Processor:
Coordinates:
1. Normalization & Secret Redaction
2. SHA-256 Fingerprint Deduplication
3. Rule Engine Evaluation
4. Scoring & Asset Correlation
5. Finding Record Generation
6. Canary Marker Detection & Latency Recording
7. Realtime SSE Event Notification
8. Case Grouping & Alerting (M3)
"""
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from sqlmodel import Session, select

from app.collectors.base import RawItemData
from app.config import settings
from app.models import RawItem, Finding, Asset, Canary
from app.pipeline.normalize import normalize
from app.pipeline.dedup import is_duplicate
from app.rules.engine import RuleEngine, RuleMatch
from app.scoring.scorer import score_finding
from app.cases.audit import log_action
from app.routers.stream import push_event

logger = logging.getLogger(__name__)

def get_rule_engine() -> RuleEngine:
    return RuleEngine(watched_domains=settings.watched_domains_list())


async def process_raw_item(session: Session, raw: RawItemData) -> Optional[RawItem]:
    """
    Process a raw item through the entire pipeline:
    normalize -> redact -> dedup -> rule match -> score -> find -> stream.
    Returns the created RawItem if not duplicate, else None.
    """
    normalized = normalize(raw)
    if is_duplicate(session, normalized["fingerprint"]):
        return None

    # Persist RawItem
    raw_item = RawItem(
        source=normalized["source"],
        url=normalized["url"],
        fetched_at=normalized["fetched_at"],
        fingerprint=normalized["fingerprint"],
        redacted_text=normalized["redacted_text"],
        data_origin=normalized["data_origin"],
    )
    session.add(raw_item)
    session.commit()
    session.refresh(raw_item)

    # Evaluate rules
    engine = get_rule_engine()
    matches = engine.evaluate(raw_item.redacted_text, raw_item.source)

    if not matches:
        return raw_item

    now = datetime.now(timezone.utc)
    watched_domains = settings.watched_domains_list()

    # Match or find asset
    matched_asset_id: Optional[int] = None
    for domain in watched_domains:
        if domain.lower() in raw_item.redacted_text.lower():
            stmt = select(Asset).where(Asset.value == domain)
            asset = session.exec(stmt).first()
            if not asset:
                asset = Asset(
                    type="domain",
                    value=domain,
                    criticality=4,
                    owner="Security Team",
                    created_at=now,
                )
                session.add(asset)
                session.commit()
                session.refresh(asset)
            matched_asset_id = asset.id
            break

    # Process each rule match into a Finding
    for match in matches:
        # Check domain match flag
        domain_match = matched_asset_id is not None or any(
            d.lower() in raw_item.redacted_text.lower() for d in watched_domains
        )

        # Freshness in hours
        fresh_hours = (now - raw_item.fetched_at).total_seconds() / 3600.0

        # Score finding
        score_res = score_finding(
            match=match,
            data_origin=raw_item.data_origin,
            source=raw_item.source,
            was_redacted=normalized["was_redacted"],
            domain_match=domain_match,
            fresh_hours=fresh_hours,
            sightings=1,
            blast_radius=0.0,
        )

        finding = Finding(
            raw_item_id=raw_item.id,
            rule_id=match.rule_id,
            category=match.category,
            severity=score_res["severity"],
            confidence=score_res["confidence"],
            score=score_res["score"],
            score_breakdown=json.dumps(score_res["breakdown"]),
            asset_id=matched_asset_id,
            first_seen=now,
            last_seen=now,
            sightings=1,
            status="new",
            title=f"{match.title} detected via {raw_item.source}",
            description=raw_item.redacted_text[:400],
            attack_techniques=json.dumps(match.attack),
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

        # Audit log entry
        log_action(
            session,
            actor="pipeline",
            action="finding_created",
            detail={
                "finding_id": finding.id,
                "rule_id": match.rule_id,
                "score": finding.score,
                "severity": finding.severity,
                "source": raw_item.source,
            },
        )

        # Check for Canary detection (M4 requirement)
        marker_match = re.search(r"CNRY-[A-Z0-9]{8}", raw_item.redacted_text)
        if marker_match or match.rule_id.startswith("DWW-CANARY"):
            marker = marker_match.group(0) if marker_match else None
            if marker:
                canary_stmt = select(Canary).where(Canary.marker == marker)
                canary = session.exec(canary_stmt).first()
                if canary and canary.first_detected_at is None:
                    canary.first_detected_at = now
                    canary.detected_source = raw_item.source
                    ttd = (now - canary.planted_at).total_seconds()
                    canary.time_to_detect_seconds = max(0.0, round(ttd, 2))
                    session.add(canary)
                    session.commit()
                    logger.info(f"Canary {marker} detected! TTD: {canary.time_to_detect_seconds}s")

        # Push to real-time SSE stream
        try:
            await push_event({
                "type": "finding_created",
                "finding": {
                    "id": finding.id,
                    "title": finding.title,
                    "rule_id": finding.rule_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "score": finding.score,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "source": raw_item.source,
                    "data_origin": raw_item.data_origin,
                    "first_seen": finding.first_seen.isoformat(),
                },
            })
        except Exception as e:
            logger.debug(f"SSE event push failed (non-critical): {e}")

        # Milestone M3: Auto-create case and alert for High & Critical findings
        if finding.severity in ("high", "critical"):
            try:
                from app.cases.manager import handle_high_severity_alert
                await handle_high_severity_alert(session, finding, match.playbook)
            except Exception as e:
                logger.warning(f"Failed to auto-create case / alert: {e}")

    return raw_item
