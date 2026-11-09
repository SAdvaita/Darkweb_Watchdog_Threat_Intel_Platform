"""
Collector registry + scheduler integration.
Wires all collectors into APScheduler and passes
fetched items through the normalization, deduplication,
rule evaluation, and scoring pipeline.
"""
import asyncio
import logging
from datetime import datetime, timezone

from sqlmodel import Session, select

from app.collectors.base import BaseCollector
from app.collectors.ransomware_live import RansomwareLiveCollector
from app.collectors.crt_sh import CrtShCollector
from app.collectors.github_gists import GitHubGistsCollector, GitHubEventsCollector
from app.collectors.hudson_rock import HudsonRockCollector
from app.collectors.otx import OTXCollector, ThreatFoxCollector
from app.database import engine
from app.models import SourceHealth
from app.pipeline.processor import process_raw_item

logger = logging.getLogger(__name__)

ALL_COLLECTORS: list[BaseCollector] = [
    RansomwareLiveCollector(),
    CrtShCollector(),
    GitHubGistsCollector(),
    GitHubEventsCollector(),
    HudsonRockCollector(),
    OTXCollector(),
    ThreatFoxCollector(),
]


def _update_health(session: Session, source: str, success: bool,
                   count: int = 0, error: str = "") -> None:
    stmt = select(SourceHealth).where(SourceHealth.source == source)
    health = session.exec(stmt).first()
    if not health:
        health = SourceHealth(source=source)
        session.add(health)

    now = datetime.now(timezone.utc)
    if success:
        health.last_success = now
        health.items_fetched += count
    else:
        health.last_error = now
        health.last_error_msg = error[:500]
        health.errors_total += 1

    session.commit()


async def run_collector(collector: BaseCollector) -> int:
    """Run one collector and process all items through the pipeline. Returns stored count."""
    try:
        raw_items = await collector.run()
    except Exception as e:
        with Session(engine) as session:
            _update_health(session, collector.name, False, error=str(e))
        return 0

    stored = 0
    with Session(engine) as session:
        for raw in raw_items:
            processed = await process_raw_item(session, raw)
            if processed:
                stored += 1

        _update_health(session, collector.name, True, count=stored)

    logger.info(f"[{collector.name}] processed and stored {stored} new items")
    return stored


async def run_all_collectors() -> dict:
    """Run all collectors concurrently."""
    tasks = [run_collector(c) for c in ALL_COLLECTORS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {c.name: r for c, r in zip(ALL_COLLECTORS, results)}
