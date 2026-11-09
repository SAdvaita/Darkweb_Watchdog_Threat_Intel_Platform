from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List
import logging

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RawItemData:
    source: str
    url: str
    text: str
    fetched_at: datetime = field(default_factory=_utcnow)
    data_origin: str = "live"  # live, replay, canary
    extra: dict = field(default_factory=dict)


class BaseCollector(ABC):
    name: str = "base"
    poll_interval_seconds: int = 900

    @abstractmethod
    async def fetch(self) -> List[RawItemData]:
        """Fetch raw items from the source. Returns list of RawItemData."""
        ...

    async def run(self) -> List[RawItemData]:
        """Run the collector with error handling."""
        try:
            items = await self.fetch()
            logger.info(f"[{self.name}] fetched {len(items)} items")
            return items
        except Exception as e:
            logger.error(f"[{self.name}] fetch failed: {e}")
            return []
