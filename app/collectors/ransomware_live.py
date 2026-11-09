"""
Ransomware.live collector — scrapes recent ransomware leak-site victims.
API: https://api.ransomware.live/v2/recentvictims
Rate limit: ~1 request/min per endpoint. We poll every 15 min and cache.
"""
import json
import logging
from datetime import datetime
from pathlib import Path

import httpx

from app.collectors.base import BaseCollector, RawItemData
from app.config import settings

logger = logging.getLogger(__name__)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "ransomware_live_victims.json"
API_URL = "https://api.ransomware.live/v2/recentvictims"
CACHE_FILE = Path("/tmp/dww_ransomware_live_cache.json")


class RansomwareLiveCollector(BaseCollector):
    name = "ransomware_live"
    poll_interval_seconds = 900  # 15 min

    async def fetch(self) -> list[RawItemData]:
        if settings.replay_mode:
            return self._load_fixture()

        headers = {}
        if settings.ransomware_live_pro_key:
            headers["Authorization"] = f"Bearer {settings.ransomware_live_pro_key}"

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(API_URL, headers=headers)
                resp.raise_for_status()
                data = resp.json()

            # Cache the response
            CACHE_FILE.write_text(json.dumps(data))
            victims = data if isinstance(data, list) else data.get("data", [])
            return self._parse(victims, "live")

        except Exception as e:
            logger.warning(f"[ransomware_live] live fetch failed: {e}. Falling back to cache.")
            return self._load_cache_or_fixture()

    def _load_fixture(self) -> list[RawItemData]:
        data = json.loads(FIXTURE.read_text())
        if isinstance(data, list):
            victims = data
        else:
            victims = data.get("victims", data.get("data", []))
        return self._parse(victims, "replay")

    def _load_cache_or_fixture(self) -> list[RawItemData]:
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text())
            victims = data if isinstance(data, list) else data.get("data", [])
            return self._parse(victims, "replay")
        return self._load_fixture()

    def _parse(self, victims: list, origin: str) -> list[RawItemData]:
        items = []
        for v in victims:
            name = v.get("victim", v.get("name", v.get("domain", "")))
            group = v.get("group", v.get("group_name", ""))
            published = v.get("published", v.get("discovered", ""))
            country = v.get("country", "")
            activity = v.get("activity", v.get("sector", ""))
            url = v.get("url", v.get("post_url", ""))

            text = (
                f"Ransomware victim: {name}\n"
                f"Group: {group}\n"
                f"Published: {published}\n"
                f"Country: {country}\n"
                f"Sector: {activity}\n"
            )

            items.append(RawItemData(
                source=self.name,
                url=url or f"https://ransomware.live/#victim={name}",
                text=text,
                data_origin=origin,
                extra={"victim": name, "group": group, "published": published},
            ))
        return items
