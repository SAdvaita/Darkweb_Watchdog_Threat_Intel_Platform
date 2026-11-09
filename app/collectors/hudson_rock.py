"""
Hudson Rock Cavalier OSINT collector — queries infostealer statistics for watched domains.
Returns statistics, NOT raw passwords. Privacy-preserving by design.
Rate limit: check Hudson Rock docs. We poll every 6 hours per domain.
"""
import json
import logging
from pathlib import Path

import httpx

from app.collectors.base import BaseCollector, RawItemData
from app.config import settings

logger = logging.getLogger(__name__)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "hudson_rock_domain.json"
BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2"


class HudsonRockCollector(BaseCollector):
    name = "hudson_rock"
    poll_interval_seconds = 21600  # 6 hours

    async def fetch(self) -> list[RawItemData]:
        if settings.replay_mode:
            return self._load_fixture()

        domains = settings.watched_domains_list()
        if not domains:
            logger.info("[hudson_rock] No watched domains configured")
            return []

        items = []
        for domain in domains:
            try:
                result = await self._query_domain(domain)
                items.extend(result)
            except Exception as e:
                logger.warning(f"[hudson_rock] query failed for {domain}: {e}")

        return items

    async def _query_domain(self, domain: str) -> list[RawItemData]:
        url = f"{BASE_URL}/osint-tools/search-by-domain"
        params = {"domain": domain}

        headers = {}
        if settings.hudson_rock_api_key:
            headers["Authorization"] = f"Bearer {settings.hudson_rock_api_key}"

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        return self._parse(data, domain, "live")

    def _parse(self, data: dict, domain: str, origin: str) -> list[RawItemData]:
        stealers = data.get("stealers", data)
        employees = stealers.get("total_corporate_credentials", 0)
        users = stealers.get("total_users", 0)
        compromised_employees = stealers.get("compromised_employees", 0)

        text = (
            f"Hudson Rock infostealer report for domain: {domain}\n"
            f"compromised_employees: {compromised_employees}\n"
            f"total_corporate_credentials: {employees}\n"
            f"total_users: {users}\n"
        )
        if compromised_employees > 0:
            text += f"stealer_logs: {compromised_employees} employees compromised\n"
            text += "credentials_exposed: true\n"

        return [RawItemData(
            source=self.name,
            url=f"https://cavalier.hudsonrock.com/",
            text=text,
            data_origin=origin,
            extra={
                "domain": domain,
                "compromised_employees": compromised_employees,
                "total_users": users,
            },
        )]

    def _load_fixture(self) -> list[RawItemData]:
        data = json.loads(FIXTURE.read_text())
        domain = data.get("domain", "example.com")
        return self._parse(data, domain, "replay")
