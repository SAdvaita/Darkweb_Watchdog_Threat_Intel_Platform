"""
AlienVault OTX collector — fetches threat pulses and indicators.
Free API key required. Poll hourly.
"""
import json
import logging
from pathlib import Path

import httpx

from app.collectors.base import BaseCollector, RawItemData
from app.config import settings

logger = logging.getLogger(__name__)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "otx_pulses.json"
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


class OTXCollector(BaseCollector):
    name = "otx_pulses"
    poll_interval_seconds = 3600  # 1 hour

    async def fetch(self) -> list[RawItemData]:
        if settings.replay_mode:
            return self._load_fixture()

        if not settings.alienvault_otx_key:
            logger.info("[otx] No OTX API key configured, using fixture")
            return self._load_fixture()

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    OTX_URL,
                    headers={"X-OTX-API-KEY": settings.alienvault_otx_key},
                    params={"limit": 20, "page": 1},
                )
                resp.raise_for_status()
                data = resp.json()

            pulses = data.get("results", [])
            return self._parse(pulses, "live")

        except Exception as e:
            logger.warning(f"[otx] fetch failed: {e}. Using fixture.")
            return self._load_fixture()

    def _parse(self, pulses: list, origin: str) -> list[RawItemData]:
        items = []
        for pulse in pulses:
            indicators = pulse.get("indicators", [])
            indicator_text = "\n".join(
                f"  {ind.get('type', '')}: {ind.get('indicator', '')}"
                for ind in indicators[:20]
            )
            text = (
                f"OTX Pulse: {pulse.get('name', '')}\n"
                f"Description: {pulse.get('description', '')}\n"
                f"Tags: {', '.join(pulse.get('tags', []))}\n"
                f"Indicators:\n{indicator_text}\n"
                f"malicious threat indicator ioc\n"
            )
            items.append(RawItemData(
                source=self.name,
                url=f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                text=text,
                data_origin=origin,
                extra={"pulse_id": pulse.get("id"), "tags": pulse.get("tags", [])},
            ))
        return items

    def _load_fixture(self) -> list[RawItemData]:
        data = json.loads(FIXTURE.read_text())
        return self._parse(data.get("results", []), "replay")


class ThreatFoxCollector(BaseCollector):
    """Fetches recent IOCs from abuse.ch ThreatFox."""
    name = "threatfox"
    poll_interval_seconds = 3600

    async def fetch(self) -> list[RawItemData]:
        if settings.replay_mode:
            return self._load_fixture()

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "get_iocs", "days": 1},
                )
                resp.raise_for_status()
                data = resp.json()

            iocs = data.get("data", [])
            return self._parse(iocs, "live")

        except Exception as e:
            logger.warning(f"[threatfox] fetch failed: {e}")
            return self._load_fixture()

    def _load_fixture(self) -> list[RawItemData]:
        fixture = Path(__file__).parents[2] / "fixtures" / "threatfox_iocs.json"
        data = json.loads(fixture.read_text())
        return self._parse(data.get("data", []), "replay")

    def _parse(self, iocs: list, origin: str) -> list[RawItemData]:
        if not iocs:
            return []
        summary = "\n".join(
            f"  {i.get('ioc_type','')}: {i.get('ioc','')} ({i.get('malware','')})"
            for i in iocs[:30]
        )
        text = f"ThreatFox IOC batch\nmalicious indicator ioc\nEntries:\n{summary}\n"
        return [RawItemData(
            source=self.name,
            url="https://threatfox.abuse.ch/",
            text=text,
            data_origin=origin,
            extra={"count": len(iocs)},
        )]
