"""
Certificate Transparency collector — queries crt.sh for new certificates
matching watched domains and detects lookalike domains.
Rate limit: ~5 req/min. We poll every 15–30 min with caching.
"""
import json
import logging
import re
from pathlib import Path

import httpx

from app.collectors.base import BaseCollector, RawItemData
from app.config import settings

logger = logging.getLogger(__name__)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "crt_sh_certs.json"
CACHE_FILE = Path("/tmp/dww_crt_sh_cache.json")


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance between two strings."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _is_lookalike(cert_name: str, watched: str, max_dist: int = 2) -> bool:
    """Check if cert_name is a lookalike of a watched domain."""
    cert_base = cert_name.lstrip("*.")
    watched_base = watched.lstrip("*.")
    if cert_base == watched_base:
        return False  # exact match, not a lookalike
    dist = _edit_distance(cert_base.split(".")[0], watched_base.split(".")[0])
    return 0 < dist <= max_dist


class CrtShCollector(BaseCollector):
    name = "crt_sh"
    poll_interval_seconds = 900

    async def fetch(self) -> list[RawItemData]:
        if settings.replay_mode:
            return self._load_fixture()

        domains = settings.watched_domains_list()
        if not domains:
            logger.info("[crt_sh] No watched domains configured")
            return []

        all_items: list[RawItemData] = []
        for domain in domains:
            try:
                items = await self._fetch_domain(domain)
                all_items.extend(items)
            except Exception as e:
                logger.warning(f"[crt_sh] fetch failed for {domain}: {e}")

        return all_items

    async def _fetch_domain(self, domain: str) -> list[RawItemData]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            certs = resp.json()

        # Cache
        CACHE_FILE.write_text(json.dumps({"domain": domain, "certs": certs[:200]}))
        return self._parse(certs[:200], domain, "live")

    def _load_fixture(self) -> list[RawItemData]:
        data = json.loads(FIXTURE.read_text())
        certs = data if isinstance(data, list) else data.get("certificates", [])
        domains = settings.watched_domains_list() or ["example.com"]
        return self._parse(certs, domains[0], "replay")

    def _parse(self, certs: list, watched_domain: str, origin: str) -> list[RawItemData]:
        items = []
        seen = set()
        for cert in certs:
            name = cert.get("common_name", cert.get("name_value", "")).split("\n")[0].strip()
            if not name or name in seen:
                continue
            seen.add(name)

            is_lookalike = _is_lookalike(name, watched_domain)
            tag = "lookalike" if is_lookalike else "subdomain"

            text = (
                f"Certificate Transparency entry\n"
                f"Domain: {name}\n"
                f"Watched domain: {watched_domain}\n"
                f"Tag: {tag}\n"
                f"Issuer: {cert.get('issuer_name', '')}\n"
                f"Logged at: {cert.get('logged_at', cert.get('not_before', ''))}\n"
            )
            if is_lookalike:
                text += f"lookalike domain {name} detected\n"

            items.append(RawItemData(
                source=self.name,
                url=f"https://crt.sh/?id={cert.get('id', '')}",
                text=text,
                data_origin=origin,
                extra={"name": name, "is_lookalike": is_lookalike, "watched": watched_domain},
            ))
        return items
