"""
GitHub collector — monitors public gists and events for exposed secrets/credentials.
Uses GitHub REST API with personal token.
Rate limit: 5000 req/hr with token, 60 req/hr without.
"""
import json
import logging
from pathlib import Path

import httpx

from app.collectors.base import BaseCollector, RawItemData
from app.config import settings

logger = logging.getLogger(__name__)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "github_gists.json"
GISTS_URL = "https://api.github.com/gists/public"
EVENTS_URL = "https://api.github.com/events"


class GitHubGistsCollector(BaseCollector):
    name = "github_gist"
    poll_interval_seconds = 300  # 5 min

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github.v3+json"}
        if settings.github_token:
            h["Authorization"] = f"token {settings.github_token}"
        return h

    async def fetch(self) -> list[RawItemData]:
        if settings.replay_mode:
            return self._load_fixture()

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    GISTS_URL,
                    headers=self._headers(),
                    params={"per_page": 30},
                )
                resp.raise_for_status()
                gists = resp.json()

            items: list[RawItemData] = []
            for gist in gists:
                content = await self._fetch_gist_content(gist)
                if content:
                    items.append(self._make_item(gist, content, "live"))
            return items

        except Exception as e:
            logger.warning(f"[github_gist] fetch failed: {e}. Using fixture.")
            return self._load_fixture()

    async def _fetch_gist_content(self, gist: dict) -> str:
        """Fetch and concatenate all files in a gist."""
        files = gist.get("files", {})
        parts = []
        for fname, finfo in files.items():
            raw_url = finfo.get("raw_url", "")
            if raw_url:
                try:
                    async with httpx.AsyncClient(timeout=10) as client:
                        r = await client.get(raw_url, headers=self._headers())
                        if r.status_code == 200:
                            parts.append(f"# {fname}\n{r.text[:2000]}")
                except Exception:
                    # Include whatever inline content we have
                    inline = finfo.get("content", "")
                    if inline:
                        parts.append(f"# {fname}\n{inline[:2000]}")
            else:
                inline = finfo.get("content", "")
                if inline:
                    parts.append(f"# {fname}\n{inline[:2000]}")
        return "\n\n".join(parts)

    def _make_item(self, gist: dict, content: str, origin: str) -> RawItemData:
        description = gist.get("description", "")
        url = gist.get("html_url", "")
        owner = gist.get("owner", {}).get("login", "unknown")
        created = gist.get("created_at", "")

        text = (
            f"GitHub Gist by {owner}\n"
            f"Description: {description}\n"
            f"Created: {created}\n"
            f"URL: {url}\n\n"
            f"{content}"
        )
        return RawItemData(source=self.name, url=url, text=text, data_origin=origin)

    def _load_fixture(self) -> list[RawItemData]:
        data = json.loads(FIXTURE.read_text())
        gists = data if isinstance(data, list) else data.get("gists", [])
        items = []
        for gist in gists:
            # Inline file content from fixture
            content_parts = []
            for fname, finfo in gist.get("files", {}).items():
                content_parts.append(f"# {fname}\n{finfo.get('content', '')}")
            content = "\n\n".join(content_parts)
            items.append(self._make_item(gist, content, "replay"))
        return items


class GitHubEventsCollector(BaseCollector):
    """Monitors GitHub public events for push events that may expose secrets."""
    name = "github_events"
    poll_interval_seconds = 300

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github.v3+json"}
        if settings.github_token:
            h["Authorization"] = f"token {settings.github_token}"
        return h

    async def fetch(self) -> list[RawItemData]:
        if settings.replay_mode:
            return []  # No separate fixture for events; piggyback on gists fixture

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    EVENTS_URL,
                    headers=self._headers(),
                    params={"per_page": 30},
                )
                resp.raise_for_status()
                events = resp.json()

            items = []
            for event in events:
                if event.get("type") not in ("PushEvent", "GistEvent", "CreateEvent"):
                    continue
                payload = event.get("payload", {})
                commits = payload.get("commits", [])
                for commit in commits:
                    msg = commit.get("message", "")
                    if msg:
                        text = (
                            f"GitHub {event['type']} by {event.get('actor', {}).get('login', '')}\n"
                            f"Repo: {event.get('repo', {}).get('name', '')}\n"
                            f"Message: {msg}\n"
                        )
                        url = f"https://github.com/{event.get('repo', {}).get('name', '')}"
                        items.append(RawItemData(
                            source=self.name, url=url, text=text, data_origin="live"
                        ))
            return items

        except Exception as e:
            logger.warning(f"[github_events] fetch failed: {e}")
            return []
