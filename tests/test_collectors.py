"""
Respx-mocked collector tests + fixture replay tests.
Every collector must be tested in both live (mocked) and replay mode.
"""
import json
import pytest
import respx
import httpx
from pathlib import Path
from unittest.mock import patch

FIXTURES = Path(__file__).parents[1] / "fixtures"


# ─── ransomware.live ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_ransomware_live_collector_live():
    """Mocked live fetch returns parsed items."""
    mock_data = [
        {"victim": "acme-corp.com", "group": "lockbit", "published": "2024-01-10",
         "country": "US", "activity": "Manufacturing", "url": ""},
    ]
    respx.get("https://api.ransomware.live/v2/recentvictims").mock(
        return_value=httpx.Response(200, json=mock_data)
    )

    with patch("app.config.settings.replay_mode", False):
        from app.collectors.ransomware_live import RansomwareLiveCollector
        c = RansomwareLiveCollector()
        items = await c.fetch()

    assert len(items) >= 1
    assert items[0].source == "ransomware_live"
    assert items[0].data_origin == "live"
    assert "acme-corp.com" in items[0].text


@pytest.mark.asyncio
async def test_ransomware_live_collector_replay():
    """Fixture replay returns items with data_origin=replay."""
    with patch("app.config.settings.replay_mode", True):
        from app.collectors.ransomware_live import RansomwareLiveCollector
        c = RansomwareLiveCollector()
        items = await c.fetch()

    assert all(i.data_origin == "replay" for i in items)
    assert all(i.source == "ransomware_live" for i in items)


# ─── crt.sh ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_crt_sh_collector_live():
    """Mocked crt.sh returns certificate entries."""
    mock_certs = [
        {"id": 111, "common_name": "api.example.com",
         "logged_at": "2024-01-15T10:00:00Z", "issuer_name": "Let's Encrypt"},
        {"id": 112, "common_name": "examp1e.com",
         "logged_at": "2024-01-15T11:00:00Z", "issuer_name": "Let's Encrypt"},
    ]
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(200, json=mock_certs)
    )

    with patch("app.config.settings.replay_mode", False), \
         patch("app.config.settings.watched_domains", "example.com"):
        from app.collectors.crt_sh import CrtShCollector
        c = CrtShCollector()
        items = await c.fetch()

    assert len(items) >= 1
    assert items[0].source == "crt_sh"


@pytest.mark.asyncio
async def test_crt_sh_collector_replay():
    with patch("app.config.settings.replay_mode", True):
        from app.collectors.crt_sh import CrtShCollector
        c = CrtShCollector()
        items = await c.fetch()

    assert all(i.data_origin == "replay" for i in items)


# ─── GitHub Gists ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_github_gists_collector_live():
    """Mocked GitHub gists fetch."""
    mock_gists = [
        {
            "id": "abc123",
            "description": "server config",
            "html_url": "https://gist.github.com/user/abc123",
            "created_at": "2024-01-15T09:00:00Z",
            "owner": {"login": "testuser"},
            "files": {
                "config.env": {
                    "filename": "config.env",
                    "raw_url": "https://gist.githubusercontent.com/user/abc123/raw/config.env",
                    "content": "DB_PASS=SuperSecret123!\n",
                }
            },
        }
    ]
    respx.get("https://api.github.com/gists/public").mock(
        return_value=httpx.Response(200, json=mock_gists)
    )
    respx.get(url__startswith="https://gist.githubusercontent.com/").mock(
        return_value=httpx.Response(200, text="DB_PASS=SuperSecret123!\n")
    )

    with patch("app.config.settings.replay_mode", False), \
         patch("app.config.settings.github_token", "fake-token"):
        from app.collectors.github_gists import GitHubGistsCollector
        c = GitHubGistsCollector()
        items = await c.fetch()

    assert len(items) >= 1
    assert items[0].source == "github_gist"
    assert items[0].data_origin == "live"


@pytest.mark.asyncio
async def test_github_gists_collector_replay():
    with patch("app.config.settings.replay_mode", True):
        from app.collectors.github_gists import GitHubGistsCollector
        c = GitHubGistsCollector()
        items = await c.fetch()

    assert all(i.data_origin == "replay" for i in items)


# ─── Hudson Rock ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_hudson_rock_collector_live():
    mock_data = {
        "stealers": {
            "total_corporate_credentials": 2,
            "total_users": 5,
            "compromised_employees": 2,
        }
    }
    respx.get(url__startswith="https://cavalier.hudsonrock.com/").mock(
        return_value=httpx.Response(200, json=mock_data)
    )

    with patch("app.config.settings.replay_mode", False), \
         patch("app.config.settings.watched_domains", "example.com"):
        from app.collectors.hudson_rock import HudsonRockCollector
        c = HudsonRockCollector()
        items = await c.fetch()

    assert len(items) >= 1
    assert "compromised_employees" in items[0].text


@pytest.mark.asyncio
async def test_hudson_rock_collector_replay():
    with patch("app.config.settings.replay_mode", True):
        from app.collectors.hudson_rock import HudsonRockCollector
        c = HudsonRockCollector()
        items = await c.fetch()

    assert all(i.data_origin == "replay" for i in items)


# ─── data_origin field integrity ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_replay_items_never_presented_as_live():
    """Critical: replay data must NEVER have data_origin=live."""
    from app.collectors.ransomware_live import RansomwareLiveCollector
    from app.collectors.crt_sh import CrtShCollector
    from app.collectors.github_gists import GitHubGistsCollector
    from app.collectors.hudson_rock import HudsonRockCollector

    collectors = [
        RansomwareLiveCollector(),
        CrtShCollector(),
        GitHubGistsCollector(),
        HudsonRockCollector(),
    ]

    with patch("app.config.settings.replay_mode", True):
        for collector in collectors:
            items = await collector.fetch()
            for item in items:
                assert item.data_origin != "live", (
                    f"{collector.name} returned data_origin='live' in replay mode!"
                )
