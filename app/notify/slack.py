import httpx
import logging
from app.config import settings

logger = logging.getLogger(__name__)


async def send_slack(message: str):
    if not settings.slack_webhook_url:
        logger.debug("Slack not configured, skipping notification")
        return
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                settings.slack_webhook_url,
                json={"text": message},
                timeout=10,
            )
    except Exception as e:
        logger.error(f"Slack notification failed: {e}")
