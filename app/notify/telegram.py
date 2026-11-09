import httpx
import logging
from app.config import settings

logger = logging.getLogger(__name__)


async def send_telegram(message: str):
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        logger.debug("Telegram not configured, skipping notification")
        return
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
                json={
                    "chat_id": settings.telegram_chat_id,
                    "text": message,
                    "parse_mode": "HTML",
                },
                timeout=10,
            )
    except Exception as e:
        logger.error(f"Telegram notification failed: {e}")
