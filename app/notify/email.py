import logging

logger = logging.getLogger(__name__)


async def send_email(subject: str, body: str, to: str):
    logger.info(f"Email notification (not configured): {subject}")
