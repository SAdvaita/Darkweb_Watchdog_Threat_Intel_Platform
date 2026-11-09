import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Set
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter()

# Active subscriber queues for Server-Sent Events
_subscribers: Set[asyncio.Queue] = set()


async def push_event(event: dict):
    """Broadcast an event to all connected SSE clients."""
    if not _subscribers:
        return
    for q in list(_subscribers):
        try:
            q.put_nowait(event)
        except Exception:
            pass


@router.get("/stream")
@router.get("/stream/findings")
async def stream_findings():
    """
    Server-Sent Events endpoint for real-time findings and alerts.
    Data items carry data_origin tags (live, replay, canary).
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _subscribers.add(queue)

    async def event_generator():
        try:
            # Initial connection confirmation
            connect_msg = {
                "type": "connected",
                "ts": datetime.now(timezone.utc).isoformat(),
                "service": "DarkWeb Watchdog Realtime Feed",
            }
            yield f"data: {json.dumps(connect_msg)}\n\n"

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(event, default=str)}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat to keep connection alive
                    hb = {"type": "heartbeat", "ts": datetime.now(timezone.utc).isoformat()}
                    yield f"data: {json.dumps(hb)}\n\n"
        finally:
            _subscribers.discard(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
