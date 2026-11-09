import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import create_db_and_tables, get_session

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()
STATIC_DIR = Path(__file__).parent / "static"


async def _run_all():
    """Scheduled task: run all collectors through the pipeline."""
    from app.collectors.registry import run_all_collectors
    results = await run_all_collectors()
    logger.info(f"Collector run complete: {results}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("DarkWeb Watchdog starting up...")
    create_db_and_tables()
    logger.info("Database initialized")

    # Schedule collectors — run every 5 minutes
    scheduler.add_job(
        _run_all,
        "interval",
        seconds=300,
        id="collector_run",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    logger.info("Scheduler started — collectors will run every 5 minutes")

    yield

    scheduler.shutdown(wait=False)
    logger.info("DarkWeb Watchdog shut down")


app = FastAPI(
    title="DarkWeb Watchdog",
    description="Canary-validated external exposure intelligence platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static Files & Dashboard UI ───────────────────────────────────────────────
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── Routers ───────────────────────────────────────────────────────────────────
from app.routers import (  # noqa: E402
    findings,
    cases,
    graph,
    rules,
    canaries,
    sources,
    metrics,
    exports,
    audit,
    stream,
)

app.include_router(findings.router, prefix="/findings", tags=["findings"])
app.include_router(cases.router, prefix="/cases", tags=["cases"])
app.include_router(graph.router, prefix="/graph", tags=["graph"])
app.include_router(rules.router, prefix="/rules", tags=["rules"])
app.include_router(canaries.router, prefix="/canaries", tags=["canaries"])
app.include_router(sources.router, prefix="/sources", tags=["sources"])
app.include_router(metrics.router, prefix="/metrics", tags=["metrics"])
app.include_router(exports.router, prefix="/export", tags=["exports"])
app.include_router(audit.router, prefix="/audit", tags=["audit"])
app.include_router(stream.router, tags=["stream"])


@app.get("/", tags=["health"])
async def root(request: Request):
    # If opened in browser (accepts html), serve the rich dashboard
    accept = request.headers.get("accept", "")
    if "text/html" in accept and (STATIC_DIR / "index.html").exists():
        return FileResponse(STATIC_DIR / "index.html")
    return {
        "name": "DarkWeb Watchdog",
        "version": "0.1.0",
        "status": "operational",
        "dashboard": "/dashboard",
        "docs": "/docs",
        "replay_mode": settings.replay_mode,
    }


@app.get("/dashboard", include_in_schema=False)
@app.get("/ui", include_in_schema=False)
async def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok"}


@app.get("/report.pdf", tags=["exports"])
async def root_report_pdf(session=Depends(get_session)):
    from app.routers.exports import export_pdf
    return await export_pdf(session=session)


@app.post("/collect/run", tags=["admin"])
async def trigger_collect():
    """Manually trigger a full collector run (admin endpoint)."""
    asyncio.create_task(_run_all())
    return {"status": "triggered"}
