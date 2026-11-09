import statistics
from typing import Dict, Any, List
from sqlmodel import Session, select
from app.models import Canary


def calculate_latency_metrics(session: Session) -> Dict[str, Any]:
    """
    Computes time-to-detect latency statistics:
    - Overall count planted, detected
    - Median time-to-detect (seconds)
    - 95th percentile time-to-detect (seconds)
    - Per-source latency breakdowns
    """
    all_canaries = session.exec(select(Canary).order_by(Canary.planted_at.desc())).all()
    detected = [c for c in all_canaries if c.time_to_detect_seconds is not None]

    total_planted = len(all_canaries)
    total_detected = len(detected)

    overall_ttd = [c.time_to_detect_seconds for c in detected]

    median_ttd = round(statistics.median(overall_ttd), 2) if overall_ttd else 0.0

    if len(overall_ttd) >= 2:
        sorted_ttd = sorted(overall_ttd)
        idx_95 = int(0.95 * len(sorted_ttd))
        p95_ttd = round(sorted_ttd[min(idx_95, len(sorted_ttd) - 1)], 2)
    elif overall_ttd:
        p95_ttd = overall_ttd[0]
    else:
        p95_ttd = 0.0

    # Group by source
    by_source: Dict[str, List[float]] = {}
    for c in detected:
        src = c.detected_source or "unknown"
        by_source.setdefault(src, []).append(c.time_to_detect_seconds)

    source_metrics = {}
    for src, times in by_source.items():
        source_metrics[src] = {
            "count": len(times),
            "median_seconds": round(statistics.median(times), 2),
            "p95_seconds": round(sorted(times)[int(0.95 * len(times))] if len(times) > 1 else times[0], 2),
        }

    return {
        "total_planted": total_planted,
        "total_detected": total_detected,
        "detection_rate_pct": round((total_detected / total_planted * 100), 1) if total_planted > 0 else 0.0,
        "median_ttd_seconds": median_ttd,
        "p95_ttd_seconds": p95_ttd,
        "by_source": source_metrics,
        "canaries": [
            {
                "id": c.id,
                "type": c.type,
                "marker": c.marker,
                "location_url": c.location_url,
                "planted_at": c.planted_at.isoformat() if c.planted_at else None,
                "first_detected_at": c.first_detected_at.isoformat() if c.first_detected_at else None,
                "detected_source": c.detected_source,
                "time_to_detect_seconds": c.time_to_detect_seconds,
                "status": "detected" if c.first_detected_at else "pending",
            }
            for c in all_canaries
        ],
    }
