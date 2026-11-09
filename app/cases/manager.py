import json
import logging
from datetime import datetime, timezone
from typing import List, Optional
from sqlmodel import Session, select

from app.models import Case, CaseFinding, Finding
from app.cases.sla import compute_sla
from app.cases.audit import log_action
from app.notify.telegram import send_telegram
from app.notify.slack import send_slack

logger = logging.getLogger(__name__)


def create_case(session: Session, title: str, severity: str, finding_ids: List[int]) -> Case:
    now = datetime.now(timezone.utc)
    ack_due, contain_due = compute_sla(severity, now)

    case = Case(
        title=title,
        severity=severity,
        sla_ack_due=ack_due,
        sla_contain_due=contain_due,
        created_at=now,
        updated_at=now,
        status="new",
    )
    session.add(case)
    session.commit()
    session.refresh(case)

    for fid in finding_ids:
        cf = CaseFinding(case_id=case.id, finding_id=fid)
        session.add(cf)

    log_action(session, "system", "case_created", {"case_id": case.id, "title": title, "severity": severity})
    session.commit()
    session.refresh(case)
    return case


async def handle_high_severity_alert(
    session: Session, finding: Finding, playbook: str = ""
) -> Case:
    """
    Called for High and Critical findings:
    1. Creates an SLA-tracked Case
    2. Links the Finding
    3. Sends formatted alerts with score breakdown and playbook link to Telegram and Slack
    """
    title = f"INC-{finding.severity.upper()}: {finding.title}"
    case = create_case(session, title=title, severity=finding.severity, finding_ids=[finding.id])

    # Format explainable score breakdown
    breakdown = json.loads(finding.score_breakdown or "{}")
    breakdown_parts = [f"{k}: +{v}" for k, v in breakdown.items() if v]
    breakdown_text = ", ".join(breakdown_parts) if breakdown_parts else "N/A"

    playbook_ref = f"/playbooks/{playbook}.md" if playbook else "N/A"

    alert_html = (
        f"🚨 <b>DarkWeb Watchdog Alert [{finding.severity.upper()}]</b>\n"
        f"<b>Title:</b> {finding.title}\n"
        f"<b>Score:</b> {finding.score}/100 (Confidence: {int(finding.confidence * 100)}%)\n"
        f"<b>Breakdown:</b> {breakdown_text}\n"
        f"<b>Case:</b> #{case.id} (SLA Ack: {case.sla_ack_due.strftime('%H:%M UTC')})\n"
        f"<b>Playbook:</b> {playbook_ref}\n"
    )

    alert_slack = (
        f":warning: *DarkWeb Watchdog Alert [{finding.severity.upper()}]*\n"
        f"*Title:* {finding.title}\n"
        f"*Score:* {finding.score}/100 (Confidence: {int(finding.confidence * 100)}%)\n"
        f"*Breakdown:* {breakdown_text}\n"
        f"*Case:* #{case.id}\n"
        f"*Playbook:* `{playbook_ref}`\n"
    )

    try:
        await send_telegram(alert_html)
    except Exception as e:
        logger.warning(f"Telegram notification dispatch error: {e}")

    try:
        await send_slack(alert_slack)
    except Exception as e:
        logger.warning(f"Slack notification dispatch error: {e}")

    return case
