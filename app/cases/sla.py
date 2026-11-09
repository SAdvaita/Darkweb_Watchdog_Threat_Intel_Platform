from datetime import datetime, timedelta

SLA_HOURS = {
    "critical": {"ack": 1, "contain": 4},
    "high": {"ack": 4, "contain": 24},
    "medium": {"ack": 24, "contain": 72},
    "low": {"ack": 72, "contain": 168},
}


def compute_sla(severity: str, created_at: datetime):
    hours = SLA_HOURS.get(severity, SLA_HOURS["low"])
    ack_due = created_at + timedelta(hours=hours["ack"])
    contain_due = created_at + timedelta(hours=hours["contain"])
    return ack_due, contain_due
