from datetime import datetime, timezone


def build_alerts(findings: list[dict]) -> list[dict]:
    alerts = []
    for index, finding in enumerate(findings, 1):
        alerts.append({
            "id": f"ALT-{index:04d}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "open",
            **finding,
        })
    return alerts
