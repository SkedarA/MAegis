from datetime import datetime, timedelta, timezone


OPEN_STATUSES = {"new", "investigating", "likely_abuse", "confirmed", "monitoring"}
SEVERITIES = ("informational", "low", "medium", "high", "critical")
STATUSES = ("new", "investigating", "likely_abuse", "confirmed", "false_positive", "monitoring", "closed")


def _value(value) -> str:
    return str(getattr(value, "value", value))


def build_dashboard_summary(
    incident_rows: list[dict],
    brands: list[dict],
    *,
    days: int = 30,
    now: datetime | None = None,
) -> dict:
    current = now or datetime.now(timezone.utc)
    threshold = None if days == 0 else current - timedelta(days=days)
    rows = [row for row in incident_rows if threshold is None or row["created_at"] >= threshold]
    by_brand = {
        brand["id"]: {
            "brand_id": brand["id"],
            "name": brand["name"],
            "monitoring_enabled": brand.get("monitoring_enabled", True),
            "total": 0,
            "open": 0,
            "critical": 0,
            "high": 0,
            "unassigned": 0,
            "max_risk": 0,
            "average_risk": 0,
            "_risk_total": 0.0,
        }
        for brand in brands
    }
    by_severity = {value: 0 for value in SEVERITIES}
    by_status = {value: 0 for value in STATUSES}
    timeline: dict[str, dict[str, int | str]] = {}

    for row in rows:
        severity = _value(row["severity"])
        status = _value(row["status"])
        risk = float(row.get("risk_score") or 0)
        brand = by_brand.setdefault(row["brand_id"], {
            "brand_id": row["brand_id"], "name": "Unknown brand", "monitoring_enabled": False,
            "total": 0, "open": 0, "critical": 0, "high": 0, "unassigned": 0,
            "max_risk": 0, "average_risk": 0, "_risk_total": 0.0,
        })
        brand["total"] += 1
        brand["open"] += int(status in OPEN_STATUSES)
        brand["critical"] += int(severity == "critical")
        brand["high"] += int(severity == "high")
        brand["unassigned"] += int(status in OPEN_STATUSES and not row.get("assigned_to"))
        brand["max_risk"] = max(brand["max_risk"], round(risk))
        brand["_risk_total"] += risk
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        day = row["created_at"].date().isoformat()
        bucket = timeline.setdefault(day, {"date": day, "total": 0, "high_critical": 0})
        bucket["total"] += 1
        bucket["high_critical"] += int(severity in {"high", "critical"})

    brand_rows = []
    for brand in by_brand.values():
        brand["average_risk"] = round(brand["_risk_total"] / brand["total"], 1) if brand["total"] else 0
        brand.pop("_risk_total")
        brand_rows.append(brand)

    total = len(rows)
    return {
        "window_days": days,
        "generated_at": current.isoformat(),
        "totals": {
            "incidents": total,
            "open": sum(by_status.get(value, 0) for value in OPEN_STATUSES),
            "critical": by_severity["critical"],
            "unassigned": sum(1 for row in rows if _value(row["status"]) in OPEN_STATUSES and not row.get("assigned_to")),
            "average_risk": round(sum(float(row.get("risk_score") or 0) for row in rows) / total, 1) if total else 0,
            "clients": len(brands),
        },
        "by_brand": sorted(brand_rows, key=lambda item: (item["open"], item["max_risk"], item["total"]), reverse=True),
        "by_severity": by_severity,
        "by_status": by_status,
        "timeline": sorted(timeline.values(), key=lambda item: item["date"]),
    }
