import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any


PARKING_MARKERS = (
    "sedoparking", "parkingcrew", "bodis", "above.com", "dan.com",
    "afternic", "undeveloped", "domain-for-sale", "parklogic",
)


def compact_snapshot(dns: dict | None, rdap: dict | None, tls: dict | None) -> dict[str, Any]:
    records = (dns or {}).get("records") or {}
    events = [
        {"action": item.get("eventAction"), "date": item.get("eventDate")}
        for item in (rdap or {}).get("events", [])
        if item.get("eventAction") in {"registration", "registered", "expiration", "last changed"}
    ]
    return {
        "dns": {key: sorted(set(records.get(key) or [])) for key in ("A", "AAAA", "CNAME", "MX", "NS")},
        "rdap": {
            "status": sorted(set((rdap or {}).get("status") or [])),
            "nameservers": sorted({item.get("ldhName", "").lower() for item in (rdap or {}).get("nameservers", []) if item.get("ldhName")}),
            "events": events,
        },
        "tls": None if not tls else {
            "sha256": tls.get("sha256"), "issuer": tls.get("issuer"),
            "not_before": tls.get("not_before"), "not_after": tls.get("not_after"),
        },
    }


def classify_snapshot(snapshot: dict[str, Any]) -> str:
    dns = snapshot.get("dns") or {}
    infrastructure = [str(value).lower() for kind in ("CNAME", "NS", "MX") for value in dns.get(kind, [])]
    if any(marker in value for marker in PARKING_MARKERS for value in infrastructure):
        return "likely_parked"
    if dns.get("A") or dns.get("AAAA") or dns.get("CNAME") or snapshot.get("tls"):
        return "active_infrastructure"
    if not any(dns.get(kind) for kind in ("A", "AAAA", "CNAME", "MX", "NS")):
        return "inactive"
    return "unknown"


def snapshot_hash(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def meaningful_changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    changes: list[str] = []
    before_class, after_class = classify_snapshot(before), classify_snapshot(after)
    if before_class != after_class:
        changes.append(f"classification:{before_class}->{after_class}")
    for kind in ("A", "AAAA", "CNAME", "MX", "NS"):
        if (before.get("dns") or {}).get(kind, []) != (after.get("dns") or {}).get(kind, []):
            changes.append(f"dns:{kind.lower()}")
    if before.get("tls") != after.get("tls"):
        changes.append("tls:certificate")
    if (before.get("rdap") or {}) != (after.get("rdap") or {}):
        changes.append("rdap:registration")
    return changes


def next_check_time(monitor_id: str, interval_seconds: int, now: datetime | None = None) -> datetime:
    """Stable ±10% jitter prevents thousands of watches firing simultaneously."""
    current = now or datetime.now(timezone.utc)
    bucket = int(hashlib.sha256(monitor_id.encode()).hexdigest()[:8], 16) % 2001 - 1000
    jitter = int(interval_seconds * bucket / 10000)
    return current + timedelta(seconds=max(900, interval_seconds + jitter))
