from datetime import datetime, timezone


def worker_is_fresh(last_seen_at: datetime | None, stale_after_seconds: int, *, now: datetime | None = None) -> bool:
    if last_seen_at is None or stale_after_seconds <= 0:
        return False
    current = now or datetime.now(timezone.utc)
    observed = last_seen_at if last_seen_at.tzinfo else last_seen_at.replace(tzinfo=timezone.utc)
    return 0 <= (current - observed).total_seconds() <= stale_after_seconds
