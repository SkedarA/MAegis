from .config import get_settings
from .database import SessionLocal
from .models import WorkerHeartbeat
from .runtime_health import worker_is_fresh


def main() -> None:
    settings = get_settings()
    with SessionLocal() as db:
        heartbeat = db.get(WorkerHeartbeat, "discovery")
        healthy = bool(
            heartbeat
            and heartbeat.status in {"healthy", "running"}
            and worker_is_fresh(heartbeat.last_seen_at, settings.worker_health_stale_seconds)
        )
    raise SystemExit(0 if healthy else 1)


if __name__ == "__main__":
    main()
