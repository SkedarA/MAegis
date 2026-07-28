import argparse

from .brand_enrollment import enroll_catalog
from .database import Base, SessionLocal, engine
from .security import DEMO_TENANT_ID


def main() -> None:
    parser = argparse.ArgumentParser(description="Idempotently enroll the curated Romanian brand catalog")
    parser.add_argument("--tenant-id", default=DEMO_TENANT_ID)
    parser.add_argument("--brand", action="append", dest="keys", help="Catalog key to enroll; repeat as needed")
    parser.add_argument("--paused", action="store_true", help="Enroll brands with monitoring disabled")
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        created, updated = enroll_catalog(
            db,
            args.tenant_id,
            args.keys,
            monitoring_enabled=not args.paused,
            actor="seed-brands-cli",
        )
        db.commit()
        state = "paused" if args.paused else "monitored"
        print(f"MAegis catalog: {len(created)} created, {len(updated)} updated, state={state}")


if __name__ == "__main__":
    main()
