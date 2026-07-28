from sqlalchemy import select
from sqlalchemy.orm import Session

from .brand_catalog import CatalogBrand, get_catalog
from .detection import canonical_brand
from .models import AuditEvent, ProtectedBrand, SourceConnector


CONNECTOR_DEFAULTS = {
    "certificate_transparency": (True, "configured"),
    "dns_candidates": (True, "configured"),
    "rdap_candidates": (True, "configured"),
    "urlscan": (True, "configured"),
    "urlhaus": (True, "configured"),
    "czds": (False, "credential_required"),
}


def ensure_connectors(db: Session, tenant_id: str) -> None:
    existing = set(
        db.scalars(select(SourceConnector.connector_type).where(SourceConnector.tenant_id == tenant_id)).all()
    )
    for connector_type, (enabled, status) in CONNECTOR_DEFAULTS.items():
        if connector_type not in existing:
            db.add(
                SourceConnector(
                    tenant_id=tenant_id,
                    connector_type=connector_type,
                    enabled=enabled,
                    status=status,
                )
            )


def enroll_catalog(
    db: Session,
    tenant_id: str,
    keys: list[str] | None = None,
    *,
    monitoring_enabled: bool = True,
    actor: str = "catalog-enrollment",
) -> tuple[list[ProtectedBrand], list[ProtectedBrand]]:
    catalog = get_catalog(keys)
    existing = {
        brand.canonical_name: brand
        for brand in db.scalars(select(ProtectedBrand).where(ProtectedBrand.tenant_id == tenant_id)).all()
    }
    created: list[ProtectedBrand] = []
    updated: list[ProtectedBrand] = []
    for entry in catalog:
        canonical_name = canonical_brand(entry.name)
        brand = existing.get(canonical_name)
        if brand:
            brand.official_domains = list(entry.official_domains)
            brand.trademarks = list(entry.trademarks)
            brand.keywords = list(entry.keywords)
            brand.permitted_variations = list(entry.permitted_variations)
            brand.monitoring_enabled = monitoring_enabled
            updated.append(brand)
            continue
        brand = ProtectedBrand(
            tenant_id=tenant_id,
            name=entry.name,
            canonical_name=canonical_name,
            official_domains=list(entry.official_domains),
            trademarks=list(entry.trademarks),
            keywords=list(entry.keywords),
            permitted_variations=list(entry.permitted_variations),
            monitoring_enabled=monitoring_enabled,
        )
        db.add(brand)
        db.flush()
        existing[canonical_name] = brand
        created.append(brand)
        db.add(
            AuditEvent(
                tenant_id=tenant_id,
                actor=actor,
                action="brand.catalog_enrolled",
                resource_type="protected_brand",
                resource_id=brand.id,
                payload={"catalog_key": entry.key, "monitoring_enabled": monitoring_enabled},
            )
        )
    ensure_connectors(db, tenant_id)
    return created, updated
