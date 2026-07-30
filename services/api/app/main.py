import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .brand_catalog import get_catalog
from .brand_enrollment import enroll_catalog
from .config import get_settings
from .database import Base, engine, get_db
from .detection import DETECTOR_VERSION, analyze_domain, canonical_brand, normalize_domain
from .domain_context import build_domain_context
from .models import AnalystAccount, AuditEvent, BackgroundJob, Candidate, EvidenceItem, Incident, IncidentNote, IncidentStatus, Observation, ProtectedBrand, ScoreContribution, Severity, SourceConnector, WorkerHeartbeat
from .runtime_health import worker_is_fresh
from .schemas import AIAnalysisView, AnalystCreate, AnalystUpdate, AnalystView, AssignmentUpdate, AuditEventView, BrandCreate, BrandUpdate, BrandView, CatalogBrandView, CatalogEnrollmentCreate, CatalogEnrollmentView, ConnectorUpdate, EvidenceView, IncidentNoteCreate, IncidentNoteView, IncidentView, SubmissionCreate, TriageUpdate
from .scoring import score_signals
from .security import Principal, require_administrator, require_analyst, require_principal


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


settings = get_settings()
app = FastAPI(
    title="MAegis Operational API",
    version="0.1.0",
    description="Live brand-abuse discovery, scoring, evidence, and analyst triage.",
    lifespan=lifespan,
    docs_url=None if settings.environment == "production" else "/docs",
    redoc_url=None if settings.environment == "production" else "/redoc",
)
cors_origins = [item.strip() for item in settings.cors_origins.split(",") if item.strip()]
app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def audit(db: Session, principal: Principal, action: str, resource_type: str, resource_id: str, payload: dict | None = None) -> None:
    db.add(AuditEvent(tenant_id=principal.tenant_id, actor=principal.subject, action=action, resource_type=resource_type, resource_id=resource_id, payload=payload or {}))


def ensure_analyst_account(db: Session, principal: Principal) -> AnalystAccount:
    account = db.scalar(
        select(AnalystAccount).where(
            AnalystAccount.tenant_id == principal.tenant_id,
            AnalystAccount.email == principal.email,
        )
    )
    if account is None:
        account = AnalystAccount(
            tenant_id=principal.tenant_id,
            email=principal.email,
            display_name=principal.display_name,
            role=principal.role,
        )
        db.add(account)
        db.flush()
    return account


@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "service": "maegis-api", "capture_enabled": get_settings().capture_enabled}


def worker_runtime(db: Session) -> dict:
    heartbeat = db.get(WorkerHeartbeat, "discovery")
    if heartbeat is None:
        return {"configured": False, "fresh": False, "status": "missing"}
    fresh = worker_is_fresh(heartbeat.last_seen_at, settings.worker_health_stale_seconds)
    return {
        "configured": True,
        "fresh": fresh,
        "status": heartbeat.status if fresh else "stale",
        "instance_id": heartbeat.instance_id,
        "cycle_count": heartbeat.cycle_count,
        "last_seen_at": heartbeat.last_seen_at,
        "last_cycle_started_at": heartbeat.last_cycle_started_at,
        "last_cycle_completed_at": heartbeat.last_cycle_completed_at,
        "last_error": heartbeat.last_error,
        "details": heartbeat.details,
    }


@app.get("/api/v1/runtime/worker")
def get_worker_runtime(db: Session = Depends(get_db), _: Principal = Depends(require_principal)) -> dict:
    return worker_runtime(db)


@app.get("/api/v1/analysts")
def list_analysts(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    current = ensure_analyst_account(db, principal)
    db.commit()
    analysts = list(
        db.scalars(
            select(AnalystAccount)
            .where(AnalystAccount.tenant_id == principal.tenant_id)
            .order_by(AnalystAccount.display_name)
        )
    )
    return {
        "me": AnalystView.model_validate(current),
        "analysts": [AnalystView.model_validate(item) for item in analysts],
    }


@app.post("/api/v1/analysts", response_model=AnalystView, status_code=status.HTTP_201_CREATED)
def create_analyst(payload: AnalystCreate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> AnalystAccount:
    require_administrator(principal)
    email = payload.email.strip().lower()
    existing = db.scalar(select(AnalystAccount).where(AnalystAccount.tenant_id == principal.tenant_id, AnalystAccount.email == email))
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    account = AnalystAccount(tenant_id=principal.tenant_id, email=email, display_name=payload.display_name.strip(), role=payload.role)
    db.add(account)
    db.flush()
    audit(db, principal, "analyst.created", "analyst_account", account.id, {"email": account.email, "role": account.role})
    db.commit()
    return account


@app.patch("/api/v1/analysts/{analyst_id}", response_model=AnalystView)
def update_analyst(analyst_id: str, payload: AnalystUpdate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> AnalystAccount:
    require_administrator(principal)
    account = db.scalar(select(AnalystAccount).where(AnalystAccount.id == analyst_id, AnalystAccount.tenant_id == principal.tenant_id))
    if not account:
        raise HTTPException(status_code=404, detail="Analyst account not found")
    if payload.active is False and account.email == principal.email:
        raise HTTPException(status_code=409, detail="You cannot deactivate your own account")
    before = {"role": account.role, "active": account.active}
    if payload.role is not None:
        account.role = payload.role
    if payload.active is not None:
        account.active = payload.active
    audit(db, principal, "analyst.updated", "analyst_account", account.id, {"before": before, "after": {"role": account.role, "active": account.active}})
    db.commit()
    return account


@app.post("/api/v1/brands", response_model=BrandView, status_code=status.HTTP_201_CREATED)
def create_brand(payload: BrandCreate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> ProtectedBrand:
    require_analyst(principal)
    official = [normalize_domain(item)[0] for item in payload.official_domains]
    brand = ProtectedBrand(
        tenant_id=principal.tenant_id,
        name=payload.name.strip(),
        canonical_name=canonical_brand(payload.name),
        official_domains=official,
        trademarks=payload.trademarks,
        keywords=payload.keywords,
        permitted_variations=payload.permitted_variations,
    )
    db.add(brand)
    db.flush()
    audit(db, principal, "brand.created", "protected_brand", brand.id, {"name": brand.name})
    for connector_type in ("certificate_transparency", "dns_candidates", "rdap_candidates", "urlscan", "urlhaus", "czds"):
        existing = db.scalar(select(SourceConnector).where(SourceConnector.tenant_id == principal.tenant_id, SourceConnector.connector_type == connector_type))
        if not existing:
            db.add(SourceConnector(tenant_id=principal.tenant_id, connector_type=connector_type, enabled=connector_type != "czds", status="configured" if connector_type != "czds" else "credential_required"))
    db.commit()
    return brand


@app.get("/api/v1/brands", response_model=list[BrandView])
def list_brands(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> list[ProtectedBrand]:
    return list(db.scalars(select(ProtectedBrand).where(ProtectedBrand.tenant_id == principal.tenant_id).order_by(ProtectedBrand.name)))


@app.patch("/api/v1/brands/{brand_id}", response_model=BrandView)
def update_brand(brand_id: str, payload: BrandUpdate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> ProtectedBrand:
    require_analyst(principal)
    brand = db.scalar(select(ProtectedBrand).where(ProtectedBrand.id == brand_id, ProtectedBrand.tenant_id == principal.tenant_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Protected brand not found")
    brand.monitoring_enabled = payload.monitoring_enabled
    audit(db, principal, "brand.monitoring_updated", "protected_brand", brand.id, {"monitoring_enabled": brand.monitoring_enabled})
    db.commit()
    return brand


@app.get("/api/v1/brand-catalog", response_model=list[CatalogBrandView])
def list_brand_catalog(_: Principal = Depends(require_principal)) -> list[dict]:
    return [
        {
            "key": item.key,
            "name": item.name,
            "sector": item.sector,
            "official_domains": list(item.official_domains),
            "trademarks": list(item.trademarks),
            "permitted_variations": list(item.permitted_variations),
            "keywords": list(item.keywords),
        }
        for item in get_catalog()
    ]


@app.post("/api/v1/brand-catalog/enroll", response_model=CatalogEnrollmentView)
def enroll_brand_catalog(
    payload: CatalogEnrollmentCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> dict:
    require_administrator(principal)
    try:
        created, updated = enroll_catalog(
            db,
            principal.tenant_id,
            payload.keys,
            monitoring_enabled=payload.monitoring_enabled,
            actor=principal.subject,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    brands = created + updated
    return {
        "created": len(created),
        "updated": len(updated),
        "monitoring_enabled": payload.monitoring_enabled,
        "brand_ids": [brand.id for brand in brands],
    }


@app.post("/api/v1/submissions", response_model=IncidentView, status_code=status.HTTP_201_CREATED)
def submit_domain(payload: SubmissionCreate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> Incident:
    require_analyst(principal)
    brand = db.scalar(select(ProtectedBrand).where(ProtectedBrand.id == payload.brand_id, ProtectedBrand.tenant_id == principal.tenant_id))
    if not brand:
        raise HTTPException(status_code=404, detail="Protected brand not found")
    domain, unicode_domain = normalize_domain(payload.value)
    signals = analyze_domain(domain, unicode_domain, brand.name, brand.official_domains)
    result = score_signals(signals)
    candidate = db.scalar(select(Candidate).where(Candidate.tenant_id == principal.tenant_id, Candidate.brand_id == brand.id, Candidate.domain == domain))
    if not candidate:
        candidate = Candidate(tenant_id=principal.tenant_id, brand_id=brand.id, domain=domain, unicode_domain=unicode_domain, source="manual_submission")
        db.add(candidate)
        db.flush()
    incident = Incident(
        tenant_id=principal.tenant_id,
        brand_id=brand.id,
        candidate_id=candidate.id,
        domain=domain,
        title=f"Potential {brand.name} impersonation",
        severity=Severity(result.severity),
        risk_score=result.score,
        confidence=result.confidence,
        summary="; ".join(signal.explanation for signal in signals) or "No high-risk brand-abuse signals were detected.",
    )
    db.add(incident)
    db.flush()
    for signal in result.contributions:
        db.add(ScoreContribution(incident_id=incident.id, signal=signal.name, weight=signal.weight, value=signal.value, explanation=signal.explanation))
    if payload.request_capture:
        if not get_settings().capture_enabled:
            raise HTTPException(status_code=409, detail="Isolated capture is disabled by the administrator")
        db.add(BackgroundJob(tenant_id=principal.tenant_id, job_type="capture_url", payload={"incident_id": incident.id, "url": payload.value}))
    db.add(BackgroundJob(tenant_id=principal.tenant_id, job_type="enrich_domain", payload={"incident_id": incident.id, "domain": domain}))
    audit(db, principal, "incident.created", "incident", incident.id, {"source": "manual_submission", "domain": domain})
    db.commit()
    return db.scalar(select(Incident).options(selectinload(Incident.contributions)).where(Incident.id == incident.id))


@app.get("/api/v1/incidents", response_model=list[IncidentView])
def list_incidents(
    incident_status: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    query: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> list[Incident]:
    statement = select(Incident).options(selectinload(Incident.contributions)).where(Incident.tenant_id == principal.tenant_id)
    if incident_status:
        statement = statement.where(Incident.status == IncidentStatus(incident_status))
    if severity:
        statement = statement.where(Incident.severity == Severity(severity))
    if query:
        statement = statement.where(Incident.domain.ilike(f"%{query}%"))
    return list(db.scalars(statement.order_by(Incident.risk_score.desc(), Incident.created_at.desc()).limit(limit)).unique())


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentView)
def get_incident(incident_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> Incident:
    incident = db.scalar(select(Incident).options(selectinload(Incident.contributions)).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.get("/api/v1/incidents/{incident_id}/evidence", response_model=list[EvidenceView])
def list_incident_evidence(
    incident_id: str,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> list[EvidenceItem]:
    incident_exists = db.scalar(
        select(Incident.id).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id)
    )
    if not incident_exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    return list(
        db.scalars(
            select(EvidenceItem)
            .where(EvidenceItem.incident_id == incident_id, EvidenceItem.tenant_id == principal.tenant_id)
            .order_by(EvidenceItem.collected_at, EvidenceItem.id)
        )
    )


@app.get("/api/v1/incidents/{incident_id}/case-context")
def incident_case_context(incident_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    incident = db.scalar(select(Incident).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    evidence = list(db.scalars(select(EvidenceItem).where(EvidenceItem.incident_id == incident.id, EvidenceItem.tenant_id == principal.tenant_id)))
    return build_domain_context(
        incident.domain,
        [{"evidence_type": item.evidence_type, "payload": item.payload} for item in evidence],
    )


@app.post("/api/v1/incidents/{incident_id}/assign", response_model=IncidentView)
def assign_incident(incident_id: str, payload: AssignmentUpdate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> Incident:
    require_analyst(principal)
    incident = db.scalar(select(Incident).options(selectinload(Incident.contributions)).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    analyst = db.scalar(select(AnalystAccount).where(AnalystAccount.id == payload.analyst_id, AnalystAccount.tenant_id == principal.tenant_id, AnalystAccount.active.is_(True)))
    if not analyst:
        raise HTTPException(status_code=404, detail="Analyst account not found")
    previous = incident.assigned_to
    incident.assigned_to = analyst.email
    if incident.status == IncidentStatus.NEW:
        incident.status = IncidentStatus.INVESTIGATING
    incident.updated_at = datetime.now(timezone.utc)
    audit(db, principal, "incident.assigned", "incident", incident.id, {"from": previous, "to": analyst.email})
    db.commit()
    return incident


@app.get("/api/v1/incidents/{incident_id}/notes", response_model=list[IncidentNoteView])
def list_incident_notes(incident_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> list[IncidentNote]:
    exists = db.scalar(select(Incident.id).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id))
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    return list(db.scalars(select(IncidentNote).where(IncidentNote.incident_id == incident_id, IncidentNote.tenant_id == principal.tenant_id).order_by(IncidentNote.created_at, IncidentNote.id)))


@app.post("/api/v1/incidents/{incident_id}/notes", response_model=IncidentNoteView, status_code=status.HTTP_201_CREATED)
def create_incident_note(incident_id: str, payload: IncidentNoteCreate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> IncidentNote:
    require_analyst(principal)
    exists = db.scalar(select(Incident.id).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id))
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")
    account = ensure_analyst_account(db, principal)
    note = IncidentNote(
        tenant_id=principal.tenant_id,
        incident_id=incident_id,
        author_id=account.id,
        author_email=account.email,
        author_name=account.display_name,
        body=payload.body.strip(),
    )
    db.add(note)
    db.flush()
    audit(db, principal, "incident.note_added", "incident", incident_id, {"note_id": note.id})
    db.commit()
    return note


@app.post("/api/v1/incidents/{incident_id}/triage", response_model=IncidentView)
def triage_incident(incident_id: str, payload: TriageUpdate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> Incident:
    require_analyst(principal)
    incident = db.scalar(select(Incident).options(selectinload(Incident.contributions)).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    previous = incident.status.value
    incident.status = IncidentStatus(payload.status)
    if payload.severity:
        incident.severity = Severity(payload.severity)
    incident.assigned_to = payload.assigned_to
    incident.decision_rationale = payload.rationale
    incident.updated_at = datetime.now(timezone.utc)
    audit(db, principal, "incident.triaged", "incident", incident.id, {"from": previous, "to": payload.status, "rationale": payload.rationale})
    db.commit()
    return incident


@app.post("/api/v1/incidents/{incident_id}/ai-analysis", response_model=AIAnalysisView)
def grounded_analysis(incident_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> AIAnalysisView:
    incident = db.scalar(select(Incident).options(selectinload(Incident.contributions)).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    facts = [{"evidence_id": item.id, "claim": item.explanation} for item in incident.contributions]
    classification = "insufficient_evidence" if not facts or incident.risk_score < 20 else "suspected_brand_abuse"
    audit(db, principal, "ai_analysis.requested", "incident", incident.id, {"provider": "deterministic_grounded_fallback"})
    db.commit()
    return AIAnalysisView(
        classification=classification,
        severity=incident.severity.value,
        confidence=incident.confidence,
        observed_facts=facts,
        inferences=[] if classification == "insufficient_evidence" else [{"claim": "The domain warrants analyst review", "evidence_ids": [item["evidence_id"] for item in facts]}],
        recommended_actions=["Review captured content and registration context", "Confirm the domain is not an authorized asset"],
        executive_summary=incident.summary,
    )


@app.post("/api/v1/incidents/{incident_id}/capture", status_code=202)
def request_capture(incident_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    require_analyst(principal)
    if not get_settings().capture_enabled:
        raise HTTPException(status_code=409, detail="Isolated capture is disabled")
    incident = db.scalar(select(Incident).where(Incident.id == incident_id, Incident.tenant_id == principal.tenant_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    job = BackgroundJob(tenant_id=principal.tenant_id, job_type="capture_url", payload={"incident_id": incident.id, "url": f"https://{incident.domain}"})
    db.add(job)
    audit(db, principal, "capture.requested", "incident", incident.id)
    db.commit()
    return {"job_id": job.id, "status": "queued"}


@app.get("/api/v1/connectors")
def list_connectors(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> list[dict]:
    connectors = db.scalars(select(SourceConnector).where(SourceConnector.tenant_id == principal.tenant_id).order_by(SourceConnector.connector_type)).all()
    return [{"id": item.id, "type": item.connector_type, "enabled": item.enabled, "status": item.status, "checkpoint": item.checkpoint, "observations_seen": item.observations_seen, "last_success_at": item.last_success_at, "last_error": item.last_error} for item in connectors]


@app.patch("/api/v1/connectors/{connector_id}")
def update_connector(connector_id: str, payload: ConnectorUpdate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    require_administrator(principal)
    connector = db.scalar(select(SourceConnector).where(SourceConnector.id == connector_id, SourceConnector.tenant_id == principal.tenant_id))
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    connector.enabled = payload.enabled
    connector.status = "configured" if connector.enabled else "disabled"
    audit(db, principal, "connector.updated", "source_connector", connector.id, {"enabled": connector.enabled, "type": connector.connector_type})
    db.commit()
    return {"id": connector.id, "type": connector.connector_type, "enabled": connector.enabled, "status": connector.status, "checkpoint": connector.checkpoint, "observations_seen": connector.observations_seen, "last_success_at": connector.last_success_at, "last_error": connector.last_error}


@app.get("/api/v1/audit-events", response_model=list[AuditEventView])
def list_audit_events(
    limit: int = Query(default=200, ge=1, le=500),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_principal),
) -> list[AuditEvent]:
    require_analyst(principal)
    return list(db.scalars(select(AuditEvent).where(AuditEvent.tenant_id == principal.tenant_id).order_by(AuditEvent.created_at.desc()).limit(limit)))


@app.get("/api/v1/operations/summary")
def operations_summary(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    tenant = principal.tenant_id
    job_rows = db.execute(select(BackgroundJob.status, func.count(BackgroundJob.id)).where(BackgroundJob.tenant_id == tenant).group_by(BackgroundJob.status)).all()
    return {
        "brands": db.scalar(select(func.count(ProtectedBrand.id)).where(ProtectedBrand.tenant_id == tenant)) or 0,
        "active_brands": db.scalar(select(func.count(ProtectedBrand.id)).where(ProtectedBrand.tenant_id == tenant, ProtectedBrand.monitoring_enabled.is_(True))) or 0,
        "observations": db.scalar(select(func.count(Observation.id)).where(Observation.tenant_id == tenant)) or 0,
        "candidates": db.scalar(select(func.count(Candidate.id)).where(Candidate.tenant_id == tenant)) or 0,
        "incidents": db.scalar(select(func.count(Incident.id)).where(Incident.tenant_id == tenant)) or 0,
        "open_incidents": db.scalar(select(func.count(Incident.id)).where(Incident.tenant_id == tenant, Incident.status.not_in([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]))) or 0,
        "evidence_items": db.scalar(select(func.count(EvidenceItem.id)).where(EvidenceItem.tenant_id == tenant)) or 0,
        "jobs": {status_name: count for status_name, count in job_rows},
        "worker": worker_runtime(db),
    }


@app.get("/api/v1/settings")
def safe_settings(_: Principal = Depends(require_principal)) -> dict:
    current = get_settings()
    return {
        "environment": current.environment,
        "capture_enabled": current.capture_enabled,
        "detector_version": DETECTOR_VERSION,
        "max_generated_candidates": current.max_generated_candidates,
        "discovery_brand_batch_size": current.discovery_brand_batch_size,
        "discovery_dns_batch_size": current.discovery_dns_batch_size,
        "discovery_rdap_batch_size": current.discovery_rdap_batch_size,
        "fresh_registration_max_age_days": current.fresh_registration_max_age_days,
        "discovery_poll_interval_seconds": current.discovery_poll_interval_seconds,
        "worker_health_stale_seconds": current.worker_health_stale_seconds,
    }


@app.get("/api/v1/metrics")
def metrics(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    rows = db.execute(select(Incident.severity, func.count(Incident.id)).where(Incident.tenant_id == principal.tenant_id).group_by(Incident.severity)).all()
    return {"open_incidents": db.scalar(select(func.count(Incident.id)).where(Incident.tenant_id == principal.tenant_id, Incident.status.not_in([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]))) or 0, "by_severity": {severity.value: count for severity, count in rows}, "worker": worker_runtime(db)}
