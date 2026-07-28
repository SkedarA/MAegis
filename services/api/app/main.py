import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .config import get_settings
from .database import Base, engine, get_db
from .detection import analyze_domain, canonical_brand, normalize_domain
from .models import AuditEvent, BackgroundJob, Candidate, Incident, IncidentStatus, ProtectedBrand, ScoreContribution, Severity, SourceConnector
from .schemas import AIAnalysisView, BrandCreate, BrandView, IncidentView, SubmissionCreate, TriageUpdate
from .scoring import score_signals
from .security import Principal, require_analyst, require_principal


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="MAegis Operational API",
    version="0.1.0",
    description="Live brand-abuse discovery, scoring, evidence, and analyst triage.",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def audit(db: Session, principal: Principal, action: str, resource_type: str, resource_id: str, payload: dict | None = None) -> None:
    db.add(AuditEvent(tenant_id=principal.tenant_id, actor=principal.subject, action=action, resource_type=resource_type, resource_id=resource_id, payload=payload or {}))


@app.get("/api/v1/health")
def health() -> dict:
    return {"status": "ok", "service": "maegis-api", "capture_enabled": get_settings().capture_enabled}


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
    for connector_type in ("certificate_transparency", "dns_candidates", "urlhaus", "czds"):
        existing = db.scalar(select(SourceConnector).where(SourceConnector.tenant_id == principal.tenant_id, SourceConnector.connector_type == connector_type))
        if not existing:
            db.add(SourceConnector(tenant_id=principal.tenant_id, connector_type=connector_type, enabled=connector_type != "czds", status="configured" if connector_type != "czds" else "credential_required"))
    db.commit()
    return brand


@app.get("/api/v1/brands", response_model=list[BrandView])
def list_brands(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> list[ProtectedBrand]:
    return list(db.scalars(select(ProtectedBrand).where(ProtectedBrand.tenant_id == principal.tenant_id).order_by(ProtectedBrand.name)))


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


@app.get("/api/v1/metrics")
def metrics(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    rows = db.execute(select(Incident.severity, func.count(Incident.id)).where(Incident.tenant_id == principal.tenant_id).group_by(Incident.severity)).all()
    return {"open_incidents": db.scalar(select(func.count(Incident.id)).where(Incident.tenant_id == principal.tenant_id, Incident.status.not_in([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]))) or 0, "by_severity": {severity.value: count for severity, count in rows}}
