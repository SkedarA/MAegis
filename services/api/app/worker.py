import asyncio
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select

from .brand_schedule import select_brand_batch
from .connectors import CZDSZoneConnector, CertificateTransparencyConnector, DNSCandidateConnector, fetch_rdap
from .config import get_settings
from .database import SessionLocal
from .detection import analyze_domain, generate_candidates, normalize_domain
from .enrichment import enrichment_signals, fetch_dns, fetch_tls
from .models import BackgroundJob, Candidate, EvidenceItem, Incident, ProtectedBrand, ScoreContribution, Severity, SourceConnector
from .scoring import score_signals


def persist_finding(db, brand: ProtectedBrand, domain: str, source: str, raw_hash: str, payload: dict) -> None:
    ascii_domain, unicode_domain = normalize_domain(domain)
    candidate = db.scalar(select(Candidate).where(Candidate.tenant_id == brand.tenant_id, Candidate.brand_id == brand.id, Candidate.domain == ascii_domain))
    if candidate:
        candidate.last_seen_at = datetime.now(timezone.utc)
        return
    signals = analyze_domain(ascii_domain, unicode_domain, brand.name, brand.official_domains)
    result = score_signals(signals)
    if result.score < 20:
        return
    candidate = Candidate(tenant_id=brand.tenant_id, brand_id=brand.id, domain=ascii_domain, unicode_domain=unicode_domain, source=source)
    db.add(candidate)
    db.flush()
    incident = Incident(tenant_id=brand.tenant_id, brand_id=brand.id, candidate_id=candidate.id, domain=ascii_domain, title=f"Potential {brand.name} impersonation", severity=Severity(result.severity), risk_score=result.score, confidence=result.confidence, summary="; ".join(item.explanation for item in signals))
    db.add(incident)
    db.flush()
    db.add(EvidenceItem(tenant_id=brand.tenant_id, incident_id=incident.id, evidence_type="source_observation", source=source, payload=payload, raw_hash=raw_hash))
    for signal in signals:
        db.add(ScoreContribution(incident_id=incident.id, signal=signal.name, weight=signal.weight, value=signal.value, explanation=signal.explanation))
    db.add(BackgroundJob(tenant_id=brand.tenant_id, job_type="enrich_domain", payload={"incident_id": incident.id, "domain": ascii_domain}))


async def poll_live_sources() -> None:
    settings = get_settings()
    with SessionLocal() as db:
        enrolled = list(db.scalars(select(ProtectedBrand).where(ProtectedBrand.monitoring_enabled.is_(True)).order_by(ProtectedBrand.id)).all())
        brands = select_brand_batch(enrolled, settings.discovery_brand_batch_size)
        for brand in brands:
            scheduled = [
                (CertificateTransparencyConnector(), brand.canonical_name),
                (CZDSZoneConnector(), brand.canonical_name),
            ]
            for candidate in generate_candidates(brand.name, limit=25):
                scheduled.append((DNSCandidateConnector(), candidate))
            for connector, target in scheduled:
                state = db.scalar(select(SourceConnector).where(SourceConnector.tenant_id == brand.tenant_id, SourceConnector.connector_type == connector.name))
                checkpoint = state.checkpoint if state else {}
                try:
                    observations, next_checkpoint = await connector.fetch(target, checkpoint)
                    for observation in observations:
                        persist_finding(db, brand, observation.domain, observation.source, observation.raw_hash, observation.payload)
                    if state:
                        state.checkpoint = next_checkpoint
                        state.last_success_at = datetime.now(timezone.utc)
                        state.status = "healthy"
                        state.observations_seen += len(observations)
                        state.last_error = None
                    db.commit()
                except Exception as exc:  # connector failure must not stop other brands
                    db.rollback()
                    if state:
                        state.status = "degraded"
                        state.last_error = str(exc)[:1000]
                        db.commit()


async def process_jobs() -> None:
    with SessionLocal() as db:
        job = db.scalar(select(BackgroundJob).where(BackgroundJob.status == "queued", BackgroundJob.job_type != "capture_url", BackgroundJob.run_after <= datetime.now(timezone.utc)).with_for_update(skip_locked=True).order_by(BackgroundJob.created_at))
        if not job:
            return
        job.status = "running"
        job.attempts += 1
        db.commit()
        try:
            if job.job_type == "enrich_domain":
                await enrich_incident(db, job)
            job.status = "complete"
            db.commit()
        except Exception:
            db.rollback()
            job = db.get(BackgroundJob, job.id)
            job.status = "failed" if job.attempts >= 3 else "queued"
            db.commit()


def add_evidence(db, job: BackgroundJob, evidence_type: str, source: str, payload: dict) -> None:
    raw_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
    existing = db.scalar(
        select(EvidenceItem.id).where(
            EvidenceItem.incident_id == job.payload["incident_id"],
            EvidenceItem.evidence_type == evidence_type,
            EvidenceItem.raw_hash == raw_hash,
        )
    )
    if not existing:
        db.add(
            EvidenceItem(
                tenant_id=job.tenant_id,
                incident_id=job.payload["incident_id"],
                evidence_type=evidence_type,
                source=source,
                payload=payload,
                raw_hash=raw_hash,
            )
        )


async def enrich_incident(db, job: BackgroundJob) -> None:
    domain = job.payload["domain"]
    payloads: dict[str, dict | None] = {"dns": None, "rdap": None, "tls": None}
    try:
        payloads["dns"] = await fetch_dns(domain)
        add_evidence(db, job, "dns", "dns", payloads["dns"])
    except Exception as exc:
        add_evidence(db, job, "enrichment_error", "dns", {"status": "error", "error_type": type(exc).__name__})
    try:
        payloads["rdap"] = await fetch_rdap(domain)
        add_evidence(db, job, "rdap", "rdap", payloads["rdap"])
    except Exception as exc:
        add_evidence(db, job, "enrichment_error", "rdap", {"status": "error", "error_type": type(exc).__name__})
    dns_payload = payloads["dns"] or {}
    if dns_payload.get("all_addresses_public"):
        try:
            payloads["tls"] = await fetch_tls(domain, dns_payload["resolved_addresses"])
            add_evidence(db, job, "tls_certificate", "tls", payloads["tls"])
        except Exception as exc:
            add_evidence(db, job, "enrichment_error", "tls", {"status": "error", "error_type": type(exc).__name__})

    incident = db.get(Incident, job.payload["incident_id"])
    if not incident or incident.tenant_id != job.tenant_id:
        raise ValueError("Incident is outside the job tenant")
    brand = db.get(ProtectedBrand, incident.brand_id)
    base_signals = analyze_domain(incident.domain, incident.domain, brand.name, brand.official_domains)
    signals = base_signals + enrichment_signals(payloads["dns"], payloads["rdap"], payloads["tls"])
    result = score_signals(signals, evidence_sources=1 + len([payload for payload in payloads.values() if payload]))
    for contribution in list(incident.contributions):
        db.delete(contribution)
    for signal in result.contributions:
        db.add(ScoreContribution(incident_id=incident.id, signal=signal.name, weight=signal.weight, value=signal.value, explanation=signal.explanation))
    incident.risk_score = result.score
    incident.confidence = result.confidence
    incident.severity = Severity(result.severity)
    incident.updated_at = datetime.now(timezone.utc)


async def main() -> None:
    while True:
        await poll_live_sources()
        for _ in range(50):
            await process_jobs()
        await asyncio.sleep(get_settings().discovery_poll_interval_seconds)


if __name__ == "__main__":
    asyncio.run(main())
