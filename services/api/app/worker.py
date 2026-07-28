import asyncio
import hashlib
from datetime import datetime, timezone

from sqlalchemy import select

from .connectors import CZDSZoneConnector, CertificateTransparencyConnector, DNSCandidateConnector, fetch_rdap
from .database import SessionLocal
from .detection import analyze_domain, generate_candidates, normalize_domain
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
    with SessionLocal() as db:
        brands = db.scalars(select(ProtectedBrand).where(ProtectedBrand.monitoring_enabled.is_(True))).all()
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
                payload = await fetch_rdap(job.payload["domain"])
                raw_hash = hashlib.sha256(repr(payload).encode()).hexdigest()
                db.add(EvidenceItem(tenant_id=job.tenant_id, incident_id=job.payload["incident_id"], evidence_type="rdap", source="rdap", payload=payload, raw_hash=raw_hash))
            job.status = "complete"
            db.commit()
        except Exception:
            db.rollback()
            job = db.get(BackgroundJob, job.id)
            job.status = "failed" if job.attempts >= 3 else "queued"
            db.commit()


async def main() -> None:
    while True:
        await poll_live_sources()
        for _ in range(50):
            await process_jobs()
        await asyncio.sleep(60)


if __name__ == "__main__":
    asyncio.run(main())
