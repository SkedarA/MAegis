import asyncio
import hashlib
import json
import os
import socket
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from .brand_schedule import select_brand_batch_at_cursor
from .candidate_schedule import brand_checkpoint, fetch_candidate_batch, prioritized_rotating_batch, with_brand_checkpoint
from .campaign_intelligence.graph import ingest_incident_public_evidence
from .campaign_intelligence.models import BrandCampaignRelevance, CampaignMember, IntelligenceCampaign
from .connectors import CZDSZoneConnector, CertificateTransparencyConnector, DNSCandidateConnector, RDAPRegistrationConnector, URLhausConnector, URLScanConnector, fetch_rdap
from .config import get_settings
from .database import Base, SessionLocal, engine
from .detection import DETECTOR_VERSION, GeneratedCandidate, Signal, analyze_domain, generate_candidate_variants, is_official_domain, normalize_domain
from .enrichment import enrichment_signals, fetch_dns, fetch_tls
from .incident_policy import should_create_incident, source_signals
from .job_retry import retry_delay_seconds
from .models import AuditEvent, BackgroundJob, Candidate, DomainMonitor, EvidenceItem, Incident, IncidentStatus, Observation, ProtectedBrand, ScoreContribution, Severity, SourceConnector, WorkerHeartbeat
from .monitoring import classify_snapshot, compact_snapshot, meaningful_changes, next_check_time, snapshot_hash
from .scoring import score_signals
from .suppression import AUTO_ALLOWLIST_RATIONALE


WORKER_NAME = "discovery"
PERSISTENT_SOURCE_SIGNALS = {"threat_feed_verdict", "generated_candidate", "fresh_registration_window"}
HIGH_YIELD_MUTATIONS = {"tld_swap", "brand_plus_keyword", "keyword_plus_brand", "unicode_homoglyph"}


def update_worker_heartbeat(
    instance_id: str,
    status: str,
    *,
    cycle_started_at: datetime | None = None,
    cycle_completed_at: datetime | None = None,
    cycle_count: int | None = None,
    last_error: str | None = None,
    details: dict | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        heartbeat = db.get(WorkerHeartbeat, WORKER_NAME)
        if heartbeat is None:
            heartbeat = WorkerHeartbeat(worker_name=WORKER_NAME, instance_id=instance_id, started_at=now)
            db.add(heartbeat)
        heartbeat.instance_id = instance_id
        heartbeat.status = status
        heartbeat.last_seen_at = now
        if cycle_started_at is not None:
            heartbeat.last_cycle_started_at = cycle_started_at
        if cycle_completed_at is not None:
            heartbeat.last_cycle_completed_at = cycle_completed_at
        if cycle_count is not None:
            heartbeat.cycle_count = cycle_count
        heartbeat.last_error = last_error
        if details is not None:
            heartbeat.details = details
        db.commit()


def get_connector_state(db, brand: ProtectedBrand, connector) -> SourceConnector:
    state = db.scalar(
        select(SourceConnector).where(
            SourceConnector.tenant_id == brand.tenant_id,
            SourceConnector.connector_type == connector.name,
        )
    )
    if state is None:
        state = SourceConnector(
            tenant_id=brand.tenant_id,
            connector_type=connector.name,
            enabled=True,
            status="configured",
        )
        db.add(state)
        db.flush()
    return state


def persist_finding(db, brand: ProtectedBrand, domain: str, source: str, raw_hash: str, payload: dict, connector_version: str = "1.0") -> None:
    ascii_domain, unicode_domain = normalize_domain(domain)
    observation = db.scalar(
        select(Observation).where(
            Observation.tenant_id == brand.tenant_id,
            Observation.source == source,
            Observation.raw_hash == raw_hash,
        )
    )
    if observation:
        return
    db.add(
        Observation(
            tenant_id=brand.tenant_id,
            brand_id=brand.id,
            source=source,
            domain=ascii_domain,
            url=payload.get("submitted_url") or payload.get("url"),
            raw_hash=raw_hash,
            raw_payload=payload,
            connector_version=connector_version,
        )
    )
    candidate = db.scalar(select(Candidate).where(Candidate.tenant_id == brand.tenant_id, Candidate.brand_id == brand.id, Candidate.domain == ascii_domain))
    signals = analyze_domain(ascii_domain, unicode_domain, brand.name, brand.official_domains)
    signals += source_signals(payload)
    if isinstance(payload.get("rdap"), dict):
        signals += enrichment_signals(None, payload["rdap"], None)
    result = score_signals(signals)
    if not should_create_incident(brand.canonical_name, signals, result.score):
        return
    if not candidate:
        candidate = Candidate(tenant_id=brand.tenant_id, brand_id=brand.id, domain=ascii_domain, unicode_domain=unicode_domain, source=source)
        db.add(candidate)
        db.flush()
    else:
        candidate.last_seen_at = datetime.now(timezone.utc)
    incident = db.scalar(select(Incident).where(Incident.candidate_id == candidate.id, Incident.tenant_id == brand.tenant_id))
    if not incident:
        incident = Incident(
            tenant_id=brand.tenant_id,
            brand_id=brand.id,
            candidate_id=candidate.id,
            domain=ascii_domain,
            title=f"Potential {brand.name} impersonation",
            severity=Severity(result.severity),
            risk_score=result.score,
            confidence=result.confidence,
            summary="; ".join(item.explanation for item in signals),
            detector_version=DETECTOR_VERSION,
        )
        db.add(incident)
        db.flush()
        db.add(BackgroundJob(tenant_id=brand.tenant_id, job_type="enrich_domain", payload={"incident_id": incident.id, "domain": ascii_domain}))
    else:
        current_signal_names = {signal.name for signal in signals}
        retained_evidence = [
            Signal(contribution.signal, contribution.value, contribution.weight, contribution.explanation)
            for contribution in incident.contributions
            if (contribution.signal.startswith("enrichment.") or contribution.signal in PERSISTENT_SOURCE_SIGNALS)
            and contribution.signal not in current_signal_names
        ]
        result = score_signals(signals + retained_evidence, evidence_sources=2 if retained_evidence else 1)
        incident.severity = Severity(result.severity)
        incident.risk_score = result.score
        incident.confidence = result.confidence
        incident.summary = "; ".join(item.explanation for item in result.contributions)
        incident.detector_version = DETECTOR_VERSION
        incident.updated_at = datetime.now(timezone.utc)
        for contribution in list(incident.contributions):
            db.delete(contribution)
    db.add(EvidenceItem(tenant_id=brand.tenant_id, incident_id=incident.id, evidence_type="source_observation", source=source, payload=payload, raw_hash=raw_hash))
    for signal in result.contributions:
        db.add(ScoreContribution(incident_id=incident.id, signal=signal.name, weight=signal.weight, value=signal.value, explanation=signal.explanation))


async def poll_live_sources(brand_cursor: int = 0) -> int:
    settings = get_settings()
    with SessionLocal() as db:
        enrolled = list(db.scalars(select(ProtectedBrand).where(ProtectedBrand.monitoring_enabled.is_(True)).order_by(ProtectedBrand.id)).all())
        brands, next_brand_cursor = select_brand_batch_at_cursor(enrolled, settings.discovery_brand_batch_size, brand_cursor)
        for brand in brands:
            live_connectors = [
                (CertificateTransparencyConnector(), brand.canonical_name),
                (URLScanConnector(), brand.canonical_name),
                (CZDSZoneConnector(), brand.canonical_name),
            ]
            for connector, target in live_connectors:
                state = get_connector_state(db, brand, connector)
                if not state.enabled:
                    continue
                checkpoint = brand_checkpoint(state.checkpoint, brand.id)
                try:
                    observations, next_checkpoint = await connector.fetch(target, checkpoint)
                    for observation in observations:
                        persist_finding(db, brand, observation.domain, observation.source, observation.raw_hash, observation.payload, connector.version)
                    state.checkpoint = with_brand_checkpoint(state.checkpoint, brand.id, next_checkpoint)
                    state.last_success_at = datetime.now(timezone.utc)
                    state.status = "healthy"
                    state.observations_seen += len(observations)
                    state.last_error = None
                    db.commit()
                except Exception as exc:  # connector failure must not stop other brands
                    db.rollback()
                    state = get_connector_state(db, brand, connector)
                    state.status = "degraded"
                    state.last_error = str(exc)[:1000]
                    db.commit()

            variants = [
                item
                for item in generate_candidate_variants(
                    brand.name,
                    keywords=brand.keywords,
                    limit=settings.max_generated_candidates,
                )
                if not is_official_domain(item.domain, brand.official_domains)
            ]
            await poll_generated_candidates(db, brand, DNSCandidateConnector(), variants, settings.discovery_dns_batch_size)
            await poll_generated_candidates(
                db,
                brand,
                RDAPRegistrationConnector(settings.fresh_registration_max_age_days),
                variants,
                settings.discovery_rdap_batch_size,
            )
        return next_brand_cursor


async def poll_generated_candidates(
    db,
    brand: ProtectedBrand,
    connector,
    variants: list[GeneratedCandidate],
    batch_size: int,
) -> None:
    state = get_connector_state(db, brand, connector)
    if not state.enabled:
        return
    checkpoint = brand_checkpoint(state.checkpoint, brand.id)
    cursor = int(checkpoint.get("cursor", 0))
    priority_cursor = int(checkpoint.get("priority_cursor", 0))
    batch, next_cursor, next_priority_cursor = prioritized_rotating_batch(
        variants,
        cursor,
        priority_cursor,
        batch_size,
        lambda item: item.mutation in HIGH_YIELD_MUTATIONS,
    )
    collected, failures = await fetch_candidate_batch(connector, batch)
    for variant, observation in collected:
        payload = {**observation.payload, "candidate_generation": variant.evidence()}
        persist_finding(
            db,
            brand,
            observation.domain,
            observation.source,
            observation.raw_hash,
            payload,
            connector.version,
        )
    observations_seen = len(collected)
    next_checkpoint = {
        "cursor": next_cursor,
        "priority_cursor": next_priority_cursor,
        "pool_size": len(variants),
        "attempted": len(batch),
        "failed": len(failures),
        "last_poll": datetime.now(timezone.utc).isoformat(),
    }
    state.checkpoint = with_brand_checkpoint(state.checkpoint, brand.id, next_checkpoint)
    state.observations_seen += observations_seen
    state.last_success_at = datetime.now(timezone.utc) if len(failures) < len(batch) else state.last_success_at
    state.status = "degraded" if failures else "healthy"
    state.last_error = "; ".join(failures)[:1000] if failures else None
    db.commit()


def load_worker_progress() -> tuple[int, int]:
    with SessionLocal() as db:
        heartbeat = db.get(WorkerHeartbeat, WORKER_NAME)
        if heartbeat is None:
            return 0, 0
        details = heartbeat.details or {}
        return max(0, int(heartbeat.cycle_count or 0)), max(0, int(details.get("brand_cursor", 0)))


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
            elif job.job_type == "rescore_brand":
                rescore_brand_incidents(db, job)
            elif job.job_type == "rebuild_intelligence":
                rebuild_intelligence(db, job)
            else:
                raise ValueError(f"Unsupported background job type: {job.job_type}")
            job.status = "complete"
            db.commit()
        except Exception as exc:
            db.rollback()
            job = db.get(BackgroundJob, job.id)
            job.status = "failed" if job.attempts >= 3 else "queued"
            job.run_after = datetime.now(timezone.utc) + timedelta(seconds=retry_delay_seconds(job.attempts))
            job.payload = {**job.payload, "last_error": f"{type(exc).__name__}: {exc}"[:1000], "last_failed_at": datetime.now(timezone.utc).isoformat()}
            db.commit()


def claim_due_monitors(limit: int, claim_seconds: int) -> list[dict]:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        monitors = list(db.scalars(
            select(DomainMonitor)
            .where(DomainMonitor.state == "active", DomainMonitor.next_check_at <= now)
            .with_for_update(skip_locked=True)
            .order_by(DomainMonitor.next_check_at)
            .limit(limit)
        ))
        claimed = [
            {"id": item.id, "tenant_id": item.tenant_id, "incident_id": item.incident_id, "domain": item.domain}
            for item in monitors
        ]
        for item in monitors:
            item.next_check_at = now + timedelta(seconds=claim_seconds)
        db.commit()
        return claimed


async def collect_monitor_snapshot(domain: str) -> dict:
    dns_payload = await fetch_dns(domain)
    rdap_payload = None
    tls_payload = None
    try:
        rdap_payload = await fetch_rdap(domain)
    except Exception:
        pass
    if dns_payload.get("all_addresses_public"):
        try:
            tls_payload = await fetch_tls(domain, dns_payload.get("resolved_addresses") or [])
        except Exception:
            pass
    return compact_snapshot(dns_payload, rdap_payload, tls_payload)


def persist_monitor_result(claim: dict, snapshot: dict | None, error: Exception | None) -> None:
    now = datetime.now(timezone.utc)
    settings = get_settings()
    with SessionLocal() as db:
        monitor = db.scalar(
            select(DomainMonitor).where(
                DomainMonitor.id == claim["id"], DomainMonitor.tenant_id == claim["tenant_id"]
            ).with_for_update()
        )
        if not monitor or monitor.state != "active":
            return
        monitor.last_checked_at = now
        monitor.check_count += 1
        if error is not None or snapshot is None:
            monitor.consecutive_failures += 1
            if monitor.consecutive_failures >= 3:
                monitor.classification = "error"
            retry_seconds = min(monitor.interval_seconds, max(900, 300 * (2 ** min(monitor.consecutive_failures, 6))))
            monitor.next_check_at = now + timedelta(seconds=retry_seconds)
            db.commit()
            return

        current_hash = snapshot_hash(snapshot)
        classification = classify_snapshot(snapshot)
        previous = monitor.last_snapshot or {}
        changes = meaningful_changes(previous, snapshot) if monitor.baseline_hash else []
        monitor.classification = classification
        monitor.consecutive_failures = 0
        monitor.last_snapshot = snapshot
        monitor.next_check_at = next_check_time(monitor.id, monitor.interval_seconds, now)
        evidence_type = None
        evidence_payload: dict = {}
        if not monitor.baseline_hash:
            monitor.baseline_hash = current_hash
            evidence_type = "monitor_baseline"
            evidence_payload = {"classification": classification, "snapshot": snapshot}
        elif changes and current_hash != monitor.baseline_hash:
            monitor.baseline_hash = current_hash
            monitor.last_change_at = now
            evidence_type = "monitor_change"
            evidence_payload = {
                "changes": changes, "previous_classification": classify_snapshot(previous),
                "classification": classification, "before": previous, "after": snapshot,
            }
            incident = db.scalar(select(Incident).where(Incident.id == monitor.incident_id, Incident.tenant_id == monitor.tenant_id))
            if incident and incident.status == IncidentStatus.MONITORING:
                incident.status = IncidentStatus.NEW
                incident.updated_at = now
                incident.decision_rationale = "Monitoring detected a meaningful infrastructure change; analyst review required."
            db.add(AuditEvent(
                tenant_id=monitor.tenant_id, actor="worker:domain-monitor", action="monitor.change_detected",
                resource_type="incident", resource_id=monitor.incident_id,
                payload={"monitor_id": monitor.id, "domain": monitor.domain, "changes": changes, "classification": classification},
            ))
            queued = db.scalar(select(BackgroundJob.id).where(
                BackgroundJob.tenant_id == monitor.tenant_id,
                BackgroundJob.job_type == "enrich_domain",
                BackgroundJob.status.in_(["queued", "running"]),
                BackgroundJob.payload["incident_id"].as_string() == monitor.incident_id,
            ))
            if not queued:
                db.add(BackgroundJob(tenant_id=monitor.tenant_id, job_type="enrich_domain", payload={"incident_id": monitor.incident_id, "domain": monitor.domain, "trigger": "monitor_change"}))
        if evidence_type:
            raw_hash = hashlib.sha256(json.dumps(evidence_payload, sort_keys=True, default=str).encode()).hexdigest()
            db.add(EvidenceItem(tenant_id=monitor.tenant_id, incident_id=monitor.incident_id, evidence_type=evidence_type, source="domain_monitor", payload=evidence_payload, raw_hash=raw_hash))
        db.commit()


async def process_domain_monitors() -> int:
    settings = get_settings()
    claims = claim_due_monitors(settings.monitor_batch_size, settings.monitor_claim_seconds)
    if not claims:
        return 0
    semaphore = asyncio.Semaphore(settings.monitor_concurrency)

    async def collect(claim: dict) -> tuple[dict, dict | None, Exception | None]:
        async with semaphore:
            try:
                return claim, await collect_monitor_snapshot(claim["domain"]), None
            except Exception as exc:
                return claim, None, exc

    results = await asyncio.gather(*(collect(claim) for claim in claims))
    for claim, snapshot, error in results:
        persist_monitor_result(claim, snapshot, error)
    return len(claims)


def rescore_brand_incidents(db, job: BackgroundJob) -> None:
    brand = db.scalar(select(ProtectedBrand).where(ProtectedBrand.id == job.payload.get("brand_id"), ProtectedBrand.tenant_id == job.tenant_id))
    if not brand:
        raise ValueError("Protected brand is outside the job tenant")
    incidents = list(db.scalars(select(Incident).where(Incident.brand_id == brand.id, Incident.tenant_id == job.tenant_id)))
    for incident in incidents:
        base_signals = analyze_domain(incident.domain, incident.domain, brand.name, brand.official_domains)
        base_names = {signal.name for signal in base_signals}
        retained = [
            Signal(item.signal, item.value, item.weight, item.explanation)
            for item in incident.contributions
            if (item.signal.startswith("enrichment.") or item.signal in PERSISTENT_SOURCE_SIGNALS) and item.signal not in base_names
        ]
        result = score_signals(base_signals + retained, evidence_sources=2 if retained else 1)
        for contribution in list(incident.contributions):
            db.delete(contribution)
        for signal in result.contributions:
            db.add(ScoreContribution(incident_id=incident.id, signal=signal.name, weight=signal.weight, value=signal.value, explanation=signal.explanation))
        allowlisted = is_official_domain(incident.domain, brand.official_domains)
        candidate = db.get(Candidate, incident.candidate_id)
        if allowlisted:
            if incident.status in {IncidentStatus.NEW, IncidentStatus.MONITORING} or incident.decision_rationale == AUTO_ALLOWLIST_RATIONALE:
                incident.status = IncidentStatus.FALSE_POSITIVE
                incident.decision_rationale = AUTO_ALLOWLIST_RATIONALE
            if candidate and candidate.tenant_id == job.tenant_id:
                candidate.status = "suppressed"
        else:
            if incident.status == IncidentStatus.FALSE_POSITIVE and incident.decision_rationale == AUTO_ALLOWLIST_RATIONALE:
                incident.status = IncidentStatus.NEW
                incident.decision_rationale = None
            if candidate and candidate.tenant_id == job.tenant_id:
                candidate.status = "active"
        incident.risk_score = result.score
        incident.confidence = result.confidence
        incident.severity = Severity(result.severity)
        incident.summary = "; ".join(item.explanation for item in result.contributions)
        incident.detector_version = DETECTOR_VERSION
        incident.updated_at = datetime.now(timezone.utc)


def rebuild_intelligence(db, job: BackgroundJob) -> None:
    # Membership and tenant relevance are derived data. Recompute them so stale
    # relationships cannot leave a domain attached to an otherwise valid profile.
    db.execute(delete(BrandCampaignRelevance))
    db.execute(delete(CampaignMember))
    for campaign in db.scalars(select(IntelligenceCampaign)):
        campaign.classification = "superseded"
    incidents = list(db.scalars(select(Incident).limit(10000)))
    relation_count = sum(ingest_incident_public_evidence(db, incident) for incident in incidents)
    job.payload = {**job.payload, "incidents_processed": len(incidents), "relations_processed": relation_count}


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
    threat_feed_signals: list[Signal] = []
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
    try:
        observations, _ = await URLhausConnector().fetch(domain, {})
        for observation in observations:
            add_evidence(db, job, "threat_feed", observation.source, observation.payload)
            threat_feed_signals.extend(source_signals(observation.payload))
    except Exception as exc:
        add_evidence(db, job, "enrichment_error", "urlhaus", {"status": "error", "error_type": type(exc).__name__})

    incident = db.get(Incident, job.payload["incident_id"])
    if not incident or incident.tenant_id != job.tenant_id:
        raise ValueError("Incident is outside the job tenant")
    brand = db.get(ProtectedBrand, incident.brand_id)
    base_signals = analyze_domain(incident.domain, incident.domain, brand.name, brand.official_domains)
    base_signal_names = {signal.name for signal in base_signals}
    current_threat_names = {signal.name for signal in threat_feed_signals}
    retained_source = [
        Signal(contribution.signal, contribution.value, contribution.weight, contribution.explanation)
        for contribution in incident.contributions
        if contribution.signal in PERSISTENT_SOURCE_SIGNALS and contribution.signal not in base_signal_names and contribution.signal not in current_threat_names
    ]
    signals = base_signals + retained_source + threat_feed_signals + enrichment_signals(payloads["dns"], payloads["rdap"], payloads["tls"])
    result = score_signals(signals, evidence_sources=1 + len([payload for payload in payloads.values() if payload]) + int(bool(threat_feed_signals)))
    for contribution in list(incident.contributions):
        db.delete(contribution)
    for signal in result.contributions:
        db.add(ScoreContribution(incident_id=incident.id, signal=signal.name, weight=signal.weight, value=signal.value, explanation=signal.explanation))
    incident.risk_score = result.score
    incident.confidence = result.confidence
    incident.severity = Severity(result.severity)
    incident.detector_version = DETECTOR_VERSION
    incident.updated_at = datetime.now(timezone.utc)
    ingest_incident_public_evidence(db, incident)


async def main() -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    instance_id = os.getenv("HOSTNAME") or socket.gethostname()
    cycle_count, brand_cursor = load_worker_progress()
    next_discovery_at = datetime.now(timezone.utc)
    update_worker_heartbeat(instance_id, "starting", cycle_count=cycle_count, details={"brand_cursor": brand_cursor, "brand_batch_size": settings.discovery_brand_batch_size})
    while True:
        cycle_started_at = datetime.now(timezone.utc)
        update_worker_heartbeat(
            instance_id,
            "running",
            cycle_started_at=cycle_started_at,
            cycle_count=cycle_count,
            details={"brand_cursor": brand_cursor, "brand_batch_size": settings.discovery_brand_batch_size},
        )
        try:
            now = datetime.now(timezone.utc)
            if now >= next_discovery_at:
                brand_cursor = await poll_live_sources(brand_cursor)
                next_discovery_at = datetime.now(timezone.utc) + timedelta(seconds=settings.discovery_poll_interval_seconds)
            for _ in range(50):
                await process_jobs()
            monitored = 0
            for _ in range(settings.monitor_batches_per_cycle):
                batch_count = await process_domain_monitors()
                monitored += batch_count
                if batch_count < settings.monitor_batch_size:
                    break
        except Exception as exc:
            update_worker_heartbeat(
                instance_id,
                "degraded",
                cycle_count=cycle_count,
                last_error=f"{type(exc).__name__}: {exc}"[:1000],
            )
            await asyncio.sleep(min(settings.monitor_poll_interval_seconds, settings.discovery_poll_interval_seconds))
            continue
        cycle_count += 1
        update_worker_heartbeat(
            instance_id,
            "healthy",
            cycle_completed_at=datetime.now(timezone.utc),
            cycle_count=cycle_count,
            details={"brand_cursor": brand_cursor, "brand_batch_size": settings.discovery_brand_batch_size, "monitors_checked": monitored},
        )
        await asyncio.sleep(min(settings.monitor_poll_interval_seconds, settings.discovery_poll_interval_seconds))


if __name__ == "__main__":
    asyncio.run(main())
