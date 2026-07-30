import hashlib
import json

from sqlalchemy import select

from ..detection import analyze_domain
from ..models import AuditEvent, BackgroundJob, Candidate, EvidenceItem, Incident, IncidentStatus, ProtectedBrand, Severity
from ..scoring import score_signals
from .models import BrandCampaignRelevance, CampaignMember, CampaignReview, InfrastructureEntity, IntelligenceCampaign
from .rules import promotion_eligible


def promote_campaign_members(db, campaign: IntelligenceCampaign, tenant_id: str, actor: str, *, domains: set[str] | None = None, automatic: bool = False) -> list[str]:
    existing_review = db.scalar(select(CampaignReview).where(CampaignReview.tenant_id == tenant_id, CampaignReview.campaign_id == campaign.id))
    if automatic and existing_review is not None:
        # Any human workflow state takes precedence over automation.
        return []
    rows = db.execute(
        select(CampaignMember, InfrastructureEntity, BrandCampaignRelevance)
        .join(InfrastructureEntity, InfrastructureEntity.id == CampaignMember.domain_entity_id)
        .join(BrandCampaignRelevance, (BrandCampaignRelevance.campaign_id == CampaignMember.campaign_id) & (BrandCampaignRelevance.domain_entity_id == CampaignMember.domain_entity_id))
        .where(CampaignMember.campaign_id == campaign.id, BrandCampaignRelevance.tenant_id == tenant_id, BrandCampaignRelevance.relevance >= .25)
        .order_by(BrandCampaignRelevance.relevance.desc(), CampaignMember.campaign_confidence.desc())
        .limit(100)
    ).all()
    promoted: list[str] = []
    for member, entity, relevance in rows:
        if domains is not None and entity.normalized_value not in domains:
            continue
        if automatic and not promotion_eligible(member.campaign_confidence, campaign.threat_confidence, relevance.relevance):
            continue
        brand_id = next((item for item in relevance.protected_brand_ids if db.scalar(select(ProtectedBrand.id).where(ProtectedBrand.id == item, ProtectedBrand.tenant_id == tenant_id))), None)
        if not brand_id:
            continue
        incident = db.scalar(select(Incident).where(Incident.tenant_id == tenant_id, Incident.domain == entity.normalized_value).order_by(Incident.created_at.desc()))
        if incident is None:
            brand = db.get(ProtectedBrand, brand_id)
            signals = analyze_domain(entity.normalized_value, entity.normalized_value, brand.name, brand.official_domains)
            result = score_signals(signals)
            candidate = db.scalar(select(Candidate).where(Candidate.tenant_id == tenant_id, Candidate.brand_id == brand_id, Candidate.domain == entity.normalized_value))
            if candidate is None:
                candidate = Candidate(tenant_id=tenant_id, brand_id=brand_id, domain=entity.normalized_value, unicode_domain=entity.normalized_value, source="campaign_intelligence")
                db.add(candidate); db.flush()
            incident = Incident(tenant_id=tenant_id, brand_id=brand_id, candidate_id=candidate.id, domain=entity.normalized_value, title=f"Campaign-linked {brand.name} domain", status=IncidentStatus.NEW, severity=Severity.HIGH if campaign.threat_confidence >= .85 else Severity.MEDIUM, risk_score=max(65, result.score), confidence=max(member.campaign_confidence, result.confidence), summary=f"Promoted for analyst review from {campaign.name}; no malicious verdict has been asserted.", detector_version="campaign-rules-2.1")
            db.add(incident); db.flush()
            db.add(BackgroundJob(tenant_id=tenant_id, job_type="enrich_domain", payload={"incident_id": incident.id, "domain": incident.domain, "trigger": "campaign_promotion"}))
        elif incident.status == IncidentStatus.MONITORING:
            incident.status = IncidentStatus.NEW
        elif automatic and incident.status in {IncidentStatus.FALSE_POSITIVE, IncidentStatus.CLOSED}:
            continue
        evidence_payload = {"campaign_id": campaign.id, "campaign_name": campaign.name, "campaign_confidence": member.campaign_confidence, "threat_confidence": campaign.threat_confidence, "brand_relevance": relevance.relevance, "reasons": member.reasons, "automatic": automatic}
        raw_hash = hashlib.sha256(json.dumps(evidence_payload, sort_keys=True).encode()).hexdigest()
        exists = db.scalar(select(EvidenceItem.id).where(EvidenceItem.incident_id == incident.id, EvidenceItem.evidence_type == "campaign_link", EvidenceItem.raw_hash == raw_hash))
        if exists and automatic:
            continue
        if not exists:
            db.add(EvidenceItem(tenant_id=tenant_id, incident_id=incident.id, evidence_type="campaign_link", source="maegis_campaign_intelligence", payload=evidence_payload, raw_hash=raw_hash))
        db.add(AuditEvent(tenant_id=tenant_id, actor=actor, action="campaign.member_promoted", resource_type="incident", resource_id=incident.id, payload={"campaign_id": campaign.id, "domain": incident.domain, "automatic": automatic}))
        promoted.append(incident.id)
    if promoted:
        review = existing_review or db.scalar(select(CampaignReview).where(CampaignReview.tenant_id == tenant_id, CampaignReview.campaign_id == campaign.id))
        if review is None:
            db.add(CampaignReview(tenant_id=tenant_id, campaign_id=campaign.id, status="promoted", updated_by=actor, rationale=f"{len(promoted)} member(s) promoted for analyst review"))
        else:
            review.status = "promoted"; review.updated_by = actor; review.rationale = f"{len(promoted)} member(s) promoted for analyst review"
    return promoted
