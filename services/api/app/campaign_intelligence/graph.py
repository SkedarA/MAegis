import hashlib
from datetime import datetime, timezone

from sqlalchemy import select

from ..detection import analyze_domain
from ..models import EvidenceItem, Incident, ProtectedBrand
from .models import BrandCampaignRelevance, CampaignMember, InfrastructureEntity, InfrastructureRelation, IntelligenceCampaign
from .rules import relation_rule


def _entity(db, kind: str, value: str, attributes: dict | None = None) -> InfrastructureEntity:
    normalized = value.strip().lower().rstrip(".")
    item = db.scalar(select(InfrastructureEntity).where(InfrastructureEntity.entity_type == kind, InfrastructureEntity.normalized_value == normalized))
    if item is None:
        item = InfrastructureEntity(entity_type=kind, normalized_value=normalized, attributes=attributes or {})
        db.add(item); db.flush()
    else:
        item.last_seen_at = datetime.now(timezone.utc)
        if attributes: item.attributes = {**(item.attributes or {}), **attributes}
    return item


def _relate(db, source, target, kind: str, source_name: str, evidence_hash: str) -> None:
    rule = relation_rule(kind, target.entity_type, target.normalized_value, target.attributes)
    relation = db.scalar(select(InfrastructureRelation).where(InfrastructureRelation.source_entity_id == source.id, InfrastructureRelation.target_entity_id == target.id, InfrastructureRelation.relation_type == kind))
    if relation is None:
        db.add(InfrastructureRelation(source_entity_id=source.id, target_entity_id=target.id, relation_type=kind, confidence=1, weight=rule.weight, source=source_name, evidence_hash=evidence_hash))
    else:
        relation.last_seen_at = datetime.now(timezone.utc); relation.evidence_hash = evidence_hash; relation.weight = rule.weight


def ingest_incident_public_evidence(db, incident: Incident) -> int:
    domain = _entity(db, "domain", incident.domain)
    evidence = list(db.scalars(select(EvidenceItem).where(EvidenceItem.incident_id == incident.id)))
    created = 0
    for item in evidence:
        payload = item.payload or {}
        if item.evidence_type == "dns":
            records = payload.get("records") or {}
            for record, entity_type, relation in (("A", "ip", "resolves_to"), ("AAAA", "ip", "resolves_to"), ("NS", "nameserver", "uses_nameserver"), ("MX", "mx", "uses_mx"), ("CNAME", "domain", "aliases_to")):
                for value in records.get(record) or []:
                    _relate(db, domain, _entity(db, entity_type, value), relation, item.source, item.raw_hash); created += 1
        elif item.evidence_type == "tls_certificate" and payload.get("sha256"):
            certificate = _entity(db, "certificate", payload["sha256"], {"issuer": payload.get("issuer")})
            _relate(db, domain, certificate, "presents_certificate", item.source, item.raw_hash); created += 1
            for san in payload.get("sans") or []:
                _relate(db, certificate, _entity(db, "domain", san), "certificate_contains", item.source, item.raw_hash); created += 1
        elif item.evidence_type == "rdap" and payload.get("registrar"):
            _relate(db, domain, _entity(db, "registrar", str(payload["registrar"])), "registered_by", item.source, item.raw_hash); created += 1
        elif item.evidence_type == "threat_feed":
            sources = sorted(set([*(domain.attributes or {}).get("threat_sources", []), item.source]))
            domain.attributes = {**(domain.attributes or {}), "threat_sources": sources}
    db.flush()
    rebuild_campaigns_for_domain(db, domain)
    return created


def rebuild_campaigns_for_domain(db, seed: InfrastructureEntity) -> None:
    relations = list(db.scalars(select(InfrastructureRelation).where(InfrastructureRelation.source_entity_id == seed.id, InfrastructureRelation.weight >= 18)))
    for relation in relations:
        peers = list(db.scalars(select(InfrastructureRelation).where(InfrastructureRelation.target_entity_id == relation.target_entity_id, InfrastructureRelation.source_entity_id != seed.id, InfrastructureRelation.weight >= 18)))
        domain_ids = sorted({seed.id, *(peer.source_entity_id for peer in peers)})
        if len(domain_ids) < 2: continue
        signature = hashlib.sha256((relation.relation_type + ":" + relation.target_entity_id).encode()).hexdigest()
        campaign = db.scalar(select(IntelligenceCampaign).where(IntelligenceCampaign.signature == signature))
        rule = relation_rule(relation.relation_type, "entity", "")
        linked_entities = [db.get(InfrastructureEntity, item) for item in domain_ids]
        threat_confidence = .85 if any((item.attributes or {}).get("threat_sources") for item in linked_entities) else .35
        if campaign is None:
            campaign = IntelligenceCampaign(signature=signature, name=f"Infrastructure cluster {signature[:8]}", classification="probable_campaign" if relation.weight >= 25 else "possible_infrastructure_reuse", threat_confidence=threat_confidence, summary=rule.reason, key_indicators=[relation.relation_type])
            db.add(campaign); db.flush()
        else:
            campaign.threat_confidence = max(campaign.threat_confidence, threat_confidence)
        campaign.last_seen_at = datetime.now(timezone.utc)
        for domain_id in domain_ids:
            entity = db.get(InfrastructureEntity, domain_id)
            member = db.scalar(select(CampaignMember).where(CampaignMember.campaign_id == campaign.id, CampaignMember.domain_entity_id == domain_id))
            if member is None:
                db.add(CampaignMember(campaign_id=campaign.id, domain_entity_id=domain_id, campaign_confidence=min(1, relation.weight / 35), threat_confidence=campaign.threat_confidence, reasons=[rule.reason]))
            tenants = list(db.scalars(select(ProtectedBrand.tenant_id).where(ProtectedBrand.monitoring_enabled.is_(True)).distinct()))
            for tenant_id in tenants:
                brands = list(db.scalars(select(ProtectedBrand).where(ProtectedBrand.tenant_id == tenant_id, ProtectedBrand.monitoring_enabled.is_(True))))
                matched, relevance, reasons = [], 0.0, []
                for brand in brands:
                    signals = analyze_domain(entity.normalized_value, entity.normalized_value, brand.name, brand.official_domains)
                    score = min(1.0, sum(max(0, signal.weight * signal.value) for signal in signals) / 100)
                    if score > relevance: relevance = score
                    if score >= .25:
                        matched.append(brand.id); reasons.append(f"Domain pattern is relevant to {brand.name}")
                relevance_row = db.scalar(select(BrandCampaignRelevance).where(BrandCampaignRelevance.tenant_id == tenant_id, BrandCampaignRelevance.campaign_id == campaign.id, BrandCampaignRelevance.domain_entity_id == domain_id))
                if relevance_row is None:
                    db.add(BrandCampaignRelevance(tenant_id=tenant_id, campaign_id=campaign.id, domain_entity_id=domain_id, relevance=relevance, protected_brand_ids=matched, reasons=reasons))
                else:
                    relevance_row.relevance = relevance; relevance_row.protected_brand_ids = matched; relevance_row.reasons = reasons
