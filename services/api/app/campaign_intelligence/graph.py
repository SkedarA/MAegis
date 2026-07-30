import hashlib
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import func, select

from ..detection import analyze_domain
from ..models import EvidenceItem, Incident, ProtectedBrand
from .fingerprints import certificate_issuance_profile, domain_lure_template, normalize_url_template, page_structure_fingerprint, rdap_registration_profile, url_hostname
from .models import BrandCampaignRelevance, CampaignMember, InfrastructureEntity, InfrastructureRelation, IntelligenceCampaign
from .rules import relation_rule, score_direct_link


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


def _relate(db, source, target, kind: str, source_name: str, evidence_hash: str, observed_at: datetime | None = None) -> None:
    observed = observed_at or datetime.now(timezone.utc)
    rule = relation_rule(kind, target.entity_type, target.normalized_value, target.attributes)
    relation = db.scalar(select(InfrastructureRelation).where(InfrastructureRelation.source_entity_id == source.id, InfrastructureRelation.target_entity_id == target.id, InfrastructureRelation.relation_type == kind))
    if relation is None:
        db.add(InfrastructureRelation(source_entity_id=source.id, target_entity_id=target.id, relation_type=kind, confidence=1, weight=rule.weight, source=source_name, evidence_hash=evidence_hash, first_seen_at=observed, last_seen_at=observed))
    else:
        relation.first_seen_at = min(relation.first_seen_at, observed); relation.last_seen_at = max(relation.last_seen_at, observed); relation.evidence_hash = evidence_hash; relation.weight = rule.weight


def ingest_incident_public_evidence(db, incident: Incident) -> int:
    domain = _entity(db, "domain", incident.domain)
    domain.first_seen_at = min(domain.first_seen_at, incident.created_at)
    brand_tokens = list(db.scalars(select(ProtectedBrand.canonical_name).where(ProtectedBrand.monitoring_enabled.is_(True))))
    lure_template = domain_lure_template(incident.domain, brand_tokens)
    if lure_template:
        _relate(db, domain, _entity(db, "domain_template", lure_template), "uses_domain_template", "maegis", hashlib.sha256(lure_template.encode()).hexdigest(), incident.created_at)
    evidence = list(db.scalars(select(EvidenceItem).where(EvidenceItem.incident_id == incident.id)))
    created = 1 if lure_template else 0
    for item in evidence:
        payload = item.payload or {}
        if item.evidence_type == "dns":
            records = payload.get("records") or {}
            for record, entity_type, relation in (("A", "ip", "resolves_to"), ("AAAA", "ip", "resolves_to"), ("NS", "nameserver", "uses_nameserver"), ("MX", "mx", "uses_mx"), ("CNAME", "domain", "aliases_to")):
                for value in records.get(record) or []:
                    _relate(db, domain, _entity(db, entity_type, value), relation, item.source, item.raw_hash, item.collected_at); created += 1
        elif item.evidence_type == "tls_certificate" and payload.get("sha256"):
            certificate = _entity(db, "certificate", payload["sha256"], {"issuer": payload.get("issuer")})
            _relate(db, domain, certificate, "presents_certificate", item.source, item.raw_hash, item.collected_at); created += 1
            for san in payload.get("sans") or []:
                _relate(db, certificate, _entity(db, "domain", san), "certificate_contains", item.source, item.raw_hash, item.collected_at); created += 1
            certificate_profile = certificate_issuance_profile(payload)
            if certificate_profile:
                _relate(db, domain, _entity(db, "certificate_profile", certificate_profile), "shares_certificate_profile", item.source, item.raw_hash, item.collected_at); created += 1
        elif item.evidence_type == "rdap":
            registrar = payload.get("registrar")
            if not registrar:
                registrar = next((entity.get("handle") for entity in payload.get("entities", []) if "registrar" in (entity.get("roles") or [])), None)
            if registrar:
                _relate(db, domain, _entity(db, "registrar", str(registrar)), "registered_by", item.source, item.raw_hash, item.collected_at); created += 1
            registration_profile = rdap_registration_profile(payload)
            if registration_profile:
                _relate(db, domain, _entity(db, "registration_profile", registration_profile), "shares_registration_profile", item.source, item.raw_hash, item.collected_at); created += 1
        elif item.evidence_type == "threat_feed":
            domain.attributes = {**(domain.attributes or {}), "threat_sources": sorted(set([*(domain.attributes or {}).get("threat_sources", []), item.source]))}
        elif item.evidence_type in {"source_observation", "website_capture", "capture"}:
            if payload.get("page_ip"):
                _relate(db, domain, _entity(db, "ip", str(payload["page_ip"])), "resolves_to", item.source, item.raw_hash, item.collected_at); created += 1
            if payload.get("page_asn"):
                asn = _entity(db, "asn", str(payload["page_asn"]), {"name": payload.get("page_asnname")})
                _relate(db, domain, asn, "hosted_by_asn", item.source, item.raw_hash, item.collected_at); created += 1
            urls = [payload.get("submitted_url"), payload.get("effective_url"), payload.get("url")]
            for template in sorted({item for item in (normalize_url_template(value) for value in urls) if item}):
                _relate(db, domain, _entity(db, "url_template", template), "uses_path_template", item.source, item.raw_hash, item.collected_at); created += 1
            submitted_host, effective_host = url_hostname(payload.get("submitted_url")), url_hostname(payload.get("effective_url"))
            if submitted_host and effective_host and submitted_host.lower() != effective_host.lower():
                _relate(db, domain, _entity(db, "domain", effective_host), "redirects_to", item.source, item.raw_hash, item.collected_at); created += 1
            if payload.get("favicon_hash"):
                _relate(db, domain, _entity(db, "favicon", str(payload["favicon_hash"])), "shares_favicon", item.source, item.raw_hash, item.collected_at); created += 1
            structure = page_structure_fingerprint(payload)
            if structure:
                _relate(db, domain, _entity(db, "page_structure", structure), "shares_structure", item.source, item.raw_hash, item.collected_at); created += 1
    db.flush(); rebuild_campaigns_for_domain(db, domain)
    return created


def _brand_relevance(db, campaign, entity) -> None:
    for tenant_id in db.scalars(select(ProtectedBrand.tenant_id).where(ProtectedBrand.monitoring_enabled.is_(True)).distinct()):
        matched, relevance, reasons = [], 0.0, []
        for brand in db.scalars(select(ProtectedBrand).where(ProtectedBrand.tenant_id == tenant_id, ProtectedBrand.monitoring_enabled.is_(True))):
            signals = analyze_domain(entity.normalized_value, entity.normalized_value, brand.name, brand.official_domains)
            score = min(1.0, sum(max(0, signal.weight * signal.value) for signal in signals) / 100)
            relevance = max(relevance, score)
            if score >= .25: matched.append(brand.id); reasons.append(f"Domain pattern is relevant to {brand.name}")
        row = db.scalar(select(BrandCampaignRelevance).where(BrandCampaignRelevance.tenant_id == tenant_id, BrandCampaignRelevance.campaign_id == campaign.id, BrandCampaignRelevance.domain_entity_id == entity.id))
        if row is None: db.add(BrandCampaignRelevance(tenant_id=tenant_id, campaign_id=campaign.id, domain_entity_id=entity.id, relevance=relevance, protected_brand_ids=matched, reasons=reasons))
        else: row.relevance, row.protected_brand_ids, row.reasons = relevance, matched, reasons


def rebuild_campaigns_for_domain(db, seed: InfrastructureEntity) -> None:
    seed_relations = list(db.scalars(select(InfrastructureRelation).where(InfrastructureRelation.source_entity_id == seed.id, InfrastructureRelation.weight > 0)))
    total_domains = db.scalar(select(func.count(InfrastructureEntity.id)).where(InfrastructureEntity.entity_type == "domain")) or 1
    peers: dict[str, list[tuple[InfrastructureRelation, int, InfrastructureEntity]]] = defaultdict(list)
    for relation in seed_relations:
        target = db.get(InfrastructureEntity, relation.target_entity_id)
        degree = db.scalar(select(func.count(InfrastructureRelation.id)).where(InfrastructureRelation.target_entity_id == relation.target_entity_id, InfrastructureRelation.source_entity_id != relation.target_entity_id)) or 1
        for peer_relation in db.scalars(select(InfrastructureRelation).where(InfrastructureRelation.target_entity_id == relation.target_entity_id, InfrastructureRelation.source_entity_id != seed.id, InfrastructureRelation.weight > 0).limit(500)):
            peer = db.get(InfrastructureEntity, peer_relation.source_entity_id)
            if peer and peer.entity_type == "domain": peers[peer.id].append((relation, degree, target))
    for peer_id, shared in peers.items():
        peer = db.get(InfrastructureEntity, peer_id)
        trusted = bool((seed.attributes or {}).get("threat_sources") or (peer.attributes or {}).get("threat_sources"))
        now = datetime.now(timezone.utc)
        signals = []
        for relation, degree, target in shared:
            last_seen = relation.last_seen_at
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            signals.append({"relation_type": relation.relation_type, "target_type": target.entity_type, "target_value": target.normalized_value, "attributes": target.attributes, "degree": degree, "total_domains": total_domains, "age_days": max(0, (now - last_seen).total_seconds() / 86400)})
        result = score_direct_link(signals, seed.first_seen_at, peer.first_seen_at, trusted)
        if not result.admitted: continue
        profile = sorted({f"{relation.relation_type}:{relation.target_entity_id}" for relation, _, _ in shared})
        signature = "v2:" + hashlib.sha256("|".join(profile).encode()).hexdigest()[:61]
        campaign = db.scalar(select(IntelligenceCampaign).where(IntelligenceCampaign.signature == signature))
        threat = .85 if trusted else .35
        indicators = [{"family": family, "score": value} for family, value in sorted(result.family_scores.items())]
        if campaign is None:
            campaign = IntelligenceCampaign(signature=signature, name=f"Correlated campaign {signature[3:11]}", classification=result.classification, threat_confidence=threat, summary=f"{result.score}% direct linkage across {result.independent_families} independent evidence families", key_indicators=indicators)
            db.add(campaign); db.flush()
        else:
            campaign.classification = result.classification; campaign.threat_confidence = max(campaign.threat_confidence, threat); campaign.summary = f"{result.score}% direct linkage across {result.independent_families} independent evidence families"; campaign.key_indicators = indicators; campaign.last_seen_at = datetime.now(timezone.utc)
        for entity in (seed, peer):
            member = db.scalar(select(CampaignMember).where(CampaignMember.campaign_id == campaign.id, CampaignMember.domain_entity_id == entity.id))
            if member is None:
                member = CampaignMember(campaign_id=campaign.id, domain_entity_id=entity.id)
                db.add(member)
            member.campaign_confidence = result.score / 100; member.threat_confidence = threat; member.reasons = result.reasons
            _brand_relevance(db, campaign, entity)
