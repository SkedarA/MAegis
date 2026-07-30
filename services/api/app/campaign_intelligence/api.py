from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditEvent, BackgroundJob, Incident
from ..security import Principal, require_analyst, require_principal
from .models import BrandCampaignRelevance, CampaignMember, CampaignPattern, CampaignReview, InfrastructureEntity, InfrastructureRelation, IntelligenceCampaign
from .promotion import promote_campaign_members
from .rules import PATTERN_CATALOG, relation_rule

router = APIRouter(prefix="/api/v1/intelligence", tags=["campaign-intelligence"])


class CampaignReviewUpdate(BaseModel):
    status: Literal["investigating", "monitoring", "dismissed"]
    assigned_to: str | None = Field(default=None, max_length=254)
    rationale: str = Field(min_length=3, max_length=2000)


class CampaignPromotionRequest(BaseModel):
    domains: list[str] | None = Field(default=None, max_length=100)
    rationale: str = Field(min_length=3, max_length=2000)


@router.get("/summary")
def summary(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    relevant = select(BrandCampaignRelevance.campaign_id).where(BrandCampaignRelevance.tenant_id == principal.tenant_id, BrandCampaignRelevance.relevance >= .25).distinct()
    return {
        "entities": db.scalar(select(func.count(InfrastructureEntity.id))) or 0,
        "relations": db.scalar(select(func.count(InfrastructureRelation.id))) or 0,
        "campaigns": db.scalar(select(func.count(IntelligenceCampaign.id)).where(IntelligenceCampaign.classification != "superseded")) or 0,
        "brand_relevant_campaigns": db.scalar(select(func.count()).select_from(relevant.subquery())) or 0,
        "patterns": len(PATTERN_CATALOG),
    }


@router.get("/patterns")
def patterns(_: Principal = Depends(require_principal)) -> list[dict]:
    return PATTERN_CATALOG


@router.get("/campaigns")
def campaigns(limit: int = Query(default=100, ge=1, le=500), relevant_only: bool = False, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> list[dict]:
    statement = select(IntelligenceCampaign).where(IntelligenceCampaign.classification != "superseded").order_by(IntelligenceCampaign.last_seen_at.desc()).limit(limit)
    if relevant_only:
        ids = select(BrandCampaignRelevance.campaign_id).where(BrandCampaignRelevance.tenant_id == principal.tenant_id, BrandCampaignRelevance.relevance >= .25)
        statement = statement.where(IntelligenceCampaign.id.in_(ids))
    rows = list(db.scalars(statement))
    output = []
    for campaign in rows:
        members = db.scalar(select(func.count(CampaignMember.id)).where(CampaignMember.campaign_id == campaign.id)) or 0
        cohesion = db.scalar(select(func.avg(CampaignMember.campaign_confidence)).where(CampaignMember.campaign_id == campaign.id)) or 0
        relevance = db.scalar(select(func.max(BrandCampaignRelevance.relevance)).where(BrandCampaignRelevance.tenant_id == principal.tenant_id, BrandCampaignRelevance.campaign_id == campaign.id)) or 0
        review = db.scalar(select(CampaignReview).where(CampaignReview.tenant_id == principal.tenant_id, CampaignReview.campaign_id == campaign.id))
        output.append({"id": campaign.id, "name": campaign.name, "classification": campaign.classification, "threat_confidence": campaign.threat_confidence, "brand_relevance": relevance, "summary": campaign.summary, "key_indicators": campaign.key_indicators, "independent_families": len(campaign.key_indicators or []), "cohesion": float(cohesion), "member_count": members, "review_status": review.status if review else "unreviewed", "assigned_to": review.assigned_to if review else None, "first_seen_at": campaign.first_seen_at, "last_seen_at": campaign.last_seen_at})
    return output


@router.get("/campaigns/{campaign_id}")
def campaign_detail(campaign_id: str, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    campaign = db.get(IntelligenceCampaign, campaign_id)
    if not campaign: raise HTTPException(status_code=404, detail="Campaign not found")
    rows = db.execute(select(CampaignMember, InfrastructureEntity).join(InfrastructureEntity, InfrastructureEntity.id == CampaignMember.domain_entity_id).where(CampaignMember.campaign_id == campaign.id).order_by(CampaignMember.campaign_confidence.desc())).all()
    relevance = {row.domain_entity_id: row for row in db.scalars(select(BrandCampaignRelevance).where(BrandCampaignRelevance.tenant_id == principal.tenant_id, BrandCampaignRelevance.campaign_id == campaign.id))}
    review = db.scalar(select(CampaignReview).where(CampaignReview.tenant_id == principal.tenant_id, CampaignReview.campaign_id == campaign.id))
    incidents = {item.domain: item.id for item in db.scalars(select(Incident).where(Incident.tenant_id == principal.tenant_id, Incident.domain.in_([entity.normalized_value for _, entity in rows])))}
    return {"campaign": {"id": campaign.id, "name": campaign.name, "classification": campaign.classification, "threat_confidence": campaign.threat_confidence, "summary": campaign.summary, "key_indicators": campaign.key_indicators, "first_seen_at": campaign.first_seen_at, "last_seen_at": campaign.last_seen_at}, "review": {"status": review.status, "assigned_to": review.assigned_to, "rationale": review.rationale, "updated_at": review.updated_at} if review else {"status": "unreviewed", "assigned_to": None, "rationale": None, "updated_at": None}, "members": [{"domain": entity.normalized_value, "campaign_confidence": member.campaign_confidence, "threat_confidence": member.threat_confidence, "brand_relevance": relevance.get(entity.id).relevance if entity.id in relevance else 0, "protected_brand_ids": relevance.get(entity.id).protected_brand_ids if entity.id in relevance else [], "incident_id": incidents.get(entity.normalized_value), "reasons": member.reasons + (relevance.get(entity.id).reasons if entity.id in relevance else [])} for member, entity in rows]}


@router.patch("/campaigns/{campaign_id}/review")
def review_campaign(campaign_id: str, payload: CampaignReviewUpdate, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    require_analyst(principal)
    campaign = db.get(IntelligenceCampaign, campaign_id)
    if not campaign or campaign.classification == "superseded": raise HTTPException(status_code=404, detail="Campaign not found")
    review = db.scalar(select(CampaignReview).where(CampaignReview.tenant_id == principal.tenant_id, CampaignReview.campaign_id == campaign.id))
    before = review.status if review else "unreviewed"
    if review is None:
        review = CampaignReview(tenant_id=principal.tenant_id, campaign_id=campaign.id, status=payload.status, assigned_to=payload.assigned_to or principal.email, rationale=payload.rationale, updated_by=principal.email)
        db.add(review)
    else:
        review.status = payload.status; review.assigned_to = payload.assigned_to or principal.email; review.rationale = payload.rationale; review.updated_by = principal.email
    db.add(AuditEvent(tenant_id=principal.tenant_id, actor=principal.subject, action="campaign.review_updated", resource_type="intelligence_campaign", resource_id=campaign.id, payload={"before": before, "after": payload.status, "rationale": payload.rationale}))
    db.commit(); db.refresh(review)
    return {"status": review.status, "assigned_to": review.assigned_to, "rationale": review.rationale, "updated_at": review.updated_at}


@router.post("/campaigns/{campaign_id}/promote")
def promote_campaign(campaign_id: str, payload: CampaignPromotionRequest, db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    require_analyst(principal)
    campaign = db.get(IntelligenceCampaign, campaign_id)
    if not campaign or campaign.classification == "superseded": raise HTTPException(status_code=404, detail="Campaign not found")
    domains = {item.lower().rstrip(".") for item in payload.domains} if payload.domains else None
    incident_ids = promote_campaign_members(db, campaign, principal.tenant_id, principal.email, domains=domains, automatic=False)
    if not incident_ids: raise HTTPException(status_code=409, detail="No protected-brand-relevant members were eligible for promotion")
    db.add(AuditEvent(tenant_id=principal.tenant_id, actor=principal.subject, action="campaign.promoted", resource_type="intelligence_campaign", resource_id=campaign.id, payload={"incident_ids": incident_ids, "rationale": payload.rationale}))
    db.commit()
    return {"campaign_id": campaign.id, "incident_ids": incident_ids, "promoted": len(incident_ids)}


@router.get("/graph")
def graph(domain: str, db: Session = Depends(get_db), _: Principal = Depends(require_principal)) -> dict:
    seed = db.scalar(select(InfrastructureEntity).where(InfrastructureEntity.entity_type == "domain", InfrastructureEntity.normalized_value == domain.lower().rstrip(".")))
    if not seed: return {"nodes": [], "edges": []}
    relations = list(db.scalars(select(InfrastructureRelation).where((InfrastructureRelation.source_entity_id == seed.id) | (InfrastructureRelation.target_entity_id == seed.id)).limit(500)))
    ids = {seed.id, *(item.source_entity_id for item in relations), *(item.target_entity_id for item in relations)}
    entities = {item.id: item for item in db.scalars(select(InfrastructureEntity).where(InfrastructureEntity.id.in_(ids)))}
    return {"nodes": [{"id": item.id, "type": item.entity_type, "value": item.normalized_value} for item in entities.values()], "edges": [{"id": item.id, "source": item.source_entity_id, "target": item.target_entity_id, "type": item.relation_type, "weight": item.weight, "reason": relation_rule(item.relation_type, entities[item.target_entity_id].entity_type, entities[item.target_entity_id].normalized_value, entities[item.target_entity_id].attributes).reason} for item in relations]}


@router.post("/rebuild", status_code=status.HTTP_202_ACCEPTED)
def rebuild(db: Session = Depends(get_db), principal: Principal = Depends(require_principal)) -> dict:
    require_analyst(principal)
    queued = db.scalar(select(BackgroundJob.id).where(BackgroundJob.tenant_id == principal.tenant_id, BackgroundJob.job_type == "rebuild_intelligence", BackgroundJob.status.in_(["queued", "running"])))
    if queued: return {"job_id": queued, "status": "already_queued"}
    job = BackgroundJob(tenant_id=principal.tenant_id, job_type="rebuild_intelligence", payload={"tenant_id": principal.tenant_id})
    db.add(job)
    db.flush()
    db.add(AuditEvent(tenant_id=principal.tenant_id, actor=principal.subject, action="intelligence.rebuild_requested", resource_type="background_job", resource_id=job.id, payload={}))
    db.commit(); return {"job_id": job.id, "status": "queued"}
