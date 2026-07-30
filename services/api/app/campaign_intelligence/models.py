from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base
from ..models import new_id


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class InfrastructureEntity(Base):
    __tablename__ = "intelligence_entities"
    __table_args__ = (UniqueConstraint("entity_type", "normalized_value", name="uq_intelligence_entity"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    normalized_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class InfrastructureRelation(Base):
    __tablename__ = "intelligence_relations"
    __table_args__ = (
        UniqueConstraint("source_entity_id", "target_entity_id", "relation_type", name="uq_intelligence_relation"),
        Index("ix_intelligence_relation_source", "source_entity_id", "relation_type"),
        Index("ix_intelligence_relation_target", "target_entity_id", "relation_type"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_entity_id: Mapped[str] = mapped_column(ForeignKey("intelligence_entities.id"), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(ForeignKey("intelligence_entities.id"), nullable=False)
    relation_type: Mapped[str] = mapped_column(String(60), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1)
    weight: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class IntelligenceCampaign(Base):
    __tablename__ = "intelligence_campaigns"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    signature: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    classification: Mapped[str] = mapped_column(String(40), default="possible_infrastructure_reuse")
    threat_confidence: Mapped[float] = mapped_column(Float, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    key_indicators: Mapped[list] = mapped_column(JSON, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class CampaignMember(Base):
    __tablename__ = "intelligence_campaign_members"
    __table_args__ = (UniqueConstraint("campaign_id", "domain_entity_id", name="uq_campaign_domain"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("intelligence_campaigns.id"), nullable=False, index=True)
    domain_entity_id: Mapped[str] = mapped_column(ForeignKey("intelligence_entities.id"), nullable=False, index=True)
    campaign_confidence: Mapped[float] = mapped_column(Float, default=0)
    threat_confidence: Mapped[float] = mapped_column(Float, default=0)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BrandCampaignRelevance(Base):
    __tablename__ = "intelligence_brand_relevance"
    __table_args__ = (UniqueConstraint("tenant_id", "campaign_id", "domain_entity_id", name="uq_brand_campaign_relevance"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("intelligence_campaigns.id"), nullable=False, index=True)
    domain_entity_id: Mapped[str] = mapped_column(ForeignKey("intelligence_entities.id"), nullable=False, index=True)
    relevance: Mapped[float] = mapped_column(Float, default=0)
    protected_brand_ids: Mapped[list] = mapped_column(JSON, default=list)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CampaignReview(Base):
    __tablename__ = "intelligence_campaign_reviews"
    __table_args__ = (UniqueConstraint("tenant_id", "campaign_id", name="uq_tenant_campaign_review"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("intelligence_campaigns.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), default="unreviewed", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(254), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(254), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CampaignPattern(Base):
    __tablename__ = "intelligence_patterns"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    key: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    version: Mapped[str] = mapped_column(String(30), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True)
    definition: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
