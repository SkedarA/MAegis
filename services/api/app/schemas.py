from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class BrandCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    official_domains: list[str] = Field(min_length=1)
    trademarks: list[str] = []
    keywords: list[str] = []
    permitted_variations: list[str] = []
    legitimate_interest_confirmed: bool

    @field_validator("legitimate_interest_confirmed")
    @classmethod
    def interest_required(cls, value: bool) -> bool:
        if not value:
            raise ValueError("A legitimate defensive or research purpose must be confirmed")
        return value


class BrandView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    canonical_name: str
    official_domains: list[str]
    keywords: list[str]
    monitoring_enabled: bool
    created_at: datetime


class CatalogBrandView(BaseModel):
    key: str
    name: str
    sector: str
    official_domains: list[str]
    trademarks: list[str]
    permitted_variations: list[str]
    keywords: list[str]


class CatalogEnrollmentCreate(BaseModel):
    keys: list[str] | None = None
    monitoring_enabled: bool = True
    legitimate_interest_confirmed: bool

    @field_validator("legitimate_interest_confirmed")
    @classmethod
    def enrollment_interest_required(cls, value: bool) -> bool:
        if not value:
            raise ValueError("A legitimate defensive or research purpose must be confirmed")
        return value


class CatalogEnrollmentView(BaseModel):
    created: int
    updated: int
    monitoring_enabled: bool
    brand_ids: list[str]


class SubmissionCreate(BaseModel):
    brand_id: str
    value: str = Field(min_length=3, max_length=2048)
    request_capture: bool = False


class TriageUpdate(BaseModel):
    status: Literal["investigating", "likely_abuse", "confirmed", "false_positive", "monitoring", "closed"]
    severity: Literal["informational", "low", "medium", "high", "critical"] | None = None
    assigned_to: str | None = Field(default=None, max_length=160)
    rationale: str = Field(min_length=5, max_length=4000)


class ContributionView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    signal: str
    weight: float
    value: float
    explanation: str


class IncidentView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    brand_id: str
    domain: str
    title: str
    status: str
    severity: str
    risk_score: float
    confidence: float
    summary: str
    assigned_to: str | None
    detector_version: str
    created_at: datetime
    updated_at: datetime
    contributions: list[ContributionView] = []


class AIAnalysisView(BaseModel):
    classification: str
    severity: str
    confidence: float
    observed_facts: list[dict]
    inferences: list[dict]
    recommended_actions: list[str]
    executive_summary: str
    evidence_pack_version: str = "1.0"
