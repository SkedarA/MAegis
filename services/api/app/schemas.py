from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator


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
    archived: bool = False
    created_at: datetime


class BrandUpdate(BaseModel):
    monitoring_enabled: bool | None = None


class OfficialAssetCreate(BaseModel):
    asset_type: Literal["domain", "subdomain", "wildcard"]
    value: str = Field(min_length=3, max_length=253)


class OfficialAssetView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    brand_id: str
    asset_type: str
    value: str
    created_by: str
    created_at: datetime


class BrandArchiveCreate(BaseModel):
    rationale: str = Field(min_length=5, max_length=1000)


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


class MonitorUpdate(BaseModel):
    state: Literal["active", "paused"] | None = None
    interval_seconds: int | None = Field(default=None, ge=900, le=604800)


class AnalystCreate(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    display_name: str = Field(min_length=2, max_length=160)
    role: Literal["viewer", "analyst", "manager", "administrator"] = "analyst"


class AnalystView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    display_name: str
    role: str
    active: bool


class AnalystUpdate(BaseModel):
    role: Literal["viewer", "analyst", "manager", "administrator"] | None = None
    active: bool | None = None


class ConnectorUpdate(BaseModel):
    enabled: bool


class AuditEventView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    payload: dict
    created_at: datetime


class AssignmentUpdate(BaseModel):
    analyst_id: str


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=2, max_length=8000)


class IncidentNoteView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    incident_id: str
    author_id: str
    author_email: str
    author_name: str
    body: str
    created_at: datetime


class DomainContextOverrideUpdate(BaseModel):
    hosting_provider_name: str | None = Field(default=None, max_length=200)
    hosting_provider_contact: str | None = Field(default=None, max_length=500)
    registrar_name: str | None = Field(default=None, max_length=200)
    registrar_contact: str | None = Field(default=None, max_length=500)
    rationale: str = Field(min_length=5, max_length=2000)
    clear: bool = False

    @field_validator("hosting_provider_contact", "registrar_contact")
    @classmethod
    def safe_contact(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        normalized = value.strip()
        if normalized.startswith("https://") or ("@" in normalized and " " not in normalized and ":" not in normalized):
            return normalized
        raise ValueError("Contact must be an HTTPS URL or email address")

    @model_validator(mode="after")
    def attribution_or_clear_required(self):
        if not self.clear and not any((self.hosting_provider_name, self.hosting_provider_contact, self.registrar_name, self.registrar_contact)):
            raise ValueError("At least one provider or registrar value is required")
        return self


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


class EvidenceView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    evidence_type: str
    source: str
    payload: dict
    raw_hash: str
    collected_at: datetime


class AIAnalysisView(BaseModel):
    classification: str
    severity: str
    confidence: float
    observed_facts: list[dict]
    inferences: list[dict]
    recommended_actions: list[str]
    executive_summary: str
    evidence_pack_version: str = "1.0"
