export type IncidentSeverity = "Informational" | "Low" | "Medium" | "High" | "Critical";
export type IncidentStatus = "New" | "Investigating" | "Likely Abuse" | "Confirmed" | "False Positive" | "Monitoring" | "Closed";

export type Incident = {
  id: string;
  brandId?: string;
  domain: string;
  brand: string;
  source: string;
  score: number;
  confidence: number;
  severity: IncidentSeverity;
  status: IncidentStatus;
  age: string;
  firstSeen: string;
  assignedTo: string | null;
  signals: string[];
  summary: string;
  references?: Array<{ label: string; url: string }>;
};

export type DashboardSummary = {
  window_days: number;
  generated_at: string;
  totals: { incidents: number; open: number; critical: number; unassigned: number; average_risk: number; clients: number };
  by_brand: Array<{ brand_id: string; name: string; monitoring_enabled: boolean; total: number; open: number; critical: number; high: number; unassigned: number; max_risk: number; average_risk: number }>;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  timeline: Array<{ date: string; total: number; high_critical: number }>;
};

export type EvidenceItem = {
  id: string;
  evidenceType: string;
  source: string;
  payload: Record<string, unknown>;
  rawHash: string;
  collectedAt: string;
};

export type AnalystAccount = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  active: boolean;
};

export type IncidentNote = {
  id: string;
  incident_id: string;
  author_id: string;
  author_email: string;
  author_name: string;
  body: string;
  created_at: string;
};

export type RelatedIncident = {
  id: string;
  domain: string;
  brand: string;
  risk_score: number;
  severity: string;
  status: string;
  shared_indicators: string[];
  reasons: string[];
};

export type DomainContext = {
  domain_type: "platform_tenant" | "registered_domain";
  registrable_domain: string;
  platform_suffix: string | null;
  hosting_provider: { name: string | null; contact: string | null; source: string; confidence: string; evidence: string | null };
  registrar: { name: string | null; contact: string | null; source: string; confidence: string; evidence: string | null };
  registration_date: string | null;
  registration_relevant: boolean;
  override: { active: boolean; updated_by: string | null; updated_at: string | null; rationale: string | null };
};
