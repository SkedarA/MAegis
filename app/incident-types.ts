export type IncidentSeverity = "Informational" | "Low" | "Medium" | "High" | "Critical";
export type IncidentStatus = "New" | "Investigating" | "Likely Abuse" | "Confirmed" | "False Positive" | "Monitoring" | "Closed";

export type Incident = {
  id: string;
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

export type EvidenceItem = {
  id: string;
  evidenceType: string;
  source: string;
  payload: Record<string, unknown>;
  rawHash: string;
  collectedAt: string;
};
