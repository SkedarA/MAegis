import type { Incident } from "../../incident-types";

export type ApiIncident = {
  id: string;
  domain: string;
  brand_id: string;
  risk_score: number;
  confidence: number;
  severity: string;
  status: string;
  summary: string;
  assigned_to: string | null;
  created_at: string;
  contributions?: Array<{ explanation: string }>;
};

export function backendUrl(path: string) {
  const baseUrl = process.env.MAEGIS_API_URL;
  return baseUrl ? `${baseUrl.replace(/\/$/, "")}${path}` : null;
}

export function backendHeaders(extra: Record<string, string> = {}) {
  return {
    ...(process.env.MAEGIS_API_KEY ? { "X-API-Key": process.env.MAEGIS_API_KEY } : {}),
    ...(process.env.MAEGIS_TENANT_ID ? { "X-Tenant-ID": process.env.MAEGIS_TENANT_ID } : {}),
    ...extra,
  };
}

export function titleCase(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function ageFrom(value: string) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export function toConsoleIncident(row: ApiIncident, brands: Map<string, string>): Incident {
  return {
    id: row.id,
    domain: row.domain,
    brand: brands.get(row.brand_id) ?? `Brand ${row.brand_id.slice(0, 8)}`,
    source: "MAegis API",
    score: Math.round(row.risk_score),
    confidence: Math.round(row.confidence * 100),
    severity: titleCase(row.severity) as Incident["severity"],
    status: titleCase(row.status) as Incident["status"],
    age: ageFrom(row.created_at),
    firstSeen: new Date(row.created_at).toLocaleString("en-GB", { timeZone: "UTC" }) + " UTC",
    assignedTo: row.assigned_to,
    signals: (row.contributions ?? []).map((item) => item.explanation),
    summary: row.summary,
  };
}

export async function fetchBrandMap() {
  const url = backendUrl("/api/v1/brands");
  if (!url) return new Map<string, string>();
  const response = await fetch(url, { headers: backendHeaders(), cache: "no-store", signal: AbortSignal.timeout(5000) });
  if (!response.ok) return new Map<string, string>();
  const rows = await response.json() as Array<{ id: string; name: string }>;
  return new Map(rows.map((row) => [row.id, row.name]));
}
