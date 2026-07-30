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

function decodedHeader(request: Request | undefined, name: string) {
  const value = request?.headers.get(name);
  if (!value) return null;
  try { return decodeURIComponent(value); } catch { return null; }
}

export function backendHeaders(request?: Request, extra: Record<string, string> = {}) {
  const authenticatedEmail = request?.headers.get("oai-authenticated-user-email");
  const authenticatedName = request?.headers.get("oai-authenticated-user-full-name-encoding") === "percent-encoded-utf-8"
    ? decodedHeader(request, "oai-authenticated-user-full-name")
    : null;
  const email = authenticatedEmail ?? process.env.MAEGIS_USER_EMAIL ?? "analyst@maegis.local";
  const isConfiguredOwner = Boolean(authenticatedEmail && process.env.MAEGIS_OWNER_EMAIL && authenticatedEmail.toLowerCase() === process.env.MAEGIS_OWNER_EMAIL.toLowerCase());
  const role = authenticatedEmail
    ? isConfiguredOwner ? "administrator" : process.env.MAEGIS_AUTHENTICATED_USER_ROLE ?? "analyst"
    : process.env.MAEGIS_USER_ROLE ?? "administrator";
  return {
    ...(process.env.MAEGIS_API_KEY ? { "X-API-Key": process.env.MAEGIS_API_KEY } : {}),
    ...(process.env.MAEGIS_TENANT_ID ? { "X-Tenant-ID": process.env.MAEGIS_TENANT_ID } : {}),
    "X-User-ID": authenticatedEmail ?? process.env.MAEGIS_USER_ID ?? "local-analyst",
    "X-User-Email": email,
    "X-User-Name": authenticatedName ?? process.env.MAEGIS_USER_NAME ?? email,
    "X-Role": role,
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
    brandId: row.brand_id,
    domain: row.domain,
    brand: brands.get(row.brand_id) ?? `Brand ${row.brand_id.slice(0, 8)}`,
    source: "MAegis API",
    score: Math.round(row.risk_score),
    confidence: Math.round(row.confidence * 100),
    severity: titleCase(row.severity) as Incident["severity"],
    status: titleCase(row.status) as Incident["status"],
    age: ageFrom(row.created_at),
    firstSeen: row.created_at,
    assignedTo: row.assigned_to,
    signals: (row.contributions ?? []).map((item) => item.explanation),
    summary: row.summary,
  };
}

export async function fetchBrandMap(request?: Request) {
  const url = backendUrl("/api/v1/brands?include_archived=true");
  if (!url) return new Map<string, string>();
  const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(5000) });
  if (!response.ok) return new Map<string, string>();
  const rows = await response.json() as Array<{ id: string; name: string }>;
  return new Map(rows.map((row) => [row.id, row.name]));
}
