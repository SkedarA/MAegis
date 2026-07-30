import { backendHeaders, backendUrl, fetchBrandMap, toConsoleIncident, type ApiIncident } from "../../shared";

type Context = { params: Promise<{ id: string }> };
const STATUSES = new Set(["investigating", "likely_abuse", "confirmed", "false_positive", "monitoring", "closed"]);
const SEVERITIES = new Set(["informational", "low", "medium", "high", "critical"]);

export async function POST(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}/triage`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as Record<string, unknown>;
  if (!STATUSES.has(String(input.status)) || (input.severity && !SEVERITIES.has(String(input.severity)))) {
    return Response.json({ error: "Invalid triage state" }, { status: 422 });
  }
  if (typeof input.rationale !== "string" || input.rationale.trim().length < 5 || input.rationale.length > 4000) {
    return Response.json({ error: "Decision rationale must contain 5–4000 characters" }, { status: 422 });
  }
  const payload = {
    status: input.status,
    severity: input.severity || null,
    assigned_to: typeof input.assignedTo === "string" && input.assignedTo.trim() ? input.assignedTo.trim() : null,
    rationale: input.rationale.trim(),
  };
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: backendHeaders(request, { "Content-Type": "application/json" }),
      body: JSON.stringify(payload),
      cache: "no-store",
      signal: AbortSignal.timeout(7000),
    });
    const body = await response.json();
    if (!response.ok) return Response.json({ error: body.detail ?? `Backend returned ${response.status}` }, { status: response.status });
    const brands = await fetchBrandMap(request);
    return Response.json({ incident: toConsoleIncident(body as ApiIncident, brands) }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Triage service unavailable" }, { status: 502 });
  }
}
