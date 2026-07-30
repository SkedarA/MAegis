import { backendHeaders, backendUrl, fetchBrandMap, toConsoleIncident, type ApiIncident } from "../../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}/assign`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as { analystId?: string };
  if (!input.analystId) return Response.json({ error: "Choose an analyst" }, { status: 422 });
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: backendHeaders(request, { "Content-Type": "application/json" }),
      body: JSON.stringify({ analyst_id: input.analystId }),
      cache: "no-store",
      signal: AbortSignal.timeout(7000),
    });
    const body = await response.json();
    if (!response.ok) return Response.json({ error: body.detail ?? "Assignment failed" }, { status: response.status });
    return Response.json({ incident: toConsoleIncident(body as ApiIncident, await fetchBrandMap(request)) });
  } catch {
    return Response.json({ error: "Assignment service unavailable" }, { status: 502 });
  }
}
