import { backendHeaders, backendUrl, fetchBrandMap, toConsoleIncident, type ApiIncident } from "../shared";

type Context = { params: Promise<{ id: string }> };

export async function GET(_: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  try {
    const [response, brands] = await Promise.all([
      fetch(url, { headers: backendHeaders(), cache: "no-store", signal: AbortSignal.timeout(7000) }),
      fetchBrandMap(),
    ]);
    const body = await response.json();
    if (!response.ok) return Response.json({ error: body.detail ?? "Incident unavailable" }, { status: response.status });
    return Response.json({ incident: toConsoleIncident(body as ApiIncident, brands) }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Incident service unavailable" }, { status: 502 });
  }
}
