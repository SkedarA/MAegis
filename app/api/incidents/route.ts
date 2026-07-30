import { backendHeaders, backendUrl, fetchBrandMap, toConsoleIncident, type ApiIncident } from "./shared";

export async function GET(request: Request) {
  const url = backendUrl("/api/v1/incidents?limit=500");
  if (!url) return Response.json({ mode: "demo", incidents: [] });

  try {
    const [response, brands] = await Promise.all([fetch(url, {
      headers: backendHeaders(request),
      cache: "no-store",
      signal: AbortSignal.timeout(15000),
    }), fetchBrandMap(request)]);
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    const rows = await response.json() as ApiIncident[];
    const incidents = rows.map((row) => toConsoleIncident(row, brands));
    return Response.json({ mode: "live", incidents }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", incidents: [] });
  }
}
