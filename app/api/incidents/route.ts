import { backendHeaders, backendUrl, fetchBrandMap, toConsoleIncident, type ApiIncident } from "./shared";

export async function GET() {
  const url = backendUrl("/api/v1/incidents?limit=100");
  if (!url) return Response.json({ mode: "demo", incidents: [] });

  try {
    const [response, brands] = await Promise.all([fetch(url, {
      headers: backendHeaders(),
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    }), fetchBrandMap()]);
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    const rows = await response.json() as ApiIncident[];
    const incidents = rows.map((row) => toConsoleIncident(row, brands));
    return Response.json({ mode: "live", incidents }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", incidents: [] });
  }
}
