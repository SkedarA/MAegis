import { backendHeaders, backendUrl, fetchBrandMap, toConsoleIncident, type ApiIncident } from "./shared";

export async function GET(request: Request) {
  const priorityUrl = backendUrl("/api/v1/incidents?limit=300&sort=priority");
  const newestUrl = backendUrl("/api/v1/incidents?limit=300&sort=newest");
  if (!priorityUrl || !newestUrl) return Response.json({ mode: "demo", incidents: [] });

  try {
    const [priorityResponse, newestResponse, brands] = await Promise.all([fetch(priorityUrl, {
      headers: backendHeaders(request),
      cache: "no-store",
      signal: AbortSignal.timeout(15000),
    }), fetch(newestUrl, {
      headers: backendHeaders(request),
      cache: "no-store",
      signal: AbortSignal.timeout(15000),
    }), fetchBrandMap(request)]);
    if (!priorityResponse.ok || !newestResponse.ok) throw new Error("Backend incident feed unavailable");
    const priorityRows = await priorityResponse.json() as ApiIncident[];
    const newestRows = await newestResponse.json() as ApiIncident[];
    const rows = [...newestRows, ...priorityRows].filter((row, index, all) => all.findIndex((item) => item.id === row.id) === index).slice(0, 500);
    const incidents = rows.map((row) => toConsoleIncident(row, brands));
    return Response.json({ mode: "live", incidents }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", incidents: [] });
  }
}
