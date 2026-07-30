import { backendHeaders, backendUrl } from "../incidents/shared";

export async function GET(request: Request) {
  const incoming = new URL(request.url);
  const params = new URLSearchParams();
  for (const key of ["state", "classification", "query"]) {
    const value = incoming.searchParams.get(key);
    if (value) params.set(key, value);
  }
  params.set("limit", incoming.searchParams.get("limit") ?? "1000");
  const listUrl = backendUrl(`/api/v1/monitors?${params}`);
  const summaryUrl = backendUrl("/api/v1/monitors/summary");
  if (!listUrl || !summaryUrl) return Response.json({ mode: "demo", monitors: [], summary: null });
  try {
    const headers = backendHeaders(request);
    const [listResponse, summaryResponse] = await Promise.all([
      fetch(listUrl, { headers, cache: "no-store", signal: AbortSignal.timeout(10000) }),
      fetch(summaryUrl, { headers, cache: "no-store", signal: AbortSignal.timeout(10000) }),
    ]);
    if (!listResponse.ok || !summaryResponse.ok) throw new Error("Monitoring API unavailable");
    return Response.json({ mode: "live", monitors: await listResponse.json(), summary: await summaryResponse.json() }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", monitors: [], summary: null });
  }
}
