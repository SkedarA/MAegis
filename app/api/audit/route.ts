import { backendHeaders, backendUrl } from "../incidents/shared";

export async function GET(request: Request) {
  const url = backendUrl("/api/v1/audit-events?limit=300");
  if (!url) return Response.json({ mode: "demo", events: [] });
  try {
    const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    if (!response.ok) throw new Error("Audit unavailable");
    return Response.json({ mode: "live", events: body }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", events: [] });
  }
}
