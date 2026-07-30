import { backendHeaders, backendUrl } from "../incidents/shared";

export async function GET(request: Request) {
  const url = backendUrl("/api/v1/operations/summary");
  if (!url) return Response.json({ mode: "demo", summary: null });
  try {
    const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(10000) });
    const body = await response.json();
    if (!response.ok) throw new Error("Operations unavailable");
    return Response.json({ mode: "live", summary: body }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", summary: null });
  }
}
