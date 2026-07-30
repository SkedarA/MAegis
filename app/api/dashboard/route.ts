import { backendHeaders, backendUrl } from "../incidents/shared";

export async function GET(request: Request) {
  const incoming = new URL(request.url);
  const days = incoming.searchParams.get("days") ?? "30";
  const url = backendUrl(`/api/v1/dashboard?days=${encodeURIComponent(days)}`);
  if (!url) return Response.json({ mode: "demo", dashboard: null });
  try {
    const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(10000) });
    const body = await response.json();
    if (!response.ok) throw new Error("Dashboard unavailable");
    return Response.json({ mode: "live", dashboard: body }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", dashboard: null });
  }
}
