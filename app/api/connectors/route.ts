import { backendHeaders, backendUrl } from "../incidents/shared";

export async function GET(request: Request) {
  const url = backendUrl("/api/v1/connectors");
  if (!url) return Response.json({ mode: "demo", connectors: [] });
  try {
    const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    if (!response.ok) throw new Error("Connectors unavailable");
    return Response.json({ mode: "live", connectors: body }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", connectors: [] });
  }
}
