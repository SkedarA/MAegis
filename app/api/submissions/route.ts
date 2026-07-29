import { backendHeaders, backendUrl, fetchBrandMap, toConsoleIncident, type ApiIncident } from "../incidents/shared";

export async function POST(request: Request) {
  const url = backendUrl("/api/v1/submissions");
  if (!url) return Response.json({ error: "Live analysis is not configured" }, { status: 409 });
  const input = await request.json() as { brandId?: string; value?: string; requestCapture?: boolean };
  if (!input.brandId || !input.value || input.value.trim().length < 3 || input.value.length > 2048) {
    return Response.json({ error: "Choose a brand and enter a valid domain or URL" }, { status: 422 });
  }
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: backendHeaders(request, { "Content-Type": "application/json" }),
      body: JSON.stringify({ brand_id: input.brandId, value: input.value.trim(), request_capture: Boolean(input.requestCapture) }),
      cache: "no-store",
      signal: AbortSignal.timeout(15000),
    });
    const body = await response.json();
    if (!response.ok) return Response.json({ error: body.detail ?? "Analysis could not be queued" }, { status: response.status });
    return Response.json({ incident: toConsoleIncident(body as ApiIncident, await fetchBrandMap(request)) }, { status: 201 });
  } catch {
    return Response.json({ error: "Analysis service unavailable" }, { status: 502 });
  }
}
