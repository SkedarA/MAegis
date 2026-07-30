import { backendHeaders, backendUrl } from "../../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}/case-context`);
  if (!url) return Response.json({ context: null }, { status: 200 });
  try {
    const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    if (!response.ok) return Response.json({ error: body.detail ?? "Context unavailable" }, { status: response.status });
    return Response.json({ context: body }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Context service unavailable" }, { status: 502 });
  }
}

export async function PUT(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}/case-context/override`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as Record<string, unknown>;
  try {
    const response = await fetch(url, {
      method: "PUT",
      headers: backendHeaders(request, { "Content-Type": "application/json" }),
      body: JSON.stringify(input),
      cache: "no-store",
      signal: AbortSignal.timeout(7000),
    });
    const body = await response.json();
    return Response.json(response.ok ? { context: body } : { error: body.detail ?? "Infrastructure update failed" }, { status: response.status });
  } catch {
    return Response.json({ error: "Context service unavailable" }, { status: 502 });
  }
}
