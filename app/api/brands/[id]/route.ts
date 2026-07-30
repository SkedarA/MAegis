import { backendHeaders, backendUrl } from "../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function PATCH(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/brands/${encodeURIComponent(id)}`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as { monitoring_enabled?: boolean };
  if (typeof input.monitoring_enabled !== "boolean") return Response.json({ error: "Invalid monitoring state" }, { status: 422 });
  try {
    const response = await fetch(url, { method: "PATCH", headers: backendHeaders(request, { "Content-Type": "application/json" }), body: JSON.stringify(input), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    return Response.json(response.ok ? { brand: body } : { error: body.detail ?? "Brand update failed" }, { status: response.status });
  } catch {
    return Response.json({ error: "Brand service unavailable" }, { status: 502 });
  }
}

export async function DELETE(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/brands/${encodeURIComponent(id)}`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as { rationale?: string };
  if (!input.rationale || input.rationale.trim().length < 5) return Response.json({ error: "Archive rationale must contain at least 5 characters" }, { status: 422 });
  try {
    const response = await fetch(url, { method: "DELETE", headers: backendHeaders(request, { "Content-Type": "application/json" }), body: JSON.stringify(input), cache: "no-store", signal: AbortSignal.timeout(7000) });
    if (response.status === 204) return new Response(null, { status: 204 });
    const body = await response.json();
    return Response.json({ error: body.detail ?? "Brand archive failed" }, { status: response.status });
  } catch {
    return Response.json({ error: "Brand service unavailable" }, { status: 502 });
  }
}
