import { backendHeaders, backendUrl } from "../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function PATCH(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/analysts/${encodeURIComponent(id)}`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as Record<string, unknown>;
  try {
    const response = await fetch(url, { method: "PATCH", headers: backendHeaders(request, { "Content-Type": "application/json" }), body: JSON.stringify(input), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    return Response.json(response.ok ? { analyst: body } : { error: body.detail ?? "Account update failed" }, { status: response.status });
  } catch {
    return Response.json({ error: "Account service unavailable" }, { status: 502 });
  }
}
