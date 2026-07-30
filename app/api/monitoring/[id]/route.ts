import { backendHeaders, backendUrl } from "../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function PATCH(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/monitors/${encodeURIComponent(id)}`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as { state?: string; interval_seconds?: number };
  if (input.state && !["active", "paused"].includes(input.state)) return Response.json({ error: "Invalid monitor state" }, { status: 422 });
  if (input.interval_seconds && (input.interval_seconds < 900 || input.interval_seconds > 604800)) return Response.json({ error: "Interval must be between 15 minutes and 7 days" }, { status: 422 });
  try {
    const response = await fetch(url, { method: "PATCH", headers: backendHeaders(request, { "Content-Type": "application/json" }), body: JSON.stringify(input), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    return Response.json(response.ok ? { monitor: body } : { error: body.detail ?? "Monitor update failed" }, { status: response.status });
  } catch { return Response.json({ error: "Monitoring service unavailable" }, { status: 502 }); }
}
