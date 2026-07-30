import { backendHeaders, backendUrl } from "../../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/monitors/${encodeURIComponent(id)}/check`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  try {
    const response = await fetch(url, { method: "POST", headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    return Response.json(response.ok ? body : { error: body.detail ?? "Check request failed" }, { status: response.status });
  } catch { return Response.json({ error: "Monitoring service unavailable" }, { status: 502 }); }
}
