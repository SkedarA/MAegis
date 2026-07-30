import { backendHeaders, backendUrl } from "../../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/brands/${encodeURIComponent(id)}/assets`);
  if (!url) return Response.json({ mode: "demo", assets: [] });
  try {
    const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    if (!response.ok) throw new Error("Whitelist unavailable");
    return Response.json({ mode: "live", assets: body }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", assets: [] });
  }
}

export async function POST(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/brands/${encodeURIComponent(id)}/assets`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as { asset_type?: string; value?: string };
  if (!input.value || !["domain", "subdomain", "wildcard"].includes(input.asset_type ?? "")) return Response.json({ error: "A valid asset type and domain are required" }, { status: 422 });
  try {
    const response = await fetch(url, { method: "POST", headers: backendHeaders(request, { "Content-Type": "application/json" }), body: JSON.stringify(input), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    return Response.json(response.ok ? { asset: body } : { error: body.detail ?? "Whitelist update failed" }, { status: response.status });
  } catch {
    return Response.json({ error: "Brand service unavailable" }, { status: 502 });
  }
}
