import { backendHeaders, backendUrl } from "../../../../incidents/shared";

type Context = { params: Promise<{ id: string; assetId: string }> };

export async function DELETE(request: Request, context: Context) {
  const { id, assetId } = await context.params;
  const url = backendUrl(`/api/v1/brands/${encodeURIComponent(id)}/assets/${encodeURIComponent(assetId)}`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  try {
    const response = await fetch(url, { method: "DELETE", headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(7000) });
    if (response.status === 204) return new Response(null, { status: 204 });
    const body = await response.json();
    return Response.json({ error: body.detail ?? "Whitelist update failed" }, { status: response.status });
  } catch {
    return Response.json({ error: "Brand service unavailable" }, { status: 502 });
  }
}
