import { backendHeaders, backendUrl } from "../../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}/evidence-bundle`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  try {
    const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(15000) });
    const body = await response.text();
    if (!response.ok) return Response.json({ error: "Evidence export failed" }, { status: response.status });
    return new Response(body, { headers: { "Content-Type": "application/json; charset=utf-8", "Content-Disposition": `attachment; filename="maegis-${id.slice(0, 8)}-evidence.json"`, "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Evidence service unavailable" }, { status: 502 });
  }
}
