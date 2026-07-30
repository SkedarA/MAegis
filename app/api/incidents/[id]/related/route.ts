import { backendHeaders, backendUrl, fetchBrandMap, titleCase } from "../../../incidents/shared";

type Context = { params: Promise<{ id: string }> };
type RelatedRow = { id: string; domain: string; brand_id: string; risk_score: number; severity: string; status: string; shared_indicators: string[]; reasons: string[] };

export async function GET(request: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}/related`);
  if (!url) return Response.json({ mode: "demo", related: [] });
  try {
    const [response, brands] = await Promise.all([fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(10000) }), fetchBrandMap(request)]);
    const body = await response.json() as RelatedRow[] | { detail?: string };
    if (!response.ok || !Array.isArray(body)) throw new Error("Related cases unavailable");
    return Response.json({ mode: "live", related: body.map((item) => ({ ...item, brand: brands.get(item.brand_id) ?? `Brand ${item.brand_id.slice(0, 8)}`, severity: titleCase(item.severity), status: titleCase(item.status) })) }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", related: [] });
  }
}
