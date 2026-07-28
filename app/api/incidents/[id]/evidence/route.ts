import { backendHeaders, backendUrl, titleCase } from "../../shared";

type Context = { params: Promise<{ id: string }> };

export async function GET(_: Request, context: Context) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}/evidence`);
  if (!url) return Response.json({ mode: "demo", evidence: [] });
  try {
    const response = await fetch(url, {
      headers: backendHeaders(),
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return Response.json({ error: `Backend returned ${response.status}` }, { status: response.status });
    const rows = await response.json() as Array<Record<string, unknown>>;
    const evidence = rows.map((row) => ({
      id: row.id,
      evidenceType: titleCase(String(row.evidence_type)),
      source: titleCase(String(row.source)),
      payload: row.payload,
      rawHash: row.raw_hash,
      collectedAt: row.collected_at,
    }));
    return Response.json({ mode: "live", evidence }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Evidence service unavailable" }, { status: 502 });
  }
}
