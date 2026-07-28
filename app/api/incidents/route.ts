type ApiIncident = {
  id: string;
  domain: string;
  brand_id: string;
  risk_score: number;
  severity: string;
  status: string;
  summary: string;
  created_at: string;
  contributions?: Array<{ explanation: string }>;
};

function titleCase(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function ageFrom(value: string) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export async function GET() {
  const baseUrl = process.env.MAEGIS_API_URL;
  if (!baseUrl) return Response.json({ mode: "demo", incidents: [] });

  try {
    const response = await fetch(`${baseUrl.replace(/\/$/, "")}/api/v1/incidents?limit=100`, {
      headers: process.env.MAEGIS_API_KEY ? { "X-API-Key": process.env.MAEGIS_API_KEY } : {},
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    const rows = await response.json() as ApiIncident[];
    const incidents = rows.map((row) => ({
      id: row.id,
      domain: row.domain,
      brand: `Brand ${row.brand_id.slice(0, 8)}`,
      source: "MAegis API",
      score: Math.round(row.risk_score),
      severity: titleCase(row.severity),
      status: titleCase(row.status),
      age: ageFrom(row.created_at),
      firstSeen: new Date(row.created_at).toLocaleString("en-GB", { timeZone: "UTC" }) + " UTC",
      signals: (row.contributions ?? []).map((item) => item.explanation),
      summary: row.summary,
    }));
    return Response.json({ mode: "live", incidents }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", incidents: [] });
  }
}
