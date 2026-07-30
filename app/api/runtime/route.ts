import { backendHeaders, backendUrl } from "../incidents/shared";

export async function GET(request: Request) {
  const url = backendUrl("/api/v1/runtime/worker");
  if (!url) return Response.json({ mode: "demo", worker: null });

  try {
    const response = await fetch(url, {
      headers: backendHeaders(request),
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    return Response.json(
      { mode: "live", worker: await response.json() },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return Response.json({ mode: "demo", worker: null });
  }
}
