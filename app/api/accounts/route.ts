import { backendHeaders, backendUrl } from "../incidents/shared";

export async function GET(request: Request) {
  const url = backendUrl("/api/v1/analysts");
  if (!url) return Response.json({ mode: "demo", me: null, analysts: [] });
  try {
    const response = await fetch(url, { headers: backendHeaders(request), cache: "no-store", signal: AbortSignal.timeout(7000) });
    const body = await response.json();
    if (!response.ok) throw new Error("Accounts unavailable");
    return Response.json({ mode: "live", ...body }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ mode: "demo", me: null, analysts: [] });
  }
}

export async function POST(request: Request) {
  const url = backendUrl("/api/v1/analysts");
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const input = await request.json() as Record<string, unknown>;
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: backendHeaders(request, { "Content-Type": "application/json" }),
      body: JSON.stringify(input),
      cache: "no-store",
      signal: AbortSignal.timeout(7000),
    });
    const body = await response.json();
    return Response.json(response.ok ? { analyst: body } : { error: body.detail ?? "Account creation failed" }, { status: response.status });
  } catch {
    return Response.json({ error: "Account service unavailable" }, { status: 502 });
  }
}
