import { backendHeaders, backendUrl } from "../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

async function proxy(request: Request, context: Context, action: "detail" | "review" | "promote") {
  const { id } = await context.params;
  const suffix = action === "detail" ? "" : `/${action}`;
  const url = backendUrl(`/api/v1/intelligence/campaigns/${encodeURIComponent(id)}${suffix}`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  const method = action === "detail" ? "GET" : action === "review" ? "PATCH" : "POST";
  try {
    const response = await fetch(url, { method, headers: backendHeaders(request, method === "GET" ? {} : { "Content-Type": "application/json" }), body: method === "GET" ? undefined : await request.text(), cache: "no-store", signal: AbortSignal.timeout(10000) });
    const body = await response.json();
    return Response.json(response.ok ? body : { error: body.detail ?? "Campaign operation failed" }, { status: response.status, headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Campaign intelligence service unavailable" }, { status: 502 });
  }
}

export async function GET(request: Request, context: Context) { return proxy(request, context, "detail"); }
export async function PATCH(request: Request, context: Context) { return proxy(request, context, "review"); }
export async function POST(request: Request, context: Context) { return proxy(request, context, "promote"); }
