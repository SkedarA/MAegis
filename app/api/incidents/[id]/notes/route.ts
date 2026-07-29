import { backendHeaders, backendUrl } from "../../../incidents/shared";

type Context = { params: Promise<{ id: string }> };

export async function GET(_: Request, context: Context) {
  return proxy(context, "GET");
}

export async function POST(request: Request, context: Context) {
  const input = await request.json() as { body?: string };
  if (!input.body || input.body.trim().length < 2) return Response.json({ error: "Note must contain at least 2 characters" }, { status: 422 });
  return proxy(context, "POST", { body: input.body.trim() });
}

async function proxy(context: Context, method: "GET" | "POST", payload?: Record<string, unknown>) {
  const { id } = await context.params;
  const url = backendUrl(`/api/v1/incidents/${encodeURIComponent(id)}/notes`);
  if (!url) return Response.json({ error: "Live API is not configured" }, { status: 409 });
  try {
    const response = await fetch(url, {
      method,
      headers: backendHeaders(payload ? { "Content-Type": "application/json" } : {}),
      body: payload ? JSON.stringify(payload) : undefined,
      cache: "no-store",
      signal: AbortSignal.timeout(7000),
    });
    const body = await response.json();
    return Response.json(response.ok ? (method === "GET" ? { notes: body } : { note: body }) : { error: body.detail ?? "Notes request failed" }, { status: response.status });
  } catch {
    return Response.json({ error: "Notes service unavailable" }, { status: 502 });
  }
}
