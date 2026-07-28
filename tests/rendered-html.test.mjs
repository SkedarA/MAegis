import assert from "node:assert/strict";
import test from "node:test";

async function request(path = "/", init) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(new Request(`http://localhost${path}`, init ?? { headers: { accept: "text/html" } }), { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } }, { waitUntil() {}, passThroughOnException() {} });
}

test("renders the operational analyst console", async () => {
  const response = await request();
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /MAegis/i);
  assert.match(html, /Brand risk command/i);
  assert.match(html, /Real brand-abuse cases/i);
  assert.match(html, /bitdefender-download\.com/i);
  assert.match(html, /Public-source historical cases/i);
  assert.match(html, /Certificate Transparency/i);
  assert.match(html, /Evidence timeline/i);
  assert.match(html, /Decision rationale/i);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton/i);
});

test("evidence route has a safe unconfigured fallback", async () => {
  const response = await request("/api/incidents/demo/evidence");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { mode: "demo", evidence: [] });
});

test("triage route refuses mutations without a private API", async () => {
  const response = await request("/api/incidents/demo/triage", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: "investigating", severity: "high", rationale: "Analyst review" }),
  });
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: "Live API is not configured" });
});
