import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
  assert.match(html, /Public-source current and historical cases/i);
  assert.match(html, /bitdefender-login\.pages\.dev/i);
  assert.match(html, /fancourier-ro\.tracking-portal\.click/i);
  assert.match(html, /Certificate Transparency/i);
  assert.match(html, /RDAP registration sweep/i);
  assert.match(html, /Fresh registration hunt/i);
  assert.match(html, /Evidence timeline/i);
  assert.match(html, /Decision rationale/i);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton/i);
});

test("evidence route has a safe unconfigured fallback", async () => {
  const response = await request("/api/incidents/demo/evidence");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { mode: "demo", evidence: [] });
});

test("runtime route fails closed when the private worker is unconfigured", async () => {
  const response = await request("/api/runtime");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { mode: "demo", worker: null });
});

test("live queue labels do not claim detections are verified", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(page, /Unconfirmed detections requiring analyst triage/);
  assert.match(page, /Review queue/);
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
