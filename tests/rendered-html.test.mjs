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
  assert.match(html, /New findings/i);
  assert.match(html, /Unassigned/i);
  assert.match(html, /Incident review queue|Real brand-abuse cases/i);
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
  assert.match(page, /Unconfirmed detections waiting for first review/);
  assert.match(page, /Incident review queue/);
});

test("dedicated incident workspace renders as a separate route", async () => {
  const response = await request("/incidents/demo-case");
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Preparing analyst workspace/);
});

test("account and domain-context routes fail closed without a private API", async () => {
  const accounts = await request("/api/accounts");
  assert.deepEqual(await accounts.json(), { mode: "demo", me: null, analysts: [] });
  const context = await request("/api/incidents/demo/context");
  assert.deepEqual(await context.json(), { context: null });
});

test("manual analysis is read-only when the operational API is absent", async () => {
  const brands = await request("/api/brands");
  assert.deepEqual(await brands.json(), { mode: "demo", brands: [] });
  const submission = await request("/api/submissions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ brandId: "demo", value: "example.test" }),
  });
  assert.equal(submission.status, 409);
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

test("hosted analyst identity is forwarded to the operational API", async () => {
  const shared = await readFile(new URL("../app/api/incidents/shared.ts", import.meta.url), "utf8");
  assert.match(shared, /oai-authenticated-user-email/);
  assert.match(shared, /oai-authenticated-user-full-name/);
});

test("operational console routes render their dedicated workspaces", async () => {
  for (const [path, title] of [
    ["/brands", "Protected brands"],
    ["/discovery", "Discovery control"],
    ["/team", "Analyst team"],
    ["/audit", "Audit trail"],
    ["/settings", "Operational settings"],
  ]) {
    const response = await request(path);
    assert.equal(response.status, 200, path);
    assert.match(await response.text(), new RegExp(title, "i"), path);
  }
});

test("operational read routes fail closed without the private API", async () => {
  const expected = [
    ["/api/connectors", { mode: "demo", connectors: [] }],
    ["/api/audit", { mode: "demo", events: [] }],
    ["/api/operations", { mode: "demo", summary: null }],
    ["/api/settings", { mode: "demo", settings: null }],
  ];
  for (const [path, body] of expected) {
    const response = await request(path);
    assert.equal(response.status, 200, path);
    assert.deepEqual(await response.json(), body, path);
  }
});

test("operational mutations are read-only without the private API", async () => {
  for (const path of ["/api/brands/demo", "/api/connectors/demo", "/api/accounts/demo"]) {
    const response = await request(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: false, active: false, monitoring_enabled: false }),
    });
    assert.equal(response.status, 409, path);
  }
});
