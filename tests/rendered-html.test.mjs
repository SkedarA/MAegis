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

test("dashboard analytics route has a safe unconfigured fallback", async () => {
  const response = await request("/api/dashboard?days=30");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { mode: "demo", dashboard: null });
});

test("domain monitoring route has a safe unconfigured fallback", async () => {
  const response = await request("/api/monitoring");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { mode: "demo", monitors: [], summary: null });
});

test("campaign intelligence route has a safe unconfigured fallback", async () => {
  const response = await request("/api/intelligence");
  assert.deepEqual(await response.json(), { mode: "demo", summary: null, campaigns: [], patterns: [] });
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

test("domain-context overrides fail closed without the private API", async () => {
  const response = await request("/api/incidents/demo/context", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hosting_provider_name: "Verified Host", rationale: "Analyst verified provider" }),
  });
  assert.equal(response.status, 409);
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

test("protected-brand and whitelist mutations fail closed without the private API", async () => {
  const assets = await request("/api/brands/demo/assets");
  assert.deepEqual(await assets.json(), { mode: "demo", assets: [] });
  for (const [path, method, body] of [
    ["/api/brands/demo", "DELETE", { rationale: "No longer monitored" }],
    ["/api/brands/demo/assets", "POST", { asset_type: "domain", value: "example.com" }],
    ["/api/brands/demo/assets/asset", "DELETE", undefined],
  ]) {
    const response = await request(path, { method, headers: { "Content-Type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) });
    assert.equal(response.status, 409, `${method} ${path}`);
  }
});

test("correlation is empty and evidence export fails closed without the private API", async () => {
  const related = await request("/api/incidents/demo/related");
  assert.deepEqual(await related.json(), { mode: "demo", related: [] });
  const bundle = await request("/api/incidents/demo/export");
  assert.equal(bundle.status, 409);
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

test("incident brand labels include archived portfolio records", async () => {
  const shared = await readFile(new URL("../app/api/incidents/shared.ts", import.meta.url), "utf8");
  assert.match(shared, /brands\?include_archived=true/);
});

test("incident feed combines newest findings with priority cases", async () => {
  const route = await readFile(new URL("../app/api/incidents/route.ts", import.meta.url), "utf8");
  assert.match(route, /sort=priority/);
  assert.match(route, /sort=newest/);
  assert.match(route, /findIndex/);
});

test("operational console routes render their dedicated workspaces", async () => {
  for (const [path, title] of [
    ["/brands", "Protected brands"],
    ["/discovery", "Discovery control"],
    ["/team", "Analyst team"],
    ["/audit", "Audit trail"],
    ["/settings", "Operational settings"],
    ["/monitoring", "Domain monitoring"],
    ["/intelligence", "Campaign intelligence"],
  ]) {
    const response = await request(path);
    assert.equal(response.status, 200, path);
    assert.match(await response.text(), new RegExp(title, "i"), path);
  }
});

test("campaign investigation workspace and safe promotion proxy are present", async () => {
  const page = await readFile(new URL("../app/campaign-workspace.tsx", import.meta.url), "utf8");
  const route = await readFile(new URL("../app/api/intelligence/[id]/route.ts", import.meta.url), "utf8");
  assert.match(page, /Deterministic campaign investigation/);
  assert.match(page, /Promote selected/);
  assert.match(page, /correlation facts, not a malicious verdict/i);
  assert.match(route, /campaigns\/\$\{encodeURIComponent\(id\)\}/);
});

test("main dashboard contains portfolio filters and client analytics", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(page, /Filter the complete dashboard/);
  assert.match(page, /Incidents by protected brand/);
  assert.match(page, /Screenshots remain manual and opt-in/);
  assert.match(page, /setInterval\(loadLiveState, 30000\)/);
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
