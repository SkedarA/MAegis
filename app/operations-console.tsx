"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { AnalystAccount } from "./incident-types";

type Section = "brands" | "discovery" | "team" | "audit" | "settings";
type Brand = { id: string; name: string; canonical_name: string; official_domains: string[]; keywords: string[]; monitoring_enabled: boolean; archived?: boolean; created_at: string };
type OfficialAsset = { id: string; brand_id: string; asset_type: "domain" | "subdomain" | "wildcard"; value: string; created_by: string; created_at: string };
type Connector = { id: string; type: string; enabled: boolean; status: string; observations_seen: number; last_success_at: string | null; last_error: string | null };
type AuditEvent = { id: string; actor: string; action: string; resource_type: string; resource_id: string; payload: Record<string, unknown>; created_at: string };
type OperationsSummary = { brands: number; active_brands: number; observations: number; candidates: number; incidents: number; open_incidents: number; evidence_items: number; jobs: Record<string, number>; worker: { fresh: boolean; status: string; cycle_count?: number; last_cycle_completed_at?: string | null } };
type OperationalSettings = { environment: string; capture_enabled: boolean; detector_version: string; max_generated_candidates: number; discovery_brand_batch_size: number; discovery_dns_batch_size: number; discovery_rdap_batch_size: number; fresh_registration_max_age_days: number; discovery_poll_interval_seconds: number; worker_health_stale_seconds: number };

const META: Record<Section, { eyebrow: string; title: string; description: string }> = {
  brands: { eyebrow: "Protection scope", title: "Protected brands", description: "Control which companies enter discovery and maintain the official-domain allowlist." },
  discovery: { eyebrow: "Collection operations", title: "Discovery control", description: "Inspect worker throughput, connector health, durable jobs, and the fresh-registration sweep." },
  team: { eyebrow: "Access and ownership", title: "Analyst team", description: "Create analyst profiles, set operational roles, and disable accounts without deleting audit history." },
  audit: { eyebrow: "Accountability", title: "Audit trail", description: "Review sensitive actions, case decisions, assignments, notes, and configuration changes." },
  settings: { eyebrow: "Runtime policy", title: "Operational settings", description: "Review active safety limits and discovery budgets. Secrets are intentionally never displayed." },
};

function humanize(value: string) { return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function compact(value: number) { return Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(value); }
function formatDate(value: string | null) { return value ? new Date(value).toLocaleString("en-GB") : "Never"; }
function initials(value: string) { return value.split(/[\s@._-]+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase(); }

export function OperationsConsole({ section }: { section: Section }) {
  const [me, setMe] = useState<AnalystAccount | null>(null);
  const [brands, setBrands] = useState<Brand[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [analysts, setAnalysts] = useState<AnalystAccount[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [summary, setSummary] = useState<OperationsSummary | null>(null);
  const [settings, setSettings] = useState<OperationalSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [brandName, setBrandName] = useState("");
  const [brandDomain, setBrandDomain] = useState("");
  const [brandKeywords, setBrandKeywords] = useState("");
  const [managedBrandId, setManagedBrandId] = useState<string | null>(null);
  const [officialAssets, setOfficialAssets] = useState<OfficialAsset[]>([]);
  const [assetType, setAssetType] = useState<OfficialAsset["asset_type"]>("domain");
  const [assetValue, setAssetValue] = useState("");
  const [archiveRationale, setArchiveRationale] = useState("");
  const [analystName, setAnalystName] = useState("");
  const [analystEmail, setAnalystEmail] = useState("");
  const [analystRole, setAnalystRole] = useState("analyst");

  useEffect(() => {
    const controller = new AbortController();
    const requests: Promise<void>[] = [fetch("/api/accounts", { signal: controller.signal }).then((response) => response.json()).then((body) => { setMe(body.me ?? null); setAnalysts(body.analysts ?? []); })];
    if (section === "brands") requests.push(fetch("/api/brands", { signal: controller.signal }).then((response) => response.json()).then((body) => setBrands(body.brands ?? [])));
    if (section === "discovery") {
      requests.push(fetch("/api/connectors", { signal: controller.signal }).then((response) => response.json()).then((body) => setConnectors(body.connectors ?? [])));
      requests.push(fetch("/api/operations", { signal: controller.signal }).then((response) => response.json()).then((body) => setSummary(body.summary ?? null)));
    }
    if (section === "audit") requests.push(fetch("/api/audit", { signal: controller.signal }).then((response) => response.json()).then((body) => setAuditEvents(body.events ?? [])));
    if (section === "settings") requests.push(fetch("/api/settings", { signal: controller.signal }).then((response) => response.json()).then((body) => setSettings(body.settings ?? null)));
    Promise.all(requests).catch((error) => { if (error.name !== "AbortError") setFeedback("Operational API is unavailable."); }).finally(() => setLoading(false));
    return () => controller.abort();
  }, [section]);

  const activeConnectors = useMemo(() => connectors.filter((item) => item.enabled).length, [connectors]);

  async function toggleBrand(brand: Brand) {
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch(`/api/brands/${encodeURIComponent(brand.id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ monitoring_enabled: !brand.monitoring_enabled }) });
      const body = await response.json(); if (!response.ok) throw new Error(body.error ?? "Brand update failed");
      setBrands((current) => current.map((item) => item.id === brand.id ? body.brand : item)); setFeedback(`${brand.name} monitoring ${body.brand.monitoring_enabled ? "enabled" : "paused"}.`);
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Brand update failed"); } finally { setBusy(false); }
  }

  async function createBrand() {
    if (brandName.trim().length < 2 || !brandDomain.trim()) return;
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch("/api/brands", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: brandName.trim(), official_domains: [brandDomain.trim()], trademarks: [brandName.trim()], keywords: brandKeywords.split(",").map((item) => item.trim()).filter(Boolean), permitted_variations: [], legitimate_interest_confirmed: true }) });
      const body = await response.json(); if (!response.ok) throw new Error(body.error ?? "Brand creation failed");
      setBrands((current) => [...current, body.brand].sort((left, right) => left.name.localeCompare(right.name))); setBrandName(""); setBrandDomain(""); setBrandKeywords(""); setShowCreate(false); setFeedback("Protected brand enrolled.");
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Brand creation failed"); } finally { setBusy(false); }
  }

  async function manageBrand(brand: Brand) {
    if (managedBrandId === brand.id) { setManagedBrandId(null); setOfficialAssets([]); return; }
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch(`/api/brands/${encodeURIComponent(brand.id)}/assets`, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok || body.mode !== "live") throw new Error(body.error ?? "Whitelist is unavailable while the API is offline");
      setManagedBrandId(brand.id); setOfficialAssets(body.assets ?? []); setAssetValue(""); setArchiveRationale("");
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Whitelist loading failed"); } finally { setBusy(false); }
  }

  async function addOfficialAsset(brand: Brand) {
    if (!assetValue.trim()) return;
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch(`/api/brands/${encodeURIComponent(brand.id)}/assets`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ asset_type: assetType, value: assetValue.trim() }) });
      const body = await response.json(); if (!response.ok) throw new Error(body.error ?? "Whitelist update failed");
      setOfficialAssets((current) => [...current, body.asset].sort((left, right) => left.value.localeCompare(right.value)));
      setBrands((current) => current.map((item) => item.id === brand.id ? { ...item, official_domains: [...item.official_domains, body.asset.value].sort() } : item));
      setAssetValue(""); setFeedback(`${body.asset.value} added to ${brand.name}'s whitelist.`);
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Whitelist update failed"); } finally { setBusy(false); }
  }

  async function removeOfficialAsset(brand: Brand, asset: OfficialAsset) {
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch(`/api/brands/${encodeURIComponent(brand.id)}/assets/${encodeURIComponent(asset.id)}`, { method: "DELETE" });
      if (!response.ok) { const body = await response.json(); throw new Error(body.error ?? "Whitelist update failed"); }
      setOfficialAssets((current) => current.filter((item) => item.id !== asset.id));
      setBrands((current) => current.map((item) => item.id === brand.id ? { ...item, official_domains: item.official_domains.filter((value) => value !== asset.value) } : item));
      setFeedback(`${asset.value} removed from ${brand.name}'s whitelist.`);
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Whitelist update failed"); } finally { setBusy(false); }
  }

  async function archiveBrand(brand: Brand) {
    if (archiveRationale.trim().length < 5) { setFeedback("Add a short archive rationale before removing the brand."); return; }
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch(`/api/brands/${encodeURIComponent(brand.id)}`, { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ rationale: archiveRationale.trim() }) });
      if (!response.ok) { const body = await response.json(); throw new Error(body.error ?? "Brand archive failed"); }
      setBrands((current) => current.filter((item) => item.id !== brand.id)); setManagedBrandId(null); setOfficialAssets([]); setArchiveRationale("");
      setFeedback(`${brand.name} archived. Existing incidents and evidence were preserved.`);
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Brand archive failed"); } finally { setBusy(false); }
  }

  async function toggleConnector(connector: Connector) {
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch(`/api/connectors/${encodeURIComponent(connector.id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: !connector.enabled }) });
      const body = await response.json(); if (!response.ok) throw new Error(body.error ?? "Connector update failed");
      setConnectors((current) => current.map((item) => item.id === connector.id ? body.connector : item)); setFeedback(`${humanize(connector.type)} ${body.connector.enabled ? "enabled" : "disabled"}.`);
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Connector update failed"); } finally { setBusy(false); }
  }

  async function createAnalyst() {
    if (analystName.trim().length < 2 || !analystEmail.includes("@")) return;
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch("/api/accounts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ display_name: analystName.trim(), email: analystEmail.trim(), role: analystRole }) });
      const body = await response.json(); if (!response.ok) throw new Error(body.error ?? "Account creation failed");
      setAnalysts((current) => [...current, body.analyst].sort((left, right) => left.display_name.localeCompare(right.display_name))); setAnalystName(""); setAnalystEmail(""); setAnalystRole("analyst"); setShowCreate(false); setFeedback("Analyst account created.");
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Account creation failed"); } finally { setBusy(false); }
  }

  async function updateAnalyst(analyst: AnalystAccount, update: Record<string, unknown>) {
    setBusy(true); setFeedback(null);
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(analyst.id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(update) });
      const body = await response.json(); if (!response.ok) throw new Error(body.error ?? "Account update failed");
      setAnalysts((current) => current.map((item) => item.id === analyst.id ? body.analyst : item)); setFeedback(`${analyst.display_name} updated.`);
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Account update failed"); } finally { setBusy(false); }
  }

  return <main className="app-shell ops-shell">
    <aside className="sidebar">
      <Link className="wordmark" href="/"><span className="brand-sigil">M</span><span>MAEGIS</span></Link>
      <nav aria-label="Primary navigation"><p className="nav-label">Monitor</p><Link className="nav-item" href="/"><span>⌁</span>Overview</Link><Link className={`nav-item ${section === "discovery" ? "active" : ""}`} href="/discovery"><span>◎</span>Discovery</Link><Link className={`nav-item ${section === "brands" ? "active" : ""}`} href="/brands"><span>◫</span>Protected brands</Link><p className="nav-label">Operate</p><Link className={`nav-item ${section === "team" ? "active" : ""}`} href="/team"><span>♙</span>Analyst team</Link><Link className={`nav-item ${section === "audit" ? "active" : ""}`} href="/audit"><span>▤</span>Audit log</Link><Link className={`nav-item ${section === "settings" ? "active" : ""}`} href="/settings"><span>⚙</span>Settings</Link></nav>
      <div className="sidebar-status"><div className="pulse-dot" /><div><strong>{summary?.worker.fresh ? "Monitoring active" : "Operations console"}</strong><span>{summary?.worker.fresh ? `Cycle ${summary.worker.cycle_count ?? 0}` : "Authenticated controls"}</span></div></div>
      <div className="profile"><span className="avatar">{initials(me?.display_name ?? "Local Analyst")}</span><div><strong>{me?.display_name ?? "Local Analyst"}</strong><span>{me?.role ?? "analyst"}</span></div></div>
    </aside>

    <section className="workspace ops-workspace">
      <header className="ops-header"><div><p className="eyebrow">{META[section].eyebrow}</p><h1>{META[section].title}</h1><p>{META[section].description}</p></div>{(section === "brands" || section === "team") && <button className="primary-button" onClick={() => setShowCreate((value) => !value)}>+ {section === "brands" ? "Enroll brand" : "Add analyst"}</button>}</header>
      {feedback && <div className="ops-feedback" role="status">{feedback}</div>}
      {loading ? <div className="ops-loading">Loading operational data…</div> : <>
        {section === "brands" && <section className="ops-panel">
          <div className="ops-panel-head"><div><h2>Monitoring portfolio</h2><p>{brands.filter((item) => item.monitoring_enabled).length} of {brands.length} brands actively monitored</p></div></div>
          {showCreate && <div className="ops-create-grid"><label>Company or brand<input value={brandName} onChange={(event) => setBrandName(event.target.value)} placeholder="Company name" /></label><label>Official domain<input value={brandDomain} onChange={(event) => setBrandDomain(event.target.value)} placeholder="company.example" /></label><label>Keywords<input value={brandKeywords} onChange={(event) => setBrandKeywords(event.target.value)} placeholder="login, delivery, support" /></label><button className="primary-button" disabled={busy || brandName.trim().length < 2 || !brandDomain.trim()} onClick={createBrand}>Enroll</button></div>}
          <div className="brand-list">{brands.map((brand) => <article className={`brand-card ${managedBrandId === brand.id ? "brand-card-open" : ""}`} key={brand.id}>
            <div className="brand-row"><span className="company-mark sage">{initials(brand.name)}</span><div className="brand-summary"><strong>{brand.name}</strong><span>{brand.official_domains.join(", ")}</span><small>{brand.keywords.length ? `${brand.keywords.length} monitored keywords` : "Default detection vocabulary"}</small></div><span className={`ops-state ${brand.monitoring_enabled ? "state-good" : "state-muted"}`}>{brand.monitoring_enabled ? "Monitoring" : "Paused"}</span><button className="secondary-button" disabled={busy} onClick={() => toggleBrand(brand)}>{brand.monitoring_enabled ? "Pause" : "Resume"}</button><button className="secondary-button" disabled={busy} onClick={() => manageBrand(brand)}>{managedBrandId === brand.id ? "Close" : "Manage whitelist"}</button></div>
            {managedBrandId === brand.id && <div className="brand-manager">
              <div className="whitelist-heading"><div><h3>Trusted domains and subdomains</h3><p>Matching assets are suppressed before an incident is created.</p></div><span>{officialAssets.length} assets</span></div>
              <div className="asset-help"><p><strong>Domain</strong> trusts the base domain and every child host.</p><p><strong>Subdomain</strong> trusts that host and its descendants.</p><p><strong>Wildcard</strong> trusts descendants only, not the base domain.</p></div>
              <div className="asset-list">{officialAssets.map((asset) => <div key={asset.id}><span className={`asset-kind asset-${asset.asset_type}`}>{asset.asset_type}</span><code>{asset.value}</code><small>Added by {asset.created_by}</small><button className="text-danger-button" disabled={busy || officialAssets.length <= 1} title={officialAssets.length <= 1 ? "A brand must retain one official asset" : `Remove ${asset.value}`} onClick={() => removeOfficialAsset(brand, asset)}>Remove</button></div>)}</div>
              <div className="asset-add"><label>Asset type<select value={assetType} onChange={(event) => setAssetType(event.target.value as OfficialAsset["asset_type"])}><option value="domain">Domain</option><option value="subdomain">Subdomain</option><option value="wildcard">Wildcard subdomains</option></select></label><label>Domain or subdomain<input value={assetValue} onChange={(event) => setAssetValue(event.target.value)} placeholder={assetType === "wildcard" ? "*.service.example" : "service.example"} /></label><button className="primary-button" disabled={busy || !assetValue.trim()} onClick={() => addOfficialAsset(brand)}>Add to whitelist</button></div>
              {me?.role === "administrator" && <div className="archive-zone"><div><strong>Remove protected brand</strong><p>Archives monitoring configuration while preserving all cases, evidence, and audit history.</p></div><input aria-label={`Archive rationale for ${brand.name}`} value={archiveRationale} onChange={(event) => setArchiveRationale(event.target.value)} placeholder="Reason for removing this brand" /><button className="danger-button" disabled={busy || archiveRationale.trim().length < 5} onClick={() => archiveBrand(brand)}>Archive brand</button></div>}
            </div>}
          </article>)}</div>
        </section>}

        {section === "discovery" && <><section className="ops-metrics">{[["Observations", summary?.observations ?? 0], ["Candidates", summary?.candidates ?? 0], ["Open incidents", summary?.open_incidents ?? 0], ["Evidence items", summary?.evidence_items ?? 0]].map(([label, value]) => <article key={String(label)}><span>{label}</span><strong>{compact(Number(value))}</strong></article>)}</section><section className="ops-grid"><article className="ops-panel"><div className="ops-panel-head"><div><h2>Source connectors</h2><p>{activeConnectors} of {connectors.length} enabled</p></div></div><div className="ops-list connector-list">{connectors.map((connector) => <article key={connector.id}><span className="source-icon">{connector.type[0].toUpperCase()}</span><div><strong>{humanize(connector.type)}</strong><span>{compact(connector.observations_seen)} retained observations · Last success {formatDate(connector.last_success_at)}</span>{connector.last_error && <small className="ops-error">{connector.last_error}</small>}</div><span className={`ops-state ${connector.status === "healthy" ? "state-good" : connector.enabled ? "state-warn" : "state-muted"}`}>{humanize(connector.status)}</span><button className="secondary-button" disabled={busy} onClick={() => toggleConnector(connector)}>{connector.enabled ? "Disable" : "Enable"}</button></article>)}</div></article><aside className="ops-panel job-panel"><div className="ops-panel-head"><div><h2>Worker and jobs</h2><p>Durable background execution</p></div></div><dl><div><dt>Worker state</dt><dd>{humanize(summary?.worker.status ?? "unavailable")}</dd></div><div><dt>Completed cycles</dt><dd>{summary?.worker.cycle_count ?? 0}</dd></div><div><dt>Last completed</dt><dd>{formatDate(summary?.worker.last_cycle_completed_at ?? null)}</dd></div>{Object.entries(summary?.jobs ?? {}).map(([status, count]) => <div key={status}><dt>{humanize(status)} jobs</dt><dd>{count}</dd></div>)}</dl></aside></section></>}

        {section === "team" && <section className="ops-panel"><div className="ops-panel-head"><div><h2>Analyst accounts</h2><p>Roles are enforced by the operational API</p></div></div>{showCreate && <div className="ops-create-grid"><label>Display name<input value={analystName} onChange={(event) => setAnalystName(event.target.value)} placeholder="Analyst name" /></label><label>Email<input type="email" value={analystEmail} onChange={(event) => setAnalystEmail(event.target.value)} placeholder="analyst@example.com" /></label><label>Role<select value={analystRole} onChange={(event) => setAnalystRole(event.target.value)}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="manager">Manager</option><option value="administrator">Administrator</option></select></label><button className="primary-button" disabled={busy || analystName.trim().length < 2 || !analystEmail.includes("@")} onClick={createAnalyst}>Create</button></div>}<div className="ops-list">{analysts.map((analyst) => <article key={analyst.id}><span className="avatar">{initials(analyst.display_name)}</span><div><strong>{analyst.display_name}{analyst.id === me?.id && " · You"}</strong><span>{analyst.email}</span></div><select aria-label={`Role for ${analyst.display_name}`} value={analyst.role} disabled={busy || !analyst.active} onChange={(event) => updateAnalyst(analyst, { role: event.target.value })}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="manager">Manager</option><option value="administrator">Administrator</option></select><button className="secondary-button" disabled={busy || analyst.id === me?.id} onClick={() => updateAnalyst(analyst, { active: !analyst.active })}>{analyst.active ? "Disable" : "Enable"}</button></article>)}</div></section>}

        {section === "audit" && <section className="ops-panel"><div className="ops-panel-head"><div><h2>Recent sensitive actions</h2><p>{auditEvents.length} newest tenant-scoped events</p></div></div><div className="audit-table"><div className="audit-row audit-head"><span>Time</span><span>Actor</span><span>Action</span><span>Resource</span></div>{auditEvents.map((event) => <div className="audit-row" key={event.id}><time>{formatDate(event.created_at)}</time><span>{event.actor}</span><strong>{humanize(event.action)}</strong><span>{humanize(event.resource_type)} · {event.resource_id.slice(0, 8)}</span></div>)}{auditEvents.length === 0 && <div className="ops-empty">No audit events are available.</div>}</div></section>}

        {section === "settings" && <section className="ops-grid settings-grid"><article className="ops-panel"><div className="ops-panel-head"><div><h2>Detection policy</h2><p>Active server-side configuration</p></div></div><dl className="settings-list"><div><dt>Detector version</dt><dd>{settings?.detector_version ?? "Unavailable"}</dd></div><div><dt>Generated candidates / brand</dt><dd>{settings?.max_generated_candidates ?? "—"}</dd></div><div><dt>Fresh-registration window</dt><dd>{settings ? `${settings.fresh_registration_max_age_days} days` : "—"}</dd></div><div><dt>RDAP checks / selected brand</dt><dd>{settings?.discovery_rdap_batch_size ?? "—"}</dd></div><div><dt>DNS checks / selected brand</dt><dd>{settings?.discovery_dns_batch_size ?? "—"}</dd></div></dl></article><article className="ops-panel"><div className="ops-panel-head"><div><h2>Safety and runtime</h2><p>Changes require environment configuration and restart</p></div></div><dl className="settings-list"><div><dt>Environment</dt><dd>{humanize(settings?.environment ?? "unavailable")}</dd></div><div><dt>Live capture</dt><dd>{settings?.capture_enabled ? "Enabled" : "Disabled"}</dd></div><div><dt>Brands / cycle</dt><dd>{settings?.discovery_brand_batch_size ?? "—"}</dd></div><div><dt>Polling interval</dt><dd>{settings ? `${Math.round(settings.discovery_poll_interval_seconds / 60)} minutes` : "—"}</dd></div><div><dt>Worker stale threshold</dt><dd>{settings ? `${Math.round(settings.worker_health_stale_seconds / 60)} minutes` : "—"}</dd></div></dl></article><article className="ops-callout"><strong>Secrets remain hidden</strong><p>API keys, database credentials, provider tokens, and tunnel configuration are never returned to the browser.</p></article></section>}
      </>}
    </section>
  </main>;
}
