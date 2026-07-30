"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { IncidentDetail } from "./incident-detail";
import type { AnalystAccount, Incident } from "./incident-types";

const seededIncidents: Incident[] = [
  {
    id: "INC-R010",
    domain: "bitdefender-login.pages.dev",
    brand: "Bitdefender",
    source: "urlscan public telemetry",
    score: 80,
    confidence: 94,
    severity: "Critical",
    status: "New",
    age: "21 hours",
    firstSeen: "2026-07-27T14:13:20Z",
    assignedTo: null,
    signals: ["Brand-plus-login hostname", "Non-official shared hosting", "Fake-support classification", "Endpoint still resolves"],
    summary: "A current public scan classified this brand-bearing Cloudflare Pages endpoint as potentially malicious and identified it as a fake-support page. It remains queued for analyst confirmation; MAegis does not treat the automated verdict alone as proof.",
    references: [{ label: "urlscan 019fa3ec", url: "https://urlscan.io/result/019fa3ec-4c1f-759b-8827-6f0a63e8e8f2/" }],
  },
  {
    id: "INC-R009",
    domain: "fancourier-ro.tracking-portal.click",
    brand: "FAN Courier",
    source: "urlscan + FAN Courier advisory",
    score: 72,
    confidence: 87,
    severity: "High",
    status: "Investigating",
    age: "5 days",
    firstSeen: "2026-07-23T08:08:03Z",
    assignedTo: null,
    signals: ["Brand-bearing tracking subdomain", "Redirect to a second FAN-themed domain", "Verification lure", "Rapid infrastructure teardown"],
    summary: "The submitted tracking-themed domain redirected to tracking.fancourier-ro.lol and presented a verification page behind bot controls. The submitted domain is now offline and the redirect host appears parked, so the archived scan—not a live visit—is the retained evidence.",
    references: [
      { label: "urlscan 019f8e04", url: "https://urlscan.io/result/019f8e04-7179-72eb-889c-a35b3a34f4f7/" },
      { label: "FAN Courier 2026 advisory", url: "https://www.fancourier.ro/en/bitdefender-over-one-million-romanians-received-fraudulent-delivery-sms-messages-in-the-largest-online-scam-campaign-of-2026/" },
    ],
  },
  {
    id: "INC-R008",
    domain: "bitdefender-download.com",
    brand: "Bitdefender",
    source: "DomainTools + WIPO",
    score: 99,
    confidence: 99,
    severity: "Critical",
    status: "Closed",
    age: "Historical",
    firstSeen: "2025-05-27T00:00:00Z",
    assignedTo: null,
    signals: ["Exact brand + download lure", "Spoofed antivirus download page", "VenomRAT delivery", "WIPO ordered transfer"],
    summary: "DomainTools documented a fake Bitdefender download page delivering VenomRAT; WIPO later ordered the domain transferred. DNS was inactive when MAegis rechecked it on 28 July 2026.",
    references: [
      { label: "DomainTools investigation", url: "https://dti.domaintools.com/research/venomrat" },
      { label: "WIPO D2025-2163", url: "https://www.wipo.int/amc/en/domains/decisions/pdf/2025/d2025-2163.pdf" },
    ],
  },
  {
    id: "INC-R007",
    domain: "bitdefendercorp.com",
    brand: "Bitdefender",
    source: "WIPO D2025-4288",
    score: 88,
    confidence: 98,
    severity: "High",
    status: "Closed",
    age: "Historical",
    firstSeen: "2025-10-20T00:00:00Z",
    assignedTo: null,
    signals: ["Exact brand + corporate token", "No legitimate interest", "Bad-faith registration", "WIPO ordered transfer"],
    summary: "A WIPO panel found the registration abusive and ordered transfer. DNS was inactive at the MAegis verification snapshot.",
    references: [{ label: "WIPO D2025-4288", url: "https://www.wipo.int/amc/en/domains/search/text.jsp?case=D2025-4288" }],
  },
  {
    id: "INC-R006",
    domain: "bitdefender.shop",
    brand: "Bitdefender",
    source: "WIPO D2024-4793",
    score: 74,
    confidence: 97,
    severity: "Medium",
    status: "Closed",
    age: "Historical",
    firstSeen: "2024-11-20T00:00:00Z",
    assignedTo: null,
    signals: ["Exact trademark domain", "Commercial TLD", "WIPO ordered transfer", "Currently no A record"],
    summary: "WIPO ordered the exact-match shopping domain transferred to Bitdefender. MAegis records it as resolved historical brand abuse, not a current malware endpoint.",
    references: [{ label: "WIPO D2024-4793", url: "https://www.wipo.int/amc/en/domains/decisions/pdf/2024/d2024-4793.pdf" }],
  },
  {
    id: "INC-R005",
    domain: "centralbitdefender.org",
    brand: "Bitdefender",
    source: "WIPO D2020-1263",
    score: 86,
    confidence: 98,
    severity: "High",
    status: "Closed",
    age: "Historical",
    firstSeen: "2020-05-19T00:00:00Z",
    assignedTo: null,
    signals: ["Reversed product mark", "Support-themed impersonation", "WIPO ordered transfer", "Currently no A record"],
    summary: "The domain combined the BITDEFENDER CENTRAL product mark in reverse order. WIPO ordered transfer and the domain is retained as a closed regression case.",
    references: [{ label: "WIPO D2020-1263", url: "https://www.wipo.int/amc/en/domains/decisions/text/2020/d2020-1263.html" }],
  },
  {
    id: "INC-R004",
    domain: "antivirusbitdefender.com",
    brand: "Bitdefender",
    source: "WIPO D2021-2530",
    score: 84,
    confidence: 98,
    severity: "High",
    status: "Closed",
    age: "Historical",
    firstSeen: "2021-08-04T00:00:00Z",
    assignedTo: null,
    signals: ["Product + exact brand", "Confusing commercial intent", "WIPO case record", "Currently no A record"],
    summary: "A resolved WIPO dispute involving a product-keyword combination around the Bitdefender mark; retained for detector and score regression testing.",
    references: [{ label: "WIPO D2021-2530", url: "https://www.wipo.int/amc/en/domains/decisions/text/2021/d2021-2530.html" }],
  },
  {
    id: "INC-R003", domain: "emag-bg.com", brand: "eMAG", source: "WIPO D2017-0207", score: 89, confidence: 99,
    severity: "High", status: "Closed", age: "Historical", firstSeen: "2017-02-02T00:00:00Z", assignedTo: null,
    signals: ["Exact brand + market token", "Competing retail storefront", "Consumer-confusion risk", "WIPO ordered transfer"],
    summary: "The domain resolved to a Bulgarian online retail platform using the eMAG mark. WIPO ordered transfer; it now resolves to loopback and is treated as remediated.",
    references: [{ label: "WIPO D2017-0207", url: "https://www.wipo.int/amc/en/domains/decisions/text/2017/d2017-0207.html" }],
  },
  {
    id: "INC-R002", domain: "emagbg.com", brand: "eMAG", source: "WIPO D2017-0207", score: 87, confidence: 99,
    severity: "High", status: "Closed", age: "Historical", firstSeen: "2017-02-02T00:00:00Z", assignedTo: null,
    signals: ["Exact brand + market token", "Competing retail storefront", "Consumer-confusion risk", "WIPO ordered transfer"],
    summary: "A companion domain in the same eMAG dispute. It was ordered transferred and currently resolves to loopback rather than an operational storefront.",
    references: [{ label: "WIPO D2017-0207", url: "https://www.wipo.int/amc/en/domains/decisions/text/2017/d2017-0207.html" }],
  },
  {
    id: "INC-R001", domain: "uipath.ai", brand: "UiPath", source: "WIPO DAI2019-0005", score: 72, confidence: 99,
    severity: "Medium", status: "Closed", age: "Historical", firstSeen: "2019-12-04T00:00:00Z", assignedTo: null,
    signals: ["Exact trademark domain", "AI-sector TLD", "Passive holding in bad faith", "WIPO ordered transfer"],
    summary: "WIPO found the exact-match .ai registration abusive and ordered transfer. The domain now resolves and may be legitimate after transfer, so it is explicitly closed.",
    references: [{ label: "WIPO DAI2019-0005", url: "https://www.wipo.int/amc/en/domains/decisions/text/2019/dai2019-0005.html" }],
  },
];

const sources = [
  { name: "Certificate Transparency", state: "Streaming", lag: "18s", seen: "14,829" },
  { name: "DNS candidates", state: "Scanning", lag: "42s", seen: "2,604" },
  { name: "RDAP registration sweep", state: "Rotating", lag: "15m", seen: "320" },
  { name: "urlscan metadata", state: "Healthy", lag: "15m", seen: "126" },
  { name: "URLhaus", state: "Healthy", lag: "4m", seen: "186" },
  { name: "CZDS zone delta", state: "Scheduled", lag: "3h", seen: "438k" },
];

type WorkerRuntime = {
  configured: boolean;
  fresh: boolean;
  status: string;
  cycle_count?: number;
  last_cycle_completed_at?: string | null;
};

type BrandChoice = { id: string; name: string };

function severityClass(severity: Incident["severity"]) {
  return `severity severity-${severity.toLowerCase()}`;
}

export default function Home() {
  const [incidents, setIncidents] = useState<Incident[]>(seededIncidents);
  const [dataMode, setDataMode] = useState<"demo" | "live">("demo");
  const [worker, setWorker] = useState<WorkerRuntime | null>(null);
  const [filter, setFilter] = useState("All");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Incident | null>(seededIncidents[0]);
  const [showSubmission, setShowSubmission] = useState(false);
  const [me, setMe] = useState<AnalystAccount | null>(null);
  const [brands, setBrands] = useState<BrandChoice[]>([]);
  const [submissionBrandId, setSubmissionBrandId] = useState("");
  const [submissionValue, setSubmissionValue] = useState("");
  const [submissionCapture, setSubmissionCapture] = useState(false);
  const [submissionFeedback, setSubmissionFeedback] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const queueStats = useMemo(() => {
    const open = incidents.filter((incident) => !["Closed", "False Positive"].includes(incident.status));
    return {
      newCount: open.filter((incident) => incident.status === "New").length,
      investigating: open.filter((incident) => incident.status === "Investigating").length,
      critical: open.filter((incident) => incident.severity === "Critical").length,
      unassigned: open.filter((incident) => !incident.assignedTo).length,
      brands: new Set(incidents.map((incident) => incident.brand)).size,
    };
  }, [incidents]);

  const brandCoverage = useMemo(() => {
    const grouped = new Map<string, { count: number; open: number; maxRisk: number }>();
    for (const incident of incidents) {
      const current = grouped.get(incident.brand) ?? { count: 0, open: 0, maxRisk: 0 };
      current.count += 1;
      current.open += ["Closed", "False Positive"].includes(incident.status) ? 0 : 1;
      current.maxRisk = Math.max(current.maxRisk, incident.score);
      grouped.set(incident.brand, current);
    }
    return [...grouped.entries()].sort((left, right) => right[1].maxRisk - left[1].maxRisk).slice(0, 6);
  }, [incidents]);

  const visible = useMemo(() => {
    return incidents.filter((incident) => {
      const matchesFilter = filter === "All"
        || (filter === "Unassigned" ? !incident.assignedTo && !["Closed", "False Positive"].includes(incident.status) : incident.status === filter || incident.severity === filter);
      const haystack = `${incident.domain} ${incident.brand} ${incident.source}`.toLowerCase();
      return matchesFilter && haystack.includes(query.toLowerCase());
    });
  }, [filter, query, incidents]);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/incidents", { signal: controller.signal })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("API unavailable")))
      .then((payload: { mode: "demo" | "live"; incidents: Incident[] }) => {
        if (payload.mode === "live") {
          setIncidents(payload.incidents);
          setSelected(payload.incidents[0] ?? null);
          setDataMode("live");
        }
      })
      .catch(() => undefined);
    fetch("/api/runtime", { signal: controller.signal })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("Runtime unavailable")))
      .then((payload: { mode: "demo" | "live"; worker: WorkerRuntime | null }) => {
        if (payload.mode === "live") setWorker(payload.worker);
      })
      .catch(() => undefined);
    fetch("/api/accounts", { signal: controller.signal })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("Accounts unavailable")))
      .then((payload: { me: AnalystAccount | null }) => setMe(payload.me))
      .catch(() => undefined);
    fetch("/api/brands", { signal: controller.signal })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("Brands unavailable")))
      .then((payload: { brands: BrandChoice[] }) => { setBrands(payload.brands); setSubmissionBrandId(payload.brands[0]?.id ?? ""); })
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  async function submitDomain() {
    if (!submissionBrandId || submissionValue.trim().length < 3) return;
    setSubmitting(true); setSubmissionFeedback(null);
    try {
      const response = await fetch("/api/submissions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ brandId: submissionBrandId, value: submissionValue, requestCapture: submissionCapture }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Analysis could not be queued");
      setIncidents((current) => [body.incident, ...current.filter((item) => item.id !== body.incident.id)]);
      setSelected(body.incident); setSubmissionValue(""); setSubmissionCapture(false); setShowSubmission(false);
    } catch (error) { setSubmissionFeedback(error instanceof Error ? error.message : "Analysis could not be queued"); }
    finally { setSubmitting(false); }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="wordmark"><span className="brand-sigil">M</span><span>MAEGIS</span></div>
        <nav aria-label="Primary navigation">
          <p className="nav-label">Monitor</p>
          <a className="nav-item active" href="#overview"><span>⌁</span>Overview</a>
          <a className="nav-item" href="#incidents"><span>◇</span>Incidents <b>{incidents.length}</b></a>
          <Link className="nav-item" href="/discovery"><span>◎</span>Discovery</Link>
          <Link className="nav-item" href="/brands"><span>◫</span>Protected brands</Link>
          <p className="nav-label">Operate</p>
          <Link className="nav-item" href="/team"><span>♙</span>Analyst team</Link>
          <Link className="nav-item" href="/audit"><span>▤</span>Audit log</Link>
          <Link className="nav-item" href="/settings"><span>⚙</span>Settings</Link>
        </nav>
        <div className="sidebar-status">
          <div className="pulse-dot" />
          <div><strong>{worker?.fresh ? "Monitoring active" : "Demonstration mode"}</strong><span>{worker?.fresh ? `Discovery cycle ${worker.cycle_count ?? 0}` : "Worker not connected"}</span></div>
        </div>
        <div className="profile"><span className="avatar">{(me?.display_name ?? "Local Analyst").split(" ").map((part) => part[0]).join("").slice(0, 2)}</span><div><strong>{me?.display_name ?? "Local Analyst"}</strong><span>{me?.role ?? "analyst"}</span></div><button aria-label="Profile options">•••</button></div>
      </aside>

      <section className="workspace" id="overview">
        <header className="topbar">
          <div><p className="eyebrow">Threat operations / Overview</p><h1>Brand risk command</h1></div>
          <div className="top-actions">
            <label className="search"><span>⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search domains, brands, IPs…" aria-label="Search incidents" /></label>
            <button className="primary-button" onClick={() => setShowSubmission(true)}>+ Analyze domain</button>
          </div>
        </header>

        <div className="operational-banner"><span className="pulse-dot" /><strong>{worker?.fresh ? "Live discovery worker" : dataMode === "live" ? "API connected — worker unavailable" : "Research-backed demonstration"}</strong><span>{worker?.fresh ? `Healthy · ${worker.cycle_count ?? 0} completed cycles` : dataMode === "live" ? "Incidents remain available while scanner health is investigated" : "Public-source current and historical cases — analyst review required"}</span><span className="banner-rule" /><span>Evidence policy</span><strong>Source linked</strong></div>

        <section className="metrics-grid" aria-label="Key risk metrics">
          <article className="metric-card"><div><span>New findings</span><b className="trend alert">Needs triage</b></div><strong>{queueStats.newCount}</strong><p>Unconfirmed detections waiting for first review</p><div className="mini-bars">{[52,64,58,73,67,85,78,92].map((height, index) => <i key={index} style={{height: `${height}%`}} />)}</div></article>
          <article className="metric-card"><div><span>Investigating</span><b className="trend">Active cases</b></div><strong>{queueStats.investigating}</strong><p>Cases currently owned by an analyst</p><div className="risk-ring"><span>{queueStats.investigating}</span></div></article>
          <article className="metric-card"><div><span>Critical open risk</span><b className="trend alert">Priority</b></div><strong>{queueStats.critical}</strong><p>Open findings requiring accelerated review</p><div className="source-stack"><i /><i /><i /><i /></div></article>
          <article className="metric-card"><div><span>Unassigned</span><b className={queueStats.unassigned ? "trend alert" : "trend good"}>{queueStats.brands} brands</b></div><strong>{queueStats.unassigned}</strong><p>Open cases without a current owner</p><div className="sparkline"><i /><i /><i /><i /><i /><i /><i /></div></article>
        </section>

        <section className="content-grid">
          <article className="panel incidents-panel" id="incidents">
            <div className="panel-heading"><div><p className="eyebrow">Prioritized analyst workflow</p><h2>{dataMode === "live" ? "Incident review queue" : "Real brand-abuse cases"}</h2></div><span className="queue-count">{visible.length} shown · risk ordered</span></div>
            <div className="filters" role="group" aria-label="Filter incidents">{["All", "New", "Investigating", "Unassigned", "Critical", "Closed"].map((item) => <button key={item} className={filter === item ? "selected" : ""} onClick={() => setFilter(item)}>{item}{item === "All" && <span>{incidents.length}</span>}{item === "Unassigned" && <span>{queueStats.unassigned}</span>}</button>)}</div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Finding</th><th>Risk</th><th>Status</th><th>Owner</th><th>First seen</th></tr></thead>
                <tbody>{visible.map((incident) => <tr key={incident.id} onClick={() => incident.status === "Investigating" ? window.open(`/incidents/${encodeURIComponent(incident.id)}`, "_blank", "noopener,noreferrer") : setSelected(incident)} className={selected?.id === incident.id ? "active-row" : ""} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") window.open(`/incidents/${encodeURIComponent(incident.id)}`, "_blank", "noopener,noreferrer"); }}>
                  <td><a className="incident-link" href={`/incidents/${encodeURIComponent(incident.id)}`} target="_blank" rel="noreferrer" onClick={(event) => event.stopPropagation()}>{incident.domain} <span>↗</span></a><span>{incident.brand} · {incident.source}</span></td>
                  <td><div className="score"><b>{incident.score}</b><span className={severityClass(incident.severity)}>{incident.severity}</span></div></td>
                  <td><span className={`status status-${incident.status.toLowerCase().replaceAll(" ", "-")}`}>{incident.status}</span></td>
                  <td><span className={incident.assignedTo ? "owner owner-assigned" : "owner owner-unassigned"}>{incident.assignedTo ?? "Unassigned"}</span></td>
                  <td><strong>{incident.age}</strong><span>ago</span></td>
                </tr>)}</tbody>
              </table>
              {visible.length === 0 && <div className="empty-state">No incidents match this view.</div>}
            </div>
          </article>

          {selected ? <IncidentDetail key={selected.id} incident={selected} mode={dataMode} onClose={() => setSelected(null)} onUpdated={(updated) => { setSelected(updated); setIncidents((current) => current.map((item) => item.id === updated.id ? updated : item)); }} /> : <aside className="panel evidence-panel"><div className="empty-detail"><span>◇</span><h3>Select an incident</h3><p>Review its score, evidence, and investigation state.</p></div></aside>}
        </section>

        <section className="bottom-grid">
          <article className="panel" id="sources"><div className="panel-heading"><div><p className="eyebrow">Ingestion</p><h2>Source health</h2></div><span className={worker?.fresh ? "all-healthy" : "health-warning"}>● {worker?.fresh ? "Worker operational" : "Static source snapshot"}</span></div><div className="source-list">{sources.map((source) => <div key={source.name}><span className="source-icon">{source.name[0]}</span><div><strong>{source.name}</strong><span>{source.seen} observations in the reference window</span></div><div className="source-state"><strong>{worker?.fresh ? source.state : "Reference"}</strong><span>{worker?.fresh ? `Lag ${source.lag}` : "Not live telemetry"}</span></div></div>)}</div></article>
          <article className="panel coverage-panel" id="brands"><div className="panel-heading"><div><p className="eyebrow">Monitored portfolio</p><h2>Brand case coverage</h2></div><span className="queue-count">Top {brandCoverage.length} by risk</span></div><div className="coverage-list">{brandCoverage.map(([brand, coverage], index) => <div key={brand}><span className={`company-mark ${["amber", "sage", "coral", "stone"][index % 4]}`}>{brand.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase()}</span><div><strong>{brand}</strong><span>{coverage.count} findings · {coverage.open} open</span></div><em>{coverage.maxRisk}</em></div>)}</div></article>
        </section>
      </section>

      {showSubmission && <div className="modal-backdrop" role="presentation" onMouseDown={() => setShowSubmission(false)}><form className="modal" role="dialog" aria-modal="true" aria-labelledby="submission-title" onSubmit={(event) => { event.preventDefault(); submitDomain(); }} onMouseDown={(event) => event.stopPropagation()}><button type="button" className="modal-close" onClick={() => setShowSubmission(false)} aria-label="Close">×</button><p className="eyebrow">Manual submission</p><h2 id="submission-title">Analyze a domain or URL</h2><p>{dataMode === "live" ? "Submit an observation to the same evidence and scoring pipeline used by live connectors." : "Connect the operational API to submit live observations. Demonstration cases remain read-only."}</p><label>Domain or URL<input autoFocus value={submissionValue} onChange={(event) => setSubmissionValue(event.target.value)} placeholder="example-login.com" maxLength={2048} disabled={dataMode !== "live"} /></label><label>Protected brand<select value={submissionBrandId} onChange={(event) => setSubmissionBrandId(event.target.value)} disabled={dataMode !== "live" || brands.length === 0}><option value="">Choose a monitored brand…</option>{brands.map((brand) => <option key={brand.id} value={brand.id}>{brand.name}</option>)}</select></label><label className="check"><input type="checkbox" checked={submissionCapture} onChange={(event) => setSubmissionCapture(event.target.checked)} disabled={dataMode !== "live"} /> Request isolated page capture</label><button className="primary-button full" disabled={submitting || dataMode !== "live" || !submissionBrandId || submissionValue.trim().length < 3}>{submitting ? "Queueing…" : "Queue analysis"}</button>{submissionFeedback && <p className="modal-error" role="alert">{submissionFeedback}</p>}<small>Live capture never enters credentials or submits forms.</small></form></div>}
    </main>
  );
}
