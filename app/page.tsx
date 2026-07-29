"use client";

import { useEffect, useMemo, useState } from "react";
import { IncidentDetail } from "./incident-detail";
import type { Incident } from "./incident-types";

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

  const visible = useMemo(() => {
    return incidents.filter((incident) => {
      const matchesFilter = filter === "All" || incident.status === filter || incident.severity === filter;
      const haystack = `${incident.domain} ${incident.brand} ${incident.source}`.toLowerCase();
      return matchesFilter && haystack.includes(query.toLowerCase());
    });
  }, [filter, query, incidents]);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/incidents", { signal: controller.signal })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("API unavailable")))
      .then((payload: { mode: "demo" | "live"; incidents: Incident[] }) => {
        if (payload.mode === "live" && payload.incidents.length > 0) {
          setIncidents(payload.incidents);
          setSelected(payload.incidents[0]);
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
    return () => controller.abort();
  }, []);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="wordmark"><span className="brand-sigil">M</span><span>MAEGIS</span></div>
        <nav aria-label="Primary navigation">
          <p className="nav-label">Monitor</p>
          <a className="nav-item active" href="#overview"><span>⌁</span>Overview</a>
          <a className="nav-item" href="#incidents"><span>◇</span>Incidents <b>{incidents.length}</b></a>
          <a className="nav-item" href="#discovery"><span>◎</span>Discovery</a>
          <a className="nav-item" href="#brands"><span>◫</span>Protected brands</a>
          <p className="nav-label">Operate</p>
          <a className="nav-item" href="#sources"><span>⇄</span>Source health</a>
          <a className="nav-item" href="#audit"><span>▤</span>Audit log</a>
          <a className="nav-item" href="#settings"><span>⚙</span>Settings</a>
        </nav>
        <div className="sidebar-status">
          <div className="pulse-dot" />
          <div><strong>{worker?.fresh ? "Monitoring active" : "Demonstration mode"}</strong><span>{worker?.fresh ? `Discovery cycle ${worker.cycle_count ?? 0}` : "Worker not connected"}</span></div>
        </div>
        <div className="profile"><span className="avatar">AM</span><div><strong>Alex Morgan</strong><span>Senior analyst</span></div><button aria-label="Profile options">•••</button></div>
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
          <article className="metric-card"><div><span>{dataMode === "live" ? "Review queue" : "Verified cases"}</span><b className="trend">{dataMode === "live" ? "Live API" : "Public demo"}</b></div><strong>{incidents.length}</strong><p>{dataMode === "live" ? "Unconfirmed detections requiring analyst triage" : "Every case links to public evidence"}</p><div className="mini-bars">{[52,64,58,73,67,85,78,92].map((height, index) => <i key={index} style={{height: `${height}%`}} />)}</div></article>
          <article className="metric-card"><div><span>Malware delivery</span><b className="trend alert">Confirmed</b></div><strong>01</strong><p>DomainTools technical analysis</p><div className="risk-ring"><span>99</span></div></article>
          <article className="metric-card"><div><span>Brands represented</span><b className="trend">Coverage</b></div><strong>04</strong><p>Bitdefender, FAN Courier, eMAG, and UiPath</p><div className="source-stack"><i /><i /><i /><i /></div></article>
          <article className="metric-card"><div><span>Fresh registration hunt</span><b className="trend alert">Rotating</b></div><strong>250</strong><p>Bounded typo candidates per brand</p><div className="sparkline"><i /><i /><i /><i /><i /><i /><i /></div></article>
        </section>

        <section className="content-grid">
          <article className="panel incidents-panel" id="incidents">
            <div className="panel-heading"><div><p className="eyebrow">Evidence-backed archive</p><h2>Real brand-abuse cases</h2></div><span className="text-button">Public sources only</span></div>
            <div className="filters" role="group" aria-label="Filter incidents">{["All", "Critical", "High", "Closed"].map((item) => <button key={item} className={filter === item ? "selected" : ""} onClick={() => setFilter(item)}>{item}{item === "All" && <span>{incidents.length}</span>}</button>)}</div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Finding</th><th>Risk</th><th>Status</th><th>First seen</th></tr></thead>
                <tbody>{visible.map((incident) => <tr key={incident.id} onClick={() => setSelected(incident)} className={selected?.id === incident.id ? "active-row" : ""} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && setSelected(incident)}>
                  <td><strong>{incident.domain}</strong><span>{incident.brand} · {incident.source}</span></td>
                  <td><div className="score"><b>{incident.score}</b><span className={severityClass(incident.severity)}>{incident.severity}</span></div></td>
                  <td><span className={`status status-${incident.status.toLowerCase()}`}>{incident.status}</span></td>
                  <td><strong>{incident.age}</strong><span>ago</span></td>
                </tr>)}</tbody>
              </table>
              {visible.length === 0 && <div className="empty-state">No incidents match this view.</div>}
            </div>
          </article>

          {selected ? <IncidentDetail key={selected.id} incident={selected} mode={dataMode} onClose={() => setSelected(null)} onUpdated={(updated) => { setSelected(updated); setIncidents((current) => current.map((item) => item.id === updated.id ? updated : item)); }} /> : <aside className="panel evidence-panel"><div className="empty-detail"><span>◇</span><h3>Select an incident</h3><p>Review its score, evidence, and investigation state.</p></div></aside>}
        </section>

        <section className="bottom-grid">
          <article className="panel" id="sources"><div className="panel-heading"><div><p className="eyebrow">Ingestion</p><h2>Source health</h2></div><span className="all-healthy">● All operational</span></div><div className="source-list">{sources.map((source) => <div key={source.name}><span className="source-icon">{source.name[0]}</span><div><strong>{source.name}</strong><span>{source.seen} observations today</span></div><div className="source-state"><strong>{source.state}</strong><span>Lag {source.lag}</span></div></div>)}</div></article>
          <article className="panel coverage-panel" id="brands"><div className="panel-heading"><div><p className="eyebrow">Research portfolio</p><h2>Brand case coverage</h2></div><span className="text-button">Historical baseline</span></div><div className="coverage-list">
            <div><span className="company-mark amber">BD</span><div><strong>Bitdefender</strong><span>5 closed · 1 under review</span></div><em>99</em></div>
            <div><span className="company-mark amber">FC</span><div><strong>FAN Courier</strong><span>1 case under review</span></div><em>87</em></div>
            <div><span className="company-mark sage">EM</span><div><strong>eMAG</strong><span>2 verified cases</span></div><em>89</em></div>
            <div><span className="company-mark coral">UI</span><div><strong>UiPath</strong><span>1 verified case</span></div><em>72</em></div>
          </div></article>
        </section>
      </section>

      {showSubmission && <div className="modal-backdrop" role="presentation" onMouseDown={() => setShowSubmission(false)}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="submission-title" onMouseDown={(event) => event.stopPropagation()}><button className="modal-close" onClick={() => setShowSubmission(false)} aria-label="Close">×</button><p className="eyebrow">Manual submission</p><h2 id="submission-title">Analyze a domain or URL</h2><p>Submit an observation to the same evidence and scoring pipeline used by live connectors.</p><label>Domain or URL<input autoFocus placeholder="example-login.com" /></label><label>Protected brand<select defaultValue="bitdefender"><option value="bitdefender">Bitdefender</option><option value="emag">eMAG</option><option value="uipath">UiPath</option><option value="fan-courier">FAN Courier</option></select></label><label className="check"><input type="checkbox" defaultChecked /> Request isolated page capture</label><button className="primary-button full" onClick={() => setShowSubmission(false)}>Queue analysis</button><small>Live capture never enters credentials or submits forms.</small></section></div>}
    </main>
  );
}
