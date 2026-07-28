"use client";

import { useMemo, useState } from "react";

type Incident = {
  id: string;
  domain: string;
  brand: string;
  source: string;
  score: number;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: "New" | "Investigating" | "Monitoring";
  age: string;
  firstSeen: string;
  signals: string[];
  summary: string;
};

const incidents: Incident[] = [
  {
    id: "INC-2048",
    domain: "acme-id-verify.com",
    brand: "Acme Financial",
    source: "Certificate Transparency",
    score: 94,
    severity: "Critical",
    status: "New",
    age: "4m",
    firstSeen: "28 Jul 2026, 10:24 UTC",
    signals: ["Brand + identity token", "Password form detected", "Domain age < 24h", "MX configured"],
    summary: "Newly certified domain combines the enrolled brand with an identity-verification lure and presents a credential form.",
  },
  {
    id: "INC-2047",
    domain: "northstar-support.net",
    brand: "Northstar Cloud",
    source: "CZDS zone delta",
    score: 86,
    severity: "High",
    status: "Investigating",
    age: "18m",
    firstSeen: "28 Jul 2026, 10:10 UTC",
    signals: ["Brand + support token", "New registration", "Unrelated nameserver"],
    summary: "Lookalike support domain was observed in a new zone delta and resolves outside the company allowlist.",
  },
  {
    id: "INC-2046",
    domain: "pay-helio.co",
    brand: "Helio Commerce",
    source: "URLhaus",
    score: 81,
    severity: "High",
    status: "New",
    age: "36m",
    firstSeen: "28 Jul 2026, 09:52 UTC",
    signals: ["Threat-feed hit", "Payment token", "Brand similarity 0.91"],
    summary: "Threat-feed URL uses a payment lure and has strong lexical similarity to the protected brand.",
  },
  {
    id: "INC-2045",
    domain: "mıdori-login.com",
    brand: "Midori Health",
    source: "CT monitor",
    score: 76,
    severity: "Medium",
    status: "Monitoring",
    age: "1h",
    firstSeen: "28 Jul 2026, 09:16 UTC",
    signals: ["Unicode confusable", "Mixed-script label", "Login token"],
    summary: "IDN label contains a confusable character and a login token, but no active page was captured.",
  },
  {
    id: "INC-2044",
    domain: "acme-careers.org",
    brand: "Acme Financial",
    source: "Generated candidate",
    score: 61,
    severity: "Medium",
    status: "Investigating",
    age: "2h",
    firstSeen: "28 Jul 2026, 08:37 UTC",
    signals: ["Brand + careers token", "Recently certified", "No MX record"],
    summary: "Brand-token domain is active and newly certified; evidence is insufficient for confirmation.",
  },
];

const sources = [
  { name: "Certificate Transparency", state: "Streaming", lag: "18s", seen: "14,829" },
  { name: "DNS candidates", state: "Scanning", lag: "42s", seen: "2,604" },
  { name: "URLhaus", state: "Healthy", lag: "4m", seen: "186" },
  { name: "CZDS zone delta", state: "Scheduled", lag: "3h", seen: "438k" },
];

function severityClass(severity: Incident["severity"]) {
  return `severity severity-${severity.toLowerCase()}`;
}

export default function Home() {
  const [filter, setFilter] = useState("All");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Incident | null>(incidents[0]);
  const [showSubmission, setShowSubmission] = useState(false);

  const visible = useMemo(() => {
    return incidents.filter((incident) => {
      const matchesFilter = filter === "All" || incident.status === filter || incident.severity === filter;
      const haystack = `${incident.domain} ${incident.brand} ${incident.source}`.toLowerCase();
      return matchesFilter && haystack.includes(query.toLowerCase());
    });
  }, [filter, query]);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="wordmark"><span className="brand-sigil">A</span><span>AEGISMARK</span></div>
        <nav aria-label="Primary navigation">
          <p className="nav-label">Monitor</p>
          <a className="nav-item active" href="#overview"><span>⌁</span>Overview</a>
          <a className="nav-item" href="#incidents"><span>◇</span>Incidents <b>12</b></a>
          <a className="nav-item" href="#discovery"><span>◎</span>Discovery</a>
          <a className="nav-item" href="#brands"><span>◫</span>Protected brands</a>
          <p className="nav-label">Operate</p>
          <a className="nav-item" href="#sources"><span>⇄</span>Source health</a>
          <a className="nav-item" href="#audit"><span>▤</span>Audit log</a>
          <a className="nav-item" href="#settings"><span>⚙</span>Settings</a>
        </nav>
        <div className="sidebar-status">
          <div className="pulse-dot" />
          <div><strong>Monitoring active</strong><span>4 sources connected</span></div>
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

        <div className="operational-banner"><span className="pulse-dot" /><strong>Live monitoring</strong><span>Last observation 18 seconds ago</span><span className="banner-rule" /><span>Coverage window</span><strong>24/7</strong></div>

        <section className="metrics-grid" aria-label="Key risk metrics">
          <article className="metric-card"><div><span>Open incidents</span><b className="trend up">↑ 18%</b></div><strong>47</strong><p>12 require analyst action</p><div className="mini-bars">{[30,42,34,55,49,72,64,83,78,92].map((height, index) => <i key={index} style={{height: `${height}%`}} />)}</div></article>
          <article className="metric-card"><div><span>Critical exposure</span><b className="trend alert">3 new</b></div><strong>08</strong><p>Across 5 protected brands</p><div className="risk-ring"><span>83</span></div></article>
          <article className="metric-card"><div><span>Domains analyzed</span><b className="trend">Today</b></div><strong>18.4k</strong><p>0.26% promoted to incidents</p><div className="source-stack"><i /><i /><i /><i /></div></article>
          <article className="metric-card"><div><span>Median time to alert</span><b className="trend good">↓ 11%</b></div><strong>2m 14s</strong><p>Target is under 5 minutes</p><div className="sparkline"><i /><i /><i /><i /><i /><i /><i /></div></article>
        </section>

        <section className="content-grid">
          <article className="panel incidents-panel" id="incidents">
            <div className="panel-heading"><div><p className="eyebrow">Priority queue</p><h2>Incidents requiring attention</h2></div><button className="text-button">View all 47 →</button></div>
            <div className="filters" role="group" aria-label="Filter incidents">{["All", "Critical", "New", "Investigating"].map((item) => <button key={item} className={filter === item ? "selected" : ""} onClick={() => setFilter(item)}>{item}{item === "All" && <span>{incidents.length}</span>}</button>)}</div>
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

          <aside className="panel evidence-panel" aria-live="polite">
            {selected && <>
              <div className="evidence-head"><div><span className={severityClass(selected.severity)}>{selected.severity}</span><span>{selected.id}</span></div><button aria-label="Close incident detail" onClick={() => setSelected(null)}>×</button></div>
              <h2>{selected.domain}</h2><p className="muted">{selected.brand} · observed {selected.age} ago</p>
              <div className="score-block"><div className="large-score">{selected.score}<span>/100</span></div><div><strong>Risk score</strong><span>Confidence 92%</span></div></div>
              <p className="summary">{selected.summary}</p>
              <h3>Evidence signals</h3>
              <ul className="signal-list">{selected.signals.map((signal, index) => <li key={signal}><span>{index < 2 ? "!" : "+"}</span>{signal}</li>)}</ul>
              <div className="fact-grid"><div><span>First seen</span><strong>{selected.firstSeen}</strong></div><div><span>Source</span><strong>{selected.source}</strong></div></div>
              <div className="detail-actions"><button className="primary-button">Start investigation</button><button className="secondary-button">View evidence</button></div>
            </>}
            {!selected && <div className="empty-detail"><span>◇</span><h3>Select an incident</h3><p>Review its score, evidence, and investigation state.</p></div>}
          </aside>
        </section>

        <section className="bottom-grid">
          <article className="panel" id="sources"><div className="panel-heading"><div><p className="eyebrow">Ingestion</p><h2>Source health</h2></div><span className="all-healthy">● All operational</span></div><div className="source-list">{sources.map((source) => <div key={source.name}><span className="source-icon">{source.name[0]}</span><div><strong>{source.name}</strong><span>{source.seen} observations today</span></div><div className="source-state"><strong>{source.state}</strong><span>Lag {source.lag}</span></div></div>)}</div></article>
          <article className="panel coverage-panel" id="brands"><div className="panel-heading"><div><p className="eyebrow">Portfolio</p><h2>Brand exposure</h2></div><button className="text-button">Manage brands →</button></div><div className="coverage-list">
            <div><span className="company-mark amber">AC</span><div><strong>Acme Financial</strong><span>18 open incidents</span></div><em>94</em></div>
            <div><span className="company-mark sage">NC</span><div><strong>Northstar Cloud</strong><span>11 open incidents</span></div><em>86</em></div>
            <div><span className="company-mark coral">HC</span><div><strong>Helio Commerce</strong><span>9 open incidents</span></div><em>81</em></div>
            <div><span className="company-mark stone">MH</span><div><strong>Midori Health</strong><span>5 open incidents</span></div><em>76</em></div>
          </div></article>
        </section>
      </section>

      {showSubmission && <div className="modal-backdrop" role="presentation" onMouseDown={() => setShowSubmission(false)}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="submission-title" onMouseDown={(event) => event.stopPropagation()}><button className="modal-close" onClick={() => setShowSubmission(false)} aria-label="Close">×</button><p className="eyebrow">Manual submission</p><h2 id="submission-title">Analyze a domain or URL</h2><p>Submit an observation to the same evidence and scoring pipeline used by live connectors.</p><label>Domain or URL<input autoFocus placeholder="example-login.com" /></label><label>Protected brand<select defaultValue="acme"><option value="acme">Acme Financial</option><option value="northstar">Northstar Cloud</option><option value="helio">Helio Commerce</option><option value="midori">Midori Health</option></select></label><label className="check"><input type="checkbox" defaultChecked /> Request isolated page capture</label><button className="primary-button full" onClick={() => setShowSubmission(false)}>Queue analysis</button><small>Live capture never enters credentials or submits forms.</small></section></div>}
    </main>
  );
}
