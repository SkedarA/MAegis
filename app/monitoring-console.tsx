"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";

type Monitor = { id: string; incident_id: string; brand_name: string; domain: string; state: string; classification: string; interval_seconds: number; next_check_at: string; last_checked_at: string | null; last_change_at: string | null; consecutive_failures: number; check_count: number; incident_status: string; severity: string; risk_score: number };
type Summary = { total: number; active: number; due: number; changed_24h: number; failing: number; by_classification: Record<string, number> };

function humanize(value: string) { return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function when(value: string | null) { return value ? new Date(value).toLocaleString("en-GB") : "Never"; }

export function MonitoringConsole() {
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [mode, setMode] = useState<"demo" | "live">("demo");
  const [query, setQuery] = useState("");
  const [classification, setClassification] = useState("all");
  const [busy, setBusy] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const refresh = useCallback(async () => {
    const response = await fetch("/api/monitoring", { cache: "no-store" });
    const payload = await response.json() as { mode: "demo" | "live"; monitors: Monitor[]; summary: Summary | null };
    setMode(payload.mode); setMonitors(payload.monitors); setSummary(payload.summary); setUpdatedAt(new Date());
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => refresh().catch(() => undefined), 0);
    const timer = window.setInterval(() => refresh().catch(() => undefined), 30000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [refresh]);

  const visible = useMemo(() => monitors.filter((item) => {
    const text = query.trim().toLowerCase();
    return (classification === "all" || item.classification === classification) && (!text || `${item.domain} ${item.brand_name}`.toLowerCase().includes(text));
  }), [monitors, query, classification]);

  async function mutate(item: Monitor, action: "toggle" | "check", interval?: number) {
    setBusy(item.id); setFeedback(null);
    const response = await fetch(action === "check" ? `/api/monitoring/${item.id}/check` : `/api/monitoring/${item.id}`, {
      method: action === "check" ? "POST" : "PATCH", headers: { "Content-Type": "application/json" },
      ...(action === "toggle" ? { body: JSON.stringify(interval ? { interval_seconds: interval } : { state: item.state === "active" ? "paused" : "active" }) } : {}),
    });
    const body = await response.json();
    if (!response.ok) setFeedback(body.error ?? "Monitoring update failed");
    else { setFeedback(action === "check" ? `${item.domain} queued for an immediate check.` : `${item.domain} updated.`); await refresh(); }
    setBusy(null);
  }

  const cards = [
    ["Watched domains", summary?.active ?? 0], ["Due now", summary?.due ?? 0],
    ["Inactive", summary?.by_classification.inactive ?? 0], ["Likely parked", summary?.by_classification.likely_parked ?? 0],
    ["Changed in 24h", summary?.changed_24h ?? 0], ["Checks failing", summary?.failing ?? 0],
  ];
  return <main className="app-shell ops-shell"><aside className="sidebar"><Link className="wordmark" href="/"><span className="brand-sigil">M</span><span>MAEGIS</span></Link><nav aria-label="Primary navigation"><p className="nav-label">Monitor</p><Link className="nav-item" href="/"><span>⌁</span>Overview</Link><Link className="nav-item active" href="/monitoring"><span>◉</span>Domain monitoring</Link><Link className="nav-item" href="/discovery"><span>◎</span>Discovery</Link><Link className="nav-item" href="/brands"><span>◫</span>Protected brands</Link><p className="nav-label">Operate</p><Link className="nav-item" href="/team"><span>♙</span>Analyst team</Link><Link className="nav-item" href="/audit"><span>▤</span>Audit log</Link><Link className="nav-item" href="/settings"><span>⚙</span>Settings</Link></nav><div className="sidebar-status"><div className="pulse-dot" /><div><strong>{mode === "live" ? "Monitoring connected" : "Monitoring unavailable"}</strong><span>30-second console refresh</span></div></div></aside><section className="workspace ops-workspace"><header className="ops-header"><div><p className="eyebrow">Dormant asset watch</p><h1>Domain monitoring</h1><p>Recheck parked and inactive typosquats, retain compact state, and return changed domains to analyst review.</p></div><button className="secondary-button" onClick={() => refresh()} disabled={Boolean(busy)}>Refresh now</button></header>{feedback && <div className="ops-feedback" role="status">{feedback}</div>}<section className="monitor-metrics">{cards.map(([label, value]) => <article key={String(label)}><span>{label}</span><strong>{value}</strong></article>)}</section><section className="ops-panel"><div className="monitor-toolbar"><label>Search<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Domain or protected brand" /></label><label>Infrastructure state<select value={classification} onChange={(event) => setClassification(event.target.value)}><option value="all">All states</option><option value="inactive">Inactive</option><option value="likely_parked">Likely parked</option><option value="active_infrastructure">Active infrastructure</option><option value="unknown">Unknown</option><option value="error">Error</option></select></label><span>{visible.length} watches · updated {updatedAt ? updatedAt.toLocaleTimeString("en-GB") : "—"}</span></div><div className="monitor-table-wrap"><table className="monitor-table"><thead><tr><th>Domain / client</th><th>Infrastructure</th><th>Checks</th><th>Last / next check</th><th>Case</th><th>Cadence</th><th>Actions</th></tr></thead><tbody>{visible.map((item) => <tr key={item.id}><td><Link href={`/incidents/${item.incident_id}`} target="_blank">{item.domain} ↗</Link><span>{item.brand_name}</span></td><td><span className={`monitor-class class-${item.classification}`}>{humanize(item.classification)}</span>{item.last_change_at && <small>Changed {when(item.last_change_at)}</small>}</td><td><strong>{item.check_count}</strong><span>{item.consecutive_failures ? `${item.consecutive_failures} failures` : "Healthy"}</span></td><td><strong>{when(item.last_checked_at)}</strong><span>Next {when(item.next_check_at)}</span></td><td><strong>{Math.round(item.risk_score)} · {humanize(item.severity)}</strong><span>{humanize(item.incident_status)}</span></td><td><select aria-label={`Check interval for ${item.domain}`} value={item.interval_seconds} disabled={busy === item.id} onChange={(event) => mutate(item, "toggle", Number(event.target.value))}><option value={3600}>Hourly</option><option value={21600}>6 hours</option><option value={43200}>12 hours</option><option value={86400}>Daily</option><option value={604800}>Weekly</option></select></td><td><button className="secondary-button" disabled={busy === item.id} onClick={() => mutate(item, "check")}>Check now</button><button className="secondary-button" disabled={busy === item.id} onClick={() => mutate(item, "toggle")}>{item.state === "active" ? "Pause" : "Resume"}</button></td></tr>)}</tbody></table>{visible.length === 0 && <div className="ops-empty">No monitored domains match this view. Put an incident into Monitoring to create a durable watch.</div>}</div></section><p className="monitor-footnote">Monitoring performs DNS, RDAP and TLS checks only. It does not capture pages, submit forms, or store a screenshot on each cycle.</p></section></main>;
}
