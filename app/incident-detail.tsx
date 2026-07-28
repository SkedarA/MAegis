"use client";

import { useEffect, useState } from "react";
import type { EvidenceItem, Incident, IncidentSeverity, IncidentStatus } from "./incident-types";

const STATUS_VALUES: Array<[string, IncidentStatus]> = [
  ["investigating", "Investigating"], ["likely_abuse", "Likely Abuse"], ["confirmed", "Confirmed"],
  ["false_positive", "False Positive"], ["monitoring", "Monitoring"], ["closed", "Closed"],
];
const SEVERITY_VALUES: Array<[string, IncidentSeverity]> = [
  ["informational", "Informational"], ["low", "Low"], ["medium", "Medium"], ["high", "High"], ["critical", "Critical"],
];

function evidenceSummary(item: EvidenceItem) {
  const payload = item.payload;
  if (item.evidenceType === "Dns") {
    const records = payload.records as Record<string, unknown[]> | undefined;
    return records ? Object.entries(records).filter(([, values]) => values.length).map(([type, values]) => `${type} ${values.length}`).join(" · ") || "No active records" : "DNS response recorded";
  }
  if (item.evidenceType === "Rdap") {
    const events = payload.events as Array<{ eventAction?: string }> | undefined;
    return `${events?.length ?? 0} registration events · ${((payload.nameservers as unknown[]) ?? []).length} nameservers`;
  }
  if (item.evidenceType === "Tls Certificate") return String(payload.issuer ?? "Certificate metadata recorded");
  if (item.evidenceType === "Enrichment Error") return `${item.source} collection returned ${String(payload.error_type ?? "an error")}`;
  if (item.evidenceType === "Score Signal") return String(payload.explanation ?? "Explainable score contribution");
  return "Source observation retained with integrity hash";
}

function seededEvidence(incident: Incident): EvidenceItem[] {
  return incident.signals.map((signal, index) => ({ id: `${incident.id}-${index}`, evidenceType: "Score Signal", source: "Rules Engine", payload: { explanation: signal }, rawHash: "demo", collectedAt: incident.firstSeen }));
}

function statusValue(status: IncidentStatus) {
  const value = status.toLowerCase().replaceAll(" ", "_");
  return value === "new" ? "investigating" : value;
}

export function IncidentDetail({ incident, mode, onClose, onUpdated }: { incident: Incident; mode: "demo" | "live"; onClose: () => void; onUpdated: (incident: Incident) => void }) {
  const [evidence, setEvidence] = useState<EvidenceItem[]>(() => mode === "demo" ? seededEvidence(incident) : []);
  const [loading, setLoading] = useState(mode === "live");
  const [status, setStatus] = useState(statusValue(incident.status));
  const [severity, setSeverity] = useState(incident.severity.toLowerCase());
  const [assignedTo, setAssignedTo] = useState(incident.assignedTo ?? "");
  const [rationale, setRationale] = useState("");
  const [feedback, setFeedback] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (mode === "demo") return;
    const controller = new AbortController();
    fetch(`/api/incidents/${encodeURIComponent(incident.id)}/evidence`, { signal: controller.signal })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("Evidence unavailable")))
      .then((body: { evidence: EvidenceItem[] }) => setEvidence(body.evidence))
      .catch((error) => { if (error.name !== "AbortError") setFeedback("Evidence could not be loaded."); })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, [incident.id, mode]);

  async function submitTriage(nextStatus = status, nextRationale = rationale) {
    if (mode !== "live") { setFeedback("Triage mutations require the private MAegis API."); return; }
    setSaving(true); setFeedback(null);
    try {
      const response = await fetch(`/api/incidents/${encodeURIComponent(incident.id)}/triage`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: nextStatus, severity, assignedTo, rationale: nextRationale }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Triage update failed");
      onUpdated(body.incident);
      setRationale(""); setFeedback("Decision saved and audit event recorded.");
    } catch (error) { setFeedback(error instanceof Error ? error.message : "Triage update failed"); }
    finally { setSaving(false); }
  }

  return <aside className="panel evidence-panel" aria-live="polite">
    <div className="evidence-head"><div><span className={`severity severity-${incident.severity.toLowerCase()}`}>{incident.severity}</span><span>{incident.id}</span></div><button aria-label="Close incident detail" onClick={onClose}>×</button></div>
    <h2>{incident.domain}</h2><p className="muted">{incident.brand} · observed {incident.age} ago</p>
    <div className="score-block"><div className="large-score">{incident.score}<span>/100</span></div><div><strong>Risk score</strong><span>Confidence {incident.confidence}%</span></div></div>
    <p className="summary">{incident.summary}</p>
    <div className="detail-actions"><button className="primary-button" disabled={saving} onClick={() => submitTriage("investigating", "Analyst opened an investigation from the priority queue.")}>Start investigation</button><button className="secondary-button" onClick={() => document.getElementById("evidence-timeline")?.scrollIntoView({ behavior: "smooth" })}>View evidence</button></div>

    <section className="evidence-timeline" id="evidence-timeline">
      <h3>Evidence timeline <span>{evidence.length}</span></h3>
      {loading && <p className="timeline-message">Loading evidence…</p>}
      {!loading && evidence.length === 0 && <p className="timeline-message">No evidence has been collected yet.</p>}
      <ol>{evidence.map((item) => <li key={item.id}><i /><div><div><strong>{item.evidenceType}</strong><time>{new Date(item.collectedAt).toLocaleString("en-GB")}</time></div><p>{evidenceSummary(item)}</p><span>{item.source} · sha256 {item.rawHash.slice(0, 10)}</span></div></li>)}</ol>
    </section>

    <form className="triage-form" onSubmit={(event) => { event.preventDefault(); submitTriage(); }}>
      <h3>Analyst decision</h3>
      <div className="triage-fields"><label>Status<select value={status} onChange={(event) => setStatus(event.target.value)}>{STATUS_VALUES.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label><label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}>{SEVERITY_VALUES.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label></div>
      <label>Assigned analyst<input value={assignedTo} onChange={(event) => setAssignedTo(event.target.value)} maxLength={160} placeholder="analyst@example.com" /></label>
      <label>Decision rationale<textarea value={rationale} onChange={(event) => setRationale(event.target.value)} minLength={5} maxLength={4000} required placeholder="State what the evidence supports and what remains uncertain." /></label>
      <button className="primary-button full" disabled={saving || rationale.trim().length < 5}>{saving ? "Saving…" : "Save decision"}</button>
      {feedback && <p className="form-feedback">{feedback}</p>}
    </form>
  </aside>;
}
