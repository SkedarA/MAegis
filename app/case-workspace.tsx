"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import Image from "next/image";
import type { AnalystAccount, DomainContext, EvidenceItem, Incident, IncidentNote } from "./incident-types";

const STATUS_OPTIONS = ["investigating", "likely_abuse", "confirmed", "false_positive", "monitoring", "closed"];
const SEVERITY_OPTIONS = ["informational", "low", "medium", "high", "critical"];

function titleCase(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function safeUrl(value: unknown) {
  if (typeof value !== "string") return null;
  try { const url = new URL(value); return url.protocol === "https:" ? url.toString() : null; } catch { return null; }
}

function contactHref(value: string | null | undefined) {
  if (!value) return null;
  if (value.startsWith("https://")) return value;
  if (value.includes("@") && !value.includes(" ") && !value.includes(":")) return `mailto:${value}`;
  return null;
}

function evidenceSummary(item: EvidenceItem) {
  if (item.evidenceType === "Dns") {
    const records = item.payload.records as Record<string, unknown[]> | undefined;
    return records ? Object.entries(records).filter(([, values]) => values.length).map(([type, values]) => `${type} ${values.length}`).join(" · ") || "No active records" : "DNS response recorded";
  }
  if (item.evidenceType === "Rdap") return `${((item.payload.events as unknown[]) ?? []).length} registry events · ${((item.payload.nameservers as unknown[]) ?? []).length} nameservers`;
  if (item.evidenceType === "Tls Certificate") return String(item.payload.issuer ?? "Certificate metadata recorded");
  if (item.evidenceType === "Enrichment Error") return `${item.source} returned ${String(item.payload.error_type ?? "an error")}`;
  return String(item.payload.explanation ?? "Source observation retained with integrity hash");
}

export function CaseWorkspace({ incidentId }: { incidentId: string }) {
  const [incident, setIncident] = useState<Incident | null>(null);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [context, setContext] = useState<DomainContext | null>(null);
  const [me, setMe] = useState<AnalystAccount | null>(null);
  const [analysts, setAnalysts] = useState<AnalystAccount[]>([]);
  const [notes, setNotes] = useState<IncidentNote[]>([]);
  const [selectedAnalyst, setSelectedAnalyst] = useState("");
  const [noteBody, setNoteBody] = useState("");
  const [status, setStatus] = useState("investigating");
  const [severity, setSeverity] = useState("medium");
  const [rationale, setRationale] = useState("");
  const [showAddAnalyst, setShowAddAnalyst] = useState(false);
  const [newAnalystName, setNewAnalystName] = useState("");
  const [newAnalystEmail, setNewAnalystEmail] = useState("");
  const [showInfrastructureEdit, setShowInfrastructureEdit] = useState(false);
  const [hostingProviderName, setHostingProviderName] = useState("");
  const [hostingProviderContact, setHostingProviderContact] = useState("");
  const [registrarName, setRegistrarName] = useState("");
  const [registrarContact, setRegistrarContact] = useState("");
  const [infrastructureRationale, setInfrastructureRationale] = useState("");
  const [feedback, setFeedback] = useState<string | null>(null);
  const [feedbackKind, setFeedbackKind] = useState<"success" | "error">("success");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      fetch(`/api/incidents/${encodeURIComponent(incidentId)}`, { signal: controller.signal }).then((r) => r.json()),
      fetch(`/api/incidents/${encodeURIComponent(incidentId)}/evidence`, { signal: controller.signal }).then((r) => r.json()),
      fetch(`/api/incidents/${encodeURIComponent(incidentId)}/context`, { signal: controller.signal }).then((r) => r.json()),
      fetch("/api/accounts", { signal: controller.signal }).then((r) => r.json()),
      fetch(`/api/incidents/${encodeURIComponent(incidentId)}/notes`, { signal: controller.signal }).then((r) => r.json()),
    ]).then(([incidentBody, evidenceBody, contextBody, accountBody, notesBody]) => {
      if (!incidentBody.incident) throw new Error(incidentBody.error ?? "Incident unavailable");
      setIncident(incidentBody.incident);
      setStatus(incidentBody.incident.status.toLowerCase().replaceAll(" ", "_") === "new" ? "investigating" : incidentBody.incident.status.toLowerCase().replaceAll(" ", "_"));
      setSeverity(incidentBody.incident.severity.toLowerCase());
      setEvidence(evidenceBody.evidence ?? []);
      const loadedContext = contextBody.context ?? null;
      setContext(loadedContext);
      setHostingProviderName(loadedContext?.hosting_provider.name ?? "");
      setHostingProviderContact(loadedContext?.hosting_provider.contact ?? "");
      setRegistrarName(loadedContext?.registrar.name ?? "");
      setRegistrarContact(loadedContext?.registrar.contact ?? "");
      setMe(accountBody.me ?? null);
      setAnalysts(accountBody.analysts ?? []);
      setSelectedAnalyst(accountBody.me?.id ?? "");
      setNotes(notesBody.notes ?? []);
    }).catch((error) => { if (error.name !== "AbortError") { setFeedbackKind("error"); setFeedback(error.message); } }).finally(() => setLoading(false));
    return () => controller.abort();
  }, [incidentId]);

  const screenshot = useMemo(() => evidence.find((item) => item.evidenceType.toLowerCase().includes("screenshot")), [evidence]);
  const screenshotUrl = screenshot ? safeUrl(screenshot.payload.url ?? screenshot.payload.artifact_url) : null;
  const assignedAnalyst = useMemo(() => analysts.find((analyst) => analyst.email === incident?.assignedTo), [analysts, incident?.assignedTo]);
  const isAssignedToMe = Boolean(me && incident?.assignedTo === me.email);

  async function assign(analystId: string) {
    if (!analystId) return;
    setBusy(true); setFeedback(null); setFeedbackKind("success");
    try {
      const response = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/assign`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ analystId }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Assignment failed");
      setIncident(body.incident); setStatus("investigating"); setFeedback(`Assigned to ${body.incident.assignedTo}.`);
    } catch (error) { setFeedbackKind("error"); setFeedback(error instanceof Error ? error.message : "Assignment failed"); }
    finally { setBusy(false); }
  }

  async function addNote() {
    if (noteBody.trim().length < 2) return;
    setBusy(true); setFeedback(null); setFeedbackKind("success");
    try {
      const response = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/notes`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ body: noteBody }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Note could not be saved");
      setNotes((current) => [...current, body.note]); setNoteBody(""); setFeedback("Note added to the audit trail.");
    } catch (error) { setFeedbackKind("error"); setFeedback(error instanceof Error ? error.message : "Note could not be saved"); }
    finally { setBusy(false); }
  }

  async function createAnalyst() {
    if (newAnalystName.trim().length < 2 || !newAnalystEmail.includes("@")) return;
    setBusy(true); setFeedback(null); setFeedbackKind("success");
    try {
      const response = await fetch("/api/accounts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ display_name: newAnalystName.trim(), email: newAnalystEmail.trim(), role: "analyst" }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Account could not be created");
      setAnalysts((current) => [...current, body.analyst].sort((left, right) => left.display_name.localeCompare(right.display_name)));
      setSelectedAnalyst(body.analyst.id); setNewAnalystName(""); setNewAnalystEmail(""); setShowAddAnalyst(false); setFeedback("Analyst account created.");
    } catch (error) { setFeedbackKind("error"); setFeedback(error instanceof Error ? error.message : "Account could not be created"); }
    finally { setBusy(false); }
  }

  async function saveDecision() {
    if (rationale.trim().length < 5) return;
    setBusy(true); setFeedback(null); setFeedbackKind("success");
    try {
      const response = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/triage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, severity, assignedTo: incident?.assignedTo ?? "", rationale }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Decision could not be saved");
      setIncident(body.incident); setRationale(""); setFeedback("Decision saved and audited.");
    } catch (error) { setFeedbackKind("error"); setFeedback(error instanceof Error ? error.message : "Decision could not be saved"); }
    finally { setBusy(false); }
  }

  async function requestCapture() {
    setBusy(true); setFeedback(null); setFeedbackKind("success");
    try {
      const response = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/capture`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Capture request failed");
      setFeedback("Isolated capture queued.");
    } catch (error) { setFeedbackKind("error"); setFeedback(error instanceof Error ? error.message : "Capture request failed"); }
    finally { setBusy(false); }
  }

  async function saveInfrastructureOverride(clear = false) {
    if (!clear && infrastructureRationale.trim().length < 5) return;
    setBusy(true); setFeedback(null); setFeedbackKind("success");
    try {
      const response = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/context`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hosting_provider_name: hostingProviderName.trim() || null,
          hosting_provider_contact: hostingProviderContact.trim() || null,
          registrar_name: registrarName.trim() || null,
          registrar_contact: registrarContact.trim() || null,
          rationale: clear ? "Analyst restored automatic infrastructure attribution." : infrastructureRationale.trim(),
          clear,
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "Infrastructure update failed");
      const updated = body.context as DomainContext;
      setContext(updated);
      setHostingProviderName(updated.hosting_provider.name ?? "");
      setHostingProviderContact(updated.hosting_provider.contact ?? "");
      setRegistrarName(updated.registrar.name ?? "");
      setRegistrarContact(updated.registrar.contact ?? "");
      setInfrastructureRationale(""); setShowInfrastructureEdit(false);
      setFeedback(clear ? "Automatic infrastructure attribution restored." : "Infrastructure attribution saved and audited.");
    } catch (error) { setFeedbackKind("error"); setFeedback(error instanceof Error ? error.message : "Infrastructure update failed"); }
    finally { setBusy(false); }
  }

  if (loading) return <main className="case-loading">Preparing analyst workspace…</main>;
  if (!incident) return <main className="case-loading"><strong>Case unavailable</strong><span>{feedback}</span><Link href="/">Return to queue</Link></main>;

  return <main className="case-shell">
    <header className="case-topbar">
      <Link className="case-brand" href="/"><span className="brand-sigil">M</span><strong>MAEGIS</strong></Link>
      <div className="case-breadcrumb"><span>Incidents</span><b>/</b><strong>{incident.id.slice(0, 8)}</strong></div>
      <div className="case-analyst"><span className="avatar">{(me?.display_name ?? "LA").split(" ").map((part) => part[0]).join("").slice(0, 2)}</span><div><strong>{me?.display_name ?? "Local Analyst"}</strong><span>{titleCase(me?.role ?? "analyst")}</span></div></div>
    </header>

    <section className="case-header">
      <div><div className="case-kicker"><span className={`severity severity-${incident.severity.toLowerCase()}`}>{incident.severity}</span><span className={`status status-${incident.status.toLowerCase().replaceAll(" ", "-")}`}>{incident.status}</span></div><h1>{incident.domain}</h1><p>{incident.brand} · First observed {incident.age} ago · Confidence {incident.confidence}%</p></div>
      <div className="case-score"><strong>{incident.score}</strong><span>Risk score</span></div>
    </section>

    <nav className="case-subnav" aria-label="Case sections"><Link href="/">← Review queue</Link><a href="#assessment">Assessment</a><a href="#capture">Capture</a><a href="#evidence">Evidence</a><a href="#notes">Notes</a><a href="#decision">Decision</a></nav>

    <section className="case-facts" aria-label="Case summary facts"><div><span>Owner</span><strong>{assignedAnalyst?.display_name ?? incident.assignedTo ?? "Unassigned"}</strong></div><div><span>Domain type</span><strong>{context?.domain_type === "platform_tenant" ? context.hosting_provider.name ?? "Hosted tenant" : "Registered domain"}</strong></div><div><span>Evidence</span><strong>{evidence.length} collected items</strong></div><div><span>First seen</span><strong>{incident.firstSeen}</strong></div></section>

    <section className="case-layout">
      <div className="case-main">
        <article className="case-card case-summary" id="assessment"><div className="case-card-head"><div><span>Case assessment</span><h2>Why this needs review</h2></div><span className="case-evidence-count">{evidence.length} evidence items</span></div><p>{incident.summary}</p><ul>{incident.signals.map((signal) => <li key={signal}><span>+</span>{signal}</li>)}</ul></article>

        <article className="case-card capture-card" id="capture"><div className="case-card-head"><div><span>Isolated browser</span><h2>Website capture</h2></div><button className="secondary-button" disabled={busy} onClick={requestCapture}>Request capture</button></div>{screenshotUrl ? <a href={screenshotUrl} target="_blank" rel="noreferrer"><Image unoptimized width={1200} height={720} src={screenshotUrl} alt={`Isolated capture of ${incident.domain}`} /></a> : <div className="capture-empty"><span>▧</span><strong>No screenshot collected</strong><p>Capture is disabled by default. When enabled, the worker records a screenshot without submitting forms or credentials.</p></div>}</article>

        <article className="case-card" id="evidence"><div className="case-card-head"><div><span>Collected facts</span><h2>Evidence timeline</h2></div></div>{evidence.length === 0 ? <div className="case-empty"><strong>No evidence collected yet</strong><p>The incident was scored from its discovery signal. Wait for enrichment or request a safe capture before making a final decision.</p></div> : <ol className="case-timeline">{evidence.map((item) => { const sourceUrl = safeUrl(item.payload.scan_url ?? item.payload.url); return <li key={item.id}><i /><div><div><strong>{item.evidenceType}</strong><time>{new Date(item.collectedAt).toLocaleString("en-GB")}</time></div><p>{evidenceSummary(item)}</p><span>{item.source} · sha256 {item.rawHash.slice(0, 12)} {sourceUrl && <a href={sourceUrl} target="_blank" rel="noreferrer">Open source ↗</a>}</span></div></li>; })}</ol>}</article>
      </div>

      <aside className="case-side">
        <article className="case-card assignment-card"><div className="case-card-head"><div><span>Ownership</span><h2>Assignment</h2></div><button className="text-button" onClick={() => setShowAddAnalyst((value) => !value)}>+ Add analyst</button></div><div className="assigned-line"><span className="avatar">{(assignedAnalyst?.display_name ?? incident.assignedTo ?? "—").split(/[ @._-]/).map((part) => part[0]).join("").slice(0, 2).toUpperCase()}</span><div><span>Current analyst</span><strong>{assignedAnalyst?.display_name ?? incident.assignedTo ?? "Unassigned"}</strong>{assignedAnalyst && <small>{assignedAnalyst.email}</small>}</div></div><button className="primary-button full" disabled={busy || !me || isAssignedToMe} onClick={() => me && assign(me.id)}>{isAssignedToMe ? "Assigned to you" : "Assign to me"}</button><div className="assign-other"><select aria-label="Assign another analyst" value={selectedAnalyst} onChange={(event) => setSelectedAnalyst(event.target.value)}><option value="">Select analyst…</option>{analysts.map((analyst) => <option key={analyst.id} value={analyst.id}>{analyst.display_name} · {titleCase(analyst.role)}</option>)}</select><button className="secondary-button" disabled={busy || !selectedAnalyst} onClick={() => assign(selectedAnalyst)}>Assign</button></div>{showAddAnalyst && <div className="add-analyst"><input value={newAnalystName} onChange={(event) => setNewAnalystName(event.target.value)} placeholder="Analyst name" maxLength={160} /><input value={newAnalystEmail} onChange={(event) => setNewAnalystEmail(event.target.value)} placeholder="analyst@example.com" maxLength={254} type="email" /><button className="secondary-button" disabled={busy || newAnalystName.trim().length < 2 || !newAnalystEmail.includes("@")} onClick={createAnalyst}>Create account</button></div>}</article>

        <article className="case-card intelligence-card">
          <div className="case-card-head"><div><span>Infrastructure</span><h2>Domain intelligence</h2></div><button className="text-button" onClick={() => setShowInfrastructureEdit((value) => !value)}>{showInfrastructureEdit ? "Cancel" : "Edit attribution"}</button></div>
          {context?.domain_type === "platform_tenant" && <p className="platform-notice"><strong>Hosted platform tenant</strong>The abusive asset is the customer subdomain. Parent-domain age and registrar data are intentionally excluded.</p>}
          {context?.override.active && <p className="override-notice"><strong>Analyst override</strong>{context.override.updated_by ?? "Analyst"} · {context.override.updated_at ? new Date(context.override.updated_at).toLocaleString("en-GB") : "saved"}<span>{context.override.rationale}</span></p>}
          <dl>
            <div><dt>Domain type</dt><dd>{context?.domain_type === "platform_tenant" ? "Hosted platform tenant" : "Registered domain"}</dd></div>
            <div><dt>Effective registry target</dt><dd>{context?.registrable_domain ?? "Unknown"}</dd></div>
            <div><dt>Hosting provider</dt><dd>{context?.hosting_provider.name ?? "Not identified"}{contactHref(context?.hosting_provider.contact) && <a href={contactHref(context?.hosting_provider.contact) ?? undefined}>Contact provider ↗</a>}<small>{context ? `${titleCase(context.hosting_provider.source)} · ${titleCase(context.hosting_provider.confidence)} confidence` : "Awaiting evidence"}</small>{context?.hosting_provider.evidence && <em>{context.hosting_provider.evidence}</em>}</dd></div>
            <div><dt>Registrar</dt><dd>{context?.registration_relevant ? context.registrar.name ?? "Not available" : "Not applicable to platform tenant"}{context?.registration_relevant && contactHref(context.registrar.contact) && <a href={contactHref(context.registrar.contact) ?? undefined}>Contact registrar ↗</a>}<small>{context?.registration_relevant ? `${titleCase(context.registrar.source)} · ${titleCase(context.registrar.confidence)} confidence` : "Platform registry intentionally excluded"}</small>{context?.registration_relevant && context.registrar.evidence && <em>{context.registrar.evidence}</em>}</dd></div>
            <div><dt>Registration date</dt><dd>{context?.registration_relevant ? context.registration_date ? new Date(context.registration_date).toLocaleDateString("en-GB") : "Not available" : "Suppressed — platform registration is unrelated"}</dd></div>
          </dl>
          {showInfrastructureEdit && <div className="infrastructure-editor">
            <p>Manual values replace automatic attribution and remain linked to your analyst identity.</p>
            <label>Hosting provider<input value={hostingProviderName} onChange={(event) => setHostingProviderName(event.target.value)} maxLength={200} placeholder="Provider name" /></label>
            <label>Provider contact<input value={hostingProviderContact} onChange={(event) => setHostingProviderContact(event.target.value)} maxLength={500} placeholder="Abuse email or https:// form" /></label>
            <label>Registrar<input value={registrarName} onChange={(event) => setRegistrarName(event.target.value)} maxLength={200} disabled={!context?.registration_relevant} placeholder="Registrar name" /></label>
            <label>Registrar contact<input value={registrarContact} onChange={(event) => setRegistrarContact(event.target.value)} maxLength={500} disabled={!context?.registration_relevant} placeholder="Abuse email or https:// form" /></label>
            <label className="full-field">Override rationale<textarea value={infrastructureRationale} onChange={(event) => setInfrastructureRationale(event.target.value)} maxLength={2000} placeholder="Explain the evidence supporting this correction…" /></label>
            <div className="infrastructure-actions">{context?.override.active && <button className="text-button danger-text" disabled={busy} onClick={() => saveInfrastructureOverride(true)}>Restore automatic</button>}<button className="primary-button" disabled={busy || infrastructureRationale.trim().length < 5 || (!hostingProviderName.trim() && !hostingProviderContact.trim() && !registrarName.trim() && !registrarContact.trim())} onClick={() => saveInfrastructureOverride(false)}>Save attribution</button></div>
          </div>}
        </article>

        <article className="case-card notes-card" id="notes"><div className="case-card-head"><div><span>Collaboration</span><h2>Analyst notes</h2></div><span>{notes.length}</span></div><div className="notes-list">{notes.length === 0 && <p>No analyst notes yet.</p>}{notes.map((note) => <div key={note.id}><strong>{note.author_name}</strong><time>{new Date(note.created_at).toLocaleString("en-GB")}</time><p>{note.body}</p></div>)}</div><textarea value={noteBody} onChange={(event) => setNoteBody(event.target.value)} maxLength={8000} placeholder="Add an evidence-based observation or handoff note…" /><div className="input-foot"><span>{noteBody.length}/8000</span><button className="secondary-button" disabled={busy || noteBody.trim().length < 2} onClick={addNote}>Add note</button></div></article>

        <article className="case-card decision-card" id="decision"><div className="case-card-head"><div><span>Disposition</span><h2>Analyst decision</h2></div></div><div className="decision-grid"><label>Status<select value={status} onChange={(event) => setStatus(event.target.value)}>{STATUS_OPTIONS.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select></label><label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}>{SEVERITY_OPTIONS.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select></label></div><label>Rationale<textarea value={rationale} onChange={(event) => setRationale(event.target.value)} placeholder="Separate observed facts from analyst judgment…" /></label><p className="decision-help">Final labels remain analyst decisions. MAegis records your rationale and never submits a takedown automatically.</p><button className="primary-button full" disabled={busy || rationale.trim().length < 5} onClick={saveDecision}>Save decision</button></article>
        {feedback && <p className={`case-feedback case-feedback-${feedbackKind}`} role={feedbackKind === "error" ? "alert" : "status"}>{feedback}</p>}
      </aside>
    </section>
  </main>;
}
