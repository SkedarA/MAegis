# MAegis

MAegis is my personal cybersecurity engineering project for monitoring brand impersonation and phishing infrastructure. It collects public domain and certificate signals, enriches suspicious findings, correlates related infrastructure, and gives analysts a practical case-review workflow.

I built MAegis to develop and demonstrate hands-on experience in detection engineering, threat-intelligence pipelines, backend and API design, secure browser automation, data modelling, and operational interface development. It is a working defensive monitoring system with deliberately bounded coverage and cost, not a commercial threat-intelligence service.

The separately bounded **Campaign Intelligence** module normalizes public DNS, TLS, URL behavior, compact page-structure fingerprints and registration-batch evidence into a global infrastructure graph. Its deterministic v2 clustering requires at least two independent evidence families, weights rare indicators more heavily, decays stale relationships and suppresses generic shared-provider hubs. It can abstract protected-brand names from lure-domain templates to recognize one kit targeting multiple firms. The analyst console exposes cohesion and evidence-family scores, while a dedicated investigation workspace supports tenant-scoped assignment, rationale, monitoring, dismissal and safe promotion into the incident queue. Screenshots remain opt-in; compact structure and form fingerprints provide correlation without bulk image retention.

![MAegis social preview](public/og.png)

## Implemented capabilities

The current version includes:

- multi-tenant protected-brand onboarding with legitimate-interest confirmation;
- targeted Certificate Transparency and passive urlscan metadata search, durably rotating DNS and RDAP candidate sweeps, URLhaus adapter, and streaming CZDS zone-file adapter;
- IDNA normalization, Unicode confusable checks, edit distance, shared-hosting and deceptive-subdomain detection, registry-wildcard suppression, deterministic scoring, and explicit score contributions;
- durable observations, candidates, incidents, evidence, connector checkpoints, audit events, and PostgreSQL jobs;
- durable parked/inactive-domain watches with jittered DNS, RDAP, and TLS rechecks, bounded snapshot storage, and automatic return-to-review when infrastructure changes;
- tenant-scoped incident APIs and an interactive analyst console;
- API-backed incident evidence timelines, assignment, severity/status decisions, rationale capture, and audited triage;
- evidence-ranked hosting and registrar attribution from platform suffixes, DNS, urlscan network metadata, and nested RDAP contacts, with audited analyst overrides;
- RDAP enrichment jobs and a separately containerized page-capture utility with SSRF controls;
- fail-soft A/AAAA/CNAME/MX/NS/TXT, RDAP, and TLS certificate enrichment with public-IP enforcement and deterministic rescoring;
- Docker Compose, CI, unit tests, health checks, and operational documentation.
- a hardened small-VM deployment profile with automatic TLS, internal-only PostgreSQL, resource limits, restart policies, durable worker heartbeats, and verified database backups.

Generated lookalikes cover alternate TLDs, omissions, duplications, transpositions, keyboard substitutions and insertions, ASCII and Unicode/IDNA homoglyphs, vowel substitutions, affixes, pluralization, hyphenation, and brand-keyword combinations. Every bounded sweep reserves capacity for exact-brand, lure-keyword, and Unicode candidates while continuing a rotating background scan across the remaining mutation families. Durable brand and candidate cursors resume after worker restarts, and one failed DNS or RDAP lookup cannot block later candidates. RDAP checks identify registrations before DNS or web content appears and emit only candidates inside the configurable freshness window (90 days by default).

The analyst feed merges a newest-findings lane with the highest-risk lane before deduplication, so fresh medium-risk registrations are not hidden behind an older high-risk backlog.

The near-zero-cost defaults generate at most 750 candidates per brand and check 20 RDAP candidates per selected brand per cycle. Tune `MAEGIS_MAX_GENERATED_CANDIDATES`, `MAEGIS_DISCOVERY_RDAP_BATCH_SIZE`, and `MAEGIS_FRESH_REGISTRATION_MAX_AGE_DAYS` to match the public RDAP service's limits. Registered domains without a usable registration event, old registrations, and unregistered candidates remain outside the fresh-registration incident path.

Live connectors are intentionally best effort. CZDS files require approved access, URLhaus requires an auth key, public RDAP services enforce rate limits, and the included CT search adapter should be replaced by a dedicated checkpointed CT monitor as volume grows.

## Architecture

```mermaid
flowchart LR
    CT["CT / urlscan / CZDS / URLhaus"] --> DW["Discovery worker"]
    DG["Generated candidates"] --> DW
    DW --> DE["Detection + scoring"]
    DE --> PG[("PostgreSQL")]
    PG --> API["FastAPI"]
    API --> UI["Analyst console"]
    PG --> EW["Enrichment jobs"]
    EW --> RDAP["RDAP / DNS"]
    PG -. disabled by default .-> CAP["Isolated capture"]
```

The control plane is a modular monolith. Discovery and page capture run independently because their dependencies and failure modes differ. A transactional job table provides durable work without adding Kafka or Redis to the first release.

## Run locally

1. Copy `.env.example` to `.env` and replace the development API key.
2. Start the stack:

   ```bash
   docker compose up --build
   ```

3. Open the analyst console at `http://localhost:3000` and API documentation at `http://localhost:8000/docs`.

The web console is also available without Docker using `pnpm dev`. The API requires Python 3.12 and PostgreSQL.

### Register a monitored brand

```bash
curl -X POST http://localhost:8000/api/v1/brands \
  -H "Content-Type: application/json" \
  -H "X-API-Key: development-only" \
  -d '{
    "name": "Example Company",
    "official_domains": ["example.com"],
    "trademarks": ["Example"],
    "keywords": ["login", "support"],
    "permitted_variations": [],
    "legitimate_interest_confirmed": true
  }'
```

The discovery worker polls enrolled brands and retains only relevant observations. Put approved `*.zone.gz` files under `data/czds/`; full zone contents are streamed and are not inserted into PostgreSQL.

The **Protected brands** panel manages the live monitoring portfolio in PostgreSQL. Analysts can pause monitoring and maintain tenant-scoped allowlist assets as base domains, exact subdomains, or descendant-only wildcards. Administrators can archive a brand with a required rationale; MAegis removes it from active monitoring but preserves its incidents, evidence, and audit history.

The **Domain monitoring** console is for parked, dormant, or currently inactive typosquats. Put a case into the `monitoring` state to create a durable watch. The worker claims due rows with `FOR UPDATE SKIP LOCKED`, checks them concurrently in bounded batches, and adds incident evidence only for the first baseline or a meaningful DNS/RDAP/TLS change. Unchanged checks overwrite the compact current snapshot instead of creating an unbounded history table. Stable per-domain jitter spreads checks across the interval, allowing multiple workers to process thousands of watches without a thundering herd. A changed domain returns to `new` for human review and receives a normal enrichment job; it is never automatically declared malicious.

Default watch policy: 100 domains per batch, up to five batches per minute, 10 concurrent network checks, and a six-hour per-domain cadence. Discovery sources retain their separate 15-minute cadence. Configure these through `MAEGIS_MONITOR_BATCH_SIZE`, `MAEGIS_MONITOR_BATCHES_PER_CYCLE`, `MAEGIS_MONITOR_CONCURRENCY`, `MAEGIS_MONITOR_POLL_INTERVAL_SECONDS`, and `MAEGIS_MONITOR_DEFAULT_INTERVAL_SECONDS`. Monitoring never captures screenshots or visits page content.

### Enroll the Romanian operational catalog

MAegis includes a reviewed catalog of 32 high-value Romanian and Romanian-international brands. It spans banking, energy, technology, retail, logistics, healthcare, aviation, property, and manufacturing. Official domains are allowlisted assets; inclusion does not imply that abuse has occurred.

Enroll every catalog brand idempotently for the default tenant:

```bash
docker compose exec api python -m app.seed_brands
```

Use `--paused` to prepare the records without live polling, or repeat `--brand KEY` to enroll a subset. The equivalent administrator API is `GET /api/v1/brand-catalog` followed by `POST /api/v1/brand-catalog/enroll` with legitimate-interest confirmation. To respect a small operational budget, discovery rotates through five brands every 15 minutes by default; both values are configurable with `MAEGIS_DISCOVERY_BRAND_BATCH_SIZE` and `MAEGIS_DISCOVERY_POLL_INTERVAL_SECONDS`.

### Submit a live finding manually

```bash
curl -X POST http://localhost:8000/api/v1/submissions \
  -H "Content-Type: application/json" \
  -H "X-API-Key: development-only" \
  -d '{"brand_id":"BRAND_ID","value":"example-login.com","request_capture":false}'
```

The response contains the normalized domain, risk, confidence, severity, detector version, and every score contribution.

The enrichment worker stores each DNS, RDAP, and TLS result independently. Retrieve the evidence timeline with `GET /api/v1/incidents/{id}/evidence`. DNS records pointing to non-public space remain visible as evidence, but MAegis will not establish a TLS connection to those addresses.

For an operational deployment, use `deploy/compose.production.yml` and follow [the operations runbook](docs/operations.md). The analyst console only displays a live-scanner state after the authenticated worker heartbeat proves a recent completed or running discovery cycle.

## Safety defaults

- Page capture is disabled unless `MAEGIS_CAPTURE_ENABLED=true`.
- Public, private, loopback, link-local, reserved, credential-bearing, non-HTTP, and nonstandard-port targets are rejected.
- Redirects and subresources are validated independently.
- Capture does not enter credentials, submit forms, accept downloads, or preserve sessions.
- Detection is evidence, not an accusation. Analyst confirmation and takedown remain manual.
- Screenshot capture remains disabled by default and is never scheduled for every incident. When enabled, analysts request individual captures only when visual evidence justifies local storage use.
- The overview dashboard separates incidents by protected client and supports client, severity, ownership, time-window, score, search, and ordering filters.
- Adding an official asset suppresses matching unreviewed incidents and queues versioned rescoring; removing an asset queues reevaluation so automatically suppressed findings can reopen.
- Case workspaces correlate shared IPs, nameservers, mail servers, certificates, ASNs, and favicon hashes, and can export an audited JSON evidence bundle without screenshot binaries.
- Tenant scope is applied server-side to operational queries.

Read [the architecture decisions](docs/architecture.md), [threat model](docs/threat-model.md), and [operations runbook](docs/operations.md) before enabling live monitoring.

## Tests

```bash
pnpm test
python -m unittest discover -s services/api/tests
python -m unittest discover -s services/capture -p "test_*.py"
```

CI additionally validates linting and container definitions.

## Roadmap

The next implementation increments are deeper DNS history, analyst-assisted campaign merge/split controls, OIDC enforcement, threshold-calibration reports, and signed evidence exports. Commercial passive DNS, Kafka, Kubernetes, automated takedown, and bulk screenshot retention are deliberately outside the current scope.
