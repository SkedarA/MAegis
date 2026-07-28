# Architecture decisions

## Modular monolith first

The API owns tenant, brand, candidate, incident, audit, and job transactions. This keeps consistency understandable for one developer. Discovery and capture are separate processes because they are bursty and untrusted respectively. Modules communicate through durable database records rather than an in-memory queue.

## Retain findings, not the internet

CZDS files and source responses are streamed through brand matching. Only relevant candidates and evidence hashes enter the operational database. This bounds storage cost and reduces unnecessary processing of unrelated domains.

## Explainable decisioning

Every detector emits a name, normalized value, weight, and explanation. The score is recomputable from a detector version and stored evidence. Confidence measures evidence sufficiency; severity measures potential impact. Analysts remain authoritative.

## Evolution path

The connector interface and durable job contract form extraction seams. If scale requires it, discovery, enrichment, and AI analysis can become services behind a transactional outbox. Kafka and OpenSearch are justified only after measured database contention or search limits—not by the desired enterprise aesthetic.

