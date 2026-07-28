# Threat model

## Protected assets

- tenant data and protected-brand definitions;
- API and feed credentials;
- captured page artifacts;
- analyst decisions and audit history;
- evidence provenance and scoring integrity.

## Primary threats and controls

| Threat | Initial controls |
| --- | --- |
| Cross-tenant disclosure | Server-side tenant predicates, opaque identifiers, authorization tests |
| SSRF through submitted URLs | HTTP(S) allowlist, global-IP validation, redirect/subresource revalidation, port restrictions |
| Browser compromise | Dedicated non-root container, dropped capabilities, read-only filesystem, no host mounts, disposable contexts |
| Feed poisoning | Source provenance, raw hashes, deterministic rules, no source treated as a verdict |
| False accusations | Human confirmation, confidence separate from severity, explicit evidence, no automatic takedown |
| Secret leakage | Environment-backed secrets, no credentials in URLs or logs, public demo is read-only |
| Queue replay or duplication | Database uniqueness constraints, source checkpoints, idempotent candidate keys |
| Oversized source artifacts | Streaming zone processing, bounded observations, capture request and body limits |
| Enrichment SSRF / DNS rebinding | Public-IP validation, connection to the validated address, fixed TLS port, bounded DNS and handshake timeouts |

## Known residual risks

DNS can change between validation and connection. Production capture should enforce network policy below the browser container in addition to application validation. The current CT adapter is an availability dependency and not a complete monitor. API-key authentication is suitable for the first private deployment; external SaaS access requires OIDC and centrally managed role assignments.
