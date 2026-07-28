# Operations runbook

## Connector health

Treat a connector as degraded after three consecutive failures or when its checkpoint stops advancing. Disable the connector rather than deleting its checkpoint. Source outages must not prevent manual submissions or triage.

## Recovery

1. Stop discovery workers while leaving the API available.
2. Back up PostgreSQL and artifact storage.
3. Restore the latest consistent database snapshot.
4. Verify connector checkpoints and queued jobs.
5. Start one worker and monitor duplicate counts before restoring normal concurrency.

## Evidence handling

Store raw evidence and generated artifacts outside the database when they become large. Retain their SHA-256 hashes, source, collection time, and object key in PostgreSQL. Do not silently replace evidence; add a new version.

## Incident response

Rotate API/feed credentials after suspected exposure, disable live capture, preserve audit logs, and record administrative actions as a dedicated internal incident. Never delete disputed evidence during investigation.

