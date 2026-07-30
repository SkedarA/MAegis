# Operations runbook

## Small-VM production profile

Use a current Ubuntu LTS VM with at least 2 vCPU, 4 GB RAM, and 40 GB of encrypted storage. Only SSH, HTTP, and HTTPS should be reachable from the internet; PostgreSQL stays on the internal Docker network.

1. Point an API hostname to the VM.
2. Clone MAegis to `/opt/maegis` and copy `.env.production.example` to `.env.production`.
3. Replace every placeholder. Use an alphanumeric database password in the SQLAlchemy URL and generate an independent API key of at least 32 random characters.
4. Validate and start the stack:

   ```bash
   docker compose --env-file .env.production -f deploy/compose.production.yml config --quiet
   docker compose --env-file .env.production -f deploy/compose.production.yml up -d --build
   docker compose --env-file .env.production -f deploy/compose.production.yml ps
   ```

5. Enroll the curated brand catalog once:

   ```bash
   docker compose --env-file .env.production -f deploy/compose.production.yml exec api python -m app.seed_brands
   ```

6. Install `deploy/systemd/maegis.service` as `/etc/systemd/system/maegis.service`, run `systemctl daemon-reload`, then `systemctl enable --now maegis` so the stack returns after reboot.
7. Store `MAEGIS_API_URL`, `MAEGIS_API_KEY`, and `MAEGIS_TENANT_ID` as server-side variables in the hosted analyst application. Never expose the key through a `NEXT_PUBLIC_` variable.

Caddy obtains and renews TLS automatically after DNS resolves. The production API disables interactive documentation and refuses startup when its API key is missing or shorter than 32 characters.

## Runtime proof

`GET /api/v1/runtime/worker` is authenticated and reports the last heartbeat, completed scan cycle, instance, and failure state. The dashboard shows **Live discovery worker** only when that heartbeat is fresh. A stale or absent worker fails closed to demonstration or degraded mode.

The worker container also runs `python -m app.worker_healthcheck`. Docker restarts it after repeated stale checks. Connector-level failures remain isolated and visible without falsely marking the whole process healthy forever.

## Connector health

Treat a connector as degraded after three consecutive failures or when its checkpoint stops advancing. Disable the connector rather than deleting its checkpoint. Source outages must not prevent manual submissions or triage.

## Recovery

1. Stop discovery workers while leaving the API available.
2. Back up PostgreSQL and artifact storage.
3. Restore the latest consistent database snapshot.
4. Verify connector checkpoints and queued jobs.
5. Start one worker and monitor duplicate counts before restoring normal concurrency.

## Backups

Run `deploy/backup-postgres.sh` from a root-owned timer or cron entry. It writes a PostgreSQL custom-format dump and a SHA-256 checksum to the chosen backup directory. Copy backups to a separate encrypted location; a backup on the same VM is not disaster recovery. Test restoration quarterly on a disposable database.

## Evidence handling

Store raw evidence and generated artifacts outside the database when they become large. Retain their SHA-256 hashes, source, collection time, and object key in PostgreSQL. Do not silently replace evidence; add a new version.

## Incident response

Rotate API/feed credentials after suspected exposure, disable live capture, preserve audit logs, and record administrative actions as a dedicated internal incident. Never delete disputed evidence during investigation.
