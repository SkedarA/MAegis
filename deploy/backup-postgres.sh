#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
backup_dir="${1:-$repo_dir/backups}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup_dir"
cd "$repo_dir"

docker compose --env-file .env.production -f deploy/compose.production.yml exec -T postgres \
  sh -c 'pg_dump --format=custom --no-owner --no-privileges --username "$POSTGRES_USER" "$POSTGRES_DB"' \
  > "$backup_dir/maegis-$timestamp.dump"

sha256sum "$backup_dir/maegis-$timestamp.dump" > "$backup_dir/maegis-$timestamp.dump.sha256"
printf '%s\n' "$backup_dir/maegis-$timestamp.dump"
