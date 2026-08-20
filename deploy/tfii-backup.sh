#!/bin/bash
# TFII nightly backup.
#
# The whole platform is ~73MB of Postgres on a single free-tier volume with no
# snapshots and WAL archiving off. One disk failure loses every IOC, CVE,
# account and campaign with no recovery path. This is that recovery path.
#
# Writes a compressed dump plus the file store, prunes anything older than
# RETAIN_DAYS, and records the outcome where /admin/health can see it — a backup
# nobody checks is the same class of problem as a notification nobody checks.
set -uo pipefail

BACKUP_DIR="${BACKUP_DIR:-/home/ubuntu/backups}"
RETAIN_DAYS="${RETAIN_DAYS:-14}"
ENVFILE="/home/ubuntu/threatfeed/.env"
STAMP=$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"

DB_NAME=$(grep -E '^DB_NAME=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
DB_NAME="${DB_NAME:-threatfeeddb}"

status="ok"; detail=""

# ── database ────────────────────────────────────────────────────────────────
DUMP="$BACKUP_DIR/tfii-db-$STAMP.sql.gz"
if sudo -u postgres pg_dump --no-owner --no-acl "$DB_NAME" 2>/tmp/tfii-bk.err | gzip -9 > "$DUMP"; then
  SIZE=$(stat -c%s "$DUMP" 2>/dev/null || echo 0)
  # A dump that is suspiciously small means pg_dump wrote an error, not data.
  if [ "$SIZE" -lt 10000 ]; then
    status="fail"; detail="dump only ${SIZE}B — treated as failed"; rm -f "$DUMP"
  else
    detail="db $(numfmt --to=iec "$SIZE" 2>/dev/null || echo "${SIZE}B")"
  fi
else
  status="fail"; detail="pg_dump failed: $(head -c 160 /tmp/tfii-bk.err)"; rm -f "$DUMP"
fi

# ── uploaded files ──────────────────────────────────────────────────────────
if [ -d /home/ubuntu/threatfeed/uploads ]; then
  TAR="$BACKUP_DIR/tfii-files-$STAMP.tar.gz"
  sudo tar czf "$TAR" -C /home/ubuntu/threatfeed uploads 2>/dev/null \
    && detail="$detail, files $(numfmt --to=iec "$(stat -c%s "$TAR")" 2>/dev/null)" \
    || detail="$detail, files FAILED"
fi

# ── prune ───────────────────────────────────────────────────────────────────
find "$BACKUP_DIR" -name 'tfii-*.gz' -mtime +"$RETAIN_DAYS" -delete 2>/dev/null
KEPT=$(find "$BACKUP_DIR" -name 'tfii-db-*.sql.gz' | wc -l)

# ── record for the health check ─────────────────────────────────────────────
PAYLOAD=$(printf '{"at":"%s","ok":%s,"detail":"%s","kept":%s}' \
  "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)" \
  "$([ "$status" = ok ] && echo true || echo false)" \
  "$(echo "$detail" | sed 's/"/\\"/g')" "$KEPT")
sudo -u postgres psql -q "$DB_NAME" -c \
  "INSERT INTO system_settings (key,value) VALUES ('backup_last_result','$PAYLOAD')
   ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value" >/dev/null 2>&1

echo "[tfii-backup] $status — $detail (retaining $KEPT dumps)"
[ "$status" = ok ]
