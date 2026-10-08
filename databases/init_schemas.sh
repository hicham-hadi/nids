#!/usr/bin/env bash
# ============================================================
# NIDS S1 — Create the alertes schema in each database.
# Idempotent: safe to re-run.
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

do_pg=1 do_ts=1 do_ch=1 do_es=1 do_ix=1
if [[ $# -gt 0 ]]; then
  do_pg=0 do_ts=0 do_ch=0 do_es=0 do_ix=0
  for a in "$@"; do
    case "$a" in
      postgres|pg)    do_pg=1 ;;
      timescale|ts)   do_pg=1; do_ts=1 ;;
      clickhouse|ch)  do_ch=1 ;;
      elasticsearch|es) do_es=1 ;;
      influxdb|ix|influx) do_ix=1 ;;
    esac
  done
fi

say() { printf "\n\033[1;32m[init] %s\033[0m\n" "$*"; }

# --- PostgreSQL -----------------------------------------------
if [[ $do_pg -eq 1 ]]; then
  say "PostgreSQL schema"
  PGPASSWORD=nids123 psql -h 127.0.0.1 -U nids -d nids_alertes \
      -v ON_ERROR_STOP=1 -f "$HERE/postgres/schema.sql"
fi

# --- TimescaleDB (promotes alertes to a hypertable) -----------
if [[ $do_ts -eq 1 ]]; then
  say "TimescaleDB hypertable + continuous aggregates"
  PGPASSWORD=nids123 psql -h 127.0.0.1 -U nids -d nids_alertes \
      -v ON_ERROR_STOP=1 -f "$HERE/timescale/setup.sql"
fi

# --- ClickHouse ----------------------------------------------
if [[ $do_ch -eq 1 ]]; then
  say "ClickHouse schema"
  clickhouse-client --queries-file "$HERE/clickhouse/schema.sql"
fi

# --- Elasticsearch -------------------------------------------
if [[ $do_es -eq 1 ]]; then
  say "Elasticsearch mapping"
  curl -s -X PUT "http://localhost:9200/alertes" \
       -H 'Content-Type: application/json' \
       -d "@$HERE/elasticsearch/mapping.json" | head -c 400
  echo
fi

# --- InfluxDB -------------------------------------------------
if [[ $do_ix -eq 1 ]]; then
  say "InfluxDB bucket (interactive setup required once)"
  if ! influx bucket list --name nids 2>/dev/null | grep -q nids; then
    cat <<'HINT'
InfluxDB 2 needs an initial setup done through the web UI the first time:
   1. Open http://<vm-ip>:8086 in a browser
   2. Create an org (e.g. "ocp") and a bucket named "nids"
   3. Copy the generated API token into databases/influxdb/token.txt
Then re-run:  ./init_schemas.sh influxdb
HINT
  else
    echo "Bucket 'nids' already exists."
  fi
fi

echo
echo "Schemas ready."
