#!/usr/bin/env bash
# ============================================================
# NIDS S1 — Multi-database bootstrap for Ubuntu VM
# ============================================================
# Installs PostgreSQL + TimescaleDB, ClickHouse, Elasticsearch
# + Kibana, and InfluxDB side by side on this host.
#
#   sudo ./install_all.sh                 # install everything
#   sudo ./install_all.sh postgres        # one DB only
#   sudo ./install_all.sh postgres clickhouse
#
# Tested on Ubuntu 22.04 / 24.04. Requires sudo.
# ============================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run with sudo." >&2
  exit 1
fi

WANT_ALL=1
INSTALL_PG=0
INSTALL_TS=0
INSTALL_CH=0
INSTALL_ES=0
INSTALL_IX=0

if [[ $# -gt 0 ]]; then
  WANT_ALL=0
  for arg in "$@"; do
    case "$arg" in
      postgres|pg)       INSTALL_PG=1 ;;
      timescale|ts)      INSTALL_PG=1; INSTALL_TS=1 ;;
      clickhouse|ch)     INSTALL_CH=1 ;;
      elasticsearch|es)  INSTALL_ES=1 ;;
      influxdb|influx|ix) INSTALL_IX=1 ;;
      *) echo "Unknown target: $arg"; exit 2 ;;
    esac
  done
else
  INSTALL_PG=1; INSTALL_TS=1; INSTALL_CH=1; INSTALL_ES=1; INSTALL_IX=1
fi

say() { printf "\n\033[1;32m[%s]\033[0m %s\n" "$(date +%H:%M:%S)" "$*"; }
warn() { printf "\n\033[1;33m[%s] WARN: %s\033[0m\n" "$(date +%H:%M:%S)" "$*"; }

# ----- common base packages ---------------------------------
say "Installing common base packages"
apt-get update -qq
apt-get install -y -qq \
    curl wget gnupg lsb-release ca-certificates \
    apt-transport-https software-properties-common

VERSION_CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")

# =============================================================
# 1. POSTGRESQL
# =============================================================
if [[ $INSTALL_PG -eq 1 ]]; then
  say "Installing PostgreSQL 16"

  # Add official PGDG repo so we get latest 16/17 cleanly.
  install -d /usr/share/postgresql-common/pgdg
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
  echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list

  apt-get update -qq
  apt-get install -y -qq postgresql-16 postgresql-contrib-16 postgresql-client-16

  systemctl enable --now postgresql

  say "Creating role 'nids' and database 'nids_alertes'"
  sudo -u postgres psql -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='nids') THEN
    CREATE ROLE nids LOGIN PASSWORD 'nids123';
  END IF;
END$$;

SELECT 'CREATE DATABASE nids_alertes OWNER nids'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='nids_alertes')\gexec

GRANT ALL PRIVILEGES ON DATABASE nids_alertes TO nids;
SQL

  # Allow network connections from the local subnet.
  PG_CONF="/etc/postgresql/16/main/postgresql.conf"
  HBA="/etc/postgresql/16/main/pg_hba.conf"
  sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$PG_CONF"
  if ! grep -q "nids_alertes" "$HBA"; then
    echo "host nids_alertes nids 192.168.0.0/16 md5" >> "$HBA"
    echo "host nids_alertes nids 127.0.0.1/32 md5" >> "$HBA"
  fi
  systemctl restart postgresql
fi

# =============================================================
# 2. TIMESCALEDB (extension on top of the PostgreSQL above)
# =============================================================
if [[ $INSTALL_TS -eq 1 ]]; then
  say "Installing TimescaleDB extension for PostgreSQL"

  curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey \
      | gpg --dearmor -o /usr/share/keyrings/timescaledb.gpg
  echo "deb [signed-by=/usr/share/keyrings/timescaledb.gpg] \
https://packagecloud.io/timescale/timescaledb/ubuntu/ ${VERSION_CODENAME} main" \
      > /etc/apt/sources.list.d/timescaledb.list

  apt-get update -qq
  apt-get install -y -qq timescaledb-2-postgresql-16 || \
      apt-get install -y -qq timescaledb-2-postgresql-14

  # Non-interactive auto-tuner
  timescaledb-tune --quiet --yes || true
  systemctl restart postgresql

  sudo -u postgres psql -d nids_alertes -v ON_ERROR_STOP=1 \
      -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
fi

# =============================================================
# 3. CLICKHOUSE
# =============================================================
if [[ $INSTALL_CH -eq 1 ]]; then
  say "Installing ClickHouse"
  mkdir -p /tmp/ch-gpg
  GNUPGHOME=/tmp/ch-gpg gpg --no-default-keyring \
      --keyring /usr/share/keyrings/clickhouse-keyring.gpg \
      --keyserver hkp://keyserver.ubuntu.com:80 \
      --recv-keys 8919F6BD2B48D754
  echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] \
https://packages.clickhouse.com/deb stable main" \
      > /etc/apt/sources.list.d/clickhouse.list

  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive \
      apt-get install -y -qq clickhouse-server clickhouse-client

  systemctl enable --now clickhouse-server
fi

# =============================================================
# 4. ELASTICSEARCH + KIBANA
# =============================================================
if [[ $INSTALL_ES -eq 1 ]]; then
  say "Installing Elasticsearch 8 + Kibana"

  # Check memory — ES wants 2 GB+ at minimum.
  TOTAL_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  if [[ $TOTAL_MB -lt 3000 ]]; then
    warn "This VM only has ${TOTAL_MB} MB of RAM. Elasticsearch will be sluggish or OOM. 4 GB+ is recommended."
  fi

  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
      | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
https://artifacts.elastic.co/packages/8.x/apt stable main" \
      > /etc/apt/sources.list.d/elastic-8.x.list

  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive \
      apt-get install -y -qq elasticsearch kibana

  # DEV MODE — disable X-Pack security so you can hit it without TLS.
  # DO NOT use these settings in production.
  ES_CONF=/etc/elasticsearch/elasticsearch.yml
  if ! grep -q "# NIDS dev" "$ES_CONF"; then
    cat >> "$ES_CONF" <<'YAML'

# NIDS dev-mode overrides — plaintext HTTP, no auth. Not for production.
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
network.host: 0.0.0.0
discovery.type: single-node
YAML
  fi

  # Cap ES heap at 1 GB to fit in a modest VM.
  echo "-Xms1g" > /etc/elasticsearch/jvm.options.d/nids.options
  echo "-Xmx1g" >> /etc/elasticsearch/jvm.options.d/nids.options

  systemctl daemon-reload
  systemctl enable --now elasticsearch
  systemctl enable --now kibana
fi

# =============================================================
# 5. INFLUXDB 2
# =============================================================
if [[ $INSTALL_IX -eq 1 ]]; then
  say "Installing InfluxDB 2"
  wget -qO- https://repos.influxdata.com/influxdata-archive.key \
      | gpg --dearmor -o /usr/share/keyrings/influxdata.gpg
  echo "deb [signed-by=/usr/share/keyrings/influxdata.gpg] \
https://repos.influxdata.com/debian stable main" \
      > /etc/apt/sources.list.d/influxdata.list

  apt-get update -qq
  apt-get install -y -qq influxdb2 influxdb2-cli

  systemctl enable --now influxdb
fi

# =============================================================
# WRAP-UP
# =============================================================
say "All requested components installed. Status:"
for svc in postgresql clickhouse-server elasticsearch kibana influxdb; do
  if systemctl list-unit-files | grep -q "^${svc}"; then
    state=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
    printf "  %-20s : %s\n" "$svc" "$state"
  fi
done

cat <<'INFO'

================================================================
NEXT STEPS
================================================================
- Run  ./init_schemas.sh  to create the `alertes` schema in each DB.
- Run  ./load_from_sqlite.py  to replay nids_alertes.db rows into them.
- Point the dashboard at any backend by editing  db_config.py:
      DB_BACKEND = "sqlite" | "postgres" | "timescale"
                 | "clickhouse" | "elasticsearch" | "influxdb"
- Default credentials used by this bootstrap:
      PostgreSQL   user=nids  password=nids123  db=nids_alertes
      ClickHouse   user=default (no password)
      Elasticsearch http://localhost:9200 (dev-mode, no auth)
      Kibana        http://localhost:5601
      InfluxDB      http://localhost:8086  (set up via web UI)

Change the Postgres password with:
      sudo -u postgres psql -c "ALTER USER nids WITH PASSWORD '<new>';"
================================================================
INFO
