# NIDS S1 — Multi-database setup for the Ubuntu VM

This folder gives you one-command installation + schema setup +
Python adapters for every database option discussed:

| Backend         | What it adds | Memory | Default port |
|-----------------|---|---|---|
| PostgreSQL      | real SQL server, multi-writer MVCC, remote access | ~150 MB | 5432 |
| TimescaleDB     | PostgreSQL extension: hypertables, continuous aggregates, compression, retention | +0 (uses PG) | 5432 |
| ClickHouse      | columnar OLAP, billions of rows, projections | ~400 MB | 9000 (TCP) / 8123 (HTTP) |
| Elasticsearch   | full-text search, SIEM-ready, Kibana dashboards | ~1 GB (JVM) | 9200 |
| Kibana          | web UI for Elasticsearch | ~400 MB | 5601 |
| InfluxDB 2      | time-series metrics (pps/bps) | ~200 MB | 8086 |

> **Memory warning.** Running every service at once on an Ubuntu VM
> needs **≥ 4 GB RAM**. The install script caps Elasticsearch's JVM
> at 1 GB (`/etc/elasticsearch/jvm.options.d/nids.options`) to help.
> If your VM is smaller, install one or two at a time and skip the
> others — see "Installing selectively" below.

---

## 0. Copy this folder to the Ubuntu VM

From Windows (dashboard side) copy the `databases/` folder next to your
NIDS project on the Ubuntu VM:

```bash
# From the Ubuntu VM
scp -r windows_user@<windows-ip>:/path/to/databases ~/nids/
cd ~/nids/databases
chmod +x install_all.sh init_schemas.sh
```

Or clone it alongside your existing `~/nids/` folder — the install
scripts don't care about location.

---

## 1. Install everything

```bash
cd ~/nids/databases
sudo ./install_all.sh
```

Takes about 5–10 min on a fresh Ubuntu 22.04/24.04. The script is
idempotent: safe to re-run.

### Installing selectively

```bash
sudo ./install_all.sh postgres                  # PostgreSQL only
sudo ./install_all.sh postgres timescale        # PG + Timescale extension
sudo ./install_all.sh clickhouse elasticsearch  # Multiple at once
sudo ./install_all.sh influxdb                  # Only InfluxDB
```

Recognised names: `postgres` (or `pg`), `timescale` (or `ts`),
`clickhouse` (or `ch`), `elasticsearch` (or `es`), `influxdb` (or `ix`).

---

## 2. Create the `alertes` schema in each

```bash
./init_schemas.sh                 # all databases that are installed
./init_schemas.sh postgres        # just one
```

What gets created:

| Backend         | What's created |
|-----------------|---|
| PostgreSQL      | `alertes` table + 6 indexes + `v_alertes_minute` view |
| TimescaleDB     | promotes `alertes` to a hypertable (1-day chunks), 2 continuous aggregates (`alertes_1min`, `alertes_1hour`), compression after 7 days, retention after 90 days |
| ClickHouse      | database `nids`, table `nids.alertes` (MergeTree, partitioned by day, 90-day TTL), projection by `couleur`, materialized view `alertes_1min` |
| Elasticsearch   | index `alertes` with typed mapping (ip, keyword, date, numeric) |
| InfluxDB        | **manual** — see `influxdb/setup.md` (needs the web wizard) |

---

## 3. Load your existing 775 alerts into the new backend(s)

```bash
pip install psycopg2-binary clickhouse-driver 'elasticsearch>=8,<9' influxdb-client

cd ~/nids
# Replay nids_alertes.db into one or many backends:
python databases/load_from_sqlite.py postgres
python databases/load_from_sqlite.py postgres clickhouse elasticsearch
```

Rate: ~2000 rows/sec per backend on a modest VM. Your 775 rows load in
under a second each.

---

## 4. Point the dashboard at a backend

Edit `~/nids/databases/db_config.py`:

```python
DB_BACKEND = "timescale"   # or "sqlite", "postgres", "clickhouse", "elasticsearch", "influxdb"
```

Then wire the dashboard to use the adapter — see **"Hooking into
dashboard.py"** below. You can switch backends at any time; the
`db_adapter.py` module exposes the same `kpis()`,
`serie_temporelle()`, `top_ip()`, etc. methods, so nothing else in the
dashboard needs to change.

### Hooking into `dashboard.py`

Add this at the very top (after the imports):

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "databases"))
from db_adapter import obtenir_backend
BE = obtenir_backend()
```

Then replace each existing data function with a thin wrapper that
calls the adapter:

```python
def obtenir_kpis():                   return BE.kpis()
def obtenir_serie_temporelle():       return BE.serie_temporelle()
def obtenir_repartition_attaques():   return BE.repartition_attaques()
def obtenir_top_ip(limite=5):         return BE.top_ip(limite)
def obtenir_regles_top(limite=4):     return BE.regles_top(limite)
def obtenir_types_attaques():         return BE.types_attaques()
def obtenir_dernieres_alertes(limite=25, filtre_couleur=None, filtre_type=None):
    return BE.dernieres_alertes(limite=limite,
                                filtre_couleur=filtre_couleur,
                                filtre_type=filtre_type)
def rechercher_alertes(**kwargs):     return BE.rechercher(**kwargs)
```

The 1-second polling intervals keep working — only the connection
layer changes.

---

## 5. Wire the capture pipeline to the new backend

Open `detection_fusion.py` (or wherever rows get written to SQLite) and
replace the direct SQLite insert with:

```python
from databases.db_adapter import obtenir_backend
BE = obtenir_backend()

# instead of: cx.execute("INSERT INTO alertes ...", ...)
BE.insert({
    "horodatage":    datetime.now().isoformat(),
    "ip_source":     src_ip,
    "ip_dest":       dst_ip,
    "port_source":   src_port,
    "port_dest":     dst_port,
    "proto":         proto,
    "nb_paquets":    pkts,
    "nb_octets":     bytes_,
    "duree":         duration,
    "debit":         rate,
    "syn": syn, "ack": ack, "fin": fin, "rst": rst,
    "verdict_regle": rule_verdict,
    "detail_regle":  rule_detail,
    "verdict_ml":    ml_verdict,
    "confiance_ml":  ml_confidence,
    "anomalie_if":   anomaly_score,
    "couleur":       severity,
    "explication":   explanation,
})
```

---

## 6. Service management cheat sheet

```bash
sudo systemctl status postgresql clickhouse-server elasticsearch kibana influxdb
sudo systemctl restart postgresql
sudo systemctl stop elasticsearch        # free up 1 GB RAM
sudo systemctl disable elasticsearch     # don't start on boot
sudo journalctl -u clickhouse-server -n 50 --no-pager
```

Web consoles:
- **Kibana**  → http://`<vm-ip>`:5601
- **InfluxDB**→ http://`<vm-ip>`:8086
- **ClickHouse** HTTP interface → http://`<vm-ip>`:8123/play

Default credentials from the install script:
- **PostgreSQL** — user `nids`, password `nids123`, db `nids_alertes`
- **ClickHouse** — user `default`, no password
- **Elasticsearch** — dev-mode, no auth (plaintext HTTP, local only)
- **InfluxDB** — set during the first-time web wizard

Change the Postgres password:
```bash
sudo -u postgres psql -c "ALTER USER nids WITH PASSWORD '<new>';"
```

---

## 7. Which backend to pick

For your internship report, **PostgreSQL + TimescaleDB** is the sweet
spot: industry-standard, keeps SQL, adds hypertables + continuous
aggregates for free, and the dashboard reads from pre-computed
`alertes_1min` / `alertes_1hour` views so it stays fast even if you
replay a huge CICIDS2017 dataset into it.

For a research angle: install **ClickHouse too**, run the same queries
on both, and benchmark them in your report. That's a legitimate
contribution.

For a SOC-style demo: use **Elasticsearch + Kibana**. You can show
Kibana dashboards next to your Dash app and your examiners immediately
recognise the SIEM pattern (Splunk / Elastic Security / Wazuh / Zeek
all live on this stack).

**InfluxDB** is only worth running if you plan to add second-level
packet/byte-rate metrics coming straight out of `capture.py` — it will
not replace your forensic SQL store.
