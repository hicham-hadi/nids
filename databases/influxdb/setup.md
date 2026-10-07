# InfluxDB 2 setup for S1

InfluxDB stores data as **points** with tags and fields. For the NIDS,
each alert becomes a point with these conventions:

| InfluxDB field | Comes from | Type |
|---|---|---|
| measurement | hardcoded `"alerte"` | — |
| tag `couleur` | couleur | low-cardinality |
| tag `verdict_regle` | verdict_regle | low-cardinality |
| tag `verdict_ml` | verdict_ml | low-cardinality |
| field `ip_source` | ip_source | string |
| field `ip_dest` | ip_dest | string |
| field `port_dest` | port_dest | integer |
| field `nb_paquets` | nb_paquets | integer |
| field `nb_octets` | nb_octets | integer |
| field `debit` | debit | float |
| field `confiance_ml` | confiance_ml | float |
| timestamp | horodatage | datetime |

## First-time setup

```bash
# 1. Open http://<vm-ip>:8086 in a browser.
# 2. Click "Get Started", create:
#      username:  nids
#      password:  nids_admin_2026
#      org:       ocp
#      bucket:    nids
# 3. On the "API Token" screen, copy the token.
# 4. Save it as plain text into:
echo '<paste-your-token-here>' > databases/influxdb/token.txt
chmod 600 databases/influxdb/token.txt
```

The `db_adapter.py` in the parent folder reads `token.txt` at startup.

## Example Flux query for the time-series chart

```flux
from(bucket: "nids")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "alerte")
  |> group(columns: ["couleur"])
  |> aggregateWindow(every: 1m, fn: count, createEmpty: false)
```

## Why InfluxDB only for metrics, not full forensics

InfluxDB is excellent at numeric time-series (packets/sec, bytes/sec, drop
rate) but **not** great at keyword search ("find every alert whose
`detail_regle` contains 'SYN flood' and whose src is in 192.168.0.0/16").
For the forensic table of the dashboard, PostgreSQL / ClickHouse /
Elasticsearch are better fits. You can run InfluxDB *alongside* them,
feeding it just the per-second counters, and have the dashboard draw
charts from Influx while reading individual alerts from Postgres.
