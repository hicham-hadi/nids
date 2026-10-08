"""
NIDS S1 — Database adapter configuration.

Change DB_BACKEND to switch which database the dashboard reads from:

    "sqlite"        — nids_alertes.db file in the project folder (default)
    "postgres"      — plain PostgreSQL
    "timescale"     — PostgreSQL with the TimescaleDB extension
    "clickhouse"    — ClickHouse
    "elasticsearch" — Elasticsearch 8+
    "influxdb"      — InfluxDB 2 (counters) + SQLite fallback for forensics
"""

DB_BACKEND = "sqlite"

PG = {
    "host":     "127.0.0.1",
    "port":     5432,
    "user":     "nids",
    "password": "nids123",
    "dbname":   "nids_alertes",
}

CH = {
    "host":     "127.0.0.1",
    "port":     9000,
    "database": "nids",
}

ES = {
    "url":   "http://127.0.0.1:9200",
    "index": "alertes",
}

IX = {
    "url":        "http://127.0.0.1:8086",
    "org":        "ocp",
    "bucket":     "nids",
    "token_file": "databases/influxdb/token.txt",
}
