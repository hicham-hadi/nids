"""
NIDS S1 — Pluggable database adapter.

Call `obtenir_backend()` to get the active backend; it exposes the same
query functions the dashboard currently calls directly against SQLite.
Switch backends by changing DB_BACKEND in db_config.py, or via the
NIDS_BACKEND environment variable.

Supported backends:
    sqlite        — the historical file (nids_alertes.db)
    postgres      — PostgreSQL (also used for timescale)
    timescale     — PostgreSQL + TimescaleDB (reads from continuous aggregates)
    clickhouse    — ClickHouse
    elasticsearch — Elasticsearch 8+
    influxdb      — InfluxDB 2 (counters only; forensic queries delegate)
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable

import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

try:
    import db_config  # user-editable config file
    DB_BACKEND = getattr(db_config, "DB_BACKEND", "sqlite")
    PG = getattr(db_config, "PG", {})
    CH = getattr(db_config, "CH", {})
    ES = getattr(db_config, "ES", {})
    IX = getattr(db_config, "IX", {})
except ModuleNotFoundError:
    DB_BACKEND = os.environ.get("NIDS_BACKEND", "sqlite")
    PG = {"host": "127.0.0.1", "port": 5432, "user": "nids",
          "password": "nids123", "dbname": "nids_alertes"}
    CH = {"host": "127.0.0.1", "port": 9000, "database": "nids"}
    ES = {"url": "http://127.0.0.1:9200", "index": "alertes"}
    IX = {"url": "http://127.0.0.1:8086", "org": "ocp", "bucket": "nids",
          "token_file": "databases/influxdb/token.txt"}


# ============================================================
# BASE INTERFACE
# ============================================================

class Backend:
    """All backends must expose this interface."""
    name = "base"

    def kpis(self) -> dict: ...
    def serie_temporelle(self) -> pd.DataFrame: ...
    def repartition_attaques(self) -> pd.DataFrame: ...
    def top_ip(self, limite: int = 5) -> pd.DataFrame: ...
    def regles_top(self, limite: int = 4) -> pd.DataFrame: ...
    def types_attaques(self) -> list[str]: ...
    def dernieres_alertes(self, limite: int = 25,
                          filtre_couleur: str | None = None,
                          filtre_type: str | None = None) -> pd.DataFrame: ...
    def rechercher(self, **kwargs) -> tuple[pd.DataFrame, int]: ...
    def insert(self, row: dict) -> None: ...


# ============================================================
# 1. SQLITE (the existing backend)
# ============================================================

class SqliteBackend(Backend):
    name = "sqlite"

    def __init__(self, path: str = "nids_alertes.db"):
        self.path = path

    def _cx(self):
        cx = sqlite3.connect(self.path, timeout=10)
        cx.execute("PRAGMA journal_mode=WAL")
        cx.row_factory = sqlite3.Row
        return cx

    def kpis(self):
        with self._cx() as cx:
            total = cx.execute("SELECT COUNT(*) FROM alertes").fetchone()[0]
            if total == 0:
                return {"total": 0, "rouge": 0, "orange": 0, "vert": 0,
                        "taux_attaque": 0.0, "ip_active": "—",
                        "derniere_alerte": "—"}
            counts = {"ROUGE": 0, "ORANGE": 0, "VERT": 0}
            for r in cx.execute(
                "SELECT couleur, COUNT(*) AS n FROM alertes GROUP BY couleur"):
                counts[r["couleur"]] = r["n"]
            ip = cx.execute(
                "SELECT ip_source FROM alertes GROUP BY ip_source "
                "ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
            last = cx.execute(
                "SELECT horodatage FROM alertes ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return {
            "total": total, "rouge": counts["ROUGE"],
            "orange": counts["ORANGE"], "vert": counts["VERT"],
            "taux_attaque": round(
                100 * (counts["ROUGE"] + counts["ORANGE"]) / total, 1),
            "ip_active": ip["ip_source"] if ip else "—",
            "derniere_alerte": last["horodatage"] if last else "—",
        }

    def serie_temporelle(self):
        q = ("SELECT strftime('%Y-%m-%dT%H:%M:00', horodatage) AS minute, "
             "couleur, COUNT(*) AS nombre FROM alertes "
             "GROUP BY minute, couleur ORDER BY minute")
        with self._cx() as cx:
            return pd.read_sql_query(q, cx)

    def repartition_attaques(self):
        q = ("SELECT verdict_regle, COUNT(*) AS nombre FROM alertes "
             "WHERE verdict_regle != 'NORMAL' GROUP BY verdict_regle "
             "ORDER BY nombre DESC")
        with self._cx() as cx:
            return pd.read_sql_query(q, cx)

    def top_ip(self, limite=5):
        with self._cx() as cx:
            return pd.read_sql_query(
                "SELECT ip_source, COUNT(*) AS nombre FROM alertes "
                "GROUP BY ip_source ORDER BY nombre DESC LIMIT ?",
                cx, params=[limite])

    def regles_top(self, limite=4):
        with self._cx() as cx:
            return pd.read_sql_query(
                "SELECT verdict_regle, COUNT(*) AS nombre FROM alertes "
                "WHERE verdict_regle != 'NORMAL' GROUP BY verdict_regle "
                "ORDER BY nombre DESC LIMIT ?", cx, params=[limite])

    def types_attaques(self):
        with self._cx() as cx:
            return [r[0] for r in cx.execute(
                "SELECT DISTINCT verdict_regle FROM alertes "
                "WHERE verdict_regle != 'NORMAL' ORDER BY verdict_regle"
            )]

    def dernieres_alertes(self, limite=25, filtre_couleur=None,
                          filtre_type=None):
        conds, params = [], []
        if filtre_couleur:
            conds.append("couleur = ?"); params.append(filtre_couleur)
        if filtre_type:
            conds.append("verdict_regle = ?"); params.append(filtre_type)
        q = ("SELECT * FROM alertes "
             + (" WHERE " + " AND ".join(conds) if conds else "")
             + " ORDER BY id DESC LIMIT ?")
        with self._cx() as cx:
            return pd.read_sql_query(q, cx, params=params + [limite])

    def rechercher(self, ip=None, couleur=None, type_attaque=None,
                   date_debut=None, date_fin=None,
                   page=0, taille_page=20):
        conds, params = [], []
        if ip:
            conds.append("(ip_source LIKE ? OR ip_dest LIKE ?)")
            params.extend([f"%{ip}%", f"%{ip}%"])
        if couleur:
            conds.append("couleur = ?"); params.append(couleur)
        if type_attaque:
            conds.append("verdict_regle = ?"); params.append(type_attaque)
        if date_debut:
            conds.append("horodatage >= ?"); params.append(date_debut)
        if date_fin:
            conds.append("horodatage <= ?"); params.append(date_fin + "T23:59:59")
        where = " WHERE " + " AND ".join(conds) if conds else ""
        with self._cx() as cx:
            total = cx.execute(
                f"SELECT COUNT(*) FROM alertes{where}", params).fetchone()[0]
            df = pd.read_sql_query(
                f"SELECT * FROM alertes{where} ORDER BY id DESC "
                f"LIMIT ? OFFSET ?",
                cx, params=params + [taille_page, page * taille_page])
        return df, total

    def insert(self, row):
        cols = ",".join(row.keys())
        qs = ",".join("?" * len(row))
        with self._cx() as cx:
            cx.execute(f"INSERT INTO alertes ({cols}) VALUES ({qs})",
                       list(row.values()))
            cx.commit()


# ============================================================
# 2. POSTGRESQL (and TimescaleDB — same driver, different reads)
# ============================================================

class PostgresBackend(Backend):
    name = "postgres"

    def __init__(self, timescale: bool = False, **conn):
        try:
            import psycopg2  # noqa
            self._pg = __import__("psycopg2")
            self._pg_extras = __import__("psycopg2.extras").extras
        except ImportError as e:
            raise RuntimeError(
                "psycopg2-binary not installed. Run: "
                "pip install psycopg2-binary") from e
        self.conn = {**{"host": "127.0.0.1", "port": 5432,
                        "user": "nids", "password": "nids123",
                        "dbname": "nids_alertes"}, **conn}
        self.timescale = timescale

    def _cx(self):
        return self._pg.connect(**self.conn)

    def _df(self, q, params=None):
        with self._cx() as cx:
            return pd.read_sql_query(q, cx, params=params)

    def kpis(self):
        total = self._df("SELECT COUNT(*) AS n FROM alertes")["n"].iloc[0]
        if total == 0:
            return {"total": 0, "rouge": 0, "orange": 0, "vert": 0,
                    "taux_attaque": 0.0, "ip_active": "—",
                    "derniere_alerte": "—"}
        counts = {"ROUGE": 0, "ORANGE": 0, "VERT": 0}
        for _, r in self._df(
                "SELECT couleur, COUNT(*) AS n FROM alertes "
                "GROUP BY couleur").iterrows():
            counts[r["couleur"]] = int(r["n"])
        ip = self._df(
            "SELECT ip_source FROM alertes GROUP BY ip_source "
            "ORDER BY COUNT(*) DESC LIMIT 1")
        last = self._df(
            "SELECT horodatage FROM alertes ORDER BY horodatage DESC LIMIT 1")
        return {
            "total": int(total),
            "rouge": counts["ROUGE"], "orange": counts["ORANGE"],
            "vert": counts["VERT"],
            "taux_attaque": round(
                100 * (counts["ROUGE"] + counts["ORANGE"]) / int(total), 1),
            "ip_active": (str(ip["ip_source"].iloc[0])
                          if not ip.empty else "—"),
            "derniere_alerte": (str(last["horodatage"].iloc[0])
                                if not last.empty else "—"),
        }

    def serie_temporelle(self):
        # TimescaleDB: use the continuous aggregate for speed.
        if self.timescale:
            q = ("SELECT bucket AS minute, couleur, nombre "
                 "FROM alertes_1min ORDER BY bucket")
            try:
                return self._df(q)
            except Exception:
                pass  # Fall through to the ad-hoc GROUP BY.
        return self._df(
            "SELECT date_trunc('minute', horodatage) AS minute, "
            "couleur, COUNT(*) AS nombre FROM alertes "
            "GROUP BY 1,2 ORDER BY 1")

    def repartition_attaques(self):
        return self._df(
            "SELECT verdict_regle, COUNT(*) AS nombre FROM alertes "
            "WHERE verdict_regle <> 'NORMAL' GROUP BY verdict_regle "
            "ORDER BY nombre DESC")

    def top_ip(self, limite=5):
        return self._df(
            "SELECT ip_source::text AS ip_source, COUNT(*) AS nombre "
            "FROM alertes GROUP BY ip_source ORDER BY nombre DESC LIMIT %s",
            [limite])

    def regles_top(self, limite=4):
        return self._df(
            "SELECT verdict_regle, COUNT(*) AS nombre FROM alertes "
            "WHERE verdict_regle <> 'NORMAL' GROUP BY verdict_regle "
            "ORDER BY nombre DESC LIMIT %s", [limite])

    def types_attaques(self):
        return self._df(
            "SELECT DISTINCT verdict_regle FROM alertes "
            "WHERE verdict_regle <> 'NORMAL' ORDER BY verdict_regle"
        )["verdict_regle"].tolist()

    def dernieres_alertes(self, limite=25, filtre_couleur=None,
                          filtre_type=None):
        conds, params = [], []
        if filtre_couleur:
            conds.append("couleur = %s"); params.append(filtre_couleur)
        if filtre_type:
            conds.append("verdict_regle = %s"); params.append(filtre_type)
        q = ("SELECT * FROM alertes"
             + (" WHERE " + " AND ".join(conds) if conds else "")
             + " ORDER BY id DESC LIMIT %s")
        return self._df(q, params + [limite])

    def rechercher(self, ip=None, couleur=None, type_attaque=None,
                   date_debut=None, date_fin=None,
                   page=0, taille_page=20):
        conds, params = [], []
        if ip:
            conds.append("(host(ip_source) LIKE %s OR host(ip_dest) LIKE %s)")
            params.extend([f"%{ip}%", f"%{ip}%"])
        if couleur:
            conds.append("couleur = %s"); params.append(couleur)
        if type_attaque:
            conds.append("verdict_regle = %s"); params.append(type_attaque)
        if date_debut:
            conds.append("horodatage >= %s"); params.append(date_debut)
        if date_fin:
            conds.append("horodatage <= %s")
            params.append(date_fin + "T23:59:59")
        where = " WHERE " + " AND ".join(conds) if conds else ""
        total = int(self._df(
            f"SELECT COUNT(*) AS n FROM alertes{where}", params
        )["n"].iloc[0])
        df = self._df(
            f"SELECT * FROM alertes{where} ORDER BY id DESC "
            f"LIMIT %s OFFSET %s",
            params + [taille_page, page * taille_page])
        return df, total

    def insert(self, row):
        cols = ",".join(row.keys())
        placeholders = ",".join(["%s"] * len(row))
        with self._cx() as cx, cx.cursor() as cur:
            cur.execute(
                f"INSERT INTO alertes ({cols}) VALUES ({placeholders})",
                list(row.values()))
            cx.commit()


# ============================================================
# 3. CLICKHOUSE
# ============================================================

class ClickHouseBackend(Backend):
    name = "clickhouse"

    def __init__(self, **conn):
        try:
            from clickhouse_driver import Client
        except ImportError as e:
            raise RuntimeError(
                "clickhouse-driver not installed. Run: "
                "pip install clickhouse-driver") from e
        c = {**{"host": "127.0.0.1", "port": 9000, "database": "nids"},
             **conn}
        self.client = Client(**c)

    def _df(self, q, params=None):
        rows, cols = self.client.execute(q, params or {},
                                         with_column_types=True)
        return pd.DataFrame(rows, columns=[c[0] for c in cols])

    def kpis(self):
        total = self._df("SELECT count() AS n FROM alertes")["n"].iloc[0]
        if total == 0:
            return {"total": 0, "rouge": 0, "orange": 0, "vert": 0,
                    "taux_attaque": 0.0, "ip_active": "—",
                    "derniere_alerte": "—"}
        counts = {"ROUGE": 0, "ORANGE": 0, "VERT": 0}
        for _, r in self._df(
                "SELECT couleur, count() AS n FROM alertes "
                "GROUP BY couleur").iterrows():
            counts[r["couleur"]] = int(r["n"])
        ip = self._df(
            "SELECT ip_source FROM alertes GROUP BY ip_source "
            "ORDER BY count() DESC LIMIT 1")
        last = self._df(
            "SELECT horodatage FROM alertes ORDER BY horodatage DESC LIMIT 1")
        return {
            "total": int(total),
            "rouge": counts["ROUGE"], "orange": counts["ORANGE"],
            "vert": counts["VERT"],
            "taux_attaque": round(
                100 * (counts["ROUGE"] + counts["ORANGE"]) / int(total), 1),
            "ip_active": (str(ip["ip_source"].iloc[0])
                          if not ip.empty else "—"),
            "derniere_alerte": (str(last["horodatage"].iloc[0])
                                if not last.empty else "—"),
        }

    def serie_temporelle(self):
        return self._df(
            "SELECT bucket AS minute, couleur, nombre FROM alertes_1min "
            "ORDER BY bucket")

    def repartition_attaques(self):
        return self._df(
            "SELECT verdict_regle, count() AS nombre FROM alertes "
            "WHERE verdict_regle <> 'NORMAL' GROUP BY verdict_regle "
            "ORDER BY nombre DESC")

    def top_ip(self, limite=5):
        return self._df(
            f"SELECT ip_source, count() AS nombre FROM alertes "
            f"GROUP BY ip_source ORDER BY nombre DESC LIMIT {int(limite)}")

    def regles_top(self, limite=4):
        return self._df(
            f"SELECT verdict_regle, count() AS nombre FROM alertes "
            f"WHERE verdict_regle <> 'NORMAL' GROUP BY verdict_regle "
            f"ORDER BY nombre DESC LIMIT {int(limite)}")

    def types_attaques(self):
        return self._df(
            "SELECT DISTINCT verdict_regle FROM alertes "
            "WHERE verdict_regle <> 'NORMAL'"
        )["verdict_regle"].tolist()

    def dernieres_alertes(self, limite=25, filtre_couleur=None,
                          filtre_type=None):
        where = []
        if filtre_couleur:
            where.append(f"couleur = '{filtre_couleur}'")
        if filtre_type:
            where.append(f"verdict_regle = '{filtre_type}'")
        q = ("SELECT * FROM alertes "
             + ("WHERE " + " AND ".join(where) + " " if where else "")
             + f"ORDER BY horodatage DESC LIMIT {int(limite)}")
        return self._df(q)

    def rechercher(self, ip=None, couleur=None, type_attaque=None,
                   date_debut=None, date_fin=None,
                   page=0, taille_page=20):
        where = []
        if ip:
            where.append(
                f"(ip_source LIKE '%{ip}%' OR ip_dest LIKE '%{ip}%')")
        if couleur:
            where.append(f"couleur = '{couleur}'")
        if type_attaque:
            where.append(f"verdict_regle = '{type_attaque}'")
        if date_debut:
            where.append(f"horodatage >= '{date_debut}'")
        if date_fin:
            where.append(f"horodatage <= '{date_fin} 23:59:59'")
        w = ("WHERE " + " AND ".join(where) + " ") if where else ""
        total = int(self._df(
            f"SELECT count() AS n FROM alertes {w}")["n"].iloc[0])
        df = self._df(
            f"SELECT * FROM alertes {w} ORDER BY horodatage DESC "
            f"LIMIT {int(taille_page)} OFFSET {int(page * taille_page)}")
        return df, total

    def insert(self, row):
        cols = list(row.keys())
        self.client.execute(
            f"INSERT INTO alertes ({','.join(cols)}) VALUES",
            [row])


# ============================================================
# 4. ELASTICSEARCH
# ============================================================

class ElasticsearchBackend(Backend):
    name = "elasticsearch"

    def __init__(self, url="http://127.0.0.1:9200", index="alertes"):
        try:
            from elasticsearch import Elasticsearch
        except ImportError as e:
            raise RuntimeError(
                "elasticsearch client not installed. Run: "
                "pip install 'elasticsearch>=8,<9'") from e
        self.es = Elasticsearch(url, request_timeout=10)
        self.idx = index

    def _hits_to_df(self, body):
        res = self.es.search(index=self.idx, body=body, size=0)
        return res

    def kpis(self):
        total = self.es.count(index=self.idx)["count"]
        if total == 0:
            return {"total": 0, "rouge": 0, "orange": 0, "vert": 0,
                    "taux_attaque": 0.0, "ip_active": "—",
                    "derniere_alerte": "—"}
        agg = self.es.search(index=self.idx, size=0, body={
            "aggs": {
                "by_couleur":  {"terms": {"field": "couleur", "size": 3}},
                "top_src":     {"terms": {"field": "ip_source",
                                          "size": 1}},
                "last":        {"max":   {"field": "horodatage"}},
            }
        })
        counts = {"ROUGE": 0, "ORANGE": 0, "VERT": 0}
        for b in agg["aggregations"]["by_couleur"]["buckets"]:
            counts[b["key"]] = b["doc_count"]
        top = agg["aggregations"]["top_src"]["buckets"]
        last_ms = agg["aggregations"]["last"]["value"]
        last_str = (pd.to_datetime(last_ms, unit="ms").isoformat()
                    if last_ms else "—")
        return {
            "total": total, "rouge": counts["ROUGE"],
            "orange": counts["ORANGE"], "vert": counts["VERT"],
            "taux_attaque": round(
                100 * (counts["ROUGE"] + counts["ORANGE"]) / total, 1),
            "ip_active": top[0]["key"] if top else "—",
            "derniere_alerte": last_str,
        }

    def serie_temporelle(self):
        res = self.es.search(index=self.idx, size=0, body={
            "aggs": {
                "per_min": {
                    "date_histogram": {"field": "horodatage",
                                       "fixed_interval": "1m"},
                    "aggs": {"by_c": {"terms": {"field": "couleur"}}}
                }
            }
        })
        rows = []
        for b in res["aggregations"]["per_min"]["buckets"]:
            for c in b["by_c"]["buckets"]:
                rows.append({"minute": b["key_as_string"],
                             "couleur": c["key"],
                             "nombre": c["doc_count"]})
        return pd.DataFrame(rows, columns=["minute", "couleur", "nombre"])

    def repartition_attaques(self):
        res = self.es.search(index=self.idx, size=0, body={
            "query": {"bool": {"must_not": {"term": {"verdict_regle":
                                                     "NORMAL"}}}},
            "aggs": {"t": {"terms": {"field": "verdict_regle",
                                     "size": 20}}}
        })
        rows = [{"verdict_regle": b["key"], "nombre": b["doc_count"]}
                for b in res["aggregations"]["t"]["buckets"]]
        return pd.DataFrame(rows, columns=["verdict_regle", "nombre"])

    def top_ip(self, limite=5):
        res = self.es.search(index=self.idx, size=0, body={
            "aggs": {"i": {"terms": {"field": "ip_source", "size": limite}}}})
        return pd.DataFrame(
            [{"ip_source": b["key"], "nombre": b["doc_count"]}
             for b in res["aggregations"]["i"]["buckets"]])

    def regles_top(self, limite=4):
        res = self.es.search(index=self.idx, size=0, body={
            "query": {"bool": {"must_not": {"term": {"verdict_regle":
                                                     "NORMAL"}}}},
            "aggs": {"r": {"terms": {"field": "verdict_regle",
                                     "size": limite}}}})
        return pd.DataFrame(
            [{"verdict_regle": b["key"], "nombre": b["doc_count"]}
             for b in res["aggregations"]["r"]["buckets"]])

    def types_attaques(self):
        res = self.es.search(index=self.idx, size=0, body={
            "query": {"bool": {"must_not": {"term": {"verdict_regle":
                                                     "NORMAL"}}}},
            "aggs": {"t": {"terms": {"field": "verdict_regle", "size": 50}}}})
        return [b["key"] for b in res["aggregations"]["t"]["buckets"]]

    def dernieres_alertes(self, limite=25, filtre_couleur=None,
                          filtre_type=None):
        must = []
        if filtre_couleur:
            must.append({"term": {"couleur": filtre_couleur}})
        if filtre_type:
            must.append({"term": {"verdict_regle": filtre_type}})
        q = {"bool": {"must": must}} if must else {"match_all": {}}
        res = self.es.search(index=self.idx, size=limite,
                             sort=[{"horodatage": "desc"}],
                             query=q)
        return pd.DataFrame([h["_source"] for h in res["hits"]["hits"]])

    def rechercher(self, ip=None, couleur=None, type_attaque=None,
                   date_debut=None, date_fin=None,
                   page=0, taille_page=20):
        must = []
        if ip:
            must.append({"bool": {"should": [
                {"term": {"ip_source": ip}},
                {"term": {"ip_dest": ip}}]}})
        if couleur: must.append({"term": {"couleur": couleur}})
        if type_attaque: must.append({"term": {"verdict_regle": type_attaque}})
        if date_debut or date_fin:
            r = {}
            if date_debut: r["gte"] = date_debut
            if date_fin: r["lte"] = date_fin + "T23:59:59"
            must.append({"range": {"horodatage": r}})
        q = {"bool": {"must": must}} if must else {"match_all": {}}
        total = self.es.count(index=self.idx, query=q)["count"]
        res = self.es.search(index=self.idx, from_=page * taille_page,
                             size=taille_page,
                             sort=[{"horodatage": "desc"}],
                             query=q)
        df = pd.DataFrame([h["_source"] for h in res["hits"]["hits"]])
        return df, total

    def insert(self, row):
        self.es.index(index=self.idx, document=row)


# ============================================================
# 5. INFLUXDB (counters only; delegates forensic queries)
# ============================================================

class InfluxBackend(Backend):
    """
    InfluxDB stores counters (per-second, per-minute aggregates).
    For forensic/table queries it falls back to a secondary backend
    (default: SQLite file). Pass `fallback=` to override.
    """
    name = "influxdb"

    def __init__(self, url="http://127.0.0.1:8086",
                 org="ocp", bucket="nids",
                 token_file="databases/influxdb/token.txt",
                 fallback: Backend | None = None):
        try:
            from influxdb_client import InfluxDBClient, Point
        except ImportError as e:
            raise RuntimeError(
                "influxdb-client not installed. Run: "
                "pip install influxdb-client") from e
        try:
            token = Path(token_file).read_text().strip()
        except FileNotFoundError:
            raise RuntimeError(
                f"InfluxDB token file not found: {token_file}\n"
                "Follow databases/influxdb/setup.md first.")
        self._mod_point = Point
        self.client = InfluxDBClient(url=url, token=token, org=org)
        self.query_api = self.client.query_api()
        self.write_api = self.client.write_api()
        self.org = org
        self.bucket = bucket
        self.fallback = fallback or SqliteBackend()

    # Forensic queries → delegate to the SQL fallback.
    def kpis(self):                    return self.fallback.kpis()
    def repartition_attaques(self):    return self.fallback.repartition_attaques()
    def top_ip(self, limite=5):        return self.fallback.top_ip(limite)
    def regles_top(self, limite=4):    return self.fallback.regles_top(limite)
    def types_attaques(self):          return self.fallback.types_attaques()
    def dernieres_alertes(self, **kw): return self.fallback.dernieres_alertes(**kw)
    def rechercher(self, **kw):        return self.fallback.rechercher(**kw)

    # Time-series query → Influx (fast).
    def serie_temporelle(self):
        flux = (
            f'from(bucket:"{self.bucket}") '
            f'|> range(start: -2h) '
            f'|> filter(fn: (r) => r._measurement == "alerte") '
            f'|> group(columns: ["couleur"]) '
            f'|> aggregateWindow(every: 1m, fn: count, createEmpty: false) '
            f'|> yield(name: "per_min")')
        tables = self.query_api.query(flux, org=self.org)
        rows = []
        for t in tables:
            for rec in t.records:
                rows.append({"minute": rec.get_time().isoformat(),
                             "couleur": rec.values.get("couleur", ""),
                             "nombre": int(rec.get_value() or 0)})
        return pd.DataFrame(rows, columns=["minute", "couleur", "nombre"])

    def insert(self, row):
        p = (self._mod_point("alerte")
             .tag("couleur", row.get("couleur", ""))
             .tag("verdict_regle", row.get("verdict_regle", ""))
             .tag("verdict_ml", row.get("verdict_ml", ""))
             .field("ip_source", str(row.get("ip_source", "")))
             .field("ip_dest", str(row.get("ip_dest", "")))
             .field("port_dest", int(row.get("port_dest") or 0))
             .field("nb_paquets", int(row.get("nb_paquets") or 0))
             .field("nb_octets", int(row.get("nb_octets") or 0))
             .field("debit", float(row.get("debit") or 0))
             .field("confiance_ml", float(row.get("confiance_ml") or 0))
             .time(row.get("horodatage")))
        self.write_api.write(bucket=self.bucket, org=self.org, record=p)
        # Also persist the full row to the SQL fallback for forensics.
        try:
            self.fallback.insert(row)
        except Exception:
            pass


# ============================================================
# FACTORY
# ============================================================

_BACKEND = None


def obtenir_backend() -> Backend:
    global _BACKEND
    if _BACKEND is not None:
        return _BACKEND
    name = (DB_BACKEND or "sqlite").lower()
    if name == "sqlite":
        _BACKEND = SqliteBackend()
    elif name == "postgres":
        _BACKEND = PostgresBackend(timescale=False, **PG)
    elif name == "timescale":
        _BACKEND = PostgresBackend(timescale=True, **PG)
    elif name == "clickhouse":
        _BACKEND = ClickHouseBackend(**CH)
    elif name == "elasticsearch":
        _BACKEND = ElasticsearchBackend(**ES)
    elif name == "influxdb":
        _BACKEND = InfluxBackend(**IX)
    else:
        raise ValueError(f"Unknown DB backend: {name!r}")
    return _BACKEND


if __name__ == "__main__":
    import json
    print(f"Active backend: {DB_BACKEND}")
    b = obtenir_backend()
    print(json.dumps(b.kpis(), indent=2, default=str))
