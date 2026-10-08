#!/usr/bin/env python3
"""
Replays every row of nids_alertes.db into the chosen backend(s).

Usage:
    python load_from_sqlite.py                 # replays into DB_BACKEND (db_config.py)
    python load_from_sqlite.py postgres clickhouse elasticsearch
    python load_from_sqlite.py --source /path/to/other.db postgres

Backends:
    postgres | timescale | clickhouse | elasticsearch | influxdb
"""
from __future__ import annotations
import argparse
import sqlite3
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from db_adapter import (  # noqa: E402
    SqliteBackend, PostgresBackend, ClickHouseBackend,
    ElasticsearchBackend, InfluxBackend, PG, CH, ES, IX,
)


BACKEND_MAP = {
    "postgres":      lambda: PostgresBackend(timescale=False, **PG),
    "timescale":     lambda: PostgresBackend(timescale=True,  **PG),
    "clickhouse":    lambda: ClickHouseBackend(**CH),
    "elasticsearch": lambda: ElasticsearchBackend(**ES),
    "influxdb":      lambda: InfluxBackend(**IX),
}


def iter_rows(db_path: str, batch: int = 500):
    cx = sqlite3.connect(db_path)
    cx.row_factory = sqlite3.Row
    cur = cx.execute("SELECT * FROM alertes ORDER BY id")
    while True:
        chunk = cur.fetchmany(batch)
        if not chunk:
            break
        yield [dict(r) for r in chunk]
    cx.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", default="nids_alertes.db",
                   help="SQLite file to read from.")
    p.add_argument("--batch", type=int, default=500)
    p.add_argument("targets", nargs="*",
                   help="One or more backend names to load into. "
                        "Omit to use DB_BACKEND from db_config.py.")
    args = p.parse_args()

    if not Path(args.source).exists():
        sys.exit(f"Source DB not found: {args.source}")

    targets = args.targets or [__import__("db_config").DB_BACKEND]
    targets = [t for t in targets if t != "sqlite"]
    if not targets:
        sys.exit("Nothing to do: pass a target backend "
                 "or set DB_BACKEND to something other than sqlite.")

    for t in targets:
        if t not in BACKEND_MAP:
            sys.exit(f"Unknown target: {t}")

    backends = [(t, BACKEND_MAP[t]()) for t in targets]

    total_src = sqlite3.connect(args.source).execute(
        "SELECT COUNT(*) FROM alertes").fetchone()[0]
    print(f"Replaying {total_src:,} rows from {args.source}")
    print(f"→ targets: {', '.join(targets)}")

    done = 0
    t0 = time.time()
    for chunk in iter_rows(args.source, args.batch):
        for name, be in backends:
            for row in chunk:
                try:
                    be.insert(row)
                except Exception as e:
                    print(f"  [{name}] insert failed on id={row.get('id')}: {e}")
                    break
        done += len(chunk)
        print(f"  {done:>7,} / {total_src:,}  "
              f"({done / total_src * 100:.1f}%)   "
              f"{done / (time.time() - t0):.0f} rows/s",
              end="\r", flush=True)
    print()
    print(f"Done in {time.time() - t0:.1f}s.")


if __name__ == "__main__":
    main()
