from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from hashlib import sha1
from typing import Iterable
from urllib.parse import urlparse

import pyarrow.dataset as ds
import s3fs


def _parse_date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def _iter_dates(start: date, end: date):
    cur = start
    while cur <= end:
        yield cur
        cur += timedelta(days=1)


def _build_s3_filesystem():
    endpoint_url = os.environ.get("S3_ENDPOINT_URL", "").strip()
    client_kwargs = {}
    config_kwargs = {}
    use_ssl = True
    if endpoint_url:
        parsed = urlparse(endpoint_url)
        use_ssl = parsed.scheme == "https"
        client_kwargs["endpoint_url"] = endpoint_url
        config_kwargs = {"s3": {"addressing_style": "path"}}
    return s3fs.S3FileSystem(
        client_kwargs=client_kwargs or None,
        config_kwargs=config_kwargs or None,
        use_ssl=use_ssl,
    )


def _iter_parquet_paths(bucket: str, prefix: str, start: date, end: date) -> list[str]:
    fs = _build_s3_filesystem()
    base = prefix.strip("/")
    paths: list[str] = []
    for d in _iter_dates(start, end):
        date_part = d.strftime("%Y-%m-%d")
        pattern = f"{bucket}/{base}/date={date_part}/hour=*/*.parquet"
        for key in fs.glob(pattern):
            paths.append(f"s3://{key}")
    return paths


def _iter_access_log_rows(
    bucket: str,
    prefix: str,
    start: date,
    end: date,
    batch_size: int,
) -> Iterable[dict]:
    fs = _build_s3_filesystem()
    paths = _iter_parquet_paths(bucket, prefix, start, end)
    if not paths:
        return []
    dataset = ds.dataset(paths, filesystem=fs, format="parquet", partitioning="hive")
    scanner = dataset.scanner(
        columns=[
            "timestamp",
            "method",
            "url",
            "host",
            "path",
            "query",
            "cache_hit",
            "cache_head_status",
        ],
        batch_size=batch_size,
    )
    for batch in scanner.to_batches():
        for row in batch.to_pylist():
            yield row


def _normalize_host_path(row: dict) -> tuple[str | None, str | None, str | None]:
    host = row.get("host")
    path = row.get("path")
    query = row.get("query")
    if host and path is not None:
        return host, path, query
    url = row.get("url")
    if not url:
        return None, None, None
    parsed = urlparse(url)
    return parsed.hostname, parsed.path, parsed.query


@dataclass(frozen=True)
class CacheKeyCandidate:
    host: str
    param: str
    distinct_values: int
    paths: int
    misses: int


def analyze_cache_fragmentation(
    bucket: str,
    prefix: str,
    start_date: str,
    end_date: str,
    db_path: str,
    batch_size: int,
    min_distinct: int,
    min_paths: int,
    min_misses: int,
    top: int,
    reset_db: bool,
) -> list[CacheKeyCandidate]:
    if reset_db and os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA cache_size=-20000;")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS host_param_stats (
            host TEXT NOT NULL,
            param TEXT NOT NULL,
            misses INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (host, param)
        );

        CREATE TABLE IF NOT EXISTS host_param_values (
            host TEXT NOT NULL,
            param TEXT NOT NULL,
            value_hash TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (host, param, value_hash)
        );

        CREATE TABLE IF NOT EXISTS host_param_paths (
            host TEXT NOT NULL,
            param TEXT NOT NULL,
            path TEXT NOT NULL,
            PRIMARY KEY (host, param, path)
        );
        """
    )

    start = _parse_date(start_date)
    end = _parse_date(end_date)
    rows = _iter_access_log_rows(bucket, prefix, start, end, batch_size)
    if rows == []:
        return []

    insert_value = (
        "INSERT INTO host_param_values (host, param, value_hash, count) "
        "VALUES (?, ?, ?, 1) "
        "ON CONFLICT(host, param, value_hash) DO UPDATE SET count=count+1"
    )
    insert_path = (
        "INSERT OR IGNORE INTO host_param_paths (host, param, path) VALUES (?, ?, ?)"
    )
    upsert_stats = (
        "INSERT INTO host_param_stats (host, param, misses) VALUES (?, ?, 1) "
        "ON CONFLICT(host, param) DO UPDATE SET misses=misses+1"
    )

    def _hash_value(value: str) -> str:
        return sha1(value.encode("utf-8")).hexdigest()

    pending = 0
    for row in rows:
        if row.get("method") != "GET":
            continue
        if row.get("cache_hit") is True:
            continue
        host, path, query = _normalize_host_path(row)
        if not host or not path or not query:
            continue
        parts = query.split("&")
        if not parts:
            continue
        for part in parts:
            if not part:
                continue
            name, _, value = part.partition("=")
            name = name.strip().lower()
            if not name:
                continue
            conn.execute(upsert_stats, (host, name))
            conn.execute(insert_path, (host, name, path))
            conn.execute(insert_value, (host, name, _hash_value(value)))
            pending += 1
        if pending >= 5000:
            conn.commit()
            pending = 0

    if pending:
        conn.commit()

    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            s.host,
            s.param,
            COUNT(v.value_hash) AS distinct_values,
            COUNT(p.path) AS paths,
            s.misses
        FROM host_param_stats AS s
        JOIN host_param_values AS v
            ON v.host = s.host AND v.param = s.param
        JOIN host_param_paths AS p
            ON p.host = s.host AND p.param = s.param
        GROUP BY s.host, s.param
        HAVING distinct_values >= ? AND paths >= ? AND s.misses >= ?
        ORDER BY distinct_values DESC, s.misses DESC
        LIMIT ?
        """,
        (min_distinct, min_paths, min_misses, top),
    )
    candidates = [
        CacheKeyCandidate(
            host=row[0],
            param=row[1],
            distinct_values=row[2],
            paths=row[3],
            misses=row[4],
        )
        for row in cur.fetchall()
    ]
    conn.close()
    return candidates
