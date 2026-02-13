import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import pyarrow as pa
import pyarrow.parquet as pq


def _parse_bytes(value: str, default: int) -> int:
    raw = (value or "").strip().lower()
    if not raw:
        return default
    multipliers = {
        "k": 1024,
        "kb": 1024,
        "m": 1024 ** 2,
        "mb": 1024 ** 2,
        "g": 1024 ** 3,
        "gb": 1024 ** 3,
    }
    for suffix, mult in multipliers.items():
        if raw.endswith(suffix):
            num = raw[: -len(suffix)].strip()
            try:
                return int(float(num) * mult)
            except ValueError:
                return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass
class AccessLogConfig:
    bucket: str
    prefix: str
    spool_dir: str
    flush_seconds: int
    flush_bytes: int
    compression: str = "snappy"


class AccessLogWriter:
    def __init__(self, s3_client, config: AccessLogConfig, logger):
        self._s3 = s3_client
        self._config = config
        self._logger = logger
        self._lock = threading.Lock()
        self._buffer: list[dict] = []
        self._buffer_bytes = 0
        self._last_flush = time.time()
        self._stop_event = threading.Event()
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        os.makedirs(self._config.spool_dir, exist_ok=True)
        self._schema = pa.schema(
            [
                ("timestamp", pa.timestamp("ms", tz="UTC")),
                ("request_id", pa.string()),
                ("client_ip", pa.string()),
                ("client_port", pa.int32()),
                ("method", pa.string()),
                ("url", pa.string()),
                ("host", pa.string()),
                ("scheme", pa.string()),
                ("port", pa.int32()),
                ("path", pa.string()),
                ("query", pa.string()),
                ("user_agent", pa.string()),
                ("request_headers", pa.map_(pa.string(), pa.string())),
                ("status_code", pa.int32()),
                ("reason", pa.string()),
                ("response_headers", pa.map_(pa.string(), pa.string())),
                ("content_length", pa.int64()),
                ("content_type", pa.string()),
                ("content_encoding", pa.string()),
                ("policy", pa.string()),
                ("cached", pa.bool_()),
                ("cache_redirect", pa.bool_()),
                ("cache_key", pa.string()),
                ("cache_vary", pa.string()),
                ("cache_hit", pa.bool_()),
                ("cache_fresh", pa.bool_()),
                ("stale_while_revalidate", pa.bool_()),
                ("stale_if_error", pa.bool_()),
                ("upstream_head_status", pa.int32()),
                ("upstream_error", pa.string()),
                ("upstream_head_time_ms", pa.int64()),
                ("cache_head_status", pa.int32()),
                ("cache_head_etag", pa.string()),
                ("cache_head_last_modified", pa.string()),
                ("cache_head_method", pa.string()),
                ("serve_reason", pa.string()),
                ("error", pa.string()),
                ("duration_ms", pa.int64()),
                ("bytes_sent", pa.int64()),
            ]
        )

    def start(self) -> None:
        if not self._flush_thread.is_alive():
            self._flush_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._flush_thread.join(timeout=5)
        self.flush()

    def add(self, record: dict) -> None:
        now = time.time()
        encoded = json.dumps(record, default=str).encode("utf-8")
        with self._lock:
            self._buffer.append(record)
            self._buffer_bytes += len(encoded)
            should_flush = self._buffer_bytes >= self._config.flush_bytes
            if not should_flush and (now - self._last_flush) >= self._config.flush_seconds:
                should_flush = True
        if should_flush:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            records = self._buffer
            self._buffer = []
            self._buffer_bytes = 0
            self._last_flush = time.time()
        try:
            self._write_records(records)
        except Exception as exc:
            self._logger.error("Access log flush failed: %s", exc)

    def _flush_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(self._config.flush_seconds)
            if self._stop_event.is_set():
                break
            self.flush()

    def _write_records(self, records: list[dict]) -> None:
        if not records:
            return
        ts = records[-1].get("timestamp")
        if isinstance(ts, datetime):
            dt = ts.astimezone(timezone.utc)
        else:
            dt = datetime.now(tz=timezone.utc)
        date_part = dt.strftime("%Y-%m-%d")
        hour_part = dt.strftime("%H")
        rel_dir = os.path.join(f"date={date_part}", f"hour={hour_part}")
        local_dir = os.path.join(self._config.spool_dir, rel_dir)
        os.makedirs(local_dir, exist_ok=True)
        filename = f"{dt.strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex}.parquet"
        local_path = os.path.join(local_dir, filename)
        table = pa.Table.from_pylist(records, schema=self._schema)
        pq.write_table(
            table,
            local_path,
            compression=self._config.compression,
            use_dictionary=True,
            write_statistics=True,
        )
        s3_key = "/".join(
            [
                self._config.prefix.strip("/"),
                rel_dir.replace(os.sep, "/"),
                filename,
            ]
        )
        self._s3.upload_file(local_path, self._config.bucket, s3_key)
        try:
            os.remove(local_path)
        except OSError:
            pass


class ErrorLogWriter(AccessLogWriter):
    def __init__(self, s3_client, config: AccessLogConfig, logger):
        super().__init__(s3_client, config, logger)
        self._schema = pa.schema(
            [
                ("timestamp", pa.timestamp("ms", tz="UTC")),
                ("request_id", pa.string()),
                ("client_ip", pa.string()),
                ("client_port", pa.int32()),
                ("method", pa.string()),
                ("url", pa.string()),
                ("host", pa.string()),
                ("scheme", pa.string()),
                ("port", pa.int32()),
                ("path", pa.string()),
                ("query", pa.string()),
                ("user_agent", pa.string()),
                ("request_headers", pa.map_(pa.string(), pa.string())),
                ("status_code", pa.int32()),
                ("response_headers", pa.map_(pa.string(), pa.string())),
                ("policy", pa.string()),
                ("cached", pa.bool_()),
                ("cache_redirect", pa.bool_()),
                ("cache_key", pa.string()),
                ("cache_vary", pa.string()),
                ("cache_head_status", pa.int32()),
                ("upstream_head_status", pa.int32()),
                ("upstream_error", pa.string()),
                ("error_type", pa.string()),
                ("error_message", pa.string()),
                ("traceback", pa.string()),
                ("context", pa.string()),
            ]
        )


def build_access_log_config(bucket: str, prefix: str, spool_dir: str, flush_seconds: str, flush_bytes: str) -> AccessLogConfig:
    interval = int(flush_seconds) if str(flush_seconds).strip() else 30
    size = _parse_bytes(str(flush_bytes), 1024 ** 3)
    return AccessLogConfig(
        bucket=bucket,
        prefix=prefix,
        spool_dir=spool_dir,
        flush_seconds=max(1, interval),
        flush_bytes=max(1024, size),
    )


def build_error_log_config(bucket: str, prefix: str, spool_dir: str, flush_seconds: str, flush_bytes: str) -> AccessLogConfig:
    return build_access_log_config(bucket, prefix, spool_dir, flush_seconds, flush_bytes)
