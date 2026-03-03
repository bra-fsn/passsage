"""FoundationDB client wrapper for passsage metadata storage.

Thread-safe FoundationDB client plus a LastAccessBatcher that batches
last_access/stored_at timestamp updates via periodic FDB transactions.
"""

import logging
import struct
import threading
from datetime import datetime, timezone

import fdb
import msgpack

LOG = logging.getLogger("passsage.proxy")

PREFIX_META = b'\x01'
PREFIX_VARY = b'\x02'
PREFIX_MANIFEST = b'\x03'
PREFIX_GC = b'\x10'

SPLIT_VALUE_CHUNK = 90_000

_db = None

fdb.api_version(730)


def configure(cluster_file: str | None = None) -> None:
    """Open the FDB database. Must be called before any client usage."""
    global _db
    _db = fdb.open(cluster_file)


def _get_db():
    if _db is None:
        raise RuntimeError("FDB not configured; call configure() first")
    return _db


def _make_key(prefix: bytes, cache_key: str) -> bytes:
    return prefix + cache_key.encode("utf-8")


def _split_write(tr, key: bytes, data: bytes) -> None:
    """Write data to FDB, splitting across continuation keys if needed."""
    tr.clear_range_startswith(key)
    if len(data) <= SPLIT_VALUE_CHUNK:
        tr[key] = data
    else:
        offset = 0
        seq = 0
        while offset < len(data):
            chunk = data[offset:offset + SPLIT_VALUE_CHUNK]
            if seq == 0:
                tr[key] = chunk
            else:
                tr[key + bytes([seq - 1])] = chunk
            offset += SPLIT_VALUE_CHUNK
            seq += 1


def _split_read(tr, key: bytes) -> bytes | None:
    """Read a possibly-split value from FDB."""
    end_key = key + b'\xff'
    result = list(tr.get_range(key, end_key))
    if not result:
        return None
    if bytes(result[0].key) != key and not bytes(result[0].key).startswith(key):
        return None
    return b''.join(bytes(kv.value) for kv in result)


def fdb_get_meta(cache_key: str) -> dict | None:
    """Get metadata for a cache key. Returns deserialized dict or None."""
    db = _get_db()
    key = _make_key(PREFIX_META, cache_key)
    data = db.create_transaction().get(key).wait()
    if data is None:
        return None
    if len(data) < SPLIT_VALUE_CHUNK:
        return msgpack.unpackb(data, raw=False)
    tr = db.create_transaction()
    full = _split_read(tr, key)
    if full is None:
        return None
    return msgpack.unpackb(full, raw=False)


def fdb_mget_meta(cache_keys: list[str]) -> dict[str, dict | None]:
    """Fetch multiple metadata documents in a single transaction."""
    if not cache_keys:
        return {}
    db = _get_db()
    tr = db.create_transaction()
    futures = {}
    for ck in cache_keys:
        key = _make_key(PREFIX_META, ck)
        futures[ck] = (key, tr.get(key))
    result = {}
    for ck, (key, fut) in futures.items():
        data = fut.wait()
        if data is None:
            result[ck] = None
        else:
            try:
                result[ck] = msgpack.unpackb(bytes(data), raw=False)
            except Exception:
                result[ck] = None
    return result


def fdb_put_meta(cache_key: str, meta: dict) -> None:
    """Upsert metadata for a cache key."""
    db = _get_db()
    data = msgpack.packb(meta, use_bin_type=True)
    key = _make_key(PREFIX_META, cache_key)

    @fdb.transactional
    def do_put(tr):
        _split_write(tr, key, data)
    do_put(db)


def fdb_delete_meta(cache_key: str) -> bool:
    """Delete metadata for a cache key. Returns True."""
    db = _get_db()
    key = _make_key(PREFIX_META, cache_key)

    @fdb.transactional
    def do_delete(tr):
        tr.clear_range_startswith(key)
    do_delete(db)
    return True


def fdb_get_vary(vary_key: str) -> dict | None:
    """Get vary index entry."""
    db = _get_db()
    key = _make_key(PREFIX_VARY, vary_key)
    data = db.create_transaction().get(key).wait()
    if data is None:
        return None
    return msgpack.unpackb(bytes(data), raw=False)


def fdb_put_vary(vary_key: str, data: dict) -> None:
    """Upsert vary index entry."""
    db = _get_db()
    packed = msgpack.packb(data, use_bin_type=True)
    key = _make_key(PREFIX_VARY, vary_key)

    @fdb.transactional
    def do_put(tr):
        tr[key] = packed
    do_put(db)


def fdb_mget_docs(cache_keys: list[str]) -> dict[str, dict | None]:
    """Fetch multiple documents (metadata or vary) in a single transaction.

    Keys containing "/_vary/" get PREFIX_VARY, others get PREFIX_META.
    This matches the old es_mget_docs behavior where both metadata and vary-index
    docs lived in the same ES index.
    """
    if not cache_keys:
        return {}
    db = _get_db()
    tr = db.create_transaction()
    futures = {}
    for ck in cache_keys:
        if "/_vary/" in ck:
            key = _make_key(PREFIX_VARY, ck)
        else:
            key = _make_key(PREFIX_META, ck)
        futures[ck] = (key, tr.get(key))
    result = {}
    for ck, (key, fut) in futures.items():
        data = fut.wait()
        if data is None:
            result[ck] = None
        else:
            try:
                result[ck] = msgpack.unpackb(bytes(data), raw=False)
            except Exception:
                result[ck] = None
    return result


def _ts_to_bytes(ts_iso: str) -> bytes:
    """Convert ISO timestamp to 8-byte big-endian epoch millis."""
    dt = datetime.fromisoformat(ts_iso)
    epoch_ms = int(dt.timestamp() * 1000)
    return struct.pack(">Q", epoch_ms)


def _gc_key(ts_iso: str, cache_key: str) -> bytes:
    return PREFIX_GC + _ts_to_bytes(ts_iso) + cache_key.encode("utf-8")


class LastAccessBatcher:
    """Batched, non-blocking last_access and stored_at timestamp updates.

    Same interface as the ES version: proxy request threads call touch()
    and refresh_stored_at() which are fast dict writes under a lock.
    A background daemon thread periodically flushes via FDB transactions.
    """

    def __init__(self, flush_interval: float = 30.0):
        self._lock = threading.Lock()
        self._pending: dict[str, str] = {}
        self._pending_stored_at: dict[str, str] = {}
        self._flush_interval = flush_interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def touch(self, doc_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._pending[doc_id] = now

    def refresh_stored_at(self, doc_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._pending_stored_at[doc_id] = now

    def _run(self) -> None:
        while not self._stop.wait(self._flush_interval):
            self._flush()

    def _flush(self) -> None:
        with self._lock:
            batch, self._pending = self._pending, {}
            stored_batch, self._pending_stored_at = self._pending_stored_at, {}
        if not batch and not stored_batch:
            return
        try:
            db = _get_db()

            @fdb.transactional
            def do_flush(tr):
                for cache_key, new_ts in batch.items():
                    meta_key = _make_key(PREFIX_META, cache_key)
                    raw = tr[meta_key]
                    if raw.present():
                        meta = msgpack.unpackb(bytes(raw), raw=False)
                        old_ts = meta.get("last_access")
                        if old_ts:
                            tr.clear(_gc_key(old_ts, cache_key))
                        meta["last_access"] = new_ts
                        stored_ts = stored_batch.pop(cache_key, None)
                        if stored_ts:
                            meta["stored_at"] = stored_ts
                        tr[meta_key] = msgpack.packb(meta, use_bin_type=True)
                        tr[_gc_key(new_ts, cache_key)] = b''
                for cache_key, ts in stored_batch.items():
                    meta_key = _make_key(PREFIX_META, cache_key)
                    raw = tr[meta_key]
                    if raw.present():
                        meta = msgpack.unpackb(bytes(raw), raw=False)
                        meta["stored_at"] = ts
                        tr[meta_key] = msgpack.packb(meta, use_bin_type=True)

            do_flush(db)
        except Exception:
            LOG.warning("bulk last_access update failed", exc_info=True)

    def shutdown(self) -> None:
        self._stop.set()
        self._flush()
