"""Elasticsearch client wrapper for passsage metadata storage.

Thread-local Elasticsearch client (same pattern as get_s3_client in proxy.py),
plus a LastAccessBatcher that batches last_access updates via periodic bulk writes.
"""

import logging
import threading
from datetime import datetime, timezone

LOG = logging.getLogger("passsage.proxy")

_tls = threading.local()

_es_url: str = ""
_es_request_timeout: float = 5.0


def configure(elasticsearch_url: str, request_timeout: float = 5.0) -> None:
    """Set the global ES URL. Must be called before any client usage."""
    global _es_url, _es_request_timeout
    _es_url = elasticsearch_url
    _es_request_timeout = request_timeout


def _get_es_client():
    """Return a thread-local Elasticsearch client instance."""
    if hasattr(_tls, "es"):
        return _tls.es
    from elasticsearch9 import Elasticsearch

    _tls.es = Elasticsearch(_es_url, request_timeout=_es_request_timeout)
    return _tls.es


def es_get_doc(index: str, doc_id: str) -> dict | None:
    """GET _doc/{id} -- real-time, no refresh needed. Returns _source or None."""
    es = _get_es_client()
    try:
        resp = es.get(index=index, id=doc_id, source=True)
        return resp.get("_source") or resp.body.get("_source")
    except Exception as exc:
        if _is_not_found(exc):
            return None
        raise


def es_index_doc(index: str, doc_id: str, body: dict) -> None:
    """PUT _doc/{id} -- index (create or overwrite) a document."""
    es = _get_es_client()
    es.index(index=index, id=doc_id, document=body)


def es_create_index(index: str, body: dict) -> None:
    """Idempotent index creation. Ignores 'resource_already_exists_exception'."""
    es = _get_es_client()
    try:
        es.indices.create(index=index, body=body)
        LOG.info("Created ES index %s", index)
    except Exception as exc:
        if "resource_already_exists_exception" in str(exc).lower():
            LOG.debug("ES index %s already exists", index)
        else:
            raise


def es_delete_doc(index: str, doc_id: str) -> bool:
    """Delete a document. Returns True if deleted, False if not found."""
    es = _get_es_client()
    try:
        es.delete(index=index, id=doc_id)
        return True
    except Exception as exc:
        if _is_not_found(exc):
            return False
        raise


def _is_not_found(exc: Exception) -> bool:
    err_str = str(exc).lower()
    if "notfounderror" in type(exc).__name__.lower():
        return True
    if "404" in err_str or "not_found" in err_str:
        return True
    status = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "info", None), "status", None
    )
    return status == 404


class LastAccessBatcher:
    """Batched, non-blocking last_access timestamp updates.

    Proxy request threads call touch() which is a fast dict write under a lock.
    A background daemon thread periodically flushes accumulated timestamps via
    the ES bulk API using a lock+swap ("double buffer") pattern.
    """

    def __init__(self, es_index: str, flush_interval: float = 30.0):
        self._lock = threading.Lock()
        self._pending: dict[str, str] = {}
        self._index = es_index
        self._flush_interval = flush_interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def touch(self, doc_id: str) -> None:
        """Record a cache access. O(1), minimal lock contention."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._pending[doc_id] = now

    def _run(self) -> None:
        while not self._stop.wait(self._flush_interval):
            self._flush()

    def _flush(self) -> None:
        with self._lock:
            batch, self._pending = self._pending, {}
        if not batch:
            return
        actions: list[dict] = []
        for doc_id, ts in batch.items():
            actions.append({"update": {"_index": self._index, "_id": doc_id}})
            actions.append({"doc": {"last_access": ts}})
        try:
            es = _get_es_client()
            es.bulk(operations=actions, refresh=False)
        except Exception:
            LOG.warning("bulk last_access update failed", exc_info=True)

    def shutdown(self) -> None:
        """Stop the background thread and do a final flush."""
        self._stop.set()
        self._flush()
