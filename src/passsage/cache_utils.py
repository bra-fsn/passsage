"""Pure utility functions for cache key derivation.

Shared by proxy.py (runtime) and cli.py (offline inspection).
"""

import hashlib
from urllib.parse import urlparse


def es_doc_id(normalized_url: str, vary_key: str | None = None) -> str:
    """Compute the Elasticsearch document _id for a normalized URL.

    Format: {scheme}/{host}/{sha224hex} or {scheme}/{host}/{sha224hex}+{vary_sha224}
    No S3-style hash prefix dirs, no meta/ prefix, no extension.
    """
    parsed = urlparse(normalized_url)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "unknown").lower()
    digest = hashlib.sha224(normalized_url.encode("utf-8")).hexdigest()
    if vary_key:
        return f"{scheme}/{host}/{digest}+{vary_key}"
    return f"{scheme}/{host}/{digest}"


def es_vary_index_id(normalized_url: str) -> str:
    """Compute the Elasticsearch document _id for a vary-index entry."""
    parsed = urlparse(normalized_url)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "unknown").lower()
    digest = hashlib.sha224(normalized_url.encode("utf-8")).hexdigest()
    return f"{scheme}/{host}/_vary/{digest}"


def url_ext(url: str, max_len: int = 20) -> str:
    """Extract the file extension from a URL path (e.g. '.whl', '.tar.gz')."""
    path = urlparse(url).path.rstrip("/")
    if not path:
        return ""
    last = path.rsplit("/", 1)[-1]
    dot = last.rfind(".")
    if dot < 1:
        return ""
    ext = last[dot:]
    if len(ext) > max_len or not all(c.isalnum() or c in ".-_" for c in ext[1:]):
        return ""
    return ext


def _add_hash_prefix(digest: str, depth: int) -> str:
    """Insert hash prefix directories: 'ff30...' with depth=4 -> 'f/f/3/0/ff30...'"""
    if depth <= 0:
        return digest
    prefix = "/".join(digest[:depth])
    return f"{prefix}/{digest}"


def hashed_s3_key(
    normalized_url: str,
    vary_key: str | None = None,
    hash_prefix_depth: int = 4,
) -> str:
    """Compute the S3 object key for a normalized URL.

    With hash_prefix_depth=4, distributes objects across 65,536 S3 prefixes
    to avoid per-prefix throttling (3,500 PUT / 5,500 GET per second per prefix).
    """
    parsed = urlparse(normalized_url)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "unknown").lower()
    digest = hashlib.sha224(normalized_url.encode("utf-8")).hexdigest()
    ext = url_ext(normalized_url)
    prefixed_digest = _add_hash_prefix(digest, hash_prefix_depth)
    if vary_key:
        return f"meta/{scheme}/{host}/{prefixed_digest}+{vary_key}{ext}"
    return f"meta/{scheme}/{host}/{prefixed_digest}{ext}"


def get_cache_key(
    normalized_url: str,
    vary_key: str | None = None,
    hash_prefix_depth: int = 4,
) -> str:
    """Return the S3 cache key for a normalized URL."""
    return hashed_s3_key(normalized_url, vary_key, hash_prefix_depth)


def get_vary_index_key(normalized_url: str, hash_prefix_depth: int = 4) -> str:
    """Return the S3 vary-index key for a normalized URL."""
    parsed = urlparse(normalized_url)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "unknown").lower()
    digest = hashlib.sha224(normalized_url.encode("utf-8")).hexdigest()
    prefixed_digest = _add_hash_prefix(digest, hash_prefix_depth)
    return f"meta/{scheme}/{host}/_vary/{prefixed_digest}"
