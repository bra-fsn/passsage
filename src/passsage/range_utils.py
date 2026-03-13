"""Pure utility functions for HTTP Range / If-Range handling (RFC 9110).

Importable without mitmproxy, so these can be unit-tested in isolation.
"""


def parse_single_range(header: str, total: int) -> tuple[int, int] | None:
    """Parse a single-range ``Range`` header.  Returns (start, end) inclusive or None."""
    if not header or not header.startswith("bytes="):
        return None
    spec = header[len("bytes="):].strip()
    if "," in spec:
        return None  # multi-range — not supported
    try:
        if spec.startswith("-"):
            suffix_len = int(spec[1:])
            if suffix_len <= 0 or suffix_len > total:
                return None
            return total - suffix_len, total - 1
        parts = spec.split("-", 1)
        start = int(parts[0])
        end = int(parts[1]) if parts[1] else total - 1
        end = min(end, total - 1)
        if start > end or start >= total:
            return None
        return start, end
    except (ValueError, IndexError):
        return None


def is_unsatisfiable_range(header: str, total: int) -> bool:
    """Return True when the Range spec is syntactically valid but wholly outside [0, total)."""
    if not header or not header.startswith("bytes="):
        return False
    spec = header[len("bytes="):].strip()
    if "," in spec:
        return False  # multi-range — not an error, just unsupported
    try:
        if spec.startswith("-"):
            suffix_len = int(spec[1:])
            return suffix_len <= 0 or suffix_len > total
        parts = spec.split("-", 1)
        start = int(parts[0])
        return start >= total
    except (ValueError, IndexError):
        return False


def if_range_matches(if_range_value: str | None, cache_meta: dict | None) -> bool:
    """Evaluate If-Range against cached metadata per RFC 9110 Section 14.5.

    Returns True if the Range should be honored (If-Range matches or is absent).
    Returns False if the Range should be ignored (serve full 200 instead).

    Parameters
    ----------
    if_range_value : the raw If-Range header value (or None)
    cache_meta : the cached metadata dict (with "headers" sub-dict), or None
    """
    if not if_range_value:
        return True
    if not cache_meta:
        return False
    if if_range_value.startswith('"') or if_range_value.startswith("W/"):
        if if_range_value.startswith("W/"):
            return False  # weak ETags not allowed in If-Range per RFC
        cached_etag = cache_meta.get("headers", {}).get("etag", "")
        return if_range_value == cached_etag
    cached_lm = (cache_meta.get("last_modified")
                 or cache_meta.get("headers", {}).get("last-modified", ""))
    return if_range_value == cached_lm
