"""Default cache key normalization rules.

This module defines built-in cache key normalization for URLs that use
signed query parameters (e.g. S3/R2). The goal is to avoid cache
fragmentation when signed URLs differ only by ephemeral credentials.

How it works
------------
- Match known object storage hosts.
- If the query contains X-Amz-* params, strip those params from the cache key.
- The upstream request still uses the original URL; only the cache key is normalized.

Example
-------
Original request URL:
    https://example.r2.cloudflarestorage.com/path/blob
    ?X-Amz-Algorithm=AWS4-HMAC-SHA256
    &X-Amz-Credential=...
    &X-Amz-Date=20260204T210046Z
    &X-Amz-Expires=1200
    &X-Amz-Signature=...

Normalized cache key:
    https://example.r2.cloudflarestorage.com/path/blob

Extending in a policy file
--------------------------
Use the same policy override file and export one of:
    - get_cache_key_rules()
    - CACHE_KEY_RULES
    - get_cache_key_resolver()
    - CACHE_KEY_RESOLVER

Example override (policy file):
    from passsage.cache_key import CallableRule

    def strip_signed_r2(ctx):
        if ctx.host and "r2.cloudflarestorage.com" in ctx.host:
            return ctx.url.split("?", 1)[0]
        return None

    def get_cache_key_rules():
        return [CallableRule(strip_signed_r2)]
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse


@dataclass(frozen=True)
class Context:
    url: str
    host: Optional[str] = None

    def __post_init__(self) -> None:
        if self.host is None and self.url:
            obj = urlparse(self.url)
            object.__setattr__(self, "host", (obj.hostname or "").lower())


class CallableRule:
    __slots__ = ("func",)

    def __init__(self, func: Callable[[Context], Optional[str]]) -> None:
        self.func = func

    def match(self, ctx: Context) -> Optional[str]:
        return self.func(ctx)


_SIGNED_QUERY_PREFIX = "x-amz-"


def _strip_signed_query(ctx: Context) -> str | None:
    parts = urlsplit(ctx.url)
    if not parts.query:
        return None
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(name.lower().startswith(_SIGNED_QUERY_PREFIX) for name, _ in pairs):
        return None
    filtered = [
        (name, value)
        for (name, value) in pairs
        if not name.lower().startswith(_SIGNED_QUERY_PREFIX)
    ]
    query = urlencode(filtered, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _signed_storage_rule(ctx: Context) -> str | None:
    if not ctx.host:
        return None
    host = ctx.host
    if "r2.cloudflarestorage.com" in host or "amazonaws.com" in host:
        return _strip_signed_query(ctx)
    return None


def default_rules():
    return [
        CallableRule(_signed_storage_rule),
    ]
