"""Default cache key normalization rules.

This module defines built-in cache key normalization for URLs that use
signed query parameters (e.g. S3/R2, Cloudflare Registry blobs). The goal
is to avoid cache fragmentation when signed URLs differ only by ephemeral
credentials.

How it works
------------
- Match known object storage hosts.
- Strip query params based on a configurable rule table:
  - remove any params with a given prefix (e.g. X-Amz-*)
  - remove any params in a given allowlist (e.g. expires, signature, version)
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

from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

from dataclasses import dataclass
from typing import Callable, Optional


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
_CLOUDFLARE_SIGNED_PARAMS = {"expires", "signature", "version"}
_SIGNED_QUERY_RULES = (
    {
        "host_suffixes": ("r2.cloudflarestorage.com", "amazonaws.com"),
        "remove_prefixes": (_SIGNED_QUERY_PREFIX,),
        "remove_params": (),
    },
    {
        "host_suffixes": ("production.cloudflare.docker.com",),
        "remove_prefixes": (),
        "remove_params": tuple(sorted(_CLOUDFLARE_SIGNED_PARAMS)),
    },
)


class _SuffixTrieNode:
    __slots__ = ("children", "rules")

    def __init__(self) -> None:
        self.children: dict[str, _SuffixTrieNode] = {}
        self.rules: list[dict[str, tuple[str, ...]]] = []


def _build_suffix_trie(rules: tuple[dict[str, tuple[str, ...]], ...]) -> _SuffixTrieNode:
    root = _SuffixTrieNode()
    for rule in rules:
        for suffix in rule["host_suffixes"]:
            node = root
            for ch in reversed(suffix):
                node = node.children.setdefault(ch, _SuffixTrieNode())
            node.rules.append(rule)
    return root


_SIGNED_QUERY_TRIE = _build_suffix_trie(_SIGNED_QUERY_RULES)


def _strip_signed_query(ctx: Context, remove_prefixes: tuple[str, ...], remove_params: tuple[str, ...]) -> str | None:
    parts = urlsplit(ctx.url)
    if not parts.query:
        return None
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(
        name.lower().startswith(remove_prefixes) or name.lower() in remove_params
        for name, _ in pairs
    ):
        return None
    filtered = [
        (name, value)
        for (name, value) in pairs
        if not name.lower().startswith(remove_prefixes) and name.lower() not in remove_params
    ]
    query = urlencode(filtered, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _signed_storage_rule(ctx: Context) -> str | None:
    if not ctx.host:
        return None
    host = ctx.host
    node = _SIGNED_QUERY_TRIE
    for ch in reversed(host):
        if ch not in node.children:
            break
        node = node.children[ch]
        if node.rules:
            for rule in node.rules:
                return _strip_signed_query(ctx, rule["remove_prefixes"], rule["remove_params"])
    return None


def default_rules():
    return [
        CallableRule(_signed_storage_rule),
    ]
