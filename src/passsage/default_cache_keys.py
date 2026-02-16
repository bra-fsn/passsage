"""Default cache key normalization rules.

This module strips ephemeral signing/credential query parameters from
*any* URL so that differently-signed requests to the same resource share
a single cache entry.  The upstream request still uses the original URL;
only the cache key is normalized.

Covered signing schemes
-----------------------
- AWS Signature V4        – ``X-Amz-*`` prefix
- AWS CloudFront signed   – Expires, Policy, Signature, Key-Pair-Id
- Azure SAS               – se, sig, sp, sv, …

Because these parameter names are unambiguous credentials/signatures,
they are stripped regardless of host.  Any remaining query parameters are
kept (sorted for determinism).

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


# AWS Signature V4 – all params start with this prefix.
# Example: S3 presigned
#   https://my-bucket.s3.amazonaws.com/object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Signature=...
# Example: R2 presigned
#   https://account.r2.cloudflarestorage.com/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...
# Example: HuggingFace (xethub) redirect – combines AWS SigV4 + CloudFront signing
#   https://cas-bridge.xethub.hf.co/xet-bridge-us/abc/def?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=...&Expires=...&Policy=...&Signature=...&Key-Pair-Id=...
_SIGNED_QUERY_PREFIXES = ("x-amz-",)

_SIGNED_QUERY_PARAMS = frozenset({
    # AWS CloudFront signed URLs
    # Example: https://d111111abcdef8.cloudfront.net/path?Expires=...&Policy=...&Signature=...&Key-Pair-Id=...
    "expires",
    "key-pair-id",
    "policy",
    "signature",
    # Azure SAS tokens
    # Example: https://pkg-containers.githubusercontent.com/ghcr1/blobs/sha256:abc?se=2026-02-04T22:30:00Z&sig=...&sv=2025-01-05
    # Example: https://myaccount.blob.core.windows.net/container/blob?sp=r&st=...&se=...&sv=...&sr=b&sig=...
    "se",
    "sig",
    "ske",
    "skoid",
    "sks",
    "skt",
    "sktid",
    "skv",
    "sp",
    "spr",
    "sr",
    "sv",
    "hmac",
})


def _is_signed_param(name: str) -> bool:
    lower = name.lower()
    return lower.startswith(_SIGNED_QUERY_PREFIXES) or lower in _SIGNED_QUERY_PARAMS


def _strip_signed_params(ctx: Context) -> str | None:
    parts = urlsplit(ctx.url)
    if not parts.query:
        return None
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(_is_signed_param(name) for name, _ in pairs):
        return None
    filtered = [(n, v) for n, v in pairs if not _is_signed_param(n)]
    if filtered:
        filtered.sort(key=lambda item: (item[0].lower(), item[0], item[1]))
    query = urlencode(filtered, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def default_rules():
    return [
        CallableRule(_strip_signed_params),
    ]
