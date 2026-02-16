import pytest

from passsage import default_cache_keys


def _strip_for(url: str) -> str | None:
    ctx = default_cache_keys.Context(url=url)
    return default_cache_keys._strip_signed_params(ctx)


def test_strips_amz_query():
    url = (
        "https://example.r2.cloudflarestorage.com/blob"
        "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=abc"
        "&X-Amz-Date=20260204T210046Z"
        "&X-Amz-Expires=1200"
        "&X-Amz-Signature=deadbeef"
        "&keep=1"
    )
    normalized = _strip_for(url)
    assert normalized == "https://example.r2.cloudflarestorage.com/blob?keep=1"


def test_strips_cloudflare_params():
    url = (
        "https://production.cloudflare.docker.com/registry/v2/blobs/sha256/aa/bb/data"
        "?expires=123&signature=abc&version=3&keep=1"
    )
    normalized = _strip_for(url)
    assert normalized == (
        "https://production.cloudflare.docker.com/registry/v2/blobs/sha256/aa/bb/data"
        "?keep=1&version=3"
    )


def test_strips_azure_params():
    url = (
        "https://pkg-containers.githubusercontent.com/ghcr1/blobs/sha256:abc"
        "?se=2026-02-04T22%3A30%3A00Z&sig=zzz&sv=2025-01-05&hmac=ffff&keep=1"
    )
    normalized = _strip_for(url)
    assert normalized == "https://pkg-containers.githubusercontent.com/ghcr1/blobs/sha256:abc?keep=1"


def test_strips_cloudfront_params():
    url = (
        "https://cas-bridge.xethub.hf.co/xet-bridge-us/abc123/deadbeef"
        "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Signature=aaa"
        "&Expires=1771273934"
        "&Policy=eyJhIjoiYiJ9"
        "&Signature=bbb"
        "&Key-Pair-Id=K2L8F4GPSG1IFC"
        "&keep=1"
    )
    normalized = _strip_for(url)
    assert normalized == "https://cas-bridge.xethub.hf.co/xet-bridge-us/abc123/deadbeef?keep=1"


def test_strips_from_unknown_host():
    url = (
        "https://totally-new-cdn.example.com/file.bin"
        "?X-Amz-Credential=abc&X-Amz-Signature=def&keep=1"
    )
    normalized = _strip_for(url)
    assert normalized == "https://totally-new-cdn.example.com/file.bin?keep=1"


def test_sorts_remaining_query():
    url = (
        "https://example.r2.cloudflarestorage.com/blob"
        "?X-Amz-Date=20260204T210046Z"
        "&b=2"
        "&a=1"
        "&A=3"
    )
    normalized = _strip_for(url)
    assert normalized == "https://example.r2.cloudflarestorage.com/blob?A=3&a=1&b=2"


def test_no_query_returns_none():
    assert _strip_for("https://example.com/path") is None


def test_no_signed_params_returns_none():
    assert _strip_for("https://example.com/path?foo=bar") is None


