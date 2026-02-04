import pytest

from passsage import default_cache_keys


def _strip_for(url: str) -> str | None:
    ctx = default_cache_keys.Context(url=url)
    return default_cache_keys._signed_storage_rule(ctx)


def test_signed_storage_rule_strips_amz_query():
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


def test_signed_storage_rule_strips_cloudflare_params():
    url = (
        "https://production.cloudflare.docker.com/registry/v2/blobs/sha256/aa/bb/data"
        "?expires=123&signature=abc&version=3&keep=1"
    )
    normalized = _strip_for(url)
    assert normalized == "https://production.cloudflare.docker.com/registry/v2/blobs/sha256/aa/bb/data?keep=1"


def test_signed_storage_rule_strips_azure_params():
    url = (
        "https://pkg-containers.githubusercontent.com/ghcr1/blobs/sha256:abc"
        "?se=2026-02-04T22%3A30%3A00Z&sig=zzz&sv=2025-01-05&hmac=ffff&keep=1"
    )
    normalized = _strip_for(url)
    assert normalized == "https://pkg-containers.githubusercontent.com/ghcr1/blobs/sha256:abc?keep=1"


