"""Tests for the --s3-proxy-url / PASSSAGE_S3_PROXY_URL feature."""

import sys
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
from click.testing import CliRunner

from passsage.cli import main


# ---------------------------------------------------------------------------
# Patch mitmproxy's @concurrent decorator before importing proxy.py.
# In newer mitmproxy versions the decorator rejects 'requestheaders',
# which prevents the module from loading outside a live mitmproxy context.
#
# proxy.py does `from mitmproxy.script import concurrent` which resolves
# via `mitmproxy.script.__init__` to the *function*, so we patch the
# attribute on the package object.
# ---------------------------------------------------------------------------


def _passthrough_decorator(fn):
    return fn


@pytest.fixture(autouse=True)
def _patch_concurrent():
    import mitmproxy.script as script_pkg

    orig = script_pkg.concurrent
    script_pkg.concurrent = _passthrough_decorator

    for key in list(sys.modules):
        if key.startswith("passsage.proxy"):
            del sys.modules[key]

    yield

    script_pkg.concurrent = orig
    for key in list(sys.modules):
        if key.startswith("passsage.proxy"):
            del sys.modules[key]


MODULE = "passsage.proxy"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeRequest:
    def __init__(self, url, method="GET"):
        self.url = url
        self.method = method
        self.headers = {}
        self.pretty_host = urlparse(url).hostname or ""


class FakeFlow:
    def __init__(self, url, method="GET", cache_key=None):
        self.request = FakeRequest(url, method)
        if cache_key:
            self._cache_key = cache_key


# ---------------------------------------------------------------------------
# CLI validation
# ---------------------------------------------------------------------------

class TestCLIValidation:
    def test_s3_proxy_url_without_cache_redirect_errors(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "--s3-proxy-url", "http://proxy.local:8080",
        ])
        assert result.exit_code != 0
        assert "--s3-proxy-url requires --cache-redirect" in result.output

    def test_s3_proxy_url_with_cache_redirect_accepted(self):
        runner = CliRunner()
        result = runner.invoke(main, [
            "--s3-proxy-url", "http://proxy.local:8080",
            "--cache-redirect",
            "--help",
        ])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# get_cache_redirect_url
# ---------------------------------------------------------------------------

class TestGetCacheRedirectUrl:
    def test_returns_proxy_url_with_cache_key(self):
        from passsage.proxy import get_cache_redirect_url, _presigned_url_cache

        _presigned_url_cache.clear()

        flow = FakeFlow("http://example.com/data.csv", cache_key="https/example.com/abc123.csv")
        ctx_options = SimpleNamespace(
            s3_proxy_url="http://xs3lerator.local:8080",
            cache_redirect=True,
            cache_redirect_signed_url=False,
        )
        with patch(f"{MODULE}.ctx") as mock_ctx:
            mock_ctx.options = ctx_options
            url = get_cache_redirect_url(flow)

        assert url == "http://xs3lerator.local:8080/https/example.com/abc123.csv"

    def test_strips_trailing_slash_from_proxy_url(self):
        from passsage.proxy import get_cache_redirect_url, _presigned_url_cache

        _presigned_url_cache.clear()

        flow = FakeFlow("http://example.com/other", cache_key="https/example.com/def456")
        ctx_options = SimpleNamespace(
            s3_proxy_url="http://xs3lerator.local:8080/",
            cache_redirect=True,
            cache_redirect_signed_url=False,
        )
        with patch(f"{MODULE}.ctx") as mock_ctx:
            mock_ctx.options = ctx_options
            url = get_cache_redirect_url(flow)

        assert url == "http://xs3lerator.local:8080/https/example.com/def456"

    def test_falls_through_to_s3_when_proxy_url_empty(self):
        from passsage.proxy import get_cache_redirect_url, _presigned_url_cache

        _presigned_url_cache.clear()

        flow = FakeFlow("http://example.com/file", cache_key="https/example.com/aaa111")
        ctx_options = SimpleNamespace(
            s3_proxy_url="",
            cache_redirect=True,
            cache_redirect_signed_url=False,
        )
        with patch(f"{MODULE}.ctx") as mock_ctx, \
             patch(f"{MODULE}.S3_PROXY_URL", ""):
            mock_ctx.options = ctx_options
            url = get_cache_redirect_url(flow)

        assert "xs3lerator" not in url
        assert "aaa111" in url

    def test_env_fallback_when_ctx_option_missing(self):
        from passsage.proxy import get_cache_redirect_url, _presigned_url_cache

        _presigned_url_cache.clear()

        flow = FakeFlow("http://example.com/f", cache_key="https/example.com/bbb222")
        ctx_options = SimpleNamespace(
            cache_redirect=True,
            cache_redirect_signed_url=False,
        )
        with patch(f"{MODULE}.ctx") as mock_ctx, \
             patch(f"{MODULE}.S3_PROXY_URL", "http://fallback-proxy:9090"):
            mock_ctx.options = ctx_options
            url = get_cache_redirect_url(flow)

        assert url == "http://fallback-proxy:9090/https/example.com/bbb222"


# ---------------------------------------------------------------------------
# serve_cache_hit
# ---------------------------------------------------------------------------

class TestServeCacheHit:
    def test_redirect_uses_proxy_url(self):
        from passsage.proxy import serve_cache_hit, _presigned_url_cache

        _presigned_url_cache.clear()

        flow = FakeFlow("http://example.com/obj", cache_key="https/example.com/ccc333")
        flow.response = None
        ctx_options = SimpleNamespace(
            s3_proxy_url="http://xs3lerator.local:8080",
            cache_redirect=True,
            cache_redirect_signed_url=False,
            no_redirect_user_agents="pip/",
        )
        with patch(f"{MODULE}.ctx") as mock_ctx:
            mock_ctx.options = ctx_options
            serve_cache_hit(flow)

        assert flow.response is not None
        assert flow.response.status_code in (302, 307)
        assert flow.response.headers["Location"] == "http://xs3lerator.local:8080/https/example.com/ccc333"
        assert flow._cached is True
        assert flow._cache_redirect is True

    def test_redirect_302_for_get(self):
        from passsage.proxy import serve_cache_hit, _presigned_url_cache

        _presigned_url_cache.clear()

        flow = FakeFlow("http://example.com/obj2", method="GET", cache_key="https/example.com/eee555")
        flow.response = None
        ctx_options = SimpleNamespace(
            s3_proxy_url="http://xs3lerator.local:8080",
            cache_redirect=True,
            cache_redirect_signed_url=False,
            no_redirect_user_agents="pip/",
        )
        with patch(f"{MODULE}.ctx") as mock_ctx:
            mock_ctx.options = ctx_options
            serve_cache_hit(flow)

        assert flow.response.status_code == 302

    def test_redirect_307_for_non_get(self):
        from passsage.proxy import serve_cache_hit, _presigned_url_cache

        _presigned_url_cache.clear()

        flow = FakeFlow("http://example.com/obj", method="POST", cache_key="https/example.com/ddd444")
        flow.response = None
        ctx_options = SimpleNamespace(
            s3_proxy_url="http://xs3lerator.local:8080",
            cache_redirect=True,
            cache_redirect_signed_url=False,
            no_redirect_user_agents="pip/",
        )
        with patch(f"{MODULE}.ctx") as mock_ctx:
            mock_ctx.options = ctx_options
            serve_cache_hit(flow)

        assert flow.response.status_code == 307


# ---------------------------------------------------------------------------
# _no_proxy_s3_hosts
# ---------------------------------------------------------------------------

class TestNoProxyS3Hosts:
    def test_includes_proxy_url_host(self):
        from passsage.proxy import _no_proxy_s3_hosts

        with patch(f"{MODULE}._S3_ENDPOINT", None), \
             patch(f"{MODULE}.S3_PROXY_URL", "http://xs3lerator.internal:8080"), \
             patch(f"{MODULE}.CACHE_REDIRECT", True), \
             patch(f"{MODULE}.SIGNED_CACHE_REDIRECT", False):
            hosts = _no_proxy_s3_hosts()

        assert "xs3lerator.internal" in hosts

    def test_excludes_s3_hosts_when_proxy_url_set(self):
        from passsage.proxy import _no_proxy_s3_hosts

        with patch(f"{MODULE}._S3_ENDPOINT", None), \
             patch(f"{MODULE}.S3_PROXY_URL", "http://proxy.local:8080"), \
             patch(f"{MODULE}.CACHE_REDIRECT", True), \
             patch(f"{MODULE}.SIGNED_CACHE_REDIRECT", False), \
             patch(f"{MODULE}.S3_BUCKET", "my-bucket"), \
             patch(f"{MODULE}.S3_REGION", "us-west-2"):
            hosts = _no_proxy_s3_hosts()

        assert "proxy.local" in hosts
        assert "my-bucket.s3.us-west-2.amazonaws.com" not in hosts

    def test_falls_back_to_s3_hosts_when_no_proxy_url(self):
        from passsage.proxy import _no_proxy_s3_hosts

        with patch(f"{MODULE}._S3_ENDPOINT", None), \
             patch(f"{MODULE}.S3_PROXY_URL", ""), \
             patch(f"{MODULE}.CACHE_REDIRECT", True), \
             patch(f"{MODULE}.SIGNED_CACHE_REDIRECT", False), \
             patch(f"{MODULE}.S3_BUCKET", "test-bucket"), \
             patch(f"{MODULE}.S3_REGION", "eu-west-1"):
            hosts = _no_proxy_s3_hosts()

        assert "test-bucket.s3.eu-west-1.amazonaws.com" in hosts

    def test_proxy_url_with_port_in_no_proxy(self):
        from passsage.proxy import _no_proxy_s3_hosts

        with patch(f"{MODULE}._S3_ENDPOINT", None), \
             patch(f"{MODULE}.S3_PROXY_URL", "https://proxy.example.com:9443/prefix"), \
             patch(f"{MODULE}.CACHE_REDIRECT", True):
            hosts = _no_proxy_s3_hosts()

        assert "proxy.example.com" in hosts


# ---------------------------------------------------------------------------
# _is_s3_cache_request -- bypass for S3 proxy host
# ---------------------------------------------------------------------------

class TestIsS3CacheRequest:
    def test_matches_s3_host(self):
        from passsage.proxy import _is_s3_cache_request

        flow = FakeFlow("http://my-bucket.s3.us-west-2.amazonaws.com/key")
        with patch(f"{MODULE}.S3_HOST", "my-bucket.s3.us-west-2.amazonaws.com"), \
             patch(f"{MODULE}._S3_PROXY_HOST", None):
            assert _is_s3_cache_request(flow) is True

    def test_matches_s3_proxy_host(self):
        from passsage.proxy import _is_s3_cache_request

        flow = FakeFlow("http://proxy-objects.ds.system1.company/some/key")
        with patch(f"{MODULE}.S3_HOST", "my-bucket.s3.us-west-2.amazonaws.com"), \
             patch(f"{MODULE}._S3_PROXY_HOST", "proxy-objects.ds.system1.company"):
            assert _is_s3_cache_request(flow) is True

    def test_no_match_for_other_host(self):
        from passsage.proxy import _is_s3_cache_request

        flow = FakeFlow("https://ftp.uni-hannover.de/debian/file.iso")
        with patch(f"{MODULE}.S3_HOST", "my-bucket.s3.us-west-2.amazonaws.com"), \
             patch(f"{MODULE}._S3_PROXY_HOST", "proxy-objects.ds.system1.company"):
            assert _is_s3_cache_request(flow) is False

    def test_no_match_when_proxy_host_is_none(self):
        from passsage.proxy import _is_s3_cache_request

        flow = FakeFlow("http://proxy-objects.ds.system1.company/some/key")
        with patch(f"{MODULE}.S3_HOST", "my-bucket.s3.us-west-2.amazonaws.com"), \
             patch(f"{MODULE}._S3_PROXY_HOST", None):
            assert _is_s3_cache_request(flow) is False
