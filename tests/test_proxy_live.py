"""Integration tests for the HTTP proxy against a live connection and live S3 backend."""

import hashlib
import os
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
import psutil
import requests
from urllib3.exceptions import InsecureRequestWarning

import urllib3

from passsage.test_server import TestServer

urllib3.disable_warnings(InsecureRequestWarning)

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:8080")
TEST_SERVER_BIND_HOST = os.environ.get("PASSSAGE_TEST_SERVER_BIND_HOST", "127.0.0.1")
TEST_SERVER_PUBLIC_HOST = os.environ.get("PASSSAGE_TEST_SERVER_HOST")
SYNC_SETTLE_SECONDS = float(os.environ.get("PASSSAGE_SYNC_SETTLE_SECONDS", "1.0"))
POLICY_HEADER = "X-Passsage-Policy"

CONCURRENT_DELAY = 5
# Each request includes upstream HEAD + GET. If HEAD is delayed too, a single request
# takes ~2*CONCURRENT_DELAY. We expect concurrency, so each request should finish
# well under 2*CONCURRENT_DELAY*2 (sequential) and allow some buffer.
CONCURRENT_MAX_RESPONSE_TIME = CONCURRENT_DELAY * 4 * 0.8
UPSTREAM_TIMEOUT_DELAY = 12
UPSTREAM_CLIENT_TIMEOUT = 20


def get_method_count(stats: dict, path: str, method: str) -> int:
    reqs = stats.get("requests", {}).get(path, [])
    return sum(1 for r in reqs if r.get("method") == method)


def assert_cached_response(resp: requests.Response) -> None:
    if "Cache-Status" in resp.headers:
        assert "Age" in resp.headers
        return
    if cache_redirect_enabled():
        if has_cache_redirect(resp):
            return
    assert "Cache-Status" in resp.headers


def has_cache_redirect(resp: requests.Response) -> bool:
    candidates = [resp] + list(resp.history or [])
    return any(r.status_code in (302, 307) and r.headers.get("Location") for r in candidates)


def cache_redirect_enabled() -> bool:
    value = os.environ.get("PASSSAGE_CACHE_REDIRECT", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def policy_headers(policy_name: str) -> dict[str, str]:
    return {POLICY_HEADER: policy_name}


def build_proxy_session(cert_path: str) -> requests.Session:
    session = requests.Session()
    session.proxies = {"http": PROXY_URL, "https": PROXY_URL}
    session.verify = cert_path
    return session


def get_available_memory_bytes() -> int | None:
    try:
        return int(psutil.virtual_memory().total)
    except (ValueError, TypeError):
        return None


@pytest.fixture(scope="session")
def cache_bust_random():
    return uuid.uuid4().hex


@pytest.fixture(scope="module", autouse=True)
def test_server():
    # Use PASSSAGE_TEST_SERVER_HOST when the proxy runs in a container (e.g. host.docker.internal).
    server = TestServer(public_host=TEST_SERVER_PUBLIC_HOST)
    server.start(host=TEST_SERVER_BIND_HOST, port=0)
    yield server
    server.stop()


@pytest.fixture(scope="session")
def mitmproxy_ca_cert_path():
    resp = requests.get(
        "http://mitm.it/cert/pem",
        proxies={"http": PROXY_URL, "https": PROXY_URL},
        timeout=10,
        verify=False,
    )
    resp.raise_for_status()
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".pem", delete=False) as f:
        f.write(resp.content)
        return f.name


@pytest.fixture(scope="session")
def proxy_session(mitmproxy_ca_cert_path):
    return build_proxy_session(mitmproxy_ca_cert_path)


def proxy_get(session: requests.Session, url: str, *, headers: dict | None = None, **kwargs) -> requests.Response:
    merged = {"x-clear-ban": "1"}
    if headers:
        merged.update(headers)
    return session.get(url, headers=merged, **kwargs)


def wait_for_cached_response(
    session: requests.Session,
    url: str,
    *,
    headers: dict | None = None,
    timeout: int = 30,
    retries: int = 5,
    sleep_seconds: float = 0.5,
) -> requests.Response:
    last_resp = None
    for _ in range(retries):
        last_resp = proxy_get(session, url, headers=headers, timeout=timeout)
        if "Cache-Status" in last_resp.headers or (
            cache_redirect_enabled() and has_cache_redirect(last_resp)
        ):
            return last_resp
        time.sleep(sleep_seconds)
    return last_resp


def get_cached_without_upstream(
    session: requests.Session,
    url: str,
    test_server: TestServer,
    path: str,
    *,
    headers: dict | None = None,
    timeout: int = 30,
    retries: int = 5,
    sleep_seconds: float = 0.5,
    **kwargs,
) -> requests.Response:
    last_resp = None
    for _ in range(retries):
        before = get_method_count(test_server.stats(), path, "GET")
        last_resp = proxy_get(session, url, headers=headers, timeout=timeout, **kwargs)
        after = get_method_count(test_server.stats(), path, "GET")
        if (
            ("Cache-Status" in last_resp.headers or has_cache_redirect(last_resp))
            and after == before
        ):
            return last_resp
        time.sleep(sleep_seconds)
    return last_resp


def version_from_response(response: requests.Response) -> int:
    prefix = "version="
    text = response.text.strip()
    if not text.startswith(prefix):
        raise AssertionError(f"Expected response to start with {prefix!r}, got {text!r}")
    return int(text[len(prefix):])


@pytest.mark.integration
class TestProxyLive:
    def test_proxy_env_script_contains_cert(self):
        resp = requests.get(
            "http://mitm.it/proxy-env.sh",
            proxies={"http": PROXY_URL, "https": PROXY_URL},
            timeout=10,
            verify=False,
        )
        resp.raise_for_status()
        script = resp.text
        assert "__PASSSAGE_MITM_CA_PEM__" not in script
        assert "BEGIN CERTIFICATE" in script
        assert "export HTTP_PROXY" in script
        assert "export HTTPS_PROXY" in script

    def test_concurrent_requests_through_proxy(
        self, mitmproxy_ca_cert_path, test_server, cache_bust_random
    ):
        # Verifies the proxy processes delayed upstream requests concurrently.
        url = test_server.url(f"/delay/{CONCURRENT_DELAY}?random={cache_bust_random}")

        def timed_get(u):
            session = build_proxy_session(mitmproxy_ca_cert_path)
            try:
                t0 = time.perf_counter()
                proxy_get(session, u, timeout=CONCURRENT_DELAY + 30)
                return time.perf_counter() - t0
            finally:
                session.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(timed_get, url) for _ in range(2)]
            response_times = [f.result() for f in as_completed(futures)]

        for i, elapsed in enumerate(response_times):
            assert elapsed < CONCURRENT_MAX_RESPONSE_TIME, (
                f"request {i+1} took {elapsed:.1f}s; expected < {CONCURRENT_MAX_RESPONSE_TIME}s"
            )

    def test_policy_no_refresh(self, proxy_session, test_server, cache_bust_random):
        # Ensures NoRefresh serves from cache after the first request.
        test_server.reset()
        url = test_server.url(f"/policy/NoRefresh?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("NoRefresh"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/NoRefresh",
            headers=policy_headers("NoRefresh"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_policy_standard(self, proxy_session, test_server, cache_bust_random):
        # Ensures Standard reuses cached content when upstream is unchanged.
        test_server.reset()
        url = test_server.url(f"/policy/Standard?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("Standard"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/Standard",
            headers=policy_headers("Standard"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_policy_no_cache(self, proxy_session, test_server, cache_bust_random):
        # Ensures NoCache always forwards to upstream (no cache hits).
        test_server.reset()
        url = test_server.url(f"/policy/NoCache?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("NoCache"), timeout=30)
        r2 = proxy_get(proxy_session, url, headers=policy_headers("NoCache"), timeout=30)
        assert r1.ok and r2.ok
        stats = test_server.stats()
        assert get_method_count(stats, "/policy/NoCache", "GET") == 2
        assert "Cache-Status" not in r2.headers

    def test_upstream_connection_refused(self, proxy_session):
        url = "http://127.0.0.1:1/connection-refused"
        resp = proxy_get(proxy_session, url, timeout=UPSTREAM_CLIENT_TIMEOUT)
        assert resp.status_code == 502
        assert "Upstream connection failed" in resp.text

    @pytest.mark.parametrize(
        ("policy_name", "expect_cached", "expect_status"),
        [
            ("Standard", False, 504),
            ("StaleIfError", True, 200),
            ("NoRefresh", True, 200),
            ("AlwaysUpstream", False, 504),
        ],
    )
    def test_upstream_timeout_policies(
        self,
        proxy_session,
        test_server,
        cache_bust_random,
        policy_name,
        expect_cached,
        expect_status,
    ):
        test_server.reset()
        url = test_server.url(
            f"/cache-control/max-age-low?random={cache_bust_random}&case={policy_name}"
        )
        r1 = proxy_get(proxy_session, url, headers=policy_headers(policy_name), timeout=30)
        assert r1.ok
        time.sleep(2)
        test_server.set_path_override(
            "/cache-control/max-age-low",
            delay=UPSTREAM_TIMEOUT_DELAY,
        )
        r2 = proxy_get(
            proxy_session,
            url,
            headers=policy_headers(policy_name),
            timeout=UPSTREAM_CLIENT_TIMEOUT,
        )
        assert r2.status_code == expect_status
        if expect_cached:
            assert_cached_response(r2)
        else:
            assert "Cache-Status" not in r2.headers

    def test_policy_always_upstream(self, proxy_session, test_server, cache_bust_random):
        # Ensures AlwaysUpstream always fetches from upstream even when cached.
        test_server.reset()
        url = test_server.url(f"/policy/AlwaysUpstream?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("AlwaysUpstream"), timeout=30)
        r2 = proxy_get(proxy_session, url, headers=policy_headers("AlwaysUpstream"), timeout=30)
        assert r1.ok and r2.ok
        stats = test_server.stats()
        assert get_method_count(stats, "/policy/AlwaysUpstream", "GET") == 2
        assert "Cache-Status" not in r2.headers

    def test_cache_updates_on_upstream_change(self, proxy_session, test_server, cache_bust_random):
        # Verifies how each policy updates cached content when upstream changes.
        cases = {
            "Standard": {"expect_cache": True, "expect_updated": True, "cache_policy": "Standard"},
            "StaleIfError": {"expect_cache": True, "expect_updated": True, "cache_policy": "StaleIfError"},
            "NoRefresh": {"expect_cache": True, "expect_updated": False, "cache_policy": "NoRefresh"},
            "AlwaysUpstream": {
                "expect_cache": True,
                "expect_updated": True,
                "cache_policy": "Standard",
            },
            "NoCache": {"expect_cache": False, "expect_updated": True, "cache_policy": None},
        }
        for policy_name, config in cases.items():
            test_server.reset()
            url = test_server.url(
                f"/cache-control/changing?random={cache_bust_random}&case={policy_name}"
            )
            r1 = proxy_get(proxy_session, url, headers=policy_headers(policy_name), timeout=30)
            assert r1.ok
            assert version_from_response(r1) == 1
            time.sleep(SYNC_SETTLE_SECONDS)

            if config["expect_cache"]:
                cached1 = get_cached_without_upstream(
                    proxy_session,
                    url,
                    test_server,
                    "/cache-control/changing",
                    headers=policy_headers(config["cache_policy"]),
                )
                assert_cached_response(cached1)
                assert version_from_response(cached1) == 1
            else:
                assert "Cache-Status" not in r1.headers

            test_server.bump_version()
            time.sleep(SYNC_SETTLE_SECONDS + 2)
            r2 = proxy_get(proxy_session, url, headers=policy_headers(policy_name), timeout=30)
            assert r2.ok
            expected_version = 2 if config["expect_updated"] else 1
            assert version_from_response(r2) == expected_version
            if config["expect_cache"]:
                cached2 = get_cached_without_upstream(
                    proxy_session,
                    url,
                    test_server,
                    "/cache-control/changing",
                    headers=policy_headers(config["cache_policy"]),
                )
                assert_cached_response(cached2)
                assert version_from_response(cached2) == expected_version
            else:
                stats = test_server.stats()
                assert get_method_count(stats, "/cache-control/changing", "GET") == 2
                assert "Cache-Status" not in r2.headers

    def test_policy_stale_if_error_404(self, proxy_session, test_server, cache_bust_random):
        # Ensures StaleIfError serves cached content on upstream 404.
        test_server.reset()
        url = test_server.url(f"/policy/StaleIfError?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("StaleIfError"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        _ = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/StaleIfError",
            headers=policy_headers("StaleIfError"),
        )
        test_server.set_policy_override("StaleIfError", status=404)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/StaleIfError",
            headers=policy_headers("StaleIfError"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_policy_stale_if_error_500(self, proxy_session, test_server, cache_bust_random):
        # Ensures StaleIfError serves cached content on upstream 500.
        test_server.reset()
        url = test_server.url(f"/policy/StaleIfError?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("StaleIfError"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        _ = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/StaleIfError",
            headers=policy_headers("StaleIfError"),
        )
        test_server.set_policy_override("StaleIfError", status=500)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/StaleIfError",
            headers=policy_headers("StaleIfError"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    @pytest.mark.slow
    def test_policy_stale_if_error_timeout(self, proxy_session, test_server, cache_bust_random):
        # Ensures StaleIfError serves cached content on upstream timeout.
        test_server.reset()
        url = test_server.url(f"/policy/StaleIfError?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("StaleIfError"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        _ = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/StaleIfError",
            headers=policy_headers("StaleIfError"),
        )
        test_server.set_policy_override("StaleIfError", delay=15)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/StaleIfError",
            headers=policy_headers("StaleIfError"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_stale_if_error_fallback_on_expired_upstream_failure(
        self, proxy_session, test_server, cache_bust_random
    ):
        # Ensures StaleIfError serves stale cache on upstream failure while others return errors.
        test_server.reset()
        case_random = uuid.uuid4().hex
        url = test_server.url(
            f"/cache-control/max-age-low?random={cache_bust_random}&case={case_random}"
        )
        r1 = proxy_get(proxy_session, url, headers=policy_headers("StaleIfError"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        cached = get_cached_without_upstream(
            proxy_session,
            url,
            headers=policy_headers("StaleIfError"),
            test_server=test_server,
            path="/cache-control/max-age-low",
            retries=10,
            sleep_seconds=SYNC_SETTLE_SECONDS,
        )
        assert "Cache-Status" in cached.headers
        time.sleep(SYNC_SETTLE_SECONDS + 2)
        test_server.set_path_override("/cache-control/max-age-low", status=500)
        r2 = proxy_get(proxy_session, url, headers=policy_headers("StaleIfError"), timeout=30)
        assert r1.ok and r2.ok
        assert_cached_response(r2)

        stats = test_server.stats()
        before_get = get_method_count(stats, "/cache-control/max-age-low", "GET")
        before_head = get_method_count(stats, "/cache-control/max-age-low", "HEAD")
        r3 = proxy_get(proxy_session, url, headers=policy_headers("NoRefresh"), timeout=30)
        stats = test_server.stats()
        after_get = get_method_count(stats, "/cache-control/max-age-low", "GET")
        after_head = get_method_count(stats, "/cache-control/max-age-low", "HEAD")
        assert r3.ok
        assert_cached_response(r3)
        assert after_get == before_get
        assert after_head == before_head

        for policy_name in ("Standard", "AlwaysUpstream", "NoCache"):
            resp = proxy_get(proxy_session, url, headers=policy_headers(policy_name), timeout=30)
            assert resp.status_code == 500
            assert "Cache-Status" not in resp.headers

    def test_cache_control_no_store(self, proxy_session, test_server, cache_bust_random):
        # Ensures Cache-Control: no-store prevents caching.
        test_server.reset()
        url = test_server.url(f"/cache-control/no-store?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, timeout=30)
        r2 = proxy_get(proxy_session, url, timeout=30)
        assert r1.ok and r2.ok
        stats = test_server.stats()
        assert get_method_count(stats, "/cache-control/no-store", "GET") == 2

    def test_cache_control_no_cache(self, proxy_session, test_server, cache_bust_random):
        # Ensures Cache-Control: no-cache forces revalidation (HEAD) while using cache.
        test_server.reset()
        url = test_server.url(f"/cache-control/no-cache?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session, url, test_server, "/cache-control/no-cache"
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_request_no_cache_revalidates(self, proxy_session, test_server, cache_bust_random):
        # Ensures request Cache-Control: no-cache forces revalidation.
        test_server.reset()
        url = test_server.url(f"/cache-control/max-age?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        stats = test_server.stats()
        before_head = get_method_count(stats, "/cache-control/max-age", "HEAD")
        r2 = proxy_get(
            proxy_session,
            url,
            headers={"Cache-Control": "no-cache"},
            timeout=30,
        )
        stats = test_server.stats()
        after_head = get_method_count(stats, "/cache-control/max-age", "HEAD")
        assert r1.ok and r2.ok
        assert after_head == before_head + 1

    def test_cache_control_max_age(self, proxy_session, test_server, cache_bust_random):
        # Ensures Cache-Control: max-age keeps cached content fresh.
        test_server.reset()
        url = test_server.url(f"/cache-control/max-age?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session, url, test_server, "/cache-control/max-age"
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_cache_control_max_age_expires(self, proxy_session, test_server, cache_bust_random):
        # Ensures Cache-Control: max-age expiry triggers revalidation.
        test_server.reset()
        case_random = uuid.uuid4().hex
        url = test_server.url(
            f"/cache-control/max-age-low?random={cache_bust_random}&case={case_random}"
        )
        r1 = proxy_get(proxy_session, url, headers=policy_headers("Standard"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS + 2)
        r2 = proxy_get(proxy_session, url, headers=policy_headers("Standard"), timeout=30)
        assert r1.ok and r2.ok
        stats = test_server.stats()
        assert get_method_count(stats, "/cache-control/max-age-low", "GET") == 1
        assert get_method_count(stats, "/cache-control/max-age-low", "HEAD") == 2
        assert_cached_response(r2)

    def test_cached_redirect_preserves_status_and_location(
        self, proxy_session, test_server, cache_bust_random
    ):
        # Ensures cached redirects preserve status code and Location header.
        test_server.reset()
        url = test_server.url(f"/redirect?random={cache_bust_random}")
        r1 = proxy_get(
            proxy_session, url, headers=policy_headers("Standard"), timeout=30, allow_redirects=False
        )
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/redirect",
            headers=policy_headers("Standard"),
            timeout=30,
            allow_redirects=False,
        )
        assert r1.status_code == 302
        assert r2.status_code == 302
        assert r2.headers.get("Location") == "/redirect-target"
        assert_cached_response(r2)

    def test_cached_headers_preserved(self, proxy_session, test_server, cache_bust_random):
        # Ensures cached hits preserve key response headers.
        test_server.reset()
        url = test_server.url(f"/headers?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("Standard"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/headers",
            headers=policy_headers("Standard"),
        )
        assert r1.ok and r2.ok
        if cache_redirect_enabled() and has_cache_redirect(r2):
            assert_cached_response(r2)
            return
        assert r2.headers.get("Content-Language") == "en"
        assert r2.headers.get("Content-Disposition") == "inline"
        assert r2.headers.get("Content-Location") == "/headers"
        assert r2.headers.get("Accept-Ranges") == "bytes"
        assert r2.headers.get("Link") == '</style.css>; rel="preload"; as="style"'
        assert_cached_response(r2)

    def test_standard_stale_if_error_directive(self, proxy_session, test_server, cache_bust_random):
        # Ensures stale-if-error allows Standard to serve stale cache on upstream failure.
        test_server.reset()
        url = test_server.url(f"/cache-control/stale-if-error?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("Standard"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS + 2)
        test_server.set_path_override("/cache-control/stale-if-error", status=500)
        r2 = proxy_get(proxy_session, url, headers=policy_headers("Standard"), timeout=30)
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_standard_stale_while_revalidate_directive(
        self, proxy_session, test_server, cache_bust_random
    ):
        # Ensures stale-while-revalidate allows serving stale cache without upstream fetch.
        test_server.reset()
        url = test_server.url(f"/cache-control/stale-while-revalidate?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("Standard"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS + 2)
        stats = test_server.stats()
        before_get = get_method_count(stats, "/cache-control/stale-while-revalidate", "GET")
        before_head = get_method_count(stats, "/cache-control/stale-while-revalidate", "HEAD")
        r2 = proxy_get(proxy_session, url, headers=policy_headers("Standard"), timeout=30)
        stats = test_server.stats()
        after_get = get_method_count(stats, "/cache-control/stale-while-revalidate", "GET")
        after_head = get_method_count(stats, "/cache-control/stale-while-revalidate", "HEAD")
        assert r1.ok and r2.ok
        assert_cached_response(r2)
        assert after_get == before_get
        assert after_head == before_head

    @pytest.mark.slow
    def test_huge_streaming_body_no_oom(self, proxy_session, test_server, cache_bust_random):
        # Ensures large streaming responses do not require holding full body in memory.
        test_server.reset()
        available_bytes = get_available_memory_bytes()
        if not available_bytes:
            pytest.skip("Unable to read MemAvailable from /proc/meminfo")
        size_bytes = available_bytes * 2
        url = test_server.url(f"/stream/{size_bytes}?random={cache_bust_random}")
        resp = proxy_get(proxy_session, url, timeout=120, stream=True)
        resp.raise_for_status()
        received = 0
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if chunk:
                received += len(chunk)
        assert received == size_bytes

    def test_cache_control_expires(self, proxy_session, test_server, cache_bust_random):
        # Ensures Expires header is honored for cache freshness.
        test_server.reset()
        url = test_server.url(f"/cache-control/expires?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session, url, test_server, "/cache-control/expires"
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_vary_accept_encoding(self, proxy_session, test_server, cache_bust_random):
        # Ensures Vary: Accept-Encoding creates distinct cache variants.
        test_server.reset()
        url = test_server.url(f"/vary/accept-encoding?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers={"Accept-Encoding": "gzip"}, timeout=30)
        r2 = proxy_get(proxy_session, url, headers={"Accept-Encoding": "identity"}, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        assert r1.ok and r2.ok
        r3 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/vary/accept-encoding",
            headers={"Accept-Encoding": "gzip"},
        )
        r4 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/vary/accept-encoding",
            headers={"Accept-Encoding": "identity"},
        )
        assert r3.ok and r4.ok
        assert r3.text == "vary gzip"
        assert r4.text == "vary identity"

    def test_cached_gzip_content_encoding(self, proxy_session, test_server, cache_bust_random):
        test_server.reset()
        url = test_server.url(f"/encoding/gzip?random={cache_bust_random}")
        headers = {"Accept-Encoding": "gzip"}
        r1 = proxy_get(proxy_session, url, headers=headers, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/encoding/gzip",
            headers=headers,
        )
        assert r1.ok and r2.ok
        assert r2.headers.get("Content-Encoding") == "gzip"
        assert r2.json() == {"status": "ok", "encoding": "gzip"}
        assert_cached_response(r2)
        stats = test_server.stats()
        assert get_method_count(stats, "/encoding/gzip", "GET") == 1

    def test_refresh_pattern_override(self, proxy_session, test_server, cache_bust_random):
        # Ensures refresh_pattern overrides response headers for caching decisions.
        if not os.environ.get("PASSSAGE_REFRESH_PATTERN"):
            pytest.skip("PASSSAGE_REFRESH_PATTERN not configured for proxy")
        test_server.reset()
        url = test_server.url(f"/cache-control/no-store?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session, url, test_server, "/cache-control/no-store"
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "url",
        [
            "https://sha256.badssl.com/",
            "https://ecc384.badssl.com/",
            "https://rsa4096.badssl.com/",
        ],
    )
    def test_tls_connectivity_through_proxy(self, proxy_session, url):
        # Ensures TLS sites are reachable through the proxy with mitm cert.
        resp = proxy_session.get(url, timeout=30)
        resp.raise_for_status()

    @pytest.mark.integration
    def test_tls_expired_cert_rejected(self, proxy_session):
        # Ensures expired upstream certificates are rejected.
        resp = proxy_session.get("https://expired.badssl.com/", timeout=30)
        assert resp.status_code == 502


# ---------------------------------------------------------------------------
# Helpers for range tests
# ---------------------------------------------------------------------------

RANGE_DATA_SIZE = 256 * 1024  # 256 KiB deterministic body


def expected_bytes(start: int, length: int) -> bytes:
    """Generate the expected deterministic content: byte[i] = i % 256."""
    return bytes((start + i) % 256 for i in range(length))


def stream_sha256(resp: requests.Response) -> str:
    h = hashlib.sha256()
    for chunk in resp.iter_content(chunk_size=64 * 1024):
        h.update(chunk)
    return h.hexdigest()


@pytest.mark.integration
class TestRangeRequests:
    """HTTP Range request tests against the live proxy."""

    # -- basic range mechanics --

    def test_full_download_no_range(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=full")
        resp = proxy_get(proxy_session, url, timeout=30)
        assert resp.status_code == 200
        assert resp.headers.get("Accept-Ranges") == "bytes"
        assert len(resp.content) == RANGE_DATA_SIZE
        assert resp.content == expected_bytes(0, RANGE_DATA_SIZE)

    def test_range_first_byte(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=first")
        resp = proxy_get(proxy_session, url, headers={"Range": "bytes=0-0"}, timeout=30)
        assert resp.status_code == 206
        assert resp.content == expected_bytes(0, 1)
        assert f"bytes 0-0/{RANGE_DATA_SIZE}" in resp.headers.get("Content-Range", "")

    def test_range_last_byte(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=last")
        last = RANGE_DATA_SIZE - 1
        resp = proxy_get(proxy_session, url, headers={"Range": f"bytes={last}-{last}"}, timeout=30)
        assert resp.status_code == 206
        assert resp.content == expected_bytes(last, 1)
        assert f"bytes {last}-{last}/{RANGE_DATA_SIZE}" in resp.headers.get("Content-Range", "")

    def test_range_first_1k(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=1k")
        resp = proxy_get(proxy_session, url, headers={"Range": "bytes=0-1023"}, timeout=30)
        assert resp.status_code == 206
        assert len(resp.content) == 1024
        assert resp.content == expected_bytes(0, 1024)

    def test_range_last_1k(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=last1k")
        start = RANGE_DATA_SIZE - 1024
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": f"bytes={start}-{RANGE_DATA_SIZE - 1}"},
            timeout=30,
        )
        assert resp.status_code == 206
        assert len(resp.content) == 1024
        assert resp.content == expected_bytes(start, 1024)

    def test_range_middle_slice(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=mid")
        start = RANGE_DATA_SIZE // 3
        end = start + 4096 - 1
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": f"bytes={start}-{end}"},
            timeout=30,
        )
        assert resp.status_code == 206
        assert len(resp.content) == 4096
        assert resp.content == expected_bytes(start, 4096)

    def test_range_entire_file(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=entire")
        last = RANGE_DATA_SIZE - 1
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": f"bytes=0-{last}"},
            timeout=30,
        )
        assert resp.status_code in (200, 206)
        assert len(resp.content) == RANGE_DATA_SIZE
        assert resp.content == expected_bytes(0, RANGE_DATA_SIZE)

    # -- open-ended and suffix ranges --

    def test_range_open_ended(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=open")
        start = RANGE_DATA_SIZE - 512
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": f"bytes={start}-"},
            timeout=30,
        )
        assert resp.status_code == 206
        assert len(resp.content) == 512
        assert resp.content == expected_bytes(start, 512)

    def test_range_suffix(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=suffix")
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": "bytes=-256"},
            timeout=30,
        )
        assert resp.status_code == 206
        assert len(resp.content) == 256
        assert resp.content == expected_bytes(RANGE_DATA_SIZE - 256, 256)

    # -- boundary / alignment cases --

    def test_range_straddles_256_boundary(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=b256")
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": "bytes=255-256"},
            timeout=30,
        )
        assert resp.status_code == 206
        assert resp.content == expected_bytes(255, 2)

    def test_range_straddles_4k_boundary(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=b4k")
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": "bytes=4095-4096"},
            timeout=30,
        )
        assert resp.status_code == 206
        assert resp.content == expected_bytes(4095, 2)

    def test_range_straddles_64k_boundary(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=b64k")
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": "bytes=65535-65536"},
            timeout=30,
        )
        assert resp.status_code == 206
        assert resp.content == expected_bytes(65535, 2)

    # -- error cases --

    def test_range_unsatisfiable_beyond_end(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=416")
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": f"bytes={RANGE_DATA_SIZE}-{RANGE_DATA_SIZE + 100}"},
            timeout=30,
        )
        assert resp.status_code == 416
        assert f"*/{RANGE_DATA_SIZE}" in resp.headers.get("Content-Range", "")

    def test_range_end_clamped_to_file_size(self, proxy_session, test_server, cache_bust_random):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=clamp")
        far_end = RANGE_DATA_SIZE + 999999
        start = RANGE_DATA_SIZE - 100
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": f"bytes={start}-{far_end}"},
            timeout=30,
        )
        assert resp.status_code == 206
        assert len(resp.content) == 100
        assert resp.content == expected_bytes(start, 100)

    # -- content integrity: proxy vs direct --

    def test_range_content_matches_full_download(
        self, proxy_session, test_server, cache_bust_random
    ):
        size = 8192
        url = test_server.url(f"/range-data/{size}?r={cache_bust_random}&t=integrity")
        full = proxy_get(proxy_session, url, timeout=30)
        assert full.status_code == 200
        full_body = full.content
        time.sleep(SYNC_SETTLE_SECONDS)

        slices = [
            (0, 255),
            (100, 4095),
            (4096, size - 1),
            (size - 1, size - 1),
        ]
        for start, end in slices:
            resp = proxy_get(
                proxy_session, url,
                headers={"Range": f"bytes={start}-{end}"},
                timeout=30,
            )
            assert resp.status_code == 206, f"bytes={start}-{end} got {resp.status_code}"
            expected = full_body[start:end + 1]
            assert resp.content == expected, (
                f"bytes={start}-{end}: "
                f"expected {len(expected)} bytes, got {len(resp.content)}"
            )

    # -- streaming hash: verify large range without holding in memory --

    def test_range_streaming_hash(self, proxy_session, test_server, cache_bust_random):
        size = 128 * 1024
        url = test_server.url(f"/range-data/{size}?r={cache_bust_random}&t=hash")
        start = 1000
        end = size - 1001
        length = end - start + 1
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": f"bytes={start}-{end}"},
            timeout=30,
            stream=True,
        )
        assert resp.status_code == 206
        digest = stream_sha256(resp)
        resp.close()
        expected_digest = hashlib.sha256(expected_bytes(start, length)).hexdigest()
        assert digest == expected_digest

    # -- cached range responses --

    def test_range_after_cached_full_download(
        self, proxy_session, test_server, cache_bust_random
    ):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=cached")
        full = proxy_get(proxy_session, url, timeout=30)
        assert full.status_code == 200
        time.sleep(SYNC_SETTLE_SECONDS)

        resp = proxy_get(
            proxy_session, url,
            headers={"Range": "bytes=0-1023"},
            timeout=30,
        )
        assert resp.status_code in (200, 206)
        body = resp.content[:1024]
        assert body == expected_bytes(0, 1024)

    def test_range_cached_content_correct(
        self, proxy_session, test_server, cache_bust_random
    ):
        url = test_server.url(f"/range-data/{RANGE_DATA_SIZE}?r={cache_bust_random}&t=cached2")
        proxy_get(proxy_session, url, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)

        start = 10000
        end = 20000
        resp = proxy_get(
            proxy_session, url,
            headers={"Range": f"bytes={start}-{end}"},
            timeout=30,
        )
        assert resp.status_code in (200, 206)
        expected = expected_bytes(start, end - start + 1)
        actual = resp.content[:end - start + 1]
        assert actual == expected

    # -- 206 must not corrupt the cache --

    def test_cached_partial_must_not_corrupt_full_download(
        self, proxy_session, test_server, cache_bust_random
    ):
        """A cached 206 partial response must not be served for a subsequent full download."""
        size = 8192
        url = test_server.url(f"/range-data/{size}?r={cache_bust_random}&t=partial_corrupt")

        partial = proxy_get(
            proxy_session, url,
            headers={"Range": "bytes=0-255"},
            timeout=30,
        )
        assert partial.status_code == 206
        assert len(partial.content) == 256
        time.sleep(SYNC_SETTLE_SECONDS)

        full = proxy_get(proxy_session, url, timeout=30)
        assert full.status_code == 200, (
            f"Expected 200 for full download, got {full.status_code}"
        )
        assert len(full.content) == size, (
            f"Full download returned {len(full.content)} bytes, expected {size}. "
            "A cached 206 partial response may have corrupted the cache."
        )
        assert full.content == expected_bytes(0, size)

    def test_range_request_does_not_overwrite_cached_full(
        self, proxy_session, test_server, cache_bust_random
    ):
        """A range request on a cached full object must not replace it with partial content."""
        size = 8192
        url = test_server.url(f"/range-data/{size}?r={cache_bust_random}&t=overwrite")

        full1 = proxy_get(proxy_session, url, timeout=30)
        assert full1.status_code == 200
        assert len(full1.content) == size
        time.sleep(SYNC_SETTLE_SECONDS)

        proxy_get(
            proxy_session, url,
            headers={"Range": "bytes=0-255"},
            timeout=30,
        )
        time.sleep(SYNC_SETTLE_SECONDS)

        full2 = proxy_get(proxy_session, url, timeout=30)
        assert full2.status_code == 200, (
            f"Expected 200 for full download after range, got {full2.status_code}"
        )
        assert len(full2.content) == size, (
            f"Full download after range returned {len(full2.content)} bytes, expected {size}. "
            "A range request may have overwritten the cached full response."
        )
        assert full2.content == expected_bytes(0, size)
