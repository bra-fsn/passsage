"""Integration tests for the HTTP proxy against a live connection and live S3 backend."""

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
TEST_SERVER_BIND_HOST = os.environ.get("PASSAGE_TEST_SERVER_BIND_HOST", "127.0.0.1")
TEST_SERVER_PUBLIC_HOST = os.environ.get("PASSAGE_TEST_SERVER_HOST")
SYNC_SETTLE_SECONDS = float(os.environ.get("PASSAGE_SYNC_SETTLE_SECONDS", "1.0"))
POLICY_HEADER = "X-Passsage-Policy"

CONCURRENT_DELAY = 5
# Each request includes upstream HEAD + GET. If HEAD is delayed too, a single request
# takes ~2*CONCURRENT_DELAY. We expect concurrency, so each request should finish
# well under 2*CONCURRENT_DELAY*2 (sequential) and allow some buffer.
CONCURRENT_MAX_RESPONSE_TIME = CONCURRENT_DELAY * 4 * 0.8


def get_method_count(stats: dict, path: str, method: str) -> int:
    reqs = stats.get("requests", {}).get(path, [])
    return sum(1 for r in reqs if r.get("method") == method)


def assert_cached_response(resp: requests.Response) -> None:
    assert "Cache-Status" in resp.headers
    assert "Age" in resp.headers


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
    # Use PASSAGE_TEST_SERVER_HOST when the proxy runs in a container (e.g. host.docker.internal).
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
        if "Cache-Status" in last_resp.headers:
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
) -> requests.Response:
    last_resp = None
    for _ in range(retries):
        before = get_method_count(test_server.stats(), path, "GET")
        last_resp = proxy_get(session, url, headers=headers, timeout=timeout)
        after = get_method_count(test_server.stats(), path, "GET")
        if "Cache-Status" in last_resp.headers and after == before:
            return last_resp
        time.sleep(sleep_seconds)
    return last_resp


@pytest.mark.integration
class TestProxyLive:
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

    def test_policy_always_cached(self, proxy_session, test_server, cache_bust_random):
        # Ensures AlwaysCached serves from cache after the first request.
        test_server.reset()
        url = test_server.url(f"/policy/AlwaysCached?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("AlwaysCached"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/AlwaysCached",
            headers=policy_headers("AlwaysCached"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_policy_modified(self, proxy_session, test_server, cache_bust_random):
        # Ensures Modified reuses cached content when upstream is unchanged.
        test_server.reset()
        url = test_server.url(f"/policy/Modified?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("Modified"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/Modified",
            headers=policy_headers("Modified"),
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

    def test_policy_missing_cached_404(self, proxy_session, test_server, cache_bust_random):
        # Ensures MissingCached serves cached content on upstream 404.
        test_server.reset()
        url = test_server.url(f"/policy/MissingCached?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("MissingCached"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        _ = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/MissingCached",
            headers=policy_headers("MissingCached"),
        )
        test_server.set_policy_override("MissingCached", status=404)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/MissingCached",
            headers=policy_headers("MissingCached"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    def test_policy_missing_cached_500(self, proxy_session, test_server, cache_bust_random):
        # Ensures MissingCached serves cached content on upstream 500.
        test_server.reset()
        url = test_server.url(f"/policy/MissingCached?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("MissingCached"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        _ = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/MissingCached",
            headers=policy_headers("MissingCached"),
        )
        test_server.set_policy_override("MissingCached", status=500)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/MissingCached",
            headers=policy_headers("MissingCached"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

    @pytest.mark.slow
    def test_policy_missing_cached_timeout(self, proxy_session, test_server, cache_bust_random):
        # Ensures MissingCached serves cached content on upstream timeout.
        test_server.reset()
        url = test_server.url(f"/policy/MissingCached?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, headers=policy_headers("MissingCached"), timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS)
        _ = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/MissingCached",
            headers=policy_headers("MissingCached"),
        )
        test_server.set_policy_override("MissingCached", delay=15)
        r2 = get_cached_without_upstream(
            proxy_session,
            url,
            test_server,
            "/policy/MissingCached",
            headers=policy_headers("MissingCached"),
        )
        assert r1.ok and r2.ok
        assert_cached_response(r2)

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
        url = test_server.url(f"/cache-control/max-age-low?random={cache_bust_random}")
        r1 = proxy_get(proxy_session, url, timeout=30)
        time.sleep(SYNC_SETTLE_SECONDS + 2)
        r2 = proxy_get(proxy_session, url, timeout=30)
        assert r1.ok and r2.ok
        stats = test_server.stats()
        assert get_method_count(stats, "/cache-control/max-age-low", "GET") == 1
        assert get_method_count(stats, "/cache-control/max-age-low", "HEAD") == 2
        assert_cached_response(r2)

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

    def test_refresh_pattern_override(self, proxy_session, test_server, cache_bust_random):
        # Ensures refresh_pattern overrides response headers for caching decisions.
        if not os.environ.get("PASSAGE_REFRESH_PATTERN"):
            pytest.skip("PASSAGE_REFRESH_PATTERN not configured for proxy")
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
        assert resp.status_code == 504
