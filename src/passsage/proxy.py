# redirects
# handle upstream authentication
# collect and expose metrics/stats (with limited number of entries), like top list for misses, hits, etc.

import copy
import json
import hashlib
import logging
import os
import re
import socket
import ssl
import tempfile
import traceback
from functools import wraps
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable, Union
from urllib.parse import urlparse

import boto3
import pytz
import requests
from requests.exceptions import ConnectionError as RequestsConnectionError
from cachetools import TTLCache
from mitmproxy import ctx, http
from mitmproxy.script import concurrent
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from werkzeug.http import parse_date

from passsage.cache_key import (
    CacheKeyResolver,
    Context as CacheKeyContext,
    get_default_cache_key_resolver,
    set_default_cache_key_resolver,
)
from passsage.policy import (
    POLICY_BY_NAME,
    Context as PolicyContext,
    NoCache,
    NoRefresh,
    PolicyResolver,
    StaleIfError,
    Standard,
    get_default_resolver,
    policy_from_name,
    set_default_resolver,
)
from passsage.cache_utils import (
    memcached_key as _memcached_key,
    parse_memcached_servers as _parse_memcached_servers,
    url_ext as _url_ext,
    hashed_s3_key as _hashed_s3_key,
    get_cache_key,
    get_vary_index_key,
    MEMCACHED_MAX_KEY_LEN,
)
from passsage.log_storage import AccessLogWriter, ErrorLogWriter, build_access_log_config, build_error_log_config

try:
    from passsage import __version__
except ImportError:
    __version__ = "dev"

LOG = logging.getLogger("passsage.proxy")

SERVER_NAME = "passsage"
SERVER_VERSION = __version__
_VIA_HOSTNAME = (socket.gethostname() or SERVER_NAME).strip() or SERVER_NAME
VIA_HEADER_VALUE = f"1.1 {_VIA_HOSTNAME} ({SERVER_NAME}/{SERVER_VERSION})"
POLICY_HEADER = "X-Passsage-Policy"

_S3_ENDPOINT = os.environ.get("S3_ENDPOINT_URL")
S3_REGION = os.environ.get("AWS_DEFAULT_REGION", os.environ.get("AWS_REGION", "us-west-2"))
S3_BUCKET = os.environ.get("S3_BUCKET", "proxy-cache")
if _S3_ENDPOINT:
    p = urlparse(_S3_ENDPOINT)
    S3_HOST = p.hostname or "localhost"
    S3_PORT = p.port or (443 if p.scheme == "https" else 80)
    S3_SCHEME = p.scheme or "http"
    S3_URL = f"{S3_SCHEME}://{S3_HOST}:{S3_PORT}/{S3_BUCKET}"
    S3_PATH_STYLE = True
else:
    S3_HOST = f"{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com"
    S3_PORT = 80
    S3_SCHEME = "http"
    S3_URL = f"{S3_SCHEME}://{S3_HOST}"
    S3_PATH_STYLE = False
CACHE_TIMEOUT = 10
UPSTREAM_TIMEOUT = 10

_TRUTHY = ("1", "true", "yes")
_FALSY = ("0", "false", "no")


def _env_bool(name, default=""):
    return os.environ.get(name, default).strip().lower() in _TRUTHY


def _env_bool_default_true(name):
    return os.environ.get(name, "1").strip().lower() not in _FALSY


HEALTH_PORT = int(os.environ.get("PASSSAGE_HEALTH_PORT", "8082"))
HEALTH_HOST = os.environ.get("PASSSAGE_HEALTH_HOST", "0.0.0.0")
HEALTH_CHECK_S3 = _env_bool_default_true("PASSSAGE_HEALTH_CHECK_S3")
PUBLIC_PROXY_URL = os.environ.get("PASSSAGE_PUBLIC_PROXY_URL", "").strip()
ACCESS_LOGS = _env_bool("PASSSAGE_ACCESS_LOGS")
ACCESS_LOG_PREFIX = os.environ.get("PASSSAGE_ACCESS_LOG_PREFIX", "__passsage_logs__").strip()
ACCESS_LOG_DIR = os.environ.get("PASSSAGE_ACCESS_LOG_DIR", "/tmp/passsage-logs").strip()
ACCESS_LOG_FLUSH_SECONDS = os.environ.get("PASSSAGE_ACCESS_LOG_FLUSH_SECONDS", "30").strip()
ACCESS_LOG_FLUSH_BYTES = os.environ.get("PASSSAGE_ACCESS_LOG_FLUSH_BYTES", "1G").strip()
ACCESS_LOG_HEADERS = os.environ.get(
    "PASSSAGE_ACCESS_LOG_HEADERS",
    "accept,accept-encoding,cache-control,content-type,content-encoding,"
    "etag,last-modified,range,user-agent,via,x-cache,x-cache-lookup,x-amz-request-id",
).strip()
ERROR_LOGS = _env_bool("PASSSAGE_ERROR_LOGS")
ERROR_LOG_PREFIX = os.environ.get("PASSSAGE_ERROR_LOG_PREFIX", "__passsage_error_logs__").strip()
ERROR_LOG_DIR = os.environ.get("PASSSAGE_ERROR_LOG_DIR", "/tmp/passsage-errors").strip()
ERROR_LOG_FLUSH_SECONDS = os.environ.get("PASSSAGE_ERROR_LOG_FLUSH_SECONDS", "30").strip()
ERROR_LOG_FLUSH_BYTES = os.environ.get("PASSSAGE_ERROR_LOG_FLUSH_BYTES", "256M").strip()
OBJECT_STORE_URL = os.environ.get("PASSSAGE_OBJECT_STORE_URL", "").strip()


class _HealthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return
        ok, message = _health_check()
        body = (message or "ok").encode("utf-8")
        self.send_response(200 if ok else 503)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _health_check() -> tuple[bool, str]:
    if HEALTH_CHECK_S3:
        try:
            get_s3_client().head_bucket(Bucket=S3_BUCKET)
        except Exception as exc:
            return False, f"s3_unhealthy: {exc}"
    return True, "ok"


def _start_health_server() -> None:
    if HEALTH_PORT <= 0:
        return
    if getattr(ctx, "_health_server", None):
        return
    try:
        server = ThreadingHTTPServer((HEALTH_HOST, HEALTH_PORT), _HealthHandler)
    except OSError as exc:
        LOG.warning("Health server failed to bind to %s:%s: %s", HEALTH_HOST, HEALTH_PORT, exc)
        return
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ctx._health_server = server
    ctx._health_thread = thread


def get_s3_client(tls=threading.local()):
    """
    Always return the same S3 client to the same thread.

    This is to utilize urllib's HTTP connection pooling instead of creating a
    new pool for each thread.
    """
    try:
        return tls.s3
    except AttributeError:
        logging.getLogger("botocore.credentials").setLevel(logging.WARNING)
        kwargs = {"region_name": S3_REGION}
        if _S3_ENDPOINT:
            kwargs["endpoint_url"] = _S3_ENDPOINT
            kwargs["config"] = BotoConfig(s3={"addressing_style": "path"})
        else:
            kwargs["config"] = BotoConfig(signature_version="s3v4")
        tls.s3 = boto3.session.Session().client("s3", **kwargs)
        return tls.s3


@dataclass
class CacheMeta:
    """Result of a cache metadata lookup.

    *status_code* is 200 when metadata was found, 404 otherwise.
    *meta* is the parsed JSON metadata dict (empty on miss).
    *source* tracks where the metadata came from ("memcached" or "s3").
    """
    status_code: int
    meta: dict
    source: str = ""


def _s3_get_json(key: str) -> dict | None:
    """Read a JSON object from S3.  Returns the parsed dict or None on 404."""
    s3 = get_s3_client()
    try:
        resp = s3.get_object(Bucket=S3_BUCKET, Key=key)
        return json.loads(resp["Body"].read())
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code in ("404", "NoSuchKey", "NotFound"):
            return None
        raise


def _s3_put_json(key: str, data: dict) -> None:
    """Write a JSON object to S3."""
    get_s3_client().put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=json.dumps(data).encode("utf-8"),
        ContentType="application/json",
    )


def _no_proxy_s3_hosts() -> str:
    return S3_HOST


def load_proxy_env_script() -> bytes:
    try:
        from importlib import resources
        script = resources.files("passsage").joinpath("onboarding/proxy-env.sh").read_text()
        public_url = os.environ.get("PASSSAGE_PUBLIC_PROXY_URL", "").strip() or "http://localhost:8080"
        script = script.replace("__PASSSAGE_PUBLIC_PROXY_URL__", public_url)
        script = script.replace("__PASSSAGE_S3_HOST__", _no_proxy_s3_hosts())
        cert_pem = _read_ca_cert_pem()
        if cert_pem:
            script = script.replace("__PASSSAGE_MITM_CA_PEM__", cert_pem)
        return script.encode("utf-8")
    except Exception as exc:
        LOG.error("Failed to load proxy env script: %s", exc)
        return b""


def _read_ca_cert_pem() -> str:
    confdir = getattr(ctx.options, "confdir", None)
    if confdir:
        candidate = os.path.join(confdir, "mitmproxy-ca-cert.pem")
        if os.path.isfile(candidate):
            return Path(candidate).read_text()
    default_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    if os.path.isfile(default_path):
        return Path(default_path).read_text()
    LOG.error("Mitmproxy CA certificate not found in confdir or ~/.mitmproxy")
    return ""


def _is_tls_verify_error(err: Exception | None) -> bool:
    if err is None:
        return False
    if isinstance(err, (requests.exceptions.SSLError, ssl.SSLError)):
        return True
    message = str(err).lower()
    return "certificate verify failed" in message or "tls" in message


def _load_policy_module(path: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location("passsage_policy_overrides", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Unable to load policy file: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_policy_overrides(path: str) -> None:
    if not path:
        return
    try:
        module = _load_policy_module(path)
    except Exception as exc:
        LOG.error("Policy file load failed path=%s error=%s", path, exc)
        return
    policy_loaded = False
    cache_key_loaded = False

    if hasattr(module, "get_resolver"):
        resolver = module.get_resolver()
        if isinstance(resolver, PolicyResolver):
            set_default_resolver(resolver)
            LOG.info("Policy overrides loaded via get_resolver path=%s", path)
            policy_loaded = True
        else:
            LOG.error("Policy file get_resolver did not return PolicyResolver path=%s", path)
    elif hasattr(module, "get_rules"):
        rules = module.get_rules()
        if rules:
            set_default_resolver(PolicyResolver(rules=rules))
            LOG.info("Policy overrides loaded via get_rules path=%s", path)
            policy_loaded = True
        else:
            LOG.error("Policy file get_rules returned no rules path=%s", path)
    elif hasattr(module, "RULES"):
        rules = module.RULES
        if rules:
            set_default_resolver(PolicyResolver(rules=rules))
            LOG.info("Policy overrides loaded via RULES path=%s", path)
            policy_loaded = True
        else:
            LOG.error("Policy file RULES is empty path=%s", path)

    if hasattr(module, "get_cache_key_resolver"):
        resolver = module.get_cache_key_resolver()
        if isinstance(resolver, CacheKeyResolver):
            set_default_cache_key_resolver(resolver)
            LOG.info("Cache key overrides loaded via get_cache_key_resolver path=%s", path)
            cache_key_loaded = True
        else:
            LOG.error(
                "Policy file get_cache_key_resolver did not return CacheKeyResolver path=%s",
                path,
            )
    elif hasattr(module, "CACHE_KEY_RESOLVER"):
        resolver = module.CACHE_KEY_RESOLVER
        if isinstance(resolver, CacheKeyResolver):
            set_default_cache_key_resolver(resolver)
            LOG.info("Cache key overrides loaded via CACHE_KEY_RESOLVER path=%s", path)
            cache_key_loaded = True
        else:
            LOG.error(
                "Policy file CACHE_KEY_RESOLVER is not CacheKeyResolver path=%s",
                path,
            )
    elif hasattr(module, "get_cache_key_rules"):
        rules = module.get_cache_key_rules()
        if rules:
            set_default_cache_key_resolver(CacheKeyResolver(rules=rules))
            LOG.info("Cache key overrides loaded via get_cache_key_rules path=%s", path)
            cache_key_loaded = True
        else:
            LOG.error("Policy file get_cache_key_rules returned no rules path=%s", path)
    elif hasattr(module, "CACHE_KEY_RULES"):
        rules = module.CACHE_KEY_RULES
        if rules:
            set_default_cache_key_resolver(CacheKeyResolver(rules=rules))
            LOG.info("Cache key overrides loaded via CACHE_KEY_RULES path=%s", path)
            cache_key_loaded = True
        else:
            LOG.error("Policy file CACHE_KEY_RULES is empty path=%s", path)

    if not policy_loaded and not cache_key_loaded:
        LOG.error(
            "Policy file missing policy or cache-key hooks path=%s",
            path,
        )


def save_response(proxy, flow, data: bytes) -> Union[bytes, Iterable[bytes]]:
    """
    This function will be called for each chunk of request/response body data that arrives at the proxy,
    and once at the end of the message with an empty bytes argument (b"").

    It may either return bytes or an iterable of bytes (which would result in multiple HTTP/2 data frames).
    """
    if flow._counter not in proxy.files:
        proxy.files[flow._counter] = tempfile.TemporaryFile()
        proxy.hashes[flow._counter] = hashlib.sha224()

    proxy.files[flow._counter].write(data)
    proxy.hashes[flow._counter].update(data)
    return data


def _parse_single_range(header: str, total: int) -> tuple[int, int] | None:
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


def _is_unsatisfiable_range(header: str, total: int) -> bool:
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


def _make_range_stream(proxy, flow, start: int, end: int):
    """Return a stream function that saves the full body but serves only [start, end] to the client."""
    pos = [0]

    def stream_fn(data: bytes):
        saved = save_response(proxy, flow, data)
        if not data:
            return saved  # end-of-stream marker
        chunk_start = pos[0]
        chunk_end = chunk_start + len(data) - 1
        pos[0] += len(data)
        if chunk_end < start or chunk_start > end:
            return b""
        slice_start = max(0, start - chunk_start)
        slice_end = min(len(data), end - chunk_start + 1)
        return data[slice_start:slice_end]

    return stream_fn


def get_policy(flow):
    if (
        flow.request.headers
        and hasattr(ctx, "options")
        and getattr(ctx.options, "allow_policy_header", False)
    ):
        policy_name = flow.request.headers.get(POLICY_HEADER)
        if policy_name:
            policy = POLICY_BY_NAME.get(policy_name.strip().lower())
            if policy:
                LOG.debug("Policy header override=%s", policy_name)
                return policy
            LOG.warning("Unknown policy header override=%s", policy_name)
    request_ctx = PolicyContext(
        url=flow.request.url,
        method=flow.request.method,
        headers=list(flow.request.headers.items()) if flow.request.headers else None,
    )
    resolver = get_default_resolver()
    if hasattr(ctx, "options") and hasattr(ctx.options, "default_policy"):
        resolver.set_default_policy(policy_from_name(ctx.options.default_policy))
    return resolver.resolve(request_ctx)


def http_2xx(r):
    if r and 200 <= r.status_code <= 299:
        return True
    return False


def _is_connection_error(err: Exception | None) -> bool:
    if not err:
        return False
    if isinstance(err, RequestsConnectionError):
        return True
    return "Connection refused" in str(err) or "Failed to establish a new connection" in str(err)


def _build_upstream_error_response(status_code: int, title: str, detail: str) -> http.Response:
    body = f"""<html>
<head><title>{status_code} {title}</title></head>
<body>
<center><h1>{status_code} {title}</h1></center>
<p>Upstream request failed.</p>
<pre>{detail}</pre>
</body>
</html>""".encode("utf-8")
    return http.Response.make(status_code, body, {"Content-Type": "text/html"})


def _is_s3_cache_request(flow: http.HTTPFlow) -> bool:
    return flow.request.pretty_host == S3_HOST


def parse_cache_control(value: str) -> dict[str, str | bool]:
    directives: dict[str, str | bool] = {}
    if not value:
        return directives
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            directives[k.strip().lower()] = v.strip().strip('"')
        else:
            directives[part.lower()] = True
    return directives


def parse_cache_control_seconds(cc: dict[str, str | bool], name: str) -> int | None:
    value = cc.get(name)
    if value is None or value is True:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class RefreshPattern:
    pattern: re.Pattern[str]
    min_seconds: int
    percent: int
    max_seconds: int
    options: set[str]

    def ttl_seconds(self, now: datetime, meta: dict) -> int:
        lastmod = meta.get("last_modified")
        if lastmod:
            lastmod_dt = parse_date(lastmod)
            age = max(0, int((now - lastmod_dt).total_seconds())) if lastmod_dt else 0
        else:
            age = 0
        ttl = self.min_seconds + int(age * (self.percent / 100))
        if self.max_seconds > 0:
            ttl = min(ttl, self.max_seconds)
        return max(0, ttl)


def parse_refresh_patterns(spec: str) -> list[RefreshPattern]:
    patterns: list[RefreshPattern] = []
    for line in (spec or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        regex, min_s, percent, max_s, *opts = parts
        try:
            patterns.append(
                RefreshPattern(
                    pattern=re.compile(regex, re.IGNORECASE),
                    min_seconds=int(min_s),
                    percent=int(percent),
                    max_seconds=int(max_s),
                    options={o.lower() for o in opts},
                )
            )
        except Exception:
            continue
    return patterns


def cache_stored_at(meta: dict) -> datetime | None:
    stored = meta.get("stored_at")
    if stored is not None:
        try:
            return datetime.fromtimestamp(float(stored), tz=pytz.utc)
        except (ValueError, TypeError, OSError):
            return None
    return None


@dataclass(frozen=True)
class CacheFreshness:
    age_seconds: int
    ttl_seconds: int | None
    is_fresh: bool
    stale_while_revalidate_seconds: int | None
    stale_if_error_seconds: int | None
    allow_stale_while_revalidate: bool
    allow_stale_if_error: bool


def cache_ttl_seconds(
    url: str,
    meta: dict,
    refresh_patterns: list[RefreshPattern],
    now: datetime,
    stored_at: datetime,
) -> int | None:
    for pattern in refresh_patterns:
        if pattern.pattern.search(url):
            return pattern.ttl_seconds(now, meta)
    hdrs = meta.get("headers", {})
    cc = parse_cache_control(hdrs.get("cache-control", ""))
    if "no-store" in cc:
        return None
    if "no-cache" in cc:
        return 0
    if (s_maxage := cc.get("s-maxage")) is not None:
        try:
            return int(s_maxage)
        except ValueError:
            return None
    if (max_age := cc.get("max-age")) is not None:
        try:
            return int(max_age)
        except ValueError:
            return None
    if (exp := hdrs.get("expires")):
        exp_dt = parse_date(exp)
        if exp_dt:
            return max(0, int((exp_dt - stored_at).total_seconds()))
    if (lastmod := meta.get("last_modified")):
        lastmod_dt = parse_date(lastmod)
        if lastmod_dt:
            lifetime = max(0, int((now - lastmod_dt).total_seconds() * 0.1))
            return lifetime
    return None


def cache_freshness(
    url: str, meta: dict, refresh_patterns: list[RefreshPattern]
) -> CacheFreshness:
    now = datetime.now(tz=pytz.utc)
    stored_at = cache_stored_at(meta)
    if stored_at is None:
        return CacheFreshness(
            age_seconds=0,
            ttl_seconds=None,
            is_fresh=False,
            stale_while_revalidate_seconds=None,
            stale_if_error_seconds=None,
            allow_stale_while_revalidate=False,
            allow_stale_if_error=False,
        )
    age_seconds = max(0, int((now - stored_at).total_seconds()))
    hdrs = meta.get("headers", {})
    cc = parse_cache_control(hdrs.get("cache-control", ""))
    ttl_seconds = cache_ttl_seconds(url, meta, refresh_patterns, now, stored_at)
    is_fresh = ttl_seconds is not None and age_seconds < ttl_seconds
    stale_while_revalidate_seconds = parse_cache_control_seconds(cc, "stale-while-revalidate")
    stale_if_error_seconds = parse_cache_control_seconds(cc, "stale-if-error")
    allow_stale_while_revalidate = False
    if (
        not is_fresh
        and ttl_seconds is not None
        and stale_while_revalidate_seconds is not None
        and age_seconds <= ttl_seconds + stale_while_revalidate_seconds
        and "must-revalidate" not in cc
        and "proxy-revalidate" not in cc
    ):
        allow_stale_while_revalidate = True
    allow_stale_if_error = False
    if (
        not is_fresh
        and ttl_seconds is not None
        and stale_if_error_seconds is not None
        and age_seconds <= ttl_seconds + stale_if_error_seconds
    ):
        allow_stale_if_error = True
    if not allow_stale_if_error and "immutable" in cc and not is_fresh and ttl_seconds is not None:
        # Immutable implies the resource is versioned; if upstream fails after expiry,
        # allow serving the stale cached copy even without stale-if-error.
        allow_stale_if_error = True
    return CacheFreshness(
        age_seconds=age_seconds,
        ttl_seconds=ttl_seconds,
        is_fresh=is_fresh,
        stale_while_revalidate_seconds=stale_while_revalidate_seconds,
        stale_if_error_seconds=stale_if_error_seconds,
        allow_stale_while_revalidate=allow_stale_while_revalidate,
        allow_stale_if_error=allow_stale_if_error,
    )


def request_requires_revalidation(request_headers: dict[str, str], freshness: CacheFreshness) -> bool:
    cc = parse_cache_control(request_headers.get("cache-control", ""))
    if "no-cache" in cc:
        return True
    if (req_max_age := parse_cache_control_seconds(cc, "max-age")) is not None:
        return freshness.age_seconds > req_max_age
    return False


def _normalize_etag(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def apply_cached_metadata(flow: http.HTTPFlow) -> None:
    """Apply cached metadata from flow._cache_head to the response."""
    meta = getattr(flow, "_cache_head", None)
    if not meta or not meta.meta:
        return
    m = meta.meta
    if (status_code := m.get("status_code")):
        if flow.response.status_code != 206:
            flow.response.status_code = int(status_code)
    if (reason := m.get("reason")):
        flow.response.reason = reason
    for k, v in m.get("headers", {}).items():
        flow.response.headers[k] = v
    if (lastmod := m.get("last_modified")):
        flow.response.headers["last-modified"] = lastmod


def refresh_cache_metadata(cache_key: str, meta: dict) -> None:
    """Update stored_at timestamp in the .meta JSON and sync to memcached."""
    meta = dict(meta)
    meta["stored_at"] = time.time()
    try:
        _s3_put_json(f"{cache_key}.meta", meta)
    except Exception as exc:
        LOG.warning("Cache metadata refresh failed for %s: %s", cache_key, exc)
    mc = _get_memcached_client()
    if mc:
        try:
            _memcached_set_metadata(mc, cache_key, meta)
        except Exception as exc:
            LOG.debug("Memcached set on metadata refresh failed: %s", exc)


def _update_memcached_client() -> None:
    servers_str = getattr(ctx.options, "memcached_servers", "") or ""
    ctx._passsage_memcached = None
    if not servers_str.strip():
        return
    servers = _parse_memcached_servers(servers_str)
    if not servers:
        return
    try:
        from pymemcache.client.hash import HashClient
        ctx._passsage_memcached = HashClient(
            servers,
            connect_timeout=2,
            timeout=2,
            dead_timeout=30,
            retry_attempts=2,
            retry_timeout=1,
        )
    except Exception as exc:
        LOG.warning("Memcached client init failed: %s", exc)


def _get_memcached_client():
    if not hasattr(ctx, "_passsage_memcached"):
        _update_memcached_client()
    return getattr(ctx, "_passsage_memcached", None)


def _memcached_set_metadata(mc, cache_key: str, meta: dict) -> None:
    mc.set(_memcached_key(cache_key), json.dumps(meta), expire=0)


def get_cache_metadata(cache_key: str) -> CacheMeta:
    mc = _get_memcached_client()
    if mc:
        try:
            raw = mc.get(_memcached_key(cache_key))
            if raw is not None:
                meta = json.loads(raw) if isinstance(raw, bytes) else json.loads(str(raw))
                return CacheMeta(200, meta, source="memcached")
        except Exception as exc:
            LOG.debug("Memcached get for cache metadata failed: %s", exc)
    data = _s3_get_json(f"{cache_key}.meta")
    if data is None:
        return CacheMeta(404, {}, source="s3")
    if mc:
        try:
            _memcached_set_metadata(mc, cache_key, data)
        except Exception as exc:
            LOG.debug("Memcached write-back for cache metadata failed: %s", exc)
    return CacheMeta(200, data, source="s3")


def get_vary_index(vary_index_key: str) -> CacheMeta:
    mc = _get_memcached_client()
    if mc:
        try:
            raw = mc.get(_memcached_key(vary_index_key))
            if raw is not None:
                data = json.loads(raw) if isinstance(raw, bytes) else json.loads(str(raw))
                return CacheMeta(200, data, source="memcached")
        except Exception as exc:
            LOG.debug("Memcached get for vary index failed: %s", exc)
    data = _s3_get_json(vary_index_key)
    if data is None:
        return CacheMeta(404, {}, source="s3")
    if mc:
        try:
            mc.set(_memcached_key(vary_index_key), json.dumps(data), expire=0)
        except Exception as exc:
            LOG.debug("Memcached write-back for vary index failed: %s", exc)
    return CacheMeta(200, data, source="s3")


def get_refresh_patterns() -> list[RefreshPattern]:
    spec = getattr(ctx.options, "refresh_pattern", "") if hasattr(ctx, "options") else ""
    cached = getattr(ctx, "_refresh_patterns_cache", None)
    if cached and cached.get("spec") == spec:
        return cached["patterns"]
    patterns = parse_refresh_patterns(spec)
    ctx._refresh_patterns_cache = {"spec": spec, "patterns": patterns}
    return patterns


def _parse_header_names(raw: str) -> list[str]:
    return [name.strip().lower() for name in raw.split(",") if name.strip()]


def _select_headers(headers, names: list[str]) -> dict[str, str]:
    if not headers or not names:
        return {}
    selected: dict[str, str] = {}
    for name in names:
        value = headers.get(name)
        if value is not None:
            selected[name] = value
    return selected


def _safe_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _access_log_writer() -> AccessLogWriter | None:
    return getattr(ctx, "_access_log_writer", None)


def _error_log_writer() -> ErrorLogWriter | None:
    return getattr(ctx, "_error_log_writer", None)


def _log_exception(
    exc: Exception,
    *,
    flow=None,
    context: dict | None = None,
    error_type: str | None = None,
    request_url: str | None = None,
    method: str | None = None,
    request_headers: dict | None = None,
) -> None:
    writer = _error_log_writer()
    if not writer:
        LOG.exception("Unhandled error: %s", exc)
        return
    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    try:
        writer.add(
            _build_error_log_record(
                error_type=error_type or type(exc).__name__,
                error_message=str(exc),
                traceback_text=tb_text,
                context=context or {},
                flow=flow,
                request_url=request_url,
                method=method,
                request_headers=request_headers,
            )
        )
    except Exception as write_exc:
        LOG.debug("Error log write skipped: %s", write_exc)


def _log_hook_errors(hook_name: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            flow = kwargs.get("flow")
            if flow is None:
                for arg in args:
                    if isinstance(arg, http.HTTPFlow):
                        flow = arg
                        break
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                _log_exception(exc, flow=flow, context={"hook": hook_name})
                raise

        return wrapper

    return decorator


def _init_access_logs() -> None:
    writer = _access_log_writer()
    if not getattr(ctx.options, "access_logs", False):
        if writer:
            writer.stop()
        ctx._access_log_writer = None
        return
    config = build_access_log_config(
        S3_BUCKET,
        getattr(ctx.options, "access_log_prefix", ACCESS_LOG_PREFIX),
        getattr(ctx.options, "access_log_dir", ACCESS_LOG_DIR),
        getattr(ctx.options, "access_log_flush_seconds", ACCESS_LOG_FLUSH_SECONDS),
        getattr(ctx.options, "access_log_flush_bytes", ACCESS_LOG_FLUSH_BYTES),
    )
    if writer:
        writer.stop()
    ctx._access_log_writer = AccessLogWriter(get_s3_client(), config, LOG)
    ctx._access_log_header_names = _parse_header_names(
        getattr(ctx.options, "access_log_headers", ACCESS_LOG_HEADERS)
    )
    ctx._access_log_writer.start()


def _init_error_logs() -> None:
    writer = _error_log_writer()
    if not getattr(ctx.options, "error_logs", False):
        if writer:
            writer.stop()
        ctx._error_log_writer = None
        return
    config = build_error_log_config(
        S3_BUCKET,
        getattr(ctx.options, "error_log_prefix", ERROR_LOG_PREFIX),
        getattr(ctx.options, "error_log_dir", ERROR_LOG_DIR),
        getattr(ctx.options, "error_log_flush_seconds", ERROR_LOG_FLUSH_SECONDS),
        getattr(ctx.options, "error_log_flush_bytes", ERROR_LOG_FLUSH_BYTES),
    )
    if writer:
        writer.stop()
    ctx._error_log_writer = ErrorLogWriter(get_s3_client(), config, LOG)
    ctx._error_log_header_names = _parse_header_names(
        getattr(ctx.options, "access_log_headers", ACCESS_LOG_HEADERS)
    )
    ctx._error_log_writer.start()


def _build_access_log_record(flow, error: str | None = None) -> dict:
    now = time.time()
    start_ts = getattr(flow, "_access_log_start", now)
    duration_ms = int((now - start_ts) * 1000)
    start_dt = datetime.fromtimestamp(start_ts, tz=pytz.utc)
    request_url = getattr(flow, "_req_orig_url", None) or flow.request.url
    parsed = urlparse(request_url)
    client_addr = getattr(flow.client_conn, "peername", None) or ()
    client_ip = client_addr[0] if isinstance(client_addr, tuple) and client_addr else None
    client_port = client_addr[1] if isinstance(client_addr, tuple) and len(client_addr) > 1 else None
    request_headers = _select_headers(
        flow.request.headers,
        getattr(ctx, "_access_log_header_names", []),
    )
    response = getattr(flow, "response", None)
    response_headers = (
        _select_headers(response.headers, getattr(ctx, "_access_log_header_names", []))
        if response
        else {}
    )
    content_length = None
    if response:
        content_length = _safe_int(response.headers.get("content-length"))
    if content_length is None and response and response.content is not None:
        content_length = len(response.content)
    cache_head = getattr(flow, "_cache_head", None)
    upstream_head = getattr(flow, "_upstream_head", None)
    upstream_error = getattr(flow, "_upstream_error", None)
    upstream_head_time = getattr(flow, "_upstream_head_time_ms", None)
    return {
        "timestamp": start_dt,
        "request_id": getattr(flow, "id", None),
        "client_ip": client_ip,
        "client_port": _safe_int(client_port),
        "method": flow.request.method,
        "url": request_url,
        "host": parsed.hostname,
        "scheme": parsed.scheme,
        "port": _safe_int(parsed.port),
        "path": parsed.path,
        "query": parsed.query,
        "user_agent": flow.request.headers.get("User-Agent"),
        "request_headers": request_headers,
        "status_code": response.status_code if response else None,
        "reason": response.reason if response else None,
        "response_headers": response_headers,
        "content_length": content_length,
        "content_type": response.headers.get("content-type") if response else None,
        "content_encoding": response.headers.get("content-encoding") if response else None,
        "policy": getattr(flow, "_policy", None).__name__ if getattr(flow, "_policy", None) else None,
        "cached": getattr(flow, "_cached", None),
        "cache_key": getattr(flow, "_cache_key", None),
        "cache_vary": getattr(flow, "_cache_vary", None),
        "cache_hit": getattr(flow, "_cache_hit", None),
        "cache_fresh": getattr(flow, "_cache_fresh", None),
        "stale_while_revalidate": getattr(flow, "_allow_stale_while_revalidate", None),
        "stale_if_error": getattr(flow, "_allow_stale_if_error", None),
        "upstream_head_status": upstream_head.status_code if upstream_head else None,
        "upstream_error": str(upstream_error) if upstream_error else None,
        "upstream_head_time_ms": upstream_head_time,
        "cache_head_status": cache_head.status_code if cache_head else None,
        "cache_head_etag": cache_head.meta.get("headers", {}).get("etag") if cache_head else None,
        "cache_head_last_modified": cache_head.meta.get("last_modified") if cache_head else None,
        "cache_head_method": cache_head.meta.get("method") if cache_head else None,
        "metadata_source": getattr(flow, "_metadata_source", None),
        "serve_reason": getattr(flow, "_serve_reason", None),
        "cached_method": getattr(flow, "_cached_method", None),
        "vary_index_key": getattr(flow, "_vary_index_key", None),
        "cache_save": getattr(flow, "_cache_saved", False),
        "range_stripped": getattr(flow, "_range_stripped", False),
        "object_store_rewrite": getattr(flow, "_object_store_rewrite", False),
        "error": error,
        "duration_ms": duration_ms,
        "bytes_sent": content_length,
    }


def _build_error_log_record(
    error_type: str,
    error_message: str,
    traceback_text: str,
    context: dict | None = None,
    flow=None,
    request_url: str | None = None,
    method: str | None = None,
    request_headers: dict | None = None,
) -> dict:
    now = time.time()
    start_ts = getattr(flow, "_access_log_start", now) if flow else now
    start_dt = datetime.fromtimestamp(start_ts, tz=pytz.utc)
    url_value = request_url or (flow.request.url if flow else None)
    parsed = urlparse(url_value) if url_value else None
    client_addr = getattr(flow.client_conn, "peername", None) if flow else None
    client_addr = client_addr or ()
    client_ip = client_addr[0] if isinstance(client_addr, tuple) and client_addr else None
    client_port = client_addr[1] if isinstance(client_addr, tuple) and len(client_addr) > 1 else None
    selected_request_headers = (
        _select_headers(
            flow.request.headers,
            getattr(ctx, "_error_log_header_names", []),
        )
        if flow
        else request_headers
        or {}
    )
    response = getattr(flow, "response", None) if flow else None
    response_headers = (
        _select_headers(response.headers, getattr(ctx, "_error_log_header_names", []))
        if response
        else {}
    )
    cache_head = getattr(flow, "_cache_head", None) if flow else None
    upstream_head = getattr(flow, "_upstream_head", None) if flow else None
    upstream_error = getattr(flow, "_upstream_error", None) if flow else None
    policy = getattr(flow, "_policy", None) if flow else None
    return {
        "timestamp": start_dt,
        "request_id": getattr(flow, "id", None) if flow else None,
        "client_ip": client_ip,
        "client_port": _safe_int(client_port),
        "method": method or (flow.request.method if flow else None),
        "url": url_value,
        "host": parsed.hostname if parsed else None,
        "scheme": parsed.scheme if parsed else None,
        "port": _safe_int(parsed.port) if parsed else None,
        "path": parsed.path if parsed else None,
        "query": parsed.query if parsed else None,
        "user_agent": flow.request.headers.get("User-Agent") if flow else None,
        "request_headers": selected_request_headers,
        "status_code": response.status_code if response else None,
        "response_headers": response_headers,
        "policy": policy.__name__ if policy else None,
        "cached": getattr(flow, "_cached", None) if flow else None,
        "cache_key": getattr(flow, "_cache_key", None) if flow else None,
        "cache_vary": getattr(flow, "_cache_vary", None) if flow else None,
        "serve_reason": getattr(flow, "_serve_reason", None) if flow else None,
        "cache_head_status": cache_head.status_code if cache_head else None,
        "upstream_head_status": upstream_head.status_code if upstream_head else None,
        "upstream_error": str(upstream_error) if upstream_error else None,
        "error_type": error_type,
        "error_message": error_message,
        "traceback": traceback_text,
        "context": json.dumps(context or {}, default=str),
    }


def _normalize_url(flow) -> str:
    request_ctx = CacheKeyContext(
        url=flow.request.url,
        method=flow.request.method,
        headers=list(flow.request.headers.items()) if flow.request.headers else None,
    )
    resolver = get_default_cache_key_resolver()
    return resolver.resolve(request_ctx)



def compute_vary_key(vary_header: str, request_headers) -> str | None:
    raw = build_vary_request(vary_header, request_headers)
    if raw is None:
        return None
    return hashlib.sha224(raw.encode("utf-8")).hexdigest()


def build_vary_request(vary_header: str, request_headers) -> str | None:
    if "*" in vary_header:
        return None
    names = [n.strip().lower() for n in vary_header.split(",") if n.strip()]
    parts = [f"{name}={request_headers.get(name, '')}" for name in names]
    return "|".join(parts)


def _rewrite_to_object_store(flow):
    """Rewrite the request to fetch the cached object from the object store.

    Modifies flow.request in-place to point at the configured object store
    URL.  The response will be handled by mitmproxy's normal proxy flow;
    metadata headers are applied later in responseheaders.
    """
    store_url = ctx.options.object_store_url
    parsed = urlparse(store_url)
    flow.request.scheme = parsed.scheme or "http"
    flow.request.host = parsed.hostname
    flow.request.port = parsed.port or (443 if parsed.scheme == "https" else 80)
    base = parsed.path.rstrip("/")
    flow.request.path = f"{base}/{flow._cache_key}"
    flow._object_store_rewrite = True
    flow._cached = True
    flow._save_response = False


def _fallback_fetch_from_object_store(flow) -> bool:
    """Fetch from the object store when we cannot rewrite (responseheaders fallback).

    Used for stale-if-error when the upstream already returned an error response
    and we need to replace it with the cached object.  Returns True on success.
    """
    cache_key = flow._cache_key
    if not cache_key:
        return False
    store_url = ctx.options.object_store_url
    parsed = urlparse(store_url)
    base = parsed.path.rstrip("/")
    url = f"{parsed.scheme}://{parsed.netloc}{base}/{cache_key}"
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            LOG.warning("Object store fallback returned %s for key=%s", resp.status_code, cache_key)
            return False
        flow.response = http.Response.make(200, resp.content, {
            "Content-Type": resp.headers.get("content-type", "application/octet-stream"),
        })
        flow.response.headers["accept-ranges"] = "bytes"
        flow._save_response = False
        flow._cached = True
        return True
    except Exception as exc:
        LOG.warning("Object store fallback failed for key=%s: %s", cache_key, exc)
        return False



def release_banned():
    # first called from __init__, when we may not yet have the option
    if not hasattr(ctx.options, "test"):
        time.sleep(5)
        ctx._executor.submit(release_banned)
        return

    if ctx.options.test:
        # don't release banned sites in test mode
        return

    with ctx._lock:
        banned = copy.deepcopy(ctx._banned)

    for (host, port, scheme) in banned:
        # this might take a while to loop through, so first check if it's
        # still there
        with ctx._lock:
            if (host, port, scheme) not in ctx._banned:
                continue

        try:
            requests.head(f"{scheme}://{host}:{port}/", timeout=8)
        except Exception as e:
            print(e)
        else:
            with ctx._lock:
                if (host, port, scheme) in ctx._banned:
                    LOG.info("REMOVE BAN for %s", (scheme, host, port))
                    del ctx._banned[(host, port, scheme)]

    time.sleep(60)
    ctx._executor.submit(release_banned)


class Proxy:
    def __init__(self):
        self.files = {}
        self.hashes = {}
        self.counter = 0
        if not getattr(ctx, "_executor", None):
            # don't (re)create these on code reloads
            ctx._lock = threading.Lock()
            ctx._executor = ThreadPoolExecutor()
            ctx._banned = TTLCache(maxsize=2048, ttl=600)
            ctx._executor.submit(release_banned)
            _start_health_server()

    @_log_hook_errors("load")
    def load(self, loader):
        loader.add_option(
            name="test",
            typespec=bool,
            default=False,
            help="Run in test mode, where banned sites are not removed",
        )
        loader.add_option(
            name="default_policy",
            typespec=str,
            default="Standard",
            help="Default policy when no rule matches (e.g. Standard, StaleIfError)",
        )
        loader.add_option(
            name="upstream_head_timeout",
            typespec=float,
            default=UPSTREAM_TIMEOUT,
            help="Timeout (seconds) for upstream HEAD requests",
        )
        loader.add_option(
            name="refresh_pattern",
            typespec=str,
            default="",
            help="Squid-like refresh_pattern rules (newline separated)",
        )
        loader.add_option(
            name="policy_file",
            typespec=str,
            default=os.environ.get("PASSSAGE_POLICY_FILE", ""),
            help="Path to a Python file defining policy overrides",
        )
        loader.add_option(
            name="allow_policy_header",
            typespec=bool,
            default=bool(os.environ.get("PASSSAGE_ALLOW_POLICY_HEADER")),
            help="Allow client policy override via X-Passsage-Policy",
        )
        loader.add_option(
            name="public_proxy_url",
            typespec=str,
            default=PUBLIC_PROXY_URL,
            help="Externally reachable proxy URL (e.g. http://proxy.example.com:3128). "
                 "Embedded in the mitm.it/proxy-env.sh onboarding script so clients "
                 "export the correct HTTP_PROXY/HTTPS_PROXY address. Required when the "
                 "proxy runs behind a load balancer or in Kubernetes where the internal "
                 "listen address differs from the address clients should connect to. "
                 "Env: PASSSAGE_PUBLIC_PROXY_URL",
        )
        loader.add_option(
            name="access_logs",
            typespec=bool,
            default=ACCESS_LOGS,
            help="Enable S3 access logs in Parquet format",
        )
        loader.add_option(
            name="access_log_prefix",
            typespec=str,
            default=ACCESS_LOG_PREFIX,
            help="S3 prefix for access logs (separate from cached objects)",
        )
        loader.add_option(
            name="access_log_dir",
            typespec=str,
            default=ACCESS_LOG_DIR,
            help="Local spool directory for access logs",
        )
        loader.add_option(
            name="access_log_flush_seconds",
            typespec=str,
            default=ACCESS_LOG_FLUSH_SECONDS,
            help="Flush interval in seconds for access logs",
        )
        loader.add_option(
            name="access_log_flush_bytes",
            typespec=str,
            default=ACCESS_LOG_FLUSH_BYTES,
            help="Flush size threshold for access logs (bytes or 1G/500M/10K)",
        )
        loader.add_option(
            name="access_log_headers",
            typespec=str,
            default=ACCESS_LOG_HEADERS,
            help="Comma-separated headers to include in access logs",
        )
        loader.add_option(
            name="error_logs",
            typespec=bool,
            default=ERROR_LOGS,
            help="Enable Parquet error logs with tracebacks",
        )
        loader.add_option(
            name="error_log_prefix",
            typespec=str,
            default=ERROR_LOG_PREFIX,
            help="S3 prefix for error logs",
        )
        loader.add_option(
            name="error_log_dir",
            typespec=str,
            default=ERROR_LOG_DIR,
            help="Local spool directory for error logs",
        )
        loader.add_option(
            name="error_log_flush_seconds",
            typespec=str,
            default=ERROR_LOG_FLUSH_SECONDS,
            help="Flush interval in seconds for error logs",
        )
        loader.add_option(
            name="error_log_flush_bytes",
            typespec=str,
            default=ERROR_LOG_FLUSH_BYTES,
            help="Flush size threshold for error logs (bytes or 1G/500M/10K)",
        )
        loader.add_option(
            name="memcached_servers",
            typespec=str,
            default="",
            help="Comma-separated memcached servers (host:port) for metadata/vary cache; e.g. cache-0.cache:11211,cache-1.cache:11211",
        )
        loader.add_option(
            name="object_store_url",
            typespec=str,
            default=OBJECT_STORE_URL,
            help="HTTP URL of the object store exposing the S3 cache namespace (required). "
                 "Cache hits are fetched from this URL. (env: PASSSAGE_OBJECT_STORE_URL)",
        )

    @_log_hook_errors("configure")
    def configure(self, updated):
        if "policy_file" in updated:
            _load_policy_overrides(ctx.options.policy_file)
        if {
            "access_logs",
            "access_log_prefix",
            "access_log_dir",
            "access_log_flush_seconds",
            "access_log_flush_bytes",
            "access_log_headers",
        }.intersection(updated):
            _init_access_logs()
        if {
            "error_logs",
            "error_log_prefix",
            "error_log_dir",
            "error_log_flush_seconds",
            "error_log_flush_bytes",
        }.intersection(updated):
            _init_error_logs()
        if "memcached_servers" in updated:
            _update_memcached_client()

    @staticmethod
    def cache_expired(cache):
        if (cache_exp := cache.headers.get("Expires")):
            exp_dt = parse_date(cache_exp).astimezone(tz=pytz.utc)
            if datetime.now(tz=pytz.utc) >= exp_dt:
                return True
        return False

    # runs in the threadpool, because we use blocking operations here
    @concurrent
    @_log_hook_errors("requestheaders")
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # these two may hold object HTTP HEAD responses for upstream/cached version
        flow._upstream_head = flow._cache_head = None
        flow._orig_data = {}
        flow._access_log_start = time.time()
        # we mark this flow as cached only if it returns data from the cache
        flow._cached = False
        flow._cache_hit = False
        flow._cache_fresh = False
        flow._allow_stale_while_revalidate = False
        flow._allow_stale_if_error = False
        flow._save_response = True
        flow._orig_range = None
        flow._range_stripped = False
        flow._serve_reason = "upstream_served"
        flow._cached_method = None
        flow._vary_index_key = None
        flow._cache_saved = False
        flow._object_store_rewrite = False
        policy = flow._policy = get_policy(flow)
        if _is_s3_cache_request(flow):
            flow._save_response = False
            flow._policy = NoCache
            flow._serve_reason = "no_cache_s3_request"
            LOG.debug(
                "Client %s sent cache-object request for %s through proxy "
                "(no_proxy not honored, user-agent: %s)",
                flow.client_conn.peername,
                flow.request.pretty_host,
                flow.request.headers.get("user-agent", "unknown"),
            )
            return
        if flow.request.pretty_host == "mitm.it" and flow.request.path in ("/proxy-env", "/proxy-env.sh"):
            public_url = getattr(ctx.options, "public_proxy_url", "").strip()
            if public_url:
                os.environ["PASSSAGE_PUBLIC_PROXY_URL"] = public_url
            body = load_proxy_env_script()
            if not body:
                flow.response = http.Response.make(
                    500,
                    b"proxy env script unavailable",
                    {"Content-Type": "text/plain"},
                )
            else:
                flow.response = http.Response.make(
                    200,
                    body,
                    {
                        "Content-Type": "text/plain",
                        "Cache-Control": "no-store",
                    },
                )
            flow._save_response = False
            flow._short_circuit = True
            return
        with ctx._lock:
            flow._counter = self.counter
            self.counter += 1
        LOG.debug("Request headers2: %s", flow.request.headers)

        # pass non-GET/HEAD and NoCache request through without caching
        if (flow.request.method not in ("GET", "HEAD")
                or policy == NoCache):
            flow._save_response = False
            flow._serve_reason = "no_cache_policy" if policy == NoCache else "no_cache_method"
            return

        # Look up the object in the cache (Vary-aware)
        flow._cache_key = None
        flow._cache_vary = None
        try:
            normalized_url = _normalize_url(flow)
            vary_index_key = get_vary_index_key(normalized_url)
            flow._vary_index_key = vary_index_key
            LOG.debug("Cache lookup vary index key=%s", vary_index_key)
            vary_index_head = get_vary_index(vary_index_key)
            LOG.debug(
                "Vary index status=%s source=%s key=%s",
                vary_index_head.status_code,
                vary_index_head.source,
                vary_index_key,
            )
            if http_2xx(vary_index_head) and (vary_hdr := vary_index_head.meta.get("vary")):
                flow._cache_vary = vary_hdr
                if "*" not in vary_hdr:
                    vary_key = compute_vary_key(vary_hdr, flow.request.headers)
                    if vary_key is not None:
                        flow._cache_key = get_cache_key(normalized_url, vary_key)
                        LOG.debug(
                            "Cache lookup vary header=%s vary_key=%s cache_key=%s",
                            vary_hdr,
                            vary_key,
                            flow._cache_key,
                        )
            if flow._cache_key is None and flow._cache_vary != "*":
                flow._cache_key = get_cache_key(normalized_url)
                LOG.debug("Cache lookup default key=%s", flow._cache_key)
            if flow._cache_key:
                flow._cache_head = get_cache_metadata(flow._cache_key)
                flow._metadata_source = flow._cache_head.source
                LOG.debug(
                    "Cache HEAD status=%s source=%s key=%s",
                    flow._cache_head.status_code,
                    flow._cache_head.source,
                    flow._cache_key,
                )
        except Exception as e:
            # if S3 is unavailable, go to upstream directly
            LOG.warning(
                "Cache metadata lookup failed for key=%s: %s",
                flow._cache_key,
                e,
            )
            _log_exception(
                e,
                flow=flow,
                context={"hook": "requestheaders", "stage": "cache_head"},
                error_type="s3_head_error",
            )
            return
        if (not (http_2xx(flow._cache_head)
                 or flow._cache_head.status_code == 404)):
            # If we got non-2xx or 404 from the S3, the proxy is not
            # functional, so return this as an error
            flow._save_response = False
            flow._serve_reason = "cache_head_error"
            flow.response = http.Response.make(
                flow._cache_head.status_code,
                f"Got {flow._cache_head.status_code} error while accessing\n{S3_URL}\nplease check its permissions!",
                {"Content-Type": "text/plain"}
            )
            return

        # if we have a GET cached, we can serve both HEAD/GET from the cache. If we have HEAD,
        # only HEAD can be served
        cached_method = False
        if http_2xx(flow._cache_head):
            meta_method = flow._cache_head.meta.get("method")
            if meta_method is None:
                cached_method = True
            elif meta_method == "GET" or meta_method == flow.request.method:
                cached_method = True
        flow._cached_method = cached_method
        if flow._cache_head is not None:
            m = flow._cache_head.meta
            LOG.debug(
                "Cache metadata status=%s method_meta=%s etag_meta=%s lastmod_meta=%s",
                flow._cache_head.status_code,
                m.get("method"),
                m.get("headers", {}).get("etag"),
                m.get("last_modified"),
            )
            LOG.debug("Cache method match cached_method=%s", cached_method)

        refresh_patterns = get_refresh_patterns()
        cache_hit = http_2xx(flow._cache_head) and cached_method
        freshness = (
            cache_freshness(flow.request.url, flow._cache_head.meta, refresh_patterns)
            if cache_hit
            else None
        )
        cache_fresh = bool(freshness and freshness.is_fresh)
        allow_stale_while_revalidate = bool(freshness and freshness.allow_stale_while_revalidate)
        allow_stale_if_error = bool(freshness and freshness.allow_stale_if_error)
        flow._allow_stale_if_error = allow_stale_if_error
        flow._allow_stale_while_revalidate = allow_stale_while_revalidate
        flow._cache_hit = cache_hit
        flow._cache_fresh = cache_fresh
        if flow.request.headers:
            request_headers = {k.lower(): v for k, v in flow.request.headers.items()}
        else:
            request_headers = {}
        if (
            cache_hit
            and freshness
            and policy in (Standard, StaleIfError)
            and request_requires_revalidation(request_headers, freshness)
        ):
            cache_fresh = False
            allow_stale_while_revalidate = False
            LOG.debug(
                "Client forced revalidation (Cache-Control: no-cache or max-age) -> cache_fresh=False"
            )
        LOG.debug(
            "Cache freshness cached_method=%s cache_fresh=%s policy=%s stale_while_revalidate=%s stale_if_error=%s",
            cached_method,
            cache_fresh,
            policy.__name__,
            allow_stale_while_revalidate,
            allow_stale_if_error,
        )

        if cache_hit:
            if policy == NoRefresh:
                flow._serve_reason = "cache_hit_norefresh"
                LOG.debug("Cache hit: NoRefresh -> rewrite to object store")
                _rewrite_to_object_store(flow)
                return
            if cache_fresh and policy in (Standard, StaleIfError):
                flow._serve_reason = "cache_hit_fresh"
                LOG.debug("Cache hit: fresh -> rewrite to object store")
                _rewrite_to_object_store(flow)
                return
            if policy in (Standard, StaleIfError) and allow_stale_while_revalidate:
                flow._serve_reason = "cache_hit_stale_while_revalidate"
                LOG.debug("Cache hit: stale-while-revalidate -> rewrite to object store")
                _rewrite_to_object_store(flow)
                return
        else:
            if (flow.request.method == "GET"
                    and flow.request.headers.get("if-modified-since")):
                # Remove the if-mod-since client side header if we don't have
                # the file, so we'll forcefully retrieve it from the
                # upstream and store it in the cache.
                # We do this to always have a copy regardless if the client has
                # in its cache or if the request matches AlwaysUpstream, so when
                # the upstream doesn't work, we have the chance of serving it.
                # save the original, we'll need that for returning 304
                flow._orig_data["if-modified-since"] = flow.request.headers.pop("if-modified-since", None)
            if flow.request.method == "GET" and "Range" in flow.request.headers:
                # Strip Range on cache miss so upstream returns the full 200.
                # We cache the full object and serve the requested range slice
                # to the client in responseheaders.
                flow._orig_range = flow.request.headers.pop("Range")
                flow._range_stripped = True
                LOG.debug("Stripped Range header on cache miss: %s", flow._orig_range)

        upstream_failed = False
        flow._upstream_error = None
        with ctx._lock:
            key = (flow.request.host, flow.request.port, flow.request.scheme)
            if key in ctx._banned:
                if flow.request.headers.get("x-clear-ban"):
                    # for testing
                    del ctx._banned[key]
                else:
                    upstream_failed = True
                    flow._upstream_error = ctx._banned.get(key)

        if not upstream_failed:
            # If the upstream is not banned, we do an upstream HEAD request
            # to see whether the site is available or the file was modified.
            # Sadly, mitmproxy doesn't support request retries on upstream failure,
            # that's why we have to do the availability check ourselves.
            upstream_hdrs = {}
            for k, v in flow.request.headers.items():
                # pass through some headers for testing
                if (k.lower().startswith("x-echo-")
                        or k.lower() in ("x-sleep", "x-status-code")):
                    upstream_hdrs[k] = v
            if cache_hit and policy in (Standard, StaleIfError):
                cm = flow._cache_head.meta
                if (etag := cm.get("headers", {}).get("etag")):
                    upstream_hdrs["If-None-Match"] = etag
                if (lastmod := cm.get("last_modified")):
                    upstream_hdrs["If-Modified-Since"] = lastmod
            try:
                timeout = getattr(ctx.options, "upstream_head_timeout", UPSTREAM_TIMEOUT)
                start = time.perf_counter()
                flow._upstream_head = requests.head(
                    flow.request.url,
                    timeout=timeout,
                    headers=upstream_hdrs,
                )
                flow._upstream_head_time_ms = int((time.perf_counter() - start) * 1000)
            except Exception as e:
                flow._upstream_head_time_ms = int((time.perf_counter() - start) * 1000)
                upstream_failed = True
                flow._upstream_error = e
                _log_exception(
                    e,
                    flow=flow,
                    context={"hook": "requestheaders", "stage": "upstream_head"},
                    error_type="upstream_head_error",
                )
                # put this server/host onto the ban list, so we don't have to
                # wait for the timeout to happen in subsequent requests
                with ctx._lock:
                    ctx._banned[
                        (flow.request.host,
                         flow.request.port,
                         flow.request.scheme)] = e

            # First, we check for StaleIfError and handle 404 status code
            # Return cached on upstream 404 and StaleIfError policy or stale-if-error directive.
            if (not upstream_failed and cache_hit
                    and flow._upstream_head.status_code == 404
                    and (policy == StaleIfError or allow_stale_if_error)):
                flow._serve_reason = "stale_if_error_upstream_404"
                _rewrite_to_object_store(flow)
                return

        # On upstream errors or if it's banned, StaleIfError may serve cached content.
        if upstream_failed or (flow._upstream_head and flow._upstream_head.status_code >= 400):
            if cache_hit and (policy == StaleIfError or allow_stale_if_error):
                flow._serve_reason = "stale_if_error_upstream_failed"
                LOG.debug("Upstream failed -> rewrite to object store (StaleIfError)")
                _rewrite_to_object_store(flow)
                return

        # If upstream didn't respond (or banned) and we have a cache miss,
        # return a 504 HTTP error
        if upstream_failed:
            flow._serve_reason = "upstream_failed"
            flow._save_response = False
            if _is_tls_verify_error(flow._upstream_error):
                detail = str(flow._upstream_error) if flow._upstream_error else "unknown"
                flow.response = _build_upstream_error_response(
                    502,
                    "Bad Gateway",
                    f"TLS certificate verification failed.\n{detail}",
                )
            elif _is_connection_error(flow._upstream_error):
                detail = str(flow._upstream_error) if flow._upstream_error else "connection error"
                flow.response = _build_upstream_error_response(
                    502,
                    "Bad Gateway",
                    f"Upstream connection failed.\n{detail}",
                )
            else:
                detail = str(flow._upstream_error) if flow._upstream_error else "upstream timeout"
                flow.response = _build_upstream_error_response(
                    504,
                    "Gateway Timeout",
                    detail,
                )
            return

        if (cache_hit
                and policy in (Standard, StaleIfError)
                and flow._upstream_head
                and (http_2xx(flow._upstream_head) or flow._upstream_head.status_code == 304)):
            # Decide whether the upstream content is the same as our cached copy.
            # ETag is the authoritative validator: if both sides have one and they
            # match, the content is identical regardless of Last-Modified differences
            # (e.g. cache stored None but upstream now returns a value).
            upstream_etag = _normalize_etag(flow._upstream_head.headers.get("etag"))
            cached_etag = _normalize_etag(flow._cache_head.meta.get("headers", {}).get("etag"))
            upstream_lastmod = flow._upstream_head.headers.get("last-modified")
            cached_lastmod = flow._cache_head.meta.get("last_modified")
            if upstream_etag and cached_etag:
                content_unchanged = upstream_etag == cached_etag
            elif upstream_lastmod or cached_lastmod:
                content_unchanged = upstream_lastmod == cached_lastmod
            else:
                content_unchanged = False
            if content_unchanged:
                flow._serve_reason = "cache_hit_revalidated"
                _rewrite_to_object_store(flow)
                if flow._cache_key:
                    ctx._executor.submit(
                        refresh_cache_metadata,
                        flow._cache_key,
                        flow._cache_head.meta,
                    )
                return
            flow._serve_reason = "cache_revalidated_content_changed"


    @_log_hook_errors("responseheaders")
    def responseheaders(self, flow):
        request_id = getattr(flow, "id", None)
        if request_id is not None:
            flow.response.headers["x-request-id"] = str(request_id)
        if (
            not flow._cached
            and flow._cache_head
            and flow._policy in (Standard, StaleIfError)
            and (
                flow.response.status_code >= 500
                or (flow.response.status_code == 404 and flow._policy == StaleIfError)
            )
            and (flow._policy == StaleIfError or getattr(flow, "_allow_stale_if_error", False))
        ):
            if _fallback_fetch_from_object_store(flow):
                flow._serve_reason = "stale_if_error_fallback"

        flow.response.headers["x-proxy-policy"] = flow._policy.__name__
        if getattr(flow, "_serve_reason", None) == "no_cache_s3_request":
            flow.response.headers["x-passsage-warning"] = (
                "no_proxy-bypass: this request to "
                + flow.request.pretty_host
                + " should bypass the proxy (check client no_proxy setting)"
            )
        # Identify proxy via Via (RFC 7230); do not rewrite Server header
        existing_via = flow.response.headers.get("via", "")
        flow.response.headers["via"] = f"{VIA_HEADER_VALUE}, {existing_via}" if existing_via else VIA_HEADER_VALUE
        if getattr(flow, "_object_store_rewrite", False):
            if flow.response.status_code in (200, 206):
                flow.response.stream = True
            elif flow.response.status_code == 404:
                LOG.warning("Object store returned 404 for key=%s (metadata/object inconsistency)",
                            getattr(flow, "_cache_key", "?"))
        elif flow._save_response:
            orig_range = getattr(flow, "_orig_range", None)
            if (
                orig_range
                and flow.response.status_code == 200
                and flow.response.headers.get("content-length")
            ):
                total = int(flow.response.headers["content-length"])
                parsed = _parse_single_range(orig_range, total)
                if parsed is not None:
                    start, end = parsed
                    length = end - start + 1
                    # Preserve original 200 so the cache stores the full object as 200
                    flow._orig_data["status_code"] = 200
                    flow._orig_data["reason"] = flow.response.reason
                    flow._orig_data["content-length"] = str(total)
                    flow.response.status_code = 206
                    flow.response.headers["content-range"] = f"bytes {start}-{end}/{total}"
                    flow.response.headers["content-length"] = str(length)
                    flow.response.stream = _make_range_stream(self, flow, start, end)
                elif _is_unsatisfiable_range(orig_range, total):
                    flow._orig_data["status_code"] = 200
                    flow._orig_data["reason"] = flow.response.reason
                    flow._orig_data["content-length"] = str(total)
                    flow.response.status_code = 416
                    flow.response.headers["content-range"] = f"bytes */{total}"
                    flow.response.headers["content-length"] = "0"
                    # Save full body for caching, but send nothing to client
                    def _discard_stream(data, _self=self, _flow=flow):
                        save_response(_self, _flow, data)
                        return b"" if data else b""
                    flow.response.stream = _discard_stream
                else:
                    # unparseable or multi-range: serve the full 200
                    flow.response.stream = lambda data: save_response(self, flow, data)
            else:
                flow.response.stream = lambda data: save_response(self, flow, data)
        else:
            flow.response.stream = True
        if flow._cached:
            LOG.debug("Cache response: serving from cache")
            flow.response.headers["cache-status"] = f"{SERVER_NAME};hit;detail=object-store"
            is_partial = flow.response.status_code == 206
            saved_range_headers = {}
            if is_partial:
                for h in ("content-length", "content-range"):
                    if h in flow.response.headers:
                        saved_range_headers[h] = flow.response.headers[h]
            apply_cached_metadata(flow)
            if is_partial:
                for h, v in saved_range_headers.items():
                    flow.response.headers[h] = v
                flow.response.status_code = 206
            meta = flow._cache_head.meta if flow._cache_head else {}
            if (stored_dt := cache_stored_at(meta)):
                stored_dt = stored_dt.astimezone(pytz.utc)
                age_seconds = int((datetime.now(tz=pytz.utc) - stored_dt).total_seconds())
                flow.response.headers["age"] = str(max(0, age_seconds))
        else:
            LOG.debug("Cache response: not cached")
        if flow.response.headers.get("last-modified"):
            # if the response has a last-modified header and we got
            # if-modified-since, compare the two and return 304 accordingly
            if (modsince := flow.request.headers.get("if-modified-since")
                    or flow._orig_data.get("if-modified-since")):
                lastmod_dt = parse_date(flow.response.headers["last-modified"])
                modsince_dt = parse_date(modsince)
                if lastmod_dt and modsince_dt and modsince_dt >= lastmod_dt:
                    flow._orig_data["status_code"] = flow.response.status_code
                    flow._orig_data["reason"] = flow.response.reason
                    flow.response.status_code = 304
                    # don't stream/save a 304
                    flow.response.stream = False
                    flow._save_response = False

    @staticmethod
    def _save_to_cache(
        status_code,
        reason,
        method,
        f,
        digest,
        headers,
        url,
        cache_key,
        vary_header,
        vary_request,
        normalized_url,
    ):
        try:
            s3 = get_s3_client()
            f.flush()
            f.seek(0)

            # 1. Upload the data object (immutable, no metadata)
            extra_args = {}
            s3_header_map = {
                "content-type": "ContentType",
                "content-encoding": "ContentEncoding",
            }
            for header, aws_key in s3_header_map.items():
                if header in headers:
                    extra_args[aws_key] = headers[header]
            s3.upload_fileobj(f, S3_BUCKET, cache_key, ExtraArgs=extra_args or None)

            # 2. Build and write the .meta JSON
            cached_headers = {}
            for k in (
                "etag",
                "vary",
                "cache-control",
                "content-type",
                "content-encoding",
                "content-length",
                "content-language",
                "content-disposition",
                "content-location",
                "content-range",
                "accept-ranges",
                "location",
                "link",
                "expires",
            ):
                if k in headers:
                    cached_headers[k] = headers[k]

            meta = {
                "status_code": int(status_code),
                "reason": reason,
                "method": method,
                "sha224": digest,
                "stored_at": time.time(),
                "url": url[:512],
                "last_modified": headers.get("last-modified"),
                "headers": cached_headers,
            }
            if vary_header:
                meta["vary"] = vary_header
            if vary_request:
                meta["vary_request"] = vary_request

            _s3_put_json(f"{cache_key}.meta", meta)

            mc = _get_memcached_client()
            if mc:
                try:
                    _memcached_set_metadata(mc, cache_key, meta)
                except Exception as mc_exc:
                    LOG.debug("Memcached set after cache save failed: %s", mc_exc)

            # 3. Write the vary index (if applicable)
            if vary_header:
                vary_index_key = get_vary_index_key(normalized_url)
                vary_data = {"vary": vary_header}
                _s3_put_json(vary_index_key, vary_data)
                if mc:
                    try:
                        mc.set(_memcached_key(vary_index_key), json.dumps(vary_data), expire=0)
                    except Exception as mc_exc:
                        LOG.debug("Memcached set for vary index failed: %s", mc_exc)
        except Exception as e:
            LOG.error("Cache save error %s, %s", url, e)
            _log_exception(
                e,
                request_url=url,
                method=method,
                request_headers=headers,
                context={"cache_key": cache_key, "url": url},
                error_type="cache_save_error",
            )
            raise
        finally:
            try:
                f.close()
            except Exception:
                pass

    @_log_hook_errors("response")
    def response(self, flow):
        if getattr(flow, "_short_circuit", False):
            self.log_response(flow)
            return
        if (flow.request.method not in ("GET", "HEAD")
                or flow._policy == NoCache or flow._cached):
            self.log_response(flow)
            with ctx._lock:
                self.cleanup(flow)
            return

        # Safety net: never cache an *upstream* 206 Partial Content response.
        # When _orig_range is set, we intentionally rewrote 200→206 in
        # responseheaders (the full body is still being saved via the range
        # stream).  Only block caching when the upstream genuinely returned 206
        # (e.g. non-GET, or upstream ignored our Range-stripping).
        if flow.response.status_code == 206 and not getattr(flow, "_orig_range", None):
            flow._save_response = False

        refresh_patterns = get_refresh_patterns()
        if not any(p.pattern.search(flow.request.url) for p in refresh_patterns):
            cc = parse_cache_control(flow.response.headers.get("cache-control", ""))
            if "no-store" in cc or "private" in cc:
                flow._save_response = False
        LOG.debug(
            "Cache save decision save=%s policy=%s cached=%s",
            flow._save_response,
            flow._policy.__name__,
            flow._cached,
        )

        vary_header = flow.response.headers.get("vary")
        if vary_header:
            if "*" in vary_header:
                flow._save_response = False
            else:
                vary_key = compute_vary_key(vary_header, flow.request.headers)
                if vary_key:
                    normalized_url = _normalize_url(flow)
                    flow._cache_key = get_cache_key(normalized_url, vary_key)
                    flow._cache_vary = vary_header
                    flow._cache_vary_request = build_vary_request(
                        vary_header, flow.request.headers
                    )
            LOG.debug(
                "Cache vary header=%s cache_key=%s",
                vary_header,
                getattr(flow, "_cache_key", None),
            )

        if (
            flow._save_response
            and flow._cache_head
            and flow.request.method == "GET"
            and flow._counter in self.hashes
        ):
            if self.hashes[flow._counter].hexdigest() == flow._cache_head.meta.get("sha224"):
                flow._save_response = False
        if flow._cache_head and flow._cache_head.meta:
            if (flow.request.method == "HEAD"
                    and flow._cache_head.meta.get("method") == "GET"):
                flow._save_response = False
        if flow._save_response:
            # save in the background
            if flow._counter not in self.files or flow._counter not in self.hashes:
                LOG.debug("Cache save skipped (no body recorded) counter=%s", flow._counter)
                flow._save_response = False
                self.log_response(flow)
                with ctx._lock:
                    self.cleanup(flow)
                return
            normalized_url = _normalize_url(flow)
            cache_key = flow._cache_key or get_cache_key(normalized_url)
            flow._cache_saved = True
            LOG.debug("Cache save enqueue key=%s", cache_key)
            save_headers = flow.response.headers
            if getattr(flow, "_orig_range", None):
                save_headers = flow.response.headers.copy()
                if "content-length" in flow._orig_data:
                    save_headers["content-length"] = flow._orig_data["content-length"]
                if "content-range" in save_headers:
                    del save_headers["content-range"]
            ctx._executor.submit(
                self._save_to_cache,
                # save the original values in the cache for eg. in a
                # 304 not-modified situation
                flow._orig_data.get("status_code") or flow.response.status_code,
                flow._orig_data.get("reason") or flow.response.reason,
                flow.request.method,
                self.files[flow._counter],
                self.hashes[flow._counter].hexdigest(),
                save_headers,
                flow.request.url,
                cache_key,
                getattr(flow, "_cache_vary", None),
                getattr(flow, "_cache_vary_request", None),
                normalized_url,
            )

        if flow.response.status_code == 304:
            # empty content on 304 not-modified, even if we have a fully cached
            # GET response, we must not return content
            flow.response.content = None

        self.log_response(flow)
        with ctx._lock:
            self.cleanup(flow)

    @_log_hook_errors("error")
    def error(self, flow):
        writer = _access_log_writer()
        if writer:
            try:
                writer.add(_build_access_log_record(flow, error=str(flow.error)))
            except Exception as exc:
                LOG.debug("Access log write skipped: %s", exc)
        err_writer = _error_log_writer()
        if err_writer:
            try:
                tb_text = ""
                if flow.error and hasattr(flow.error, "__traceback__"):
                    tb_text = "".join(
                        traceback.format_exception(
                            type(flow.error), flow.error, flow.error.__traceback__
                        )
                    )
                if not tb_text:
                    tb_text = traceback.format_exc()
                    err_writer.add(
                        _build_error_log_record(
                            error_type=type(flow.error).__name__ if flow.error else "flow_error",
                            error_message=str(flow.error),
                        traceback_text=tb_text,
                            context={},
                            flow=flow,
                        )
                    )
            except Exception as exc:
                LOG.debug("Error log write skipped: %s", exc)
        with ctx._lock:
            self.cleanup(flow)

    @_log_hook_errors("done")
    def done(self):
        writer = _access_log_writer()
        if writer:
            writer.stop()
        err_writer = _error_log_writer()
        if err_writer:
            err_writer.stop()

    def cleanup(self, flow):
        if not hasattr(flow, "_counter"):
            return
        if flow._counter in self.files:
            del self.files[flow._counter]
        if flow._counter in self.hashes:
            del self.hashes[flow._counter]

    def log_response(self, flow):
        writer = _access_log_writer()
        if writer:
            try:
                writer.add(_build_access_log_record(flow))
            except Exception as exc:
                LOG.debug("Access log write skipped: %s", exc)
        LOG.info(
            "[%s] %s %s %s %s/%s/%s",
            datetime.now().strftime("%m/%d/%Y:%H:%M:%S"),
            flow.request.method,
            flow.request.url,
            flow.response.status_code,
            flow._policy.__name__,
            flow._cached,
            flow._save_response,
        )


addons = [
    Proxy(),
]
