# redirects
# handle upstream authentication
# collect and expose metrics/stats (with limited number of entries), like top list for misses, hits, etc.

import copy
import hashlib
import logging
import os
import re
import socket
import ssl
import tempfile
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
from cachetools import TTLCache
from mitmproxy import ctx, http
from mitmproxy.script import concurrent
from botocore.exceptions import ClientError
from werkzeug.http import parse_date

from passsage.policy import (
    POLICY_BY_NAME,
    Context,
    NoCache,
    NoRefresh,
    PolicyResolver,
    StaleIfError,
    Standard,
    get_default_resolver,
    policy_from_name,
    set_default_resolver,
)
from passsage.access_logs import AccessLogWriter, build_access_log_config

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
S3_BUCKET = os.environ.get("S3_BUCKET", "364189071156-ds-proxy-us-west-2") if not _S3_ENDPOINT else os.environ.get("S3_BUCKET", "proxy-cache")
if _S3_ENDPOINT:
    p = urlparse(_S3_ENDPOINT)
    S3_HOST = p.hostname or "localhost"
    S3_PORT = p.port or (443 if p.scheme == "https" else 80)
    S3_SCHEME = p.scheme or "http"
    S3_URL = f"{S3_SCHEME}://{S3_HOST}:{S3_PORT}/{S3_BUCKET}"
    S3_PATH_STYLE = True
else:
    S3_HOST = f"{S3_BUCKET}.s3.us-west-2.amazonaws.com"
    S3_PORT = 80
    S3_SCHEME = "http"
    S3_URL = f"{S3_SCHEME}://{S3_HOST}"
    S3_PATH_STYLE = False
CACHE_TIMEOUT = 10
UPSTREAM_TIMEOUT = 10
HEALTH_PORT = int(os.environ.get("PASSSAGE_HEALTH_PORT", "8082"))
HEALTH_HOST = os.environ.get("PASSSAGE_HEALTH_HOST", "0.0.0.0")
HEALTH_CHECK_S3 = os.environ.get("PASSSAGE_HEALTH_CHECK_S3", "1").strip().lower() not in (
    "0",
    "false",
    "no",
)
CACHE_REDIRECT = os.environ.get("PASSSAGE_CACHE_REDIRECT", "").strip().lower() in (
    "1",
    "true",
    "yes",
)
SIGNED_CACHE_REDIRECT = os.environ.get("PASSSAGE_CACHE_REDIRECT_SIGNED_URL", "").strip().lower() not in (
    "0",
    "false",
    "no",
)
PUBLIC_PROXY_URL = os.environ.get("PASSSAGE_PUBLIC_PROXY_URL", "").strip()
ACCESS_LOGS = os.environ.get("PASSSAGE_ACCESS_LOGS", "").strip().lower() in (
    "1",
    "true",
    "yes",
)
ACCESS_LOG_PREFIX = os.environ.get("PASSSAGE_ACCESS_LOG_PREFIX", "__passsage_logs__").strip()
ACCESS_LOG_DIR = os.environ.get("PASSSAGE_ACCESS_LOG_DIR", "/tmp/passsage-logs").strip()
ACCESS_LOG_FLUSH_SECONDS = os.environ.get("PASSSAGE_ACCESS_LOG_FLUSH_SECONDS", "30").strip()
ACCESS_LOG_FLUSH_BYTES = os.environ.get("PASSSAGE_ACCESS_LOG_FLUSH_BYTES", "1G").strip()
ACCESS_LOG_HEADERS = os.environ.get(
    "PASSSAGE_ACCESS_LOG_HEADERS",
    "accept,accept-encoding,cache-control,content-type,content-encoding,"
    "etag,last-modified,range,user-agent,via,x-cache,x-cache-lookup,x-amz-request-id",
).strip()


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
    # suppress `Found credentials in shared credentials file` messages
    logging.getLogger("botocore.credentials").setLevel(logging.WARNING)
    try:
        return tls.s3
    except AttributeError:
        kwargs = {}
        if _S3_ENDPOINT:
            from botocore.config import Config
            kwargs["endpoint_url"] = _S3_ENDPOINT
            kwargs["config"] = Config(s3={"addressing_style": "path"})
        tls.s3 = boto3.session.Session().client("s3", **kwargs)
        return tls.s3


@dataclass
class S3HeadResponse:
    status_code: int
    headers: dict


def s3_head_object(cache_key: str) -> S3HeadResponse:
    s3 = get_s3_client()
    try:
        response = s3.head_object(Bucket=S3_BUCKET, Key=cache_key)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code in ("404", "NoSuchKey", "NotFound"):
            return S3HeadResponse(404, {})
        raise
    headers = {}
    http_headers = response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    headers.update(http_headers)
    for key, value in (response.get("Metadata") or {}).items():
        headers[f"x-amz-meta-{key}"] = value
    return S3HeadResponse(200, headers)


def load_proxy_env_script() -> bytes:
    try:
        from importlib import resources
        script = resources.files("passsage").joinpath("onboarding/proxy-env.sh").read_text()
        public_url = os.environ.get("PASSSAGE_PUBLIC_PROXY_URL", "").strip()
        if public_url:
            script = script.replace("__PASSSAGE_PUBLIC_PROXY_URL__", public_url)
        script = script.replace("__PASSSAGE_S3_HOST__", S3_HOST)
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

    if hasattr(module, "get_resolver"):
        resolver = module.get_resolver()
        if isinstance(resolver, PolicyResolver):
            set_default_resolver(resolver)
            LOG.info("Policy overrides loaded via get_resolver path=%s", path)
            return
        LOG.error("Policy file get_resolver did not return PolicyResolver path=%s", path)
        return
    if hasattr(module, "get_rules"):
        rules = module.get_rules()
        if rules:
            set_default_resolver(PolicyResolver(rules=rules))
            LOG.info("Policy overrides loaded via get_rules path=%s", path)
            return
        LOG.error("Policy file get_rules returned no rules path=%s", path)
        return
    if hasattr(module, "RULES"):
        rules = module.RULES
        if rules:
            set_default_resolver(PolicyResolver(rules=rules))
            LOG.info("Policy overrides loaded via RULES path=%s", path)
            return
        LOG.error("Policy file RULES is empty path=%s", path)
        return

    LOG.error("Policy file missing get_resolver/get_rules/RULES path=%s", path)


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
    request_ctx = Context(
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

    def ttl_seconds(self, now: datetime, headers: dict[str, str]) -> int:
        if (lastmod := headers.get("x-amz-meta-last-modified") or headers.get("last-modified")):
            lastmod_dt = parse_date(lastmod)
            if lastmod_dt:
                age = max(0, int((now - lastmod_dt).total_seconds()))
            else:
                age = 0
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


def cache_stored_at(headers: dict[str, str]) -> datetime | None:
    if (stored := headers.get("x-amz-meta-stored-at")):
        try:
            return datetime.fromtimestamp(float(stored), tz=pytz.utc)
        except ValueError:
            return None
    if (s3_lastmod := headers.get("last-modified")):
        return parse_date(s3_lastmod)
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
    headers: dict[str, str],
    refresh_patterns: list[RefreshPattern],
    now: datetime,
    stored_at: datetime,
) -> int | None:
    for pattern in refresh_patterns:
        if pattern.pattern.search(url):
            return pattern.ttl_seconds(now, headers)
    cc = parse_cache_control(headers.get("cache-control", ""))
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
    if (exp := headers.get("expires")):
        exp_dt = parse_date(exp)
        if exp_dt:
            return max(0, int((exp_dt - stored_at).total_seconds()))
    if (lastmod := headers.get("x-amz-meta-last-modified") or headers.get("last-modified")):
        lastmod_dt = parse_date(lastmod)
        if lastmod_dt:
            lifetime = max(0, int((now - lastmod_dt).total_seconds() * 0.1))
            return lifetime
    return None


def cache_freshness(
    url: str, headers: dict[str, str], refresh_patterns: list[RefreshPattern]
) -> CacheFreshness:
    now = datetime.now(tz=pytz.utc)
    stored_at = cache_stored_at(headers)
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
    cc = parse_cache_control(headers.get("cache-control", ""))
    ttl_seconds = cache_ttl_seconds(url, headers, refresh_patterns, now, stored_at)
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


def apply_cached_metadata(flow: http.HTTPFlow) -> None:
    if (status_code := flow.response.headers.get("x-amz-meta-status-code")):
        flow.response.status_code = int(status_code)
    if (reason := flow.response.headers.get("x-amz-meta-reason")):
        flow.response.reason = reason
    for k, v in flow.response.headers.items():
        if not k.startswith("x-amz-meta-header-"):
            continue
        k = k.replace("x-amz-meta-header-", "")
        flow.response.headers[k] = v
    if (lastmod := flow.response.headers.get("x-amz-meta-last-modified")):
        flow.response.headers["last-modified"] = lastmod


def refresh_cache_metadata(cache_key: str, cache_headers: dict[str, str]) -> None:
    metadata: dict[str, str] = {}
    for key, value in cache_headers.items():
        if key.lower().startswith("x-amz-meta-"):
            metadata[key[len("x-amz-meta-"):]] = value
    if not metadata:
        return
    metadata["stored-at"] = str(time.time())
    copy_args = {
        "Bucket": S3_BUCKET,
        "Key": cache_key,
        "CopySource": {"Bucket": S3_BUCKET, "Key": cache_key},
        "Metadata": metadata,
        "MetadataDirective": "REPLACE",
    }
    header_map = {
        "content-type": "ContentType",
        "content-encoding": "ContentEncoding",
        "cache-control": "CacheControl",
        "expires": "Expires",
    }
    for header, aws_key in header_map.items():
        if header in cache_headers:
            copy_args[aws_key] = cache_headers[header]
    try:
        s3 = get_s3_client()
        s3.copy_object(**copy_args)
    except Exception as exc:
        LOG.warning("Cache metadata refresh failed for %s: %s", cache_key, exc)


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


def _build_access_log_record(flow, error: str | None = None) -> dict:
    now = time.time()
    start_ts = getattr(flow, "_access_log_start", now)
    duration_ms = int((now - start_ts) * 1000)
    start_dt = datetime.fromtimestamp(start_ts, tz=pytz.utc)
    parsed = urlparse(flow.request.url)
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
        "url": flow.request.url,
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
        "cache_redirect": getattr(flow, "_cache_redirect", None),
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
        "cache_head_etag": cache_head.headers.get("x-amz-meta-header-etag") if cache_head else None,
        "cache_head_last_modified": cache_head.headers.get("x-amz-meta-last-modified") if cache_head else None,
        "cache_head_method": cache_head.headers.get("x-amz-meta-method") if cache_head else None,
        "error": error,
        "duration_ms": duration_ms,
        "bytes_sent": content_length,
    }


def get_quoted_url(flow):
    return flow.request.url


def get_cache_key(url: str, vary_key: str | None = None) -> str:
    base = url
    if vary_key:
        return f"{base}__vary__{vary_key}"
    return base


def get_vary_index_key(url: str) -> str:
    return f"{url}__vary_index"


def compute_vary_key(vary_header: str, request_headers) -> str | None:
    raw = build_vary_request(vary_header, request_headers)
    if raw is None:
        return None
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_vary_request(vary_header: str, request_headers) -> str | None:
    if "*" in vary_header:
        return None
    names = [n.strip().lower() for n in vary_header.split(",") if n.strip()]
    parts = [f"{name}={request_headers.get(name, '')}" for name in names]
    return "|".join(parts)


def get_cache_path_key(cache_key: str) -> str:
    return requests.utils.quote(cache_key, safe="/")


def get_cache_url(flow, key_override: str | None = None):
    key = key_override or get_quoted_url(flow)
    cache_key = get_cache_path_key(key)
    return f"{S3_URL}/{cache_key}"


def get_cache_redirect_url(flow) -> str:
    cache_key = getattr(flow, "_cache_key", None) or get_quoted_url(flow)
    cache_path_key = get_cache_path_key(cache_key)
    if getattr(ctx.options, "cache_redirect_signed_url", False):
        return get_s3_client().generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": cache_key},
            ExpiresIn=3600,
        )
    path_prefix = f"/{S3_BUCKET}/" if S3_PATH_STYLE else "/"
    scheme = S3_SCHEME if _S3_ENDPOINT else "https"
    port = S3_PORT if _S3_ENDPOINT else 443
    host = S3_HOST
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    return f"{scheme}://{netloc}{path_prefix}{cache_path_key}"


def cache_redirect_response(flow) -> None:
    status = 302 if flow.request.method == "GET" else 307
    location = get_cache_redirect_url(flow)
    flow.response = http.Response.make(status, b"", {"Location": location})
    flow._save_response = False
    flow._cached = True
    flow._cache_redirect = True


def cache_redirect(flow):
    if getattr(flow, "_req_orig_url", None):
        # We've been already called, don't rewrite again
        return
    flow._req_orig_url = flow.request.url
    cache_key = getattr(flow, "_cache_key", None) or get_quoted_url(flow)
    LOG.debug("Cache redirect key=%s", cache_key)
    path_prefix = f"/{S3_BUCKET}/" if S3_PATH_STYLE else "/"
    cache_path_key = get_cache_path_key(cache_key)
    flow.request.path = f"{path_prefix}{cache_path_key}"
    flow.request.host = S3_HOST
    flow.request.port = S3_PORT
    flow.request.scheme = S3_SCHEME
    # we don't want to save the cache response
    flow._save_response = False
    # mark this response as returned from the cache
    flow._cached = True


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
            help="Public proxy URL embedded in mitm.it/proxy-env responses",
        )
        loader.add_option(
            name="cache_redirect",
            typespec=bool,
            default=CACHE_REDIRECT,
            help="Return a redirect to the cached S3 object on cache hits",
        )
        loader.add_option(
            name="cache_redirect_signed_url",
            typespec=bool,
            default=SIGNED_CACHE_REDIRECT,
            help="Redirect cache hits to a signed S3 URL instead of public S3 access",
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

    @staticmethod
    def cache_expired(cache):
        if (cache_exp := cache.headers.get("Expires")):
            exp_dt = parse_date(cache_exp).astimezone(tz=pytz.utc)
            if datetime.now(tz=pytz.utc) >= exp_dt:
                return True
        return False

    # runs in the threadpool, because we use blocking operations here
    @concurrent
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # these two may hold object HTTP HEAD responses for upstream/cached version
        flow._upstream_head = flow._cache_head = None
        flow._orig_data = {}
        flow._access_log_start = time.time()
        # we mark this flow as cached only if it returns data from the cache
        flow._cached = False
        flow._cache_redirect = False
        flow._cache_hit = False
        flow._cache_fresh = False
        flow._allow_stale_while_revalidate = False
        flow._allow_stale_if_error = False
        flow._save_response = True
        policy = flow._policy = get_policy(flow)
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
            return

        # Look up the object in the cache (Vary-aware)
        flow._cache_key = None
        flow._cache_vary = None
        try:
            vary_index_key = get_vary_index_key(flow.request.url)
            LOG.debug("Cache lookup vary index key=%s", vary_index_key)
            vary_index_head = s3_head_object(vary_index_key)
            if http_2xx(vary_index_head) and (vary_hdr := vary_index_head.headers.get("x-amz-meta-vary")):
                flow._cache_vary = vary_hdr
                if "*" not in vary_hdr:
                    vary_key = compute_vary_key(vary_hdr, flow.request.headers)
                    if vary_key is not None:
                        flow._cache_key = get_cache_key(flow.request.url, vary_key)
                        LOG.debug(
                            "Cache lookup vary header=%s vary_key=%s cache_key=%s",
                            vary_hdr,
                            vary_key,
                            flow._cache_key,
                        )
            if flow._cache_key is None and flow._cache_vary != "*":
                flow._cache_key = get_cache_key(flow.request.url)
                LOG.debug("Cache lookup default key=%s", flow._cache_key)
            if flow._cache_key:
                flow._cache_head = s3_head_object(flow._cache_key)
                LOG.debug(
                    "Cache HEAD status=%s key=%s",
                    flow._cache_head.status_code,
                    flow._cache_key,
                )
        except Exception as e:
            # if S3 is unavailable, go to upstream directly
            LOG.warning(
                "HTTP HEAD to\n%s\nhas failed with:\n%s",
                get_cache_url(flow),
                e,
            )
            return
        if (not (http_2xx(flow._cache_head)
                 or flow._cache_head.status_code == 404)):
            # If we got non-2xx or 404 from the S3, the proxy is not
            # functional, so return this as an error
            flow._save_response = False
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
            meta_method = flow._cache_head.headers.get("x-amz-meta-method")
            if meta_method is None:
                cached_method = True
            elif meta_method == "GET" or meta_method == flow.request.method:
                cached_method = True
        if flow._cache_head is not None:
            LOG.debug(
                "Cache metadata status=%s method_meta=%s etag_meta=%s lastmod_meta=%s",
                getattr(flow._cache_head, "status_code", None),
                flow._cache_head.headers.get("x-amz-meta-method"),
                flow._cache_head.headers.get("x-amz-meta-header-etag"),
                flow._cache_head.headers.get("x-amz-meta-last-modified"),
            )
            LOG.debug("Cache method match cached_method=%s", cached_method)

        refresh_patterns = get_refresh_patterns()
        cache_hit = http_2xx(flow._cache_head) and cached_method
        freshness = (
            cache_freshness(flow.request.url, flow._cache_head.headers, refresh_patterns)
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
            "Cache freshness cached_method=%s cache_fresh=%s policy=%s stale_while_revalidate=%s stale_if_error=%s",
            cached_method,
            cache_fresh,
            policy.__name__,
            allow_stale_while_revalidate,
            allow_stale_if_error,
        )

        if cache_hit:
            if policy == NoRefresh:
                LOG.debug("Cache hit: NoRefresh -> cache_redirect")
                if getattr(ctx.options, "cache_redirect", False):
                    cache_redirect_response(flow)
                    return
                cache_redirect(flow)
                return
            if cache_fresh and policy in (Standard, StaleIfError):
                LOG.debug("Cache hit: fresh -> cache_redirect")
                if getattr(ctx.options, "cache_redirect", False):
                    cache_redirect_response(flow)
                    return
                cache_redirect(flow)
                return
            if policy in (Standard, StaleIfError) and allow_stale_while_revalidate:
                LOG.debug("Cache hit: stale-while-revalidate -> cache_redirect")
                if getattr(ctx.options, "cache_redirect", False):
                    cache_redirect_response(flow)
                    return
                cache_redirect(flow)
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
                if (etag := flow._cache_head.headers.get("x-amz-meta-header-etag")):
                    upstream_hdrs["If-None-Match"] = etag
                if (lastmod := flow._cache_head.headers.get("x-amz-meta-last-modified")):
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
                if getattr(ctx.options, "cache_redirect", False):
                    cache_redirect_response(flow)
                    return
                cache_redirect(flow)
                return

        # On upstream errors or if it's banned, StaleIfError may serve cached content.
        if upstream_failed or (flow._upstream_head and flow._upstream_head.status_code >= 400):
            if cache_hit and (policy == StaleIfError or allow_stale_if_error):
                LOG.debug("Upstream failed -> cache_redirect (StaleIfError)")
                if getattr(ctx.options, "cache_redirect", False):
                    cache_redirect_response(flow)
                    return
                cache_redirect(flow)
                return

        # If upstream didn't respond (or banned) and we have a cache miss,
        # return a 504 HTTP error
        if upstream_failed:
            flow._save_response = False
            if _is_tls_verify_error(flow._upstream_error):
                detail = str(flow._upstream_error) if flow._upstream_error else "unknown"
                flow.response = http.Response.make(
                    502,
                    f"""<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<p>Upstream TLS certificate verification failed.</p>
<pre>{detail}</pre>
</body>
    </html>""".encode("utf-8"),
                    {"Content-Type": "text/html"},
                )
            else:
                flow.response = http.Response.make(
                    504,
                    b"""<html>
<head><title>504 Gateway Time-out</title></head>
<body>
<center><h1>504 Gateway Time-out</h1></center>
</body>
</html>""",
                    {"Content-Type": "text/html"},
                )
            return

        if (cache_hit
                and policy in (Standard, StaleIfError)
                and flow._upstream_head
                and (http_2xx(flow._upstream_head) or flow._upstream_head.status_code == 304)):
            # if any of lastmod or etag changed, we must re-fetch the object,
            # otherwise return the stored variant (revalidated)
            if not (flow._upstream_head.headers.get("last-modified")
                    != flow._cache_head.headers.get("x-amz-meta-last-modified")
                    or flow._upstream_head.headers.get("etag") != flow._cache_head.headers.get("x-amz-meta-header-etag")):
                if flow._cache_key:
                    refresh_cache_metadata(flow._cache_key, flow._cache_head.headers)
                cache_redirect(flow)
                return


    def responseheaders(self, flow):
        if getattr(flow, "_cache_redirect", False):
            flow.response.headers["x-proxy-policy"] = flow._policy.__name__
            existing_via = flow.response.headers.get("via", "")
            flow.response.headers["via"] = (
                f"{VIA_HEADER_VALUE}, {existing_via}" if existing_via else VIA_HEADER_VALUE
            )
            flow.response.headers["Cache-Status"] = f"{SERVER_NAME};hit;detail=redirect"
            if flow._cache_head and (stored_dt := cache_stored_at(flow._cache_head.headers)):
                stored_dt = stored_dt.astimezone(pytz.utc)
                age_seconds = int((datetime.now(tz=pytz.utc) - stored_dt).total_seconds())
                flow.response.headers["Age"] = str(max(0, age_seconds))
            return
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
            cache_key = flow._cache_key or get_cache_key(flow.request.url)
            try:
                cached_resp = requests.get(
                    get_cache_url(flow, cache_key),
                    timeout=CACHE_TIMEOUT,
                )
                if http_2xx(cached_resp):
                    flow.response = http.Response.make(
                        cached_resp.status_code,
                        cached_resp.content,
                        dict(cached_resp.headers),
                    )
                    flow._cached = True
                    flow._save_response = False
            except Exception as e:
                LOG.debug("Cache fallback fetch failed: %s", e)

        flow.response.headers["x-proxy-policy"] = flow._policy.__name__
        # Identify proxy via Via (RFC 7230); do not rewrite Server header
        existing_via = flow.response.headers.get("via", "")
        flow.response.headers["via"] = f"{VIA_HEADER_VALUE}, {existing_via}" if existing_via else VIA_HEADER_VALUE
        if flow._save_response:
            # save the stream if we may want to cache it
            flow.response.stream = lambda data: save_response(self, flow, data)
        else:
            flow.response.stream = True
        if flow._cached:
            # this is a cached response, rewrite headers from cache (origin Server preserved)
            LOG.debug("Cache response: serving from cache")
            flow.response.headers["Cache-Status"] = f"{SERVER_NAME};hit;detail=stored"
            apply_cached_metadata(flow)
            if (stored_dt := cache_stored_at(flow.response.headers)):
                stored_dt = stored_dt.astimezone(pytz.utc)
                age_seconds = int((datetime.now(tz=pytz.utc) - stored_dt).total_seconds())
                flow.response.headers["Age"] = str(max(0, age_seconds))
        else:
            LOG.debug("Cache response: not cached")
            apply_cached_metadata(flow)
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
    def _save_to_cache(status_code, reason, method, f, digest, headers, url, cache_key, vary_header, vary_request):
        try:
            extras = {"Metadata": {
                "status-code": str(status_code),
                "reason": reason,
                "method": method,
            }}
            s3 = get_s3_client()
            f.flush()
            f.seek(0)
            extras["Metadata"]["sha224"] = digest
            extras["Metadata"]["stored-at"] = str(time.time())
            if vary_header:
                extras["Metadata"]["vary"] = vary_header
            if vary_request:
                extras["Metadata"]["vary-request"] = vary_request
            if "last-modified" in headers:
                extras["Metadata"]["last-modified"] = headers["last-modified"]
            # cache any headers, which we'll return unmodified when responding
            # from the cache. S3 limits the size of metadata and possibly
            # responds with MetadataTooLarge if it gets too large...
            for k in (
                "location",
                "etag",
                "vary",
                "content-language",
                "content-disposition",
                "content-location",
                "content-range",
                "accept-ranges",
                "link",
                "cache-control",
            ):
                if k not in headers:
                    continue
                extras["Metadata"][f"header-{k}"] = headers[k]
            # map HTTP headers to AWS S3 ExtraArgs
            m = {
                "content-type": "ContentType",
                "content-encoding": "ContentEncoding",
                "cache-control": "CacheControl",
                "expires": "Expires",
            }
            for header, aws_key in m.items():
                if header in headers:
                    extras[aws_key] = headers[header]
            s3.upload_fileobj(f, S3_BUCKET, cache_key, ExtraArgs=extras)
            if vary_header:
                s3.put_object(
                    Bucket=S3_BUCKET,
                    Key=get_vary_index_key(url),
                    Metadata={"vary": vary_header},
                )
            f.close()
        except Exception as e:
            LOG.error("Cache save error %s, %s", url, e)
            f.close()

    def response(self, flow):
        if getattr(flow, "_short_circuit", False):
            self.log_response(flow)
            return
        if (flow.request.method not in ("GET", "HEAD")
                or flow._policy == NoCache or flow._cached):
            self.log_response(flow)
            # bail out quickly if we have nothing to do with the response
            with ctx._lock:
                self.cleanup(flow)
            return

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
                    flow._cache_key = get_cache_key(flow.request.url, vary_key)
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
            # check if the downloaded file and the cached are the same and if
            # so, don't save it again
            if self.hashes[flow._counter].hexdigest() == flow._cache_head.headers.get("x-amz-meta-sha224"):
                flow._save_response = False
        if flow._cache_head:
            # only store HEAD responses if we haven't yet completed a GET
            if (flow.request.method == "HEAD"
                    and flow._cache_head.headers["x-amz-meta-method"] == "GET"):
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
            cache_key = flow._cache_key or get_cache_key(flow.request.url)
            LOG.debug("Cache save enqueue key=%s", cache_key)
            ctx._executor.submit(
                self._save_to_cache,
                # save the original values in the cache for eg. in a
                # 304 not-modified situation
                flow._orig_data.get("status_code") or flow.response.status_code,
                flow._orig_data.get("reason") or flow.response.reason,
                flow.request.method,
                self.files[flow._counter],
                self.hashes[flow._counter].hexdigest(),
                flow.response.headers,
                flow.request.url,
                cache_key,
                getattr(flow, "_cache_vary", None),
                getattr(flow, "_cache_vary_request", None),
            )

        if flow.response.status_code == 304:
            # empty content on 304 not-modified, even if we have a fully cached
            # GET response, we must not return content
            flow.response.content = None

        self.log_response(flow)
        with ctx._lock:
            self.cleanup(flow)

    def error(self, flow):
        writer = _access_log_writer()
        if writer:
            try:
                writer.add(_build_access_log_record(flow, error=str(flow.error)))
            except Exception as exc:
                LOG.debug("Access log write skipped: %s", exc)
        with ctx._lock:
            self.cleanup(flow)

    def done(self):
        writer = _access_log_writer()
        if writer:
            writer.stop()

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
