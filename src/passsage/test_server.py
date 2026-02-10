"""Threaded local HTTP server for integration tests."""

from __future__ import annotations

import gzip
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

RFC1123 = "%a, %d %b %Y %H:%M:%S GMT"


def _httpdate(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(RFC1123)


@dataclass
class _TestState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    counts: Dict[str, int] = field(default_factory=dict)
    requests: Dict[str, list[dict]] = field(default_factory=dict)
    last_modified: datetime = field(default_factory=lambda: datetime(2024, 1, 1, tzinfo=timezone.utc))
    version: int = 1
    policy_overrides: Dict[str, dict] = field(default_factory=dict)

    def reset(self) -> None:
        with self.lock:
            self.counts.clear()
            self.requests.clear()
            self.last_modified = datetime(2024, 1, 1, tzinfo=timezone.utc)
            self.version = 1
            self.policy_overrides.clear()

    def record(self, path: str, record: dict) -> None:
        with self.lock:
            self.counts[path] = self.counts.get(path, 0) + 1
            self.requests.setdefault(path, []).append(record)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "counts": dict(self.counts),
                "requests": {k: list(v) for k, v in self.requests.items()},
                "policy_overrides": dict(self.policy_overrides),
            }

    def set_policy_override(self, policy_name: str, *, status: int | None = None, delay: float | None = None) -> None:
        path = f"/policy/{policy_name}"
        with self.lock:
            self.policy_overrides[path] = {
                "status": status,
                "delay": delay,
            }

    def set_path_override(self, path: str, *, status: int | None = None, delay: float | None = None) -> None:
        with self.lock:
            self.policy_overrides[path] = {
                "status": status,
                "delay": delay,
            }

    def bump_version(self) -> None:
        with self.lock:
            self.version += 1
            self.last_modified = datetime.now(tz=timezone.utc)


class _Handler(BaseHTTPRequestHandler):
    server: "_TestHTTPServer"

    def log_message(self, format: str, *args) -> None:
        return

    def do_HEAD(self) -> None:
        self._handle_request(send_body=False)

    def do_GET(self) -> None:
        self._handle_request(send_body=True)

    def _handle_request(self, send_body: bool) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        record = {
            "method": self.command,
            "path": path,
            "query": query,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }
        self.server.state.record(path, record)

        if path.startswith("/delay/"):
            seconds = float(path.split("/delay/", 1)[1] or "0")
            time.sleep(seconds)
            self._respond_text(HTTPStatus.OK, f"delayed {seconds}", send_body)
            return

        if path.startswith("/status/"):
            code_str = path.split("/status/", 1)[1] or "200"
            code = int(code_str)
            self._respond_text(code, f"status {code}", send_body)
            return

        if path.startswith("/policy/"):
            policy_name = path.split("/policy/", 1)[1] or "Unknown"
            self._respond_policy(policy_name, query, send_body)
            return

        if path.startswith("/vary/accept-encoding"):
            self._respond_vary_accept_encoding(send_body)
            return

        if path.startswith("/encoding/gzip"):
            self._respond_gzip_json(send_body)
            return

        if path.startswith("/cache-control/"):
            case = path.split("/cache-control/", 1)[1] or ""
            self._respond_cache_control(case, send_body)
            return

        if path == "/redirect":
            self._respond_redirect(send_body)
            return

        if path == "/headers":
            self._respond_headers(send_body)
            return

        if path.startswith("/range-data/"):
            size_str = path.split("/range-data/", 1)[1] or "0"
            size_bytes = int(size_str)
            self._respond_range_data(size_bytes, send_body)
            return

        if path.startswith("/stream/"):
            size_str = path.split("/stream/", 1)[1] or "0"
            size_bytes = int(size_str)
            bandwidth = None
            if "bandwidth" in query:
                try:
                    bandwidth = float(query.get("bandwidth", ["0"])[0])
                except (TypeError, ValueError):
                    bandwidth = None
            self._respond_stream(size_bytes, bandwidth, send_body)
            return

        if path == "/stats":
            payload = json.dumps(self.server.state.snapshot()).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if send_body:
                self.wfile.write(payload)
            return

        if path == "/reset":
            self.server.state.reset()
            self._respond_text(HTTPStatus.OK, "reset", send_body)
            return

        self._respond_text(HTTPStatus.NOT_FOUND, "not found", send_body)

    def _respond_policy(self, policy_name: str, query: dict, send_body: bool) -> None:
        path = f"/policy/{policy_name}"
        override = self.server.state.policy_overrides.get(path, {})
        delay = override.get("delay")
        if delay is None and "delay" in query:
            delay = float(query.get("delay", ["0"])[0])
        if delay:
            time.sleep(delay)
        status = override.get("status")
        if status is None and "status" in query:
            status = int(query.get("status", ["200"])[0])
        status = status or HTTPStatus.OK
        body = f"policy {policy_name}".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Last-Modified", _httpdate(self.server.state.last_modified))
        self.send_header("ETag", f"\"{policy_name}-etag\"")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _respond_cache_control(self, case: str, send_body: bool) -> None:
        path = f"/cache-control/{case}"
        override = self.server.state.policy_overrides.get(path, {})
        delay = override.get("delay")
        if delay:
            time.sleep(delay)
        status = override.get("status") or HTTPStatus.OK
        cache_control = None
        expires_value = None
        body = f"cache-control {case}".encode("utf-8")
        etag = f"\"cache-{case}\""
        if case == "no-store":
            cache_control = "no-store"
        elif case == "no-cache":
            cache_control = "no-cache"
        elif case == "max-age":
            cache_control = "max-age=60"
        elif case == "max-age-low":
            cache_control = "max-age=1"
        elif case == "expires":
            exp = datetime.now(tz=timezone.utc) + timedelta(seconds=60)
            expires_value = _httpdate(exp)
        elif case == "private":
            cache_control = "private, max-age=60"
        elif case == "stale-if-error":
            cache_control = "max-age=1, stale-if-error=60"
        elif case == "stale-while-revalidate":
            cache_control = "max-age=1, stale-while-revalidate=60"
        elif case == "changing":
            cache_control = "max-age=1"
            body = f"version={self.server.state.version}".encode("utf-8")
            etag = f"\"cache-changing-{self.server.state.version}\""
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Last-Modified", _httpdate(self.server.state.last_modified))
        self.send_header("ETag", etag)
        if cache_control:
            self.send_header("Cache-Control", cache_control)
        if case == "expires":
            self.send_header("Expires", expires_value)
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _respond_vary_accept_encoding(self, send_body: bool) -> None:
        accept_encoding = self.headers.get("Accept-Encoding", "")
        if "gzip" in accept_encoding:
            body = b"vary gzip"
        else:
            body = b"vary identity"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Vary", "Accept-Encoding")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _respond_gzip_json(self, send_body: bool) -> None:
        payload = json.dumps({"status": "ok", "encoding": "gzip"}).encode("utf-8")
        body = gzip.compress(payload)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Vary", "Accept-Encoding")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Last-Modified", _httpdate(self.server.state.last_modified))
        self.send_header("ETag", "\"encoding-gzip\"")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _respond_redirect(self, send_body: bool) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", "/redirect-target")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "public, max-age=3600")
        body = b"redirect"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _respond_headers(self, send_body: bool) -> None:
        body = b"headers"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Language", "en")
        self.send_header("Content-Disposition", "inline")
        self.send_header("Content-Location", "/headers")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Link", '</style.css>; rel="preload"; as="style"')
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _respond_range_data(self, total_size: int, send_body: bool) -> None:
        """Serve deterministic data with full HTTP Range support.

        The content at byte position i is (i % 256).  Any slice can be
        independently generated without materialising the full body.
        """
        range_header = self.headers.get("Range", "")
        etag = f'"range-data-{total_size}"'

        if not range_header:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(total_size))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Last-Modified", _httpdate(self.server.state.last_modified))
            self.end_headers()
            if send_body:
                self._write_deterministic(0, total_size)
            return

        start, end = self._parse_range(range_header, total_size)
        if start is None:
            self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
            self.send_header("Content-Range", f"bytes */{total_size}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        length = end - start + 1
        self.send_response(HTTPStatus.PARTIAL_CONTENT)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Range", f"bytes {start}-{end}/{total_size}")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Last-Modified", _httpdate(self.server.state.last_modified))
        self.end_headers()
        if send_body:
            self._write_deterministic(start, length)

    @staticmethod
    def _parse_range(header: str, total: int) -> tuple[int | None, int | None]:
        """Parse a single Range: bytes=... header.  Returns (start, end) inclusive or (None, None)."""
        if not header.startswith("bytes="):
            return None, None
        spec = header[len("bytes="):].strip()
        if "," in spec:
            return None, None
        if spec.startswith("-"):
            suffix_len = int(spec[1:])
            if suffix_len <= 0 or suffix_len > total:
                return None, None
            return total - suffix_len, total - 1
        parts = spec.split("-", 1)
        start = int(parts[0])
        end = int(parts[1]) if parts[1] else total - 1
        end = min(end, total - 1)
        if start > end or start >= total:
            return None, None
        return start, end

    def _write_deterministic(self, offset: int, length: int) -> None:
        """Write `length` bytes of the deterministic pattern starting at `offset`."""
        chunk_size = 64 * 1024
        written = 0
        try:
            while written < length:
                to_write = min(chunk_size, length - written)
                pos = offset + written
                buf = bytearray(to_write)
                for i in range(to_write):
                    buf[i] = (pos + i) % 256
                self.wfile.write(buf)
                written += to_write
        except BrokenPipeError:
            return

    def _respond_stream(self, size_bytes: int, bandwidth: float | None, send_body: bool) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size_bytes))
        self.send_header("Last-Modified", _httpdate(self.server.state.last_modified))
        self.send_header("ETag", f"\"stream-{size_bytes}\"")
        self.send_header("Cache-Control", "public, max-age=60")
        self.end_headers()
        if not send_body:
            return
        chunk_size = 64 * 1024
        chunk = b"0" * chunk_size
        remaining = size_bytes
        if bandwidth is not None and bandwidth <= 0:
            bandwidth = None
        try:
            while remaining > 0:
                to_send = min(chunk_size, remaining)
                self.wfile.write(chunk[:to_send])
                remaining -= to_send
                if bandwidth:
                    time.sleep(to_send / bandwidth)
        except BrokenPipeError:
            return

    def _respond_text(self, status: int | HTTPStatus, text: str, send_body: bool) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)


class _TestHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.state = _TestState()


class TestServer:
    __test__ = False

    def __init__(self, public_host: str | None = None) -> None:
        self._server: Optional[_TestHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._public_host = public_host

    def start(self, host: str = "127.0.0.1", port: int = 0) -> None:
        if self._server is not None:
            return
        self._server = _TestHTTPServer((host, port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("Server not started")
        host, port = self._server.server_address
        return host, port

    @property
    def base_url(self) -> str:
        host, port = self.address
        public_host = self._public_host or host
        return f"http://{public_host}:{port}"

    def url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url}{path}"

    def reset(self) -> None:
        if self._server is None:
            return
        self._server.state.reset()

    def stats(self) -> dict:
        if self._server is None:
            return {"counts": {}, "requests": {}}
        return self._server.state.snapshot()

    def set_policy_override(self, policy_name: str, *, status: int | None = None, delay: float | None = None) -> None:
        if self._server is None:
            raise RuntimeError("Server not started")
        self._server.state.set_policy_override(policy_name, status=status, delay=delay)

    def set_path_override(self, path: str, *, status: int | None = None, delay: float | None = None) -> None:
        if self._server is None:
            raise RuntimeError("Server not started")
        self._server.state.set_path_override(path, status=status, delay=delay)

    def bump_version(self) -> None:
        if self._server is None:
            raise RuntimeError("Server not started")
        self._server.state.bump_version()
