"""Threaded local HTTP server for integration tests."""

from __future__ import annotations

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
    policy_overrides: Dict[str, dict] = field(default_factory=dict)

    def reset(self) -> None:
        with self.lock:
            self.counts.clear()
            self.requests.clear()
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

        if path.startswith("/cache-control/"):
            case = path.split("/cache-control/", 1)[1] or ""
            self._respond_cache_control(case, send_body)
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
        body = f"cache-control {case}".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Last-Modified", _httpdate(self.server.state.last_modified))
        self.send_header("ETag", f"\"cache-{case}\"")
        if case == "no-store":
            self.send_header("Cache-Control", "no-store")
        elif case == "no-cache":
            self.send_header("Cache-Control", "no-cache")
        elif case == "max-age":
            self.send_header("Cache-Control", "max-age=60")
        elif case == "max-age-low":
            self.send_header("Cache-Control", "max-age=1")
        elif case == "expires":
            exp = datetime.now(tz=timezone.utc) + timedelta(seconds=60)
            self.send_header("Expires", _httpdate(exp))
        elif case == "private":
            self.send_header("Cache-Control", "private, max-age=60")
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
