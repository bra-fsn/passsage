import json
import os
import statistics
from datetime import date, datetime, timedelta
from urllib.parse import urlparse

import pyarrow.dataset as ds
import s3fs
from rich import box
from rich.console import Group
from rich.table import Table
from textual.app import App, ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Static, TabbedContent, TabPane, Tabs


def _parse_date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def _iter_dates(start: date, end: date):
    cur = start
    while cur <= end:
        yield cur
        cur += timedelta(days=1)


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    idx = max(0, min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def _format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"


def load_access_logs(bucket: str, prefix: str, start: date, end: date, limit: int | None):
    endpoint_url = os.environ.get("S3_ENDPOINT_URL", "").strip()
    client_kwargs = {}
    config_kwargs = {}
    use_ssl = True
    if endpoint_url:
        parsed = urlparse(endpoint_url)
        use_ssl = parsed.scheme == "https"
        client_kwargs["endpoint_url"] = endpoint_url
        config_kwargs = {"s3": {"addressing_style": "path"}}
    fs = s3fs.S3FileSystem(
        client_kwargs=client_kwargs or None,
        config_kwargs=config_kwargs or None,
        use_ssl=use_ssl,
    )
    base = prefix.strip("/")
    paths: list[str] = []
    for d in _iter_dates(start, end):
        date_part = d.strftime("%Y-%m-%d")
        pattern = f"{bucket}/{base}/date={date_part}/hour=*/*.parquet"
        for key in fs.glob(pattern):
            paths.append(f"s3://{key}")
    if not paths:
        return []
    dataset = ds.dataset(paths, filesystem=fs, format="parquet", partitioning="hive")
    table = dataset.to_table()
    rows = table.to_pylist()
    if limit:
        rows = rows[:limit]
    return rows


class ToggleFocusTable(DataTable):
    def on_key(self, event) -> None:
        if event.key in ("tab", "shift+tab"):
            event.stop()
            self.app.action_toggle_focus()
        if event.key == "enter":
            event.stop()
            self.app.action_show_details()


class QueryInput(Input):
    def on_key(self, event) -> None:
        if event.key in ("tab", "shift+tab"):
            event.stop()
            self.app.action_toggle_focus()
        if event.key == "enter":
            event.stop()
            self.app.action_apply_query()
        if event.key == "escape":
            event.stop()
            self.app.action_hide_query()


class DetailsScreen(ModalScreen):
    def __init__(self, content) -> None:
        super().__init__()
        self._content = content

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(self._content)

    def on_key(self, event) -> None:
        if event.key in ("escape", "q", "enter"):
            event.stop()
            self.app.pop_screen()


class AccessLogApp(App):
    CSS = """
    Screen { layout: vertical; }
    #query { height: 3; }
    #summary { height: 6; }
    #table { height: 1fr; }
    .hidden { display: none; }
    """
    BINDINGS = [
        ("/", "focus_search", "Search"),
        ("tab", "toggle_focus", "Toggle focus"),
        ("shift+tab", "toggle_focus", "Toggle focus"),
        ("ctrl+tab", "next_tab", "Next tab"),
        ("ctrl+shift+tab", "prev_tab", "Previous tab"),
        ("alt+right", "next_tab", "Next tab"),
        ("alt+left", "prev_tab", "Previous tab"),
        ("1", "show_logs_tab", "Logs tab"),
        ("2", "show_stats_tab", "Stats tab"),
    ]

    def __init__(self, rows: list[dict]):
        super().__init__()
        self._rows = rows
        self._filtered = rows
        self._visible_rows: list[dict] = []
        self._query_value = ""
        self._summary = Static(id="summary")
        self._table = ToggleFocusTable(id="table")
        self._host_stats = DataTable(id="host_stats")
        self._ua_stats = DataTable(id="ua_stats")
        self._client_stats = DataTable(id="client_stats")
        self._search_input = QueryInput(placeholder="Search url/ua", id="query")
        self._search_input.add_class("hidden")

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield self._search_input
            with TabbedContent(id="tabs"):
                with TabPane("Logs", id="logs"):
                    yield self._summary
                    yield self._table
                with TabPane("Stats", id="stats"):
                    yield Static("By upstream host")
                    yield self._host_stats
                    yield Static("By user agent")
                    yield self._ua_stats
                    yield Static("By client IP")
                    yield self._client_stats
        yield Footer()

    def on_mount(self) -> None:
        self._table.add_columns(
            "timestamp",
            "method",
            "status",
            "host",
            "path",
            "cached",
            "duration_ms",
            "bytes",
            "user_agent",
        )
        self._host_stats.add_columns(
            "host",
            "count",
            "cached",
            "cache_rate",
            "mean_ms",
            "p95_ms",
            "total_bytes",
        )
        self._ua_stats.add_columns(
            "user_agent",
            "count",
            "cached",
            "cache_rate",
            "mean_ms",
            "p95_ms",
            "total_bytes",
        )
        self._client_stats.add_columns(
            "client_ip",
            "count",
            "cached",
            "cache_rate",
            "mean_ms",
            "p95_ms",
            "total_bytes",
        )
        self._refresh_view()
        self.set_focus(self._table)

    def action_toggle_focus(self) -> None:
        if self.focused is self._table:
            self.set_focus(self._search_input)
        else:
            self.set_focus(self._table)

    def action_focus_search(self) -> None:
        self._search_input.remove_class("hidden")
        self.set_focus(self._search_input)

    def action_apply_query(self) -> None:
        self._query_value = self._search_input.value.strip()
        self._refresh_view()
        self.action_hide_query()

    def action_hide_query(self) -> None:
        self._search_input.add_class("hidden")
        self.set_focus(self._table)

    def on_key(self, event) -> None:
        if event.key == "/":
            event.stop()
            self.action_focus_search()

    def action_next_tab(self) -> None:
        self._cycle_tab(1)

    def action_prev_tab(self) -> None:
        self._cycle_tab(-1)

    def _cycle_tab(self, direction: int) -> None:
        tabbed = self.query_one("#tabs", TabbedContent)
        tab_ids = ["logs", "stats"]
        current = tabbed.active or tab_ids[0]
        if current not in tab_ids:
            tabbed.active = tab_ids[0]
            return
        idx = tab_ids.index(current)
        tabbed.active = tab_ids[(idx + direction) % len(tab_ids)]

    def action_show_logs_tab(self) -> None:
        self._set_tab_and_focus("logs", self._table)

    def action_show_stats_tab(self) -> None:
        self._set_tab_and_focus("stats", self._host_stats)

    def _set_tab_and_focus(self, tab_id: str, widget: DataTable) -> None:
        tabbed = self.query_one("#tabs", TabbedContent)
        tabbed.active = tab_id
        self.set_focus(widget)

    def _refresh_view(self) -> None:
        self._filtered = self._apply_filters(self._rows)
        self._render_summary(self._filtered)
        self._render_table(self._filtered)
        self._render_stats(self._filtered)

    def _apply_filters(self, rows: list[dict]) -> list[dict]:
        filtered = []
        for row in rows:
            if self._query_value:
                term = self._query_value.lower()
                url = (row.get("url") or "").lower()
                ua = (row.get("user_agent") or "").lower()
                if term not in url and term not in ua:
                    continue
            filtered.append(row)
        return filtered

    def _render_summary(self, rows: list[dict]) -> None:
        count = len(rows)
        cached = sum(1 for r in rows if r.get("cached"))
        durations = [r.get("duration_ms") or 0 for r in rows]
        bytes_sent = [r.get("bytes_sent") or 0 for r in rows]
        mean_ms = statistics.mean(durations) if durations else 0.0
        p95_ms = _percentile(durations, 95)
        total_bytes = sum(bytes_sent)
        summary = (
            f"count={count} cached={cached} "
            f"cache_rate={cached / count:.2%} " if count else "count=0 cached=0 "
        )
        summary += (
            f"mean_ms={mean_ms:.1f} p95_ms={p95_ms:.1f} "
            f"total_bytes={_format_bytes(total_bytes)}"
        )
        self._summary.update(summary)

    def _render_table(self, rows: list[dict]) -> None:
        self._table.clear()
        self._visible_rows = rows[:500]
        for row in self._visible_rows:
            ts = row.get("timestamp")
            ts_text = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
            self._table.add_row(
                ts_text,
                row.get("method"),
                str(row.get("status_code") or ""),
                row.get("host"),
                row.get("path"),
                str(row.get("cached")),
                str(row.get("duration_ms") or ""),
                str(row.get("bytes_sent") or ""),
                row.get("user_agent") or "",
            )

    def _render_stats(self, rows: list[dict]) -> None:
        self._render_grouped_stats(self._host_stats, rows, "host", 50)
        self._render_grouped_stats(self._ua_stats, rows, "user_agent", 50)
        self._render_grouped_stats(self._client_stats, rows, "client_ip", 50)

    def _render_grouped_stats(
        self,
        table: DataTable,
        rows: list[dict],
        key: str,
        limit: int,
    ) -> None:
        groups: dict[str, list[dict]] = {}
        for row in rows:
            value = row.get(key) or ""
            groups.setdefault(value, []).append(row)
        stats_rows = []
        for value, items in groups.items():
            count = len(items)
            cached = sum(1 for r in items if r.get("cached"))
            durations = [r.get("duration_ms") or 0 for r in items]
            bytes_sent = [r.get("bytes_sent") or 0 for r in items]
            mean_ms = statistics.mean(durations) if durations else 0.0
            p95_ms = _percentile(durations, 95)
            total_bytes = sum(bytes_sent)
            cache_rate = f"{cached / count:.2%}" if count else "0.00%"
            stats_rows.append(
                (
                    str(value),
                    str(count),
                    str(cached),
                    cache_rate,
                    f"{mean_ms:.1f}",
                    f"{p95_ms:.1f}",
                    _format_bytes(total_bytes),
                )
            )
        stats_rows.sort(key=lambda r: int(r[1]), reverse=True)
        table.clear()
        for row in stats_rows[:limit]:
            table.add_row(*row)
    def action_show_details(self) -> None:
        if not self._visible_rows:
            return
        row_index = self._table.cursor_row
        if row_index is None or row_index >= len(self._visible_rows):
            return
        row = self._visible_rows[row_index]
        self.push_screen(DetailsScreen(_build_details_renderable(row)))


def _format_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _format_kv_table(title: str, items: list[tuple[str, str]]) -> Table:
    table = Table(title=title, box=box.SIMPLE, show_header=False)
    table.add_column("key", style="bold cyan", no_wrap=True)
    table.add_column("value", style="white")
    for key, value in items:
        table.add_row(key, value)
    return table


def _format_headers_table(title: str, headers) -> Table | None:
    if not headers:
        return None
    if isinstance(headers, list):
        headers = {k: v for k, v in headers if len((k, v)) == 2}
    table = Table(title=title, box=box.SIMPLE, show_header=False)
    table.add_column("header", style="bold magenta", no_wrap=True)
    table.add_column("value", style="white")
    for key in sorted(headers.keys()):
        table.add_row(key, str(headers[key]))
    return table


def _build_details_renderable(row: dict):
    request_items = [
        ("timestamp", _format_value(row.get("timestamp"))),
        ("request_id", _format_value(row.get("request_id"))),
        ("method", _format_value(row.get("method"))),
        ("url", _format_value(row.get("url"))),
        ("host", _format_value(row.get("host"))),
        ("path", _format_value(row.get("path"))),
        ("query", _format_value(row.get("query"))),
        ("scheme", _format_value(row.get("scheme"))),
        ("port", _format_value(row.get("port"))),
        ("client_ip", _format_value(row.get("client_ip"))),
        ("client_port", _format_value(row.get("client_port"))),
        ("user_agent", _format_value(row.get("user_agent"))),
    ]
    response_items = [
        ("status_code", _format_value(row.get("status_code"))),
        ("reason", _format_value(row.get("reason"))),
        ("content_length", _format_value(row.get("content_length"))),
        ("content_type", _format_value(row.get("content_type"))),
        ("content_encoding", _format_value(row.get("content_encoding"))),
    ]
    cache_items = [
        ("policy", _format_value(row.get("policy"))),
        ("cached", _format_value(row.get("cached"))),
        ("cache_redirect", _format_value(row.get("cache_redirect"))),
        ("cache_key", _format_value(row.get("cache_key"))),
        ("cache_vary", _format_value(row.get("cache_vary"))),
        ("cache_hit", _format_value(row.get("cache_hit"))),
        ("cache_fresh", _format_value(row.get("cache_fresh"))),
        ("stale_while_revalidate", _format_value(row.get("stale_while_revalidate"))),
        ("stale_if_error", _format_value(row.get("stale_if_error"))),
        ("cache_head_status", _format_value(row.get("cache_head_status"))),
        ("cache_head_etag", _format_value(row.get("cache_head_etag"))),
        ("cache_head_last_modified", _format_value(row.get("cache_head_last_modified"))),
        ("cache_head_method", _format_value(row.get("cache_head_method"))),
    ]
    upstream_items = [
        ("upstream_head_status", _format_value(row.get("upstream_head_status"))),
        ("upstream_head_time_ms", _format_value(row.get("upstream_head_time_ms"))),
        ("upstream_error", _format_value(row.get("upstream_error"))),
    ]
    timing_items = [
        ("duration_ms", _format_value(row.get("duration_ms"))),
        ("bytes_sent", _format_value(row.get("bytes_sent"))),
    ]
    error_items = [
        ("error", _format_value(row.get("error"))),
    ]
    group_items = [
        _format_kv_table("Request", request_items),
        _format_kv_table("Response", response_items),
        _format_kv_table("Cache", cache_items),
        _format_kv_table("Upstream", upstream_items),
        _format_kv_table("Timing", timing_items),
        _format_kv_table("Errors", error_items),
    ]
    req_headers_table = _format_headers_table("Request Headers", row.get("request_headers"))
    if req_headers_table:
        group_items.append(req_headers_table)
    resp_headers_table = _format_headers_table("Response Headers", row.get("response_headers"))
    if resp_headers_table:
        group_items.append(resp_headers_table)
    return Group(*group_items)


def run_logs_ui(bucket: str, prefix: str, start_date: str, end_date: str, limit: int | None) -> None:
    start = _parse_date(start_date)
    end = _parse_date(end_date)
    rows = load_access_logs(bucket, prefix, start, end, limit)
    AccessLogApp(rows).run()
