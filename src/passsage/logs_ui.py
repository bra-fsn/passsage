import os
import statistics
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from urllib.parse import urlparse

import pyarrow.dataset as ds
import s3fs
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Footer, Header, Input, Static


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
    ]

    def __init__(self, rows: list[dict]):
        super().__init__()
        self._rows = rows
        self._filtered = rows
        self._query_value = ""
        self._summary = Static(id="summary")
        self._table = ToggleFocusTable(id="table")
        self._search_input = QueryInput(placeholder="Search url/ua", id="query")
        self._search_input.add_class("hidden")

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield self._search_input
            yield self._summary
            yield self._table
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

    def _refresh_view(self) -> None:
        self._filtered = self._apply_filters(self._rows)
        self._render_summary(self._filtered)
        self._render_table(self._filtered)

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
        for row in rows[:500]:
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


def run_logs_ui(bucket: str, prefix: str, start_date: str, end_date: str, limit: int | None) -> None:
    start = _parse_date(start_date)
    end = _parse_date(end_date)
    rows = load_access_logs(bucket, prefix, start, end, limit)
    AccessLogApp(rows).run()
