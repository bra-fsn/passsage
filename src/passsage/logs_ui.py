import json
import os
from datetime import datetime

import duckdb
from rich import box
from rich.console import Group
from rich.table import Table
from textual.app import App, ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Static, TabbedContent, TabPane

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

ACCESS_TABLE_COLUMNS = (
    "timestamp",
    "method",
    "status_code",
    "host",
    "path",
    "cached",
    "duration_ms",
    "bytes_sent",
    "user_agent",
)

ERROR_TABLE_COLUMNS = (
    "timestamp",
    "error_type",
    "method",
    "status_code",
    "host",
    "path",
    "error_message",
    "user_agent",
)

ACCESS_ALL_COLUMNS = (
    "timestamp", "request_id", "client_ip", "client_port", "method", "url",
    "host", "scheme", "port", "path", "query", "user_agent",
    "status_code", "reason", "content_length", "content_type", "content_encoding",
    "policy", "cached", "cache_redirect", "cache_key", "cache_vary",
    "cache_hit", "cache_fresh", "stale_while_revalidate", "stale_if_error",
    "upstream_head_status", "upstream_error", "upstream_head_time_ms",
    "cache_head_status", "cache_head_etag", "cache_head_last_modified", "cache_head_method",
    "error", "duration_ms", "bytes_sent",
)

ERROR_ALL_COLUMNS = (
    "timestamp", "request_id", "client_ip", "client_port", "method", "url",
    "host", "scheme", "port", "path", "query", "user_agent",
    "status_code", "policy", "cached", "cache_redirect", "cache_key", "cache_vary",
    "cache_head_status", "upstream_head_status", "upstream_error",
    "error_type", "error_message", "traceback", "context",
)

ACCESS_STRING_COLUMNS = (
    "request_id", "client_ip", "method", "url", "host", "scheme", "path", "query",
    "user_agent", "reason", "content_type", "content_encoding", "policy",
    "cache_key", "cache_vary", "upstream_error",
    "cache_head_etag", "cache_head_last_modified", "cache_head_method", "error",
)

ERROR_STRING_COLUMNS = (
    "request_id", "client_ip", "method", "url", "host", "scheme", "path", "query",
    "user_agent", "policy", "cache_key", "cache_vary", "upstream_error",
    "error_type", "error_message", "traceback", "context",
)

# Heavy MAP columns excluded from windowed queries, fetched on demand
DETAIL_ONLY_COLUMNS = ("request_headers", "response_headers")


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def _parse_datetime(value: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse datetime: {value!r} (expected YYYY-MM-DD[THH[:MM]])")


def _has_time_component(date_str: str) -> bool:
    return "T" in date_str or " " in date_str.strip()


# ---------------------------------------------------------------------------
# DuckDB connection setup
# ---------------------------------------------------------------------------

def _init_duckdb_connection() -> duckdb.DuckDBPyConnection:
    conn = duckdb.connect()
    conn.execute("INSTALL httpfs; LOAD httpfs;")
    conn.execute("INSTALL aws; LOAD aws;")
    profile = os.environ.get("AWS_PROFILE", "").strip()
    if profile:
        conn.execute(f"CALL load_aws_credentials('{profile}');")
    else:
        conn.execute("CALL load_aws_credentials();")
    region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION", "")
    region = region.strip()
    if region:
        conn.execute(f"SET s3_region = '{region}';")
    endpoint_url = os.environ.get("S3_ENDPOINT_URL", "").strip()
    if endpoint_url:
        conn.execute(f"SET s3_endpoint = '{endpoint_url}';")
        conn.execute("SET s3_url_style = 'path';")
        if endpoint_url.startswith("http://"):
            conn.execute("SET s3_use_ssl = false;")
    return conn


# ---------------------------------------------------------------------------
# SQL query builder
# ---------------------------------------------------------------------------

def _escape_sql_string(value: str) -> str:
    return value.replace("'", "''")


def _build_query(
    bucket: str,
    prefix: str,
    start_date: str,
    end_date: str,
    *,
    grep: str | None = None,
    filters: list[str] | None = None,
    where: str | None = None,
    view: str = "access",
    extra_search: str | None = None,
    columns: tuple[str, ...] | None = None,
) -> str:
    base = prefix.strip("/")
    s3_glob = f"s3://{bucket}/{base}/**/*.parquet"
    source = f"read_parquet('{s3_glob}', hive_partitioning=true)"

    if columns is None:
        columns = ACCESS_ALL_COLUMNS if view == "access" else ERROR_ALL_COLUMNS
    col_list = ", ".join(columns)

    clauses: list[str] = []

    start = _parse_datetime(start_date)
    end = _parse_datetime(end_date)
    if not _has_time_component(end_date):
        end = end.replace(hour=23, minute=59, second=59)

    clauses.append(f"timestamp >= '{start.strftime('%Y-%m-%d %H:%M:%S')}'::TIMESTAMPTZ")
    clauses.append(f"timestamp <= '{end.strftime('%Y-%m-%d %H:%M:%S')}'::TIMESTAMPTZ")

    start_date_part = start.strftime("%Y-%m-%d")
    end_date_part = end.strftime("%Y-%m-%d")
    clauses.append(f"date >= '{start_date_part}'")
    clauses.append(f"date <= '{end_date_part}'")

    if grep:
        string_cols = ACCESS_STRING_COLUMNS if view == "access" else ERROR_STRING_COLUMNS
        or_parts = [
            f"regexp_matches(CAST({c} AS VARCHAR), '{_escape_sql_string(grep)}', 'i')"
            for c in string_cols
        ]
        clauses.append(f"({' OR '.join(or_parts)})")

    for spec in (filters or []):
        eq = spec.find("=")
        if eq < 1:
            raise ValueError(f"Invalid filter: {spec!r} (expected field=regex)")
        field = spec[:eq]
        pattern = spec[eq + 1:]
        clauses.append(
            f"regexp_matches(CAST({field} AS VARCHAR), '{_escape_sql_string(pattern)}', 'i')"
        )

    if where:
        clauses.append(f"({where})")

    if extra_search:
        string_cols = ACCESS_STRING_COLUMNS if view == "access" else ERROR_STRING_COLUMNS
        or_parts = [
            f"CAST({c} AS VARCHAR) ILIKE '%{_escape_sql_string(extra_search)}%'"
            for c in string_cols
        ]
        clauses.append(f"({' OR '.join(or_parts)})")

    where_sql = " AND ".join(clauses)
    return f"SELECT {col_list} FROM {source} WHERE {where_sql} ORDER BY timestamp"


# ---------------------------------------------------------------------------
# LogBrowser — windowed access to DuckDB query results
# ---------------------------------------------------------------------------

class LogBrowser:
    PAGE_SIZE = 500
    PREFETCH_MARGIN = 50

    def __init__(
        self,
        conn: duckdb.DuckDBPyConnection,
        bucket: str,
        prefix: str,
        start_date: str,
        end_date: str,
        *,
        grep: str | None = None,
        filters: list[str] | None = None,
        where: str | None = None,
        view: str = "access",
    ):
        self._conn = conn
        self._bucket = bucket
        self._prefix = prefix
        self._start_date = start_date
        self._end_date = end_date
        self._grep = grep
        self._filters = filters
        self._where = where
        self._view = view
        self._extra_search: str | None = None
        self._total: int | None = None

    @property
    def view(self) -> str:
        return self._view

    def set_search(self, term: str | None) -> None:
        self._extra_search = term or None
        self._total = None

    def _base_query(self, columns: tuple[str, ...] | None = None) -> str:
        return _build_query(
            self._bucket, self._prefix, self._start_date, self._end_date,
            grep=self._grep, filters=self._filters, where=self._where,
            view=self._view, extra_search=self._extra_search,
            columns=columns,
        )

    def total_count(self) -> int:
        if self._total is None:
            base = self._base_query()
            count_q = f"SELECT count(*) FROM ({base}) AS _sub"
            self._total = self._conn.execute(count_q).fetchone()[0]
        return self._total

    def fetch_window(self, offset: int, limit: int | None = None) -> list[dict]:
        if limit is None:
            limit = self.PAGE_SIZE
        base = self._base_query()
        sql = f"{base} LIMIT {limit} OFFSET {offset}"
        result = self._conn.execute(sql)
        columns = [desc[0] for desc in result.description]
        return [dict(zip(columns, row)) for row in result.fetchall()]

    def fetch_detail_row(self, request_id: str, timestamp) -> dict | None:
        base = self._prefix.strip("/")
        s3_glob = f"s3://{self._bucket}/{base}/**/*.parquet"
        source = f"read_parquet('{s3_glob}', hive_partitioning=true)"
        sql = (
            f"SELECT * FROM {source} "
            f"WHERE request_id = '{_escape_sql_string(request_id)}' "
            f"AND timestamp = '{timestamp}'::TIMESTAMPTZ "
            f"LIMIT 1"
        )
        result = self._conn.execute(sql)
        columns = [desc[0] for desc in result.description]
        row = result.fetchone()
        if row is None:
            return None
        return dict(zip(columns, row))

    def aggregate_stats(self, group_col: str, limit: int = 50) -> list[dict]:
        base = self._base_query()
        sql = f"""
            SELECT
                CAST({group_col} AS VARCHAR) AS group_key,
                count(*) AS cnt,
                count(*) FILTER (WHERE cached = true) AS cached_cnt,
                CASE WHEN count(*) > 0
                     THEN round(100.0 * count(*) FILTER (WHERE cached = true) / count(*), 2)
                     ELSE 0 END AS cache_rate,
                round(avg(COALESCE(duration_ms, 0)), 1) AS mean_ms,
                round(quantile_cont(COALESCE(duration_ms, 0), 0.95), 1) AS p95_ms,
                COALESCE(sum(bytes_sent), 0) AS total_bytes
            FROM ({base}) AS _sub
            GROUP BY group_key
            ORDER BY cnt DESC
            LIMIT {limit}
        """
        result = self._conn.execute(sql)
        columns = [desc[0] for desc in result.description]
        return [dict(zip(columns, row)) for row in result.fetchall()]

    def summary_stats(self) -> dict:
        base = self._base_query()
        if self._view == "error":
            sql = f"""
                SELECT
                    count(*) AS cnt,
                    array_agg(DISTINCT error_type) FILTER (WHERE error_type IS NOT NULL) AS error_types
                FROM ({base}) AS _sub
            """
        else:
            sql = f"""
                SELECT
                    count(*) AS cnt,
                    count(*) FILTER (WHERE cached = true) AS cached_cnt,
                    round(avg(COALESCE(duration_ms, 0)), 1) AS mean_ms,
                    round(quantile_cont(COALESCE(duration_ms, 0), 0.95), 1) AS p95_ms,
                    COALESCE(sum(bytes_sent), 0) AS total_bytes
                FROM ({base}) AS _sub
            """
        result = self._conn.execute(sql)
        columns = [desc[0] for desc in result.description]
        row = result.fetchone()
        return dict(zip(columns, row))


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _format_bytes(value) -> str:
    if value is None:
        return ""
    value = int(value)
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"


def _format_timestamp(value) -> str:
    if not isinstance(value, datetime):
        return str(value) if value is not None else ""
    base = value.strftime("%Y-%m-%dT%H:%M:%S")
    frac = int(value.microsecond / 10000)
    return f"{base}.{frac:02d}Z"


def _format_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return _format_timestamp(value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    if isinstance(value, list):
        try:
            return json.dumps(dict(value), sort_keys=True)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


# ---------------------------------------------------------------------------
# Detail view
# ---------------------------------------------------------------------------

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
        ("serve_reason", _format_value(row.get("serve_reason"))),
        ("cached_method", _format_value(row.get("cached_method"))),
        ("vary_index_key", _format_value(row.get("vary_index_key"))),
        ("cache_save", _format_value(row.get("cache_save"))),
        ("range_stripped", _format_value(row.get("range_stripped"))),
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
        ("error_type", _format_value(row.get("error_type"))),
        ("error_message", _format_value(row.get("error_message"))),
        ("traceback", _format_value(row.get("traceback"))),
        ("context", _format_value(row.get("context"))),
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


# ---------------------------------------------------------------------------
# TUI widgets
# ---------------------------------------------------------------------------

class QueryInput(Input):
    def on_key(self, event) -> None:
        if event.key == "escape":
            event.stop()
            self.app.action_hide_query()
        elif event.key == "enter":
            event.stop()
            self.app.action_apply_query()


class DetailsScreen(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close"), ("q", "dismiss", "Close")]

    def __init__(self, renderable):
        super().__init__()
        self._renderable = renderable

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(self._renderable)

    def on_key(self, event) -> None:
        if event.key == "enter":
            event.stop()
            self.dismiss()


class ToggleFocusTable(DataTable):
    def on_key(self, event) -> None:
        if event.key in ("tab", "shift+tab"):
            event.stop()
            self.app.action_toggle_focus()
        if event.key == "enter":
            event.stop()
            self.app.action_show_details()
        if event.key == "end":
            event.stop()
            self.app.action_jump_to_end()
        if event.key == "home":
            event.stop()
            self.app.action_jump_to_start()
        if event.key in ("down", "pagedown") and self.cursor_row >= self.row_count - 1:
            event.stop()
            self.app.action_load_next_window()
        if event.key in ("up", "pageup") and self.cursor_row <= 0:
            event.stop()
            self.app.action_load_prev_window()


# ---------------------------------------------------------------------------
# Main TUI application
# ---------------------------------------------------------------------------

class AccessLogApp(App):
    CSS = """
    Screen { layout: vertical; }
    #query { height: 3; }
    #summary { height: 6; }
    #table { height: 1fr; }
    #position { height: 1; dock: bottom; }
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

    def __init__(self, browser: LogBrowser, view: str = "access"):
        super().__init__()
        self._browser = browser
        self._view = view
        self._window_offset = 0
        self._window_rows: list[dict] = []
        self._total_count: int | None = None
        self._loading = False

        self._summary = Static(id="summary")
        self._table = ToggleFocusTable(id="table")
        self._position_bar = Static("", id="position")
        self._host_stats = DataTable(id="host_stats")
        self._ua_stats = DataTable(id="ua_stats")
        self._client_stats = DataTable(id="client_stats")
        placeholder = "Search url/ua" if self._view == "access" else "Search url/ua/error"
        self._search_input = QueryInput(placeholder=placeholder, id="query")
        self._search_input.add_class("hidden")

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield self._search_input
            with TabbedContent(id="tabs"):
                with TabPane("Logs", id="logs"):
                    yield self._summary
                    yield self._table
                    yield self._position_bar
                with TabPane("Stats", id="stats"):
                    yield Static("By upstream host")
                    yield self._host_stats
                    yield Static("By user agent")
                    yield self._ua_stats
                    yield Static("By client IP")
                    yield self._client_stats
        yield Footer()

    def on_mount(self) -> None:
        table_cols = ACCESS_TABLE_COLUMNS if self._view == "access" else ERROR_TABLE_COLUMNS
        display_names = {
            "status_code": "status",
            "bytes_sent": "bytes",
            "error_message": "message",
        }
        for col in table_cols:
            self._table.add_column(display_names.get(col, col), key=col)

        for tbl, label_col in [
            (self._host_stats, "host"),
            (self._ua_stats, "user_agent"),
            (self._client_stats, "client_ip"),
        ]:
            tbl.add_columns(label_col, "count", "cached", "cache_rate", "mean_ms", "p95_ms", "total_bytes")

        self._load_window(0)
        self._load_summary()
        self._load_stats()
        self.set_focus(self._table)

    # -- Window management --------------------------------------------------

    def _load_window(self, offset: int) -> None:
        if self._loading:
            return
        self._loading = True
        try:
            rows = self._browser.fetch_window(offset, LogBrowser.PAGE_SIZE)
            self._window_offset = offset
            self._window_rows = rows
            self._render_table()
            self._update_position_bar()
        finally:
            self._loading = False

    def _update_position_bar(self) -> None:
        if self._total_count is None:
            try:
                self._total_count = self._browser.total_count()
            except Exception:
                self._total_count = -1
        total = self._total_count
        if total < 0:
            total_str = "?"
        else:
            total_str = f"{total:,}"
        start = self._window_offset + 1
        end = self._window_offset + len(self._window_rows)
        self._position_bar.update(f"  rows {start:,}-{end:,} of {total_str}")

    def _check_scroll_boundary(self) -> None:
        if self._loading or not self._window_rows:
            return
        cursor = self._table.cursor_row
        if cursor is None:
            return
        page = LogBrowser.PAGE_SIZE
        margin = LogBrowser.PREFETCH_MARGIN

        if cursor >= len(self._window_rows) - margin:
            new_offset = self._window_offset + page - 2 * margin
            total = self._total_count or 0
            if total > 0 and new_offset >= total:
                return
            if new_offset == self._window_offset:
                return
            target_global = self._window_offset + cursor
            self._load_window(new_offset)
            new_cursor = target_global - new_offset
            new_cursor = max(0, min(new_cursor, len(self._window_rows) - 1))
            self._table.move_cursor(row=new_cursor)

        elif cursor < margin and self._window_offset > 0:
            new_offset = max(0, self._window_offset - page + 2 * margin)
            if new_offset == self._window_offset:
                return
            target_global = self._window_offset + cursor
            self._load_window(new_offset)
            new_cursor = target_global - new_offset
            new_cursor = max(0, min(new_cursor, len(self._window_rows) - 1))
            self._table.move_cursor(row=new_cursor)

    def on_data_table_cursor_moved(self, event) -> None:
        self._check_scroll_boundary()

    def action_jump_to_end(self) -> None:
        if self._total_count is None:
            try:
                self._total_count = self._browser.total_count()
            except Exception:
                return
        total = self._total_count
        if total <= 0:
            return
        page = LogBrowser.PAGE_SIZE
        last_offset = max(0, total - page)
        self._load_window(last_offset)
        if self._window_rows:
            self._table.move_cursor(row=len(self._window_rows) - 1)

    def action_jump_to_start(self) -> None:
        self._load_window(0)
        if self._window_rows:
            self._table.move_cursor(row=0)

    def action_load_next_window(self) -> None:
        page = LogBrowser.PAGE_SIZE
        margin = LogBrowser.PREFETCH_MARGIN
        new_offset = self._window_offset + page - 2 * margin
        total = self._total_count or 0
        if total > 0 and new_offset >= total:
            return
        if new_offset == self._window_offset:
            return
        self._load_window(new_offset)
        if self._window_rows:
            self._table.move_cursor(row=min(margin, len(self._window_rows) - 1))

    def action_load_prev_window(self) -> None:
        if self._window_offset <= 0:
            return
        page = LogBrowser.PAGE_SIZE
        margin = LogBrowser.PREFETCH_MARGIN
        new_offset = max(0, self._window_offset - page + 2 * margin)
        if new_offset == self._window_offset:
            return
        self._load_window(new_offset)
        if self._window_rows:
            self._table.move_cursor(row=max(0, len(self._window_rows) - margin - 1))

    # -- Rendering ----------------------------------------------------------

    def _render_table(self) -> None:
        self._table.clear()
        table_cols = ACCESS_TABLE_COLUMNS if self._view == "access" else ERROR_TABLE_COLUMNS
        for row in self._window_rows:
            cells = []
            for col in table_cols:
                val = row.get(col)
                if col == "timestamp":
                    cells.append(_format_timestamp(val))
                elif col == "bytes_sent":
                    cells.append(_format_bytes(val))
                elif col == "error_message":
                    msg = str(val) if val else ""
                    cells.append(f"{msg[:117]}..." if len(msg) > 120 else msg)
                else:
                    cells.append(str(val) if val is not None else "")
            self._table.add_row(*cells)

    def _load_summary(self) -> None:
        try:
            stats = self._browser.summary_stats()
        except Exception as exc:
            self._summary.update(f"Error loading summary: {exc}")
            return
        if self._view == "error":
            cnt = stats.get("cnt", 0)
            types = stats.get("error_types") or []
            type_text = ", ".join(str(t) for t in types[:5])
            suffix = f" types={len(types)} {type_text}" if types else ""
            self._summary.update(f"count={cnt}{suffix}")
        else:
            cnt = stats.get("cnt", 0)
            cached = stats.get("cached_cnt", 0)
            rate = f"{cached / cnt:.2%}" if cnt else "0.00%"
            mean_ms = stats.get("mean_ms", 0)
            p95_ms = stats.get("p95_ms", 0)
            total_bytes = _format_bytes(stats.get("total_bytes", 0))
            self._summary.update(
                f"count={cnt} cached={cached} cache_rate={rate} "
                f"mean_ms={mean_ms} p95_ms={p95_ms} total_bytes={total_bytes}"
            )

    def _load_stats(self) -> None:
        for tbl, col in [
            (self._host_stats, "host"),
            (self._ua_stats, "user_agent"),
            (self._client_stats, "client_ip"),
        ]:
            tbl.clear()
            try:
                rows = self._browser.aggregate_stats(col)
            except Exception:
                continue
            for row in rows:
                tbl.add_row(
                    str(row.get("group_key") or ""),
                    str(row.get("cnt", 0)),
                    str(row.get("cached_cnt", 0)),
                    f"{row.get('cache_rate', 0)}%",
                    str(row.get("mean_ms", 0)),
                    str(row.get("p95_ms", 0)),
                    _format_bytes(row.get("total_bytes", 0)),
                )

    # -- Search / query -----------------------------------------------------

    def action_toggle_focus(self) -> None:
        if self.focused is self._table:
            self.set_focus(self._search_input)
        else:
            self.set_focus(self._table)

    def action_focus_search(self) -> None:
        self._search_input.remove_class("hidden")
        self.set_focus(self._search_input)

    def action_apply_query(self) -> None:
        term = self._search_input.value.strip()
        self._browser.set_search(term if term else None)
        self._total_count = None
        self._load_window(0)
        self._load_summary()
        self._load_stats()
        self.action_hide_query()

    def action_hide_query(self) -> None:
        self._search_input.add_class("hidden")
        self.set_focus(self._table)

    def on_key(self, event) -> None:
        if event.key == "/":
            event.stop()
            self.action_focus_search()

    # -- Tabs ---------------------------------------------------------------

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

    # -- Detail view --------------------------------------------------------

    def action_show_details(self) -> None:
        if not self._window_rows:
            return
        row_index = self._table.cursor_row
        if row_index is None or row_index >= len(self._window_rows):
            return
        row = self._window_rows[row_index]
        request_id = row.get("request_id")
        timestamp = row.get("timestamp")
        if request_id and timestamp:
            detail = self._browser.fetch_detail_row(request_id, timestamp)
            if detail:
                row = detail
        self.push_screen(DetailsScreen(_build_details_renderable(row)))


# ---------------------------------------------------------------------------
# Entry points (called from cli.py)
# ---------------------------------------------------------------------------

def run_logs_ui(
    bucket: str,
    prefix: str,
    start_date: str,
    end_date: str,
    grep: str | None = None,
    filters: list[str] | None = None,
    where: str | None = None,
) -> None:
    conn = _init_duckdb_connection()
    browser = LogBrowser(
        conn, bucket, prefix, start_date, end_date,
        grep=grep, filters=filters, where=where, view="access",
    )
    AccessLogApp(browser, view="access").run()


def run_errors_ui(
    bucket: str,
    prefix: str,
    start_date: str,
    end_date: str,
    grep: str | None = None,
    filters: list[str] | None = None,
    where: str | None = None,
) -> None:
    conn = _init_duckdb_connection()
    browser = LogBrowser(
        conn, bucket, prefix, start_date, end_date,
        grep=grep, filters=filters, where=where, view="error",
    )
    AccessLogApp(browser, view="error").run()
