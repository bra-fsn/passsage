"""Tests for RFC 9110 If-Range evaluation in passsage proxy."""

import pytest

from passsage.proxy import _if_range_matches, _is_unsatisfiable_range, _parse_single_range


class _FakeHeaders(dict):
    """Case-insensitive header dict mimicking mitmproxy's Headers."""

    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


class _FakeCacheHead:
    def __init__(self, meta):
        self.meta = meta


class _FakeFlow:
    def __init__(self, headers, cache_meta=None):
        self.request = type("Request", (), {"headers": _FakeHeaders(headers)})()
        self._cache_head = _FakeCacheHead(cache_meta) if cache_meta is not None else None


class TestIfRangeMatches:
    """RFC 9110 Section 14.5: If-Range evaluation."""

    def test_no_if_range_honors_range(self):
        flow = _FakeFlow({"Range": "bytes=0-100"})
        assert _if_range_matches(flow) is True

    def test_matching_strong_etag(self):
        flow = _FakeFlow(
            {"if-range": '"abc123"', "Range": "bytes=0-100"},
            cache_meta={"headers": {"etag": '"abc123"'}},
        )
        assert _if_range_matches(flow) is True

    def test_non_matching_strong_etag(self):
        flow = _FakeFlow(
            {"if-range": '"abc123"', "Range": "bytes=0-100"},
            cache_meta={"headers": {"etag": '"xyz789"'}},
        )
        assert _if_range_matches(flow) is False

    def test_weak_etag_always_fails(self):
        flow = _FakeFlow(
            {"if-range": 'W/"abc123"', "Range": "bytes=0-100"},
            cache_meta={"headers": {"etag": 'W/"abc123"'}},
        )
        assert _if_range_matches(flow) is False

    def test_matching_last_modified(self):
        date = "Tue, 11 Mar 2026 12:00:00 GMT"
        flow = _FakeFlow(
            {"if-range": date, "Range": "bytes=0-100"},
            cache_meta={"headers": {"last-modified": date}},
        )
        assert _if_range_matches(flow) is True

    def test_non_matching_last_modified(self):
        flow = _FakeFlow(
            {"if-range": "Tue, 11 Mar 2026 12:00:00 GMT", "Range": "bytes=0-100"},
            cache_meta={"headers": {"last-modified": "Mon, 10 Mar 2026 12:00:00 GMT"}},
        )
        assert _if_range_matches(flow) is False

    def test_last_modified_from_meta_top_level(self):
        date = "Tue, 11 Mar 2026 12:00:00 GMT"
        flow = _FakeFlow(
            {"if-range": date, "Range": "bytes=0-100"},
            cache_meta={"last_modified": date, "headers": {}},
        )
        assert _if_range_matches(flow) is True

    def test_no_cache_metadata_returns_false(self):
        flow = _FakeFlow({"if-range": '"abc"', "Range": "bytes=0-100"})
        assert _if_range_matches(flow) is False

    def test_empty_cache_metadata_returns_false(self):
        flow = _FakeFlow(
            {"if-range": '"abc"', "Range": "bytes=0-100"},
            cache_meta={"headers": {}},
        )
        assert _if_range_matches(flow) is False

    def test_etag_missing_from_cache(self):
        flow = _FakeFlow(
            {"if-range": '"abc"', "Range": "bytes=0-100"},
            cache_meta={"headers": {"last-modified": "Tue, 11 Mar 2026 12:00:00 GMT"}},
        )
        assert _if_range_matches(flow) is False


class TestParseAndUnsatisfiable:
    """Existing range helpers still behave correctly."""

    def test_satisfiable_range(self):
        assert _parse_single_range("bytes=0-100", 200) == (0, 100)

    def test_unsatisfiable_start_beyond_total(self):
        assert _is_unsatisfiable_range("bytes=200-", 100) is True

    def test_satisfiable_suffix(self):
        assert _is_unsatisfiable_range("bytes=-50", 100) is False

    def test_suffix_beyond_total(self):
        assert _is_unsatisfiable_range("bytes=-150", 100) is True

    def test_no_range_header(self):
        assert _is_unsatisfiable_range("", 100) is False

    def test_multi_range_not_error(self):
        assert _is_unsatisfiable_range("bytes=0-50,60-100", 200) is False
