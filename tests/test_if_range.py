"""Tests for RFC 9110 If-Range evaluation in passsage proxy."""

import pytest

from passsage.range_utils import if_range_matches, is_unsatisfiable_range, parse_single_range


class TestIfRangeMatches:
    """RFC 9110 Section 14.5: If-Range evaluation."""

    def test_no_if_range_honors_range(self):
        assert if_range_matches(None, {"headers": {}}) is True

    def test_matching_strong_etag(self):
        assert if_range_matches(
            '"abc123"', {"headers": {"etag": '"abc123"'}},
        ) is True

    def test_non_matching_strong_etag(self):
        assert if_range_matches(
            '"abc123"', {"headers": {"etag": '"xyz789"'}},
        ) is False

    def test_weak_etag_always_fails(self):
        assert if_range_matches(
            'W/"abc123"', {"headers": {"etag": 'W/"abc123"'}},
        ) is False

    def test_matching_last_modified(self):
        date = "Tue, 11 Mar 2026 12:00:00 GMT"
        assert if_range_matches(
            date, {"headers": {"last-modified": date}},
        ) is True

    def test_non_matching_last_modified(self):
        assert if_range_matches(
            "Tue, 11 Mar 2026 12:00:00 GMT",
            {"headers": {"last-modified": "Mon, 10 Mar 2026 12:00:00 GMT"}},
        ) is False

    def test_last_modified_from_meta_top_level(self):
        date = "Tue, 11 Mar 2026 12:00:00 GMT"
        assert if_range_matches(
            date, {"last_modified": date, "headers": {}},
        ) is True

    def test_no_cache_metadata_returns_false(self):
        assert if_range_matches('"abc"', None) is False

    def test_empty_cache_metadata_returns_false(self):
        assert if_range_matches('"abc"', {"headers": {}}) is False

    def test_etag_missing_from_cache(self):
        assert if_range_matches(
            '"abc"',
            {"headers": {"last-modified": "Tue, 11 Mar 2026 12:00:00 GMT"}},
        ) is False


class TestParseSingleRange:
    """Existing range helpers still behave correctly."""

    def test_satisfiable_range(self):
        assert parse_single_range("bytes=0-100", 200) == (0, 100)

    def test_open_ended_range(self):
        assert parse_single_range("bytes=50-", 200) == (50, 199)

    def test_suffix_range(self):
        assert parse_single_range("bytes=-50", 200) == (150, 199)

    def test_start_beyond_total(self):
        assert parse_single_range("bytes=200-", 100) is None

    def test_multi_range_returns_none(self):
        assert parse_single_range("bytes=0-50,60-100", 200) is None

    def test_empty_header(self):
        assert parse_single_range("", 100) is None

    def test_no_bytes_prefix(self):
        assert parse_single_range("items=0-10", 100) is None


class TestIsUnsatisfiableRange:

    def test_unsatisfiable_start_beyond_total(self):
        assert is_unsatisfiable_range("bytes=200-", 100) is True

    def test_satisfiable_range(self):
        assert is_unsatisfiable_range("bytes=0-50", 100) is False

    def test_satisfiable_suffix(self):
        assert is_unsatisfiable_range("bytes=-50", 100) is False

    def test_suffix_beyond_total(self):
        assert is_unsatisfiable_range("bytes=-150", 100) is True

    def test_no_range_header(self):
        assert is_unsatisfiable_range("", 100) is False

    def test_multi_range_not_error(self):
        assert is_unsatisfiable_range("bytes=0-50,60-100", 200) is False
