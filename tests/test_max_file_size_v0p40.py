"""v0.40 step 2 — ``--max-file-size`` cap parsing + wiring tests."""

from __future__ import annotations

import pytest

from sharesift.cli import _parse_size


class TestParseSize:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("100", 100),
            ("100K", 100 * 1024),
            ("100k", 100 * 1024),
            ("5M", 5 * 1024 * 1024),
            ("5m", 5 * 1024 * 1024),
            ("1G", 1024 * 1024 * 1024),
            ("1g", 1024 * 1024 * 1024),
            ("0.5M", 524288),
            ("10M", 10 * 1024 * 1024),
        ],
    )
    def test_parses_known_suffixes(self, text, expected):
        assert _parse_size(text) == expected

    def test_none_passes_through(self):
        assert _parse_size(None) is None

    def test_empty_string_yields_none(self):
        assert _parse_size("") is None

    def test_whitespace_only_yields_none(self):
        assert _parse_size("   ") is None

    @pytest.mark.parametrize("bad", ["abc", "5T", "5KB", "K", "1.2.3", "5MM"])
    def test_invalid_size_raises_systemexit(self, bad):
        with pytest.raises(SystemExit, match="invalid size"):
            _parse_size(bad)

    def test_whitespace_around_value_handled(self):
        assert _parse_size("  10M  ") == 10 * 1024 * 1024
