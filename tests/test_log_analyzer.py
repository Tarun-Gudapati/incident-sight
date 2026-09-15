"""Tests for deterministic log extraction."""

from incidentsight.analyzers.logs import RegexLogAnalyzer


def test_extracts_supported_signal_types_deterministically() -> None:
    log_text = """\
2026-09-15 INFO request started
2026-09-15 warning dependency slow
2026-09-15 ERROR CheckoutException: timed out; status=503
GET /ready HTTP/1.1
2026-09-15 CRITICAL TypeError response status: 429
10.0.0.1 "GET /health HTTP/1.1" 200 12
"""

    result = RegexLogAnalyzer().analyze(log_text)

    assert result.line_count == 6
    assert result.level_counts == {
        "CRITICAL": 1,
        "ERROR": 1,
        "INFO": 1,
        "WARN": 1,
    }
    assert result.exception_counts == {"CheckoutException": 1, "TypeError": 1}
    assert result.timeout_count == 1
    assert result.http_status_counts == {200: 1, 429: 1, 503: 1}


def test_ignores_bare_numbers_and_words_containing_level_names() -> None:
    result = RegexLogAnalyzer().analyze(
        "port=5000 information=useful ERRORING=false HTTP request took 404ms"
    )

    assert result.level_counts == {}
    assert result.exception_counts == {}
    assert result.timeout_count == 0
    assert result.http_status_counts == {}


def test_counts_repeated_exceptions_and_timeout_spellings() -> None:
    result = RegexLogAnalyzer().analyze(
        "SocketTimeoutException timeout\nSocketTimeoutException timed out\nValueError"
    )

    assert result.exception_counts == {
        "SocketTimeoutException": 2,
        "ValueError": 1,
    }
    assert result.timeout_count == 4


def test_empty_log_has_no_signals() -> None:
    result = RegexLogAnalyzer().analyze("")

    assert result.line_count == 0
    assert result.level_counts == {}
    assert result.exception_counts == {}
    assert result.timeout_count == 0
    assert result.http_status_counts == {}
