"""Deterministic regular-expression log signal extraction."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

from incidentsight.models import LogAnalysis

_LEVEL_PATTERN = re.compile(
    r"(?<![A-Z])(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)(?![A-Z])",
    re.IGNORECASE,
)
_EXCEPTION_PATTERN = re.compile(r"\b(?:[A-Za-z_][\w]*\.)*[A-Za-z_][\w]*(?:Exception|Error)\b")
_TIMEOUT_PATTERN = re.compile(
    r"\b(?:[\w.]*timeout(?:exception|error)?s?|time(?:d)?\s*out)\b",
    re.IGNORECASE,
)
_HTTP_CONTEXT_PATTERN = re.compile(
    r"""
    (?:
        \bHTTP/\d(?:\.\d)?\s+
        |
        \b(?:http[_ -]?)?status(?:[_ -]?code)?\s*[:=]\s*
        |
        \bresponse\s+(?:status|code)\s*[:=]\s*
    )
    (?P<code>[1-5]\d{2})\b
    """,
    re.IGNORECASE | re.VERBOSE,
)
_ACCESS_LOG_STATUS_PATTERN = re.compile(
    r'"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+[^"]*"\s+(?P<code>[1-5]\d{2})\b',
    re.IGNORECASE,
)


def _ordered_counts(values: Iterable[str]) -> dict[str, int]:
    """Count values with stable lexical key ordering."""

    counts = Counter(values)
    return dict(sorted(counts.items()))


class RegexLogAnalyzer:
    """Extracts only explicit syntactic signals; it does not infer intent."""

    def analyze(self, log_text: str) -> LogAnalysis:
        """Return deterministic level, exception, timeout, and HTTP status signals."""

        levels = (
            "WARN" if match.group(0).upper() == "WARNING" else match.group(0).upper()
            for match in _LEVEL_PATTERN.finditer(log_text)
        )
        exceptions = (match.group(0) for match in _EXCEPTION_PATTERN.finditer(log_text))

        http_codes: list[int] = [
            int(match.group("code")) for match in _HTTP_CONTEXT_PATTERN.finditer(log_text)
        ]
        http_codes.extend(
            int(match.group("code")) for match in _ACCESS_LOG_STATUS_PATTERN.finditer(log_text)
        )

        return LogAnalysis(
            line_count=len(log_text.splitlines()) if log_text else 0,
            level_counts=_ordered_counts(levels),
            exception_counts=_ordered_counts(exceptions),
            timeout_count=sum(1 for _ in _TIMEOUT_PATTERN.finditer(log_text)),
            http_status_counts=dict(sorted(Counter(http_codes).items())),
        )
