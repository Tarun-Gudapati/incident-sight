"""Tests for baseline triage policy and output safety."""

import asyncio
from io import BytesIO

import pytest
from PIL import Image

from incidentsight.analyzers import PillowImageInspector, RegexLogAnalyzer
from incidentsight.interfaces import ImagePayload
from incidentsight.models import IncidentMetadata, LogAnalysis, Severity
from incidentsight.triage import BaselineTriageOrchestrator, _severity_for


def _signals(
    *,
    levels: dict[str, int] | None = None,
    exceptions: dict[str, int] | None = None,
    timeouts: int = 0,
    statuses: dict[int, int] | None = None,
) -> LogAnalysis:
    return LogAnalysis(
        line_count=1,
        level_counts=levels or {},
        exception_counts=exceptions or {},
        timeout_count=timeouts,
        http_status_counts=statuses or {},
    )


@pytest.mark.parametrize(
    ("signals", "expected"),
    [
        (_signals(levels={"FATAL": 1}), Severity.CRITICAL),
        (_signals(levels={"ERROR": 1}, statuses={503: 1}), Severity.HIGH),
        (_signals(exceptions={"TypeError": 2}), Severity.HIGH),
        (_signals(levels={"ERROR": 3}), Severity.HIGH),
        (_signals(levels={"ERROR": 1}), Severity.MEDIUM),
        (_signals(timeouts=1), Severity.MEDIUM),
        (_signals(statuses={500: 1}), Severity.MEDIUM),
        (_signals(statuses={429: 1}), Severity.MEDIUM),
        (_signals(levels={"WARN": 1}), Severity.LOW),
        (_signals(statuses={404: 1}), Severity.LOW),
        (_signals(), Severity.INFORMATIONAL),
    ],
)
def test_severity_heuristic(signals: LogAnalysis, expected: Severity) -> None:
    assert _severity_for(signals) is expected


def test_triage_separates_evidence_hypotheses_and_human_actions() -> None:
    image_buffer = BytesIO()
    Image.new("RGB", (4, 3), color="red").save(image_buffer, format="PNG")
    orchestrator = BaselineTriageOrchestrator(
        log_analyzer=RegexLogAnalyzer(),
        image_inspector=PillowImageInspector(max_bytes=10_000, max_pixels=10_000),
    )

    result = asyncio.run(
        orchestrator.triage(
            metadata=IncidentMetadata(
                incident_id="INC-42",
                title="Checkout requests failing",
                service="checkout",
                environment="production",
                reported_impact="Some checkouts fail.",
            ),
            log_text=(
                "ERROR CheckoutException upstream timed out status=503\n"
                "response status=429\nresponse status=401\nresponse status=404"
            ),
            image=ImagePayload(
                content=image_buffer.getvalue(),
                filename="screen.png",
                content_type="image/png",
            ),
        )
    )

    assert result.severity is Severity.HIGH
    assert {item.signal for item in result.evidence} >= {
        "reported_context",
        "line_count",
        "log_levels",
        "exceptions",
        "timeouts",
        "http_status_codes",
        "image_metadata",
    }
    assert all(item.is_hypothesis for item in result.hypotheses)
    assert len(result.hypotheses) == 6
    assert any("human review" in check for check in result.suggested_checks)
    assert result.action_plan.human_approval_required is True
    assert result.action_plan.automation_executed is False
    assert all(step.requires_human_approval for step in result.action_plan.steps)
    assert "No screenshot semantics were used" in result.summary
    assert any("True screenshot interpretation" in item for item in result.limitations)


def test_no_diagnostic_signal_produces_low_confidence_incompleteness_hypothesis() -> None:
    orchestrator = BaselineTriageOrchestrator(
        log_analyzer=RegexLogAnalyzer(),
        image_inspector=PillowImageInspector(max_bytes=1_000, max_pixels=1_000),
    )

    result = asyncio.run(
        orchestrator.triage(
            metadata=IncidentMetadata(
                incident_id="INC-QUIET",
                title="Investigate",
                service="api",
                environment="test",
            ),
            log_text="request completed",
            image=None,
        )
    )

    assert result.severity is Severity.INFORMATIONAL
    assert len(result.hypotheses) == 1
    assert "may omit" in result.hypotheses[0].statement
    assert not any(item.source == "image" for item in result.evidence)
    assert not any("human review" in check for check in result.suggested_checks)
