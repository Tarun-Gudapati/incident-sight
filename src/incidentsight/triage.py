"""Deterministic baseline triage orchestration."""

from __future__ import annotations

from collections.abc import Mapping

from incidentsight.interfaces import ImageInspector, ImagePayload, LogAnalyzer
from incidentsight.models import (
    ActionPlan,
    ActionPlanStep,
    Confidence,
    Evidence,
    Hypothesis,
    ImageMetadata,
    IncidentMetadata,
    LogAnalysis,
    Severity,
    TriageResponse,
)


def _severity_for(signals: LogAnalysis) -> Severity:
    """Apply the documented, deterministic baseline severity heuristic."""

    critical_levels = signals.level_counts.get("CRITICAL", 0) + signals.level_counts.get("FATAL", 0)
    errors = signals.level_counts.get("ERROR", 0)
    warnings = signals.level_counts.get("WARN", 0)
    exceptions = sum(signals.exception_counts.values())
    server_errors = sum(
        count for code, count in signals.http_status_counts.items() if 500 <= code <= 599
    )
    client_errors = sum(
        count for code, count in signals.http_status_counts.items() if 400 <= code <= 499
    )
    throttling = signals.http_status_counts.get(429, 0)

    if critical_levels:
        return Severity.CRITICAL
    if (
        (server_errors and (errors or exceptions or signals.timeout_count))
        or exceptions >= 2
        or errors >= 3
    ):
        return Severity.HIGH
    if errors or exceptions or signals.timeout_count or server_errors or throttling:
        return Severity.MEDIUM
    if warnings or client_errors:
        return Severity.LOW
    return Severity.INFORMATIONAL


def _format_counts(counts: Mapping[str, int] | Mapping[int, int]) -> list[str]:
    return [f"{key}={value}" for key, value in counts.items()]


def _build_evidence(
    metadata: IncidentMetadata,
    signals: LogAnalysis,
    image: ImageMetadata | None,
) -> list[Evidence]:
    evidence = [
        Evidence(
            source="metadata",
            signal="reported_context",
            detail="Caller-supplied context; not independently verified.",
            observed_values=[
                f"service={metadata.service}",
                f"environment={metadata.environment}",
            ],
        ),
        Evidence(
            source="logs",
            signal="line_count",
            detail="Number of submitted log lines.",
            observed_values=[str(signals.line_count)],
            count=signals.line_count or None,
        ),
    ]

    if signals.level_counts:
        evidence.append(
            Evidence(
                source="logs",
                signal="log_levels",
                detail="Explicit log-level tokens found case-insensitively.",
                observed_values=_format_counts(signals.level_counts),
                count=sum(signals.level_counts.values()),
            )
        )
    if signals.exception_counts:
        evidence.append(
            Evidence(
                source="logs",
                signal="exceptions",
                detail="Exception- or Error-suffixed identifiers found in log text.",
                observed_values=_format_counts(signals.exception_counts),
                count=sum(signals.exception_counts.values()),
            )
        )
    if signals.timeout_count:
        evidence.append(
            Evidence(
                source="logs",
                signal="timeouts",
                detail="Explicit timeout phrases found in log text.",
                observed_values=[f"timeout_mentions={signals.timeout_count}"],
                count=signals.timeout_count,
            )
        )
    if signals.http_status_counts:
        evidence.append(
            Evidence(
                source="logs",
                signal="http_status_codes",
                detail="HTTP status codes found only in recognized HTTP/status contexts.",
                observed_values=_format_counts(signals.http_status_counts),
                count=sum(signals.http_status_counts.values()),
            )
        )
    if image is not None:
        evidence.append(
            Evidence(
                source="image",
                signal="image_metadata",
                detail=(
                    "Raster metadata only. IncidentSight did not interpret text, UI state, "
                    "or visual meaning."
                ),
                observed_values=[
                    f"format={image.detected_format}",
                    f"dimensions={image.width}x{image.height}",
                    f"size_bytes={image.size_bytes}",
                ],
            )
        )

    return evidence


def _build_hypotheses(signals: LogAnalysis) -> list[Hypothesis]:
    hypotheses: list[Hypothesis] = []

    if signals.exception_counts:
        hypotheses.append(
            Hypothesis(
                statement="An application code path may be failing.",
                rationale=(
                    "The submitted logs contain exception-like identifiers; the identifiers "
                    "alone do not establish root cause."
                ),
                confidence=Confidence.MEDIUM,
            )
        )
    if signals.timeout_count:
        hypotheses.append(
            Hypothesis(
                statement="A dependency, network path, or constrained resource may be slow.",
                rationale="The submitted logs contain explicit timeout wording.",
                confidence=Confidence.MEDIUM,
            )
        )
    if any(500 <= code <= 599 for code in signals.http_status_counts):
        hypotheses.append(
            Hypothesis(
                statement="A server-side component or one of its dependencies may be failing.",
                rationale="At least one explicitly contextualized HTTP 5xx status was observed.",
                confidence=Confidence.MEDIUM,
            )
        )
    if 429 in signals.http_status_counts:
        hypotheses.append(
            Hypothesis(
                statement="A caller or service may be encountering rate limiting.",
                rationale="An explicitly contextualized HTTP 429 status was observed.",
                confidence=Confidence.MEDIUM,
            )
        )
    if {401, 403}.intersection(signals.http_status_counts):
        hypotheses.append(
            Hypothesis(
                statement="Authentication, authorization, or credential configuration may differ.",
                rationale="An explicitly contextualized HTTP 401 or 403 status was observed.",
                confidence=Confidence.LOW,
            )
        )
    if 404 in signals.http_status_counts:
        hypotheses.append(
            Hypothesis(
                statement="A route, deployment, or requested resource may be missing.",
                rationale="An explicitly contextualized HTTP 404 status was observed.",
                confidence=Confidence.LOW,
            )
        )
    if not hypotheses:
        hypotheses.append(
            Hypothesis(
                statement="The submitted excerpt may omit the failure signal.",
                rationale="No exception, timeout, or diagnostic HTTP status produced a hypothesis.",
                confidence=Confidence.LOW,
            )
        )

    return hypotheses


def _build_checks(signals: LogAnalysis, image: ImageMetadata | None) -> list[str]:
    checks = [
        "Confirm the affected service, environment, time window, and user-visible impact.",
    ]
    if signals.exception_counts:
        checks.append("Locate the first matching exception and inspect its full stack trace.")
    if signals.timeout_count:
        checks.append(
            "Check dependency latency, connection-pool saturation, and timeout configuration."
        )
    if any(500 <= code <= 599 for code in signals.http_status_counts):
        checks.append(
            "Correlate HTTP 5xx responses with server traces, health, and recent deploys."
        )
    if 429 in signals.http_status_counts:
        checks.append("Inspect rate-limit headers, quotas, and caller retry behavior.")
    if {401, 403}.intersection(signals.http_status_counts):
        checks.append("Compare credentials, token claims, permissions, and clock synchronization.")
    if 404 in signals.http_status_counts:
        checks.append("Verify the route, resource identifier, and deployed version.")
    if image is not None:
        checks.append(
            "Have a human review the screenshot; this baseline inspected image metadata only."
        )
    checks.append("Compare the incident timeline with configuration and deployment changes.")
    return checks


def _build_action_plan(checks: list[str]) -> ActionPlan:
    return ActionPlan(
        steps=[
            ActionPlanStep(
                order=1,
                action="Validate the submitted evidence and incident scope.",
                rationale="Reported metadata and regex matches can be incomplete or misleading.",
            ),
            ActionPlanStep(
                order=2,
                action="Run the suggested read-only checks in the relevant observability tools.",
                rationale=(
                    f"The response proposes {len(checks)} checks; a human must choose access."
                ),
            ),
            ActionPlanStep(
                order=3,
                action="Select, peer-review, and approve any mitigation before execution.",
                rationale=(
                    "This scaffold does not verify root cause or execute operational changes."
                ),
            ),
        ]
    )


class BaselineTriageOrchestrator:
    """Combines local analyzers; it never calls an LLM or executes remediation."""

    def __init__(self, *, log_analyzer: LogAnalyzer, image_inspector: ImageInspector) -> None:
        self._log_analyzer = log_analyzer
        self._image_inspector = image_inspector

    async def triage(
        self,
        *,
        metadata: IncidentMetadata,
        log_text: str,
        image: ImagePayload | None,
    ) -> TriageResponse:
        """Produce a deterministic triage result."""

        signals = self._log_analyzer.analyze(log_text)
        image_metadata = self._image_inspector.inspect(image) if image is not None else None
        severity = _severity_for(signals)
        evidence = _build_evidence(metadata, signals, image_metadata)
        hypotheses = _build_hypotheses(signals)
        checks = _build_checks(signals, image_metadata)

        diagnostic_groups = sum(
            (
                bool(signals.level_counts),
                bool(signals.exception_counts),
                bool(signals.timeout_count),
                bool(signals.http_status_counts),
            )
        )
        summary = (
            f"Deterministic baseline assigned {severity.value} severity from "
            f"{diagnostic_groups} observed log signal group(s) across "
            f"{signals.line_count} line(s). No screenshot semantics were used."
        )

        return TriageResponse(
            incident_id=metadata.incident_id,
            severity=severity,
            summary=summary,
            evidence=evidence,
            hypotheses=hypotheses,
            suggested_checks=checks,
            action_plan=_build_action_plan(checks),
            limitations=[
                "Log extraction uses regex patterns and can miss or misclassify unusual formats.",
                (
                    "Severity is a fixed heuristic and does not know your SLA or actual "
                    "business impact."
                ),
                (
                    "Images are validated for format, dimensions, and size only. True screenshot "
                    "interpretation requires a separately configured multimodal provider."
                ),
                "Every hypothesis is a possibility to investigate, not a root-cause conclusion.",
            ],
        )
