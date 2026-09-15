"""Validated domain and API models for IncidentSight."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class StrictModel(BaseModel):
    """Base model that rejects unexpected input fields."""

    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    """Deterministic triage severity."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Qualitative confidence for a non-factual hypothesis."""

    LOW = "low"
    MEDIUM = "medium"


class IncidentMetadata(StrictModel):
    """Caller-supplied context. It is treated as untrusted reported information."""

    incident_id: Annotated[NonEmptyText, StringConstraints(max_length=100)]
    title: Annotated[NonEmptyText, StringConstraints(max_length=200)]
    service: Annotated[NonEmptyText, StringConstraints(max_length=100)]
    environment: Annotated[NonEmptyText, StringConstraints(max_length=50)]
    occurred_at: datetime | None = None
    description: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2_000)] = ""
    reported_impact: Annotated[
        str,
        StringConstraints(strip_whitespace=True, max_length=1_000),
    ] = ""


class LogAnalysis(StrictModel):
    """Signals extracted from log text without interpreting unstructured meaning."""

    line_count: int = Field(ge=0)
    level_counts: dict[str, int]
    exception_counts: dict[str, int]
    timeout_count: int = Field(ge=0)
    http_status_counts: dict[int, int]


class ImageMetadata(StrictModel):
    """Safe-to-report raster metadata; this is not screenshot interpretation."""

    filename: str | None
    declared_content_type: str | None
    detected_format: str
    width: int = Field(gt=0)
    height: int = Field(gt=0)
    size_bytes: int = Field(gt=0)


class Evidence(StrictModel):
    """An observed input fact used by the deterministic baseline."""

    source: Literal["metadata", "logs", "image"]
    signal: str
    detail: str
    observed_values: list[str] = Field(default_factory=list)
    count: int | None = Field(default=None, ge=1)


class Hypothesis(StrictModel):
    """A possible explanation, deliberately distinguished from evidence."""

    statement: str
    rationale: str
    confidence: Confidence
    is_hypothesis: Literal[True] = True


class ActionPlanStep(StrictModel):
    """A proposed action that cannot be represented as pre-approved."""

    order: int = Field(ge=1)
    action: str
    rationale: str
    requires_human_approval: Literal[True] = True


class ActionPlan(StrictModel):
    """Read-only recommendations; IncidentSight executes no remediation."""

    human_approval_required: Literal[True] = True
    automation_executed: Literal[False] = False
    steps: list[ActionPlanStep]


class TriageResponse(StrictModel):
    """Complete deterministic triage result."""

    incident_id: str
    severity: Severity
    summary: str
    evidence: list[Evidence]
    hypotheses: list[Hypothesis]
    suggested_checks: list[str]
    action_plan: ActionPlan
    limitations: list[str]


class ProviderInterpretation(StrictModel):
    """Normalized future provider output; no provider is included in this scaffold."""

    provider_name: str
    narrative: str
    hypotheses: list[Hypothesis]


class HealthResponse(StrictModel):
    """Service readiness response."""

    status: Literal["ok"] = "ok"
    mode: Literal["deterministic-baseline"] = "deterministic-baseline"
    screenshot_interpretation: Literal["not_configured"] = "not_configured"


class ErrorDetail(StrictModel):
    """One validation failure."""

    location: list[str | int]
    message: str
    type: str


class ErrorBody(StrictModel):
    """Stable API error body."""

    code: str
    message: str
    details: list[ErrorDetail] = Field(default_factory=list)


class ErrorResponse(StrictModel):
    """Stable API error envelope."""

    error: ErrorBody
