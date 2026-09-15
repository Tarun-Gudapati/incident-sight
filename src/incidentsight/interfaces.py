"""Ports that keep analysis and orchestration implementations replaceable."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from incidentsight.models import (
    ImageMetadata,
    IncidentMetadata,
    LogAnalysis,
    ProviderInterpretation,
    TriageResponse,
)


@dataclass(frozen=True, slots=True)
class ImagePayload:
    """In-memory upload passed to image-related ports."""

    content: bytes
    filename: str | None
    content_type: str | None


class LogAnalyzer(Protocol):
    """Extract observable signals from plain-text logs."""

    def analyze(self, log_text: str) -> LogAnalysis:
        """Return deterministic signals."""
        ...


class ImageInspector(Protocol):
    """Inspect raster metadata only, without claiming visual understanding."""

    def inspect(self, image: ImagePayload) -> ImageMetadata:
        """Validate the image and return dimensions, format, and byte size."""
        ...


class TriageOrchestrator(Protocol):
    """Combine analyzers into an API response."""

    async def triage(
        self,
        *,
        metadata: IncidentMetadata,
        log_text: str,
        image: ImagePayload | None,
    ) -> TriageResponse:
        """Produce a triage response without taking action."""
        ...


class MultimodalProvider(Protocol):
    """Future opt-in port for actual screenshot interpretation.

    No implementation is configured or called by the deterministic baseline.
    A provider adapter, credentials, consent controls, and data-handling review
    are required before screenshot pixels can be semantically interpreted.
    """

    async def interpret(
        self,
        *,
        metadata: IncidentMetadata,
        log_text: str,
        image: ImagePayload,
    ) -> ProviderInterpretation:
        """Return clearly attributed provider output."""
        ...
