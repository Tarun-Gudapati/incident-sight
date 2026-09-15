"""FastAPI application factory and HTTP boundary."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from incidentsight.analyzers import PillowImageInspector, RegexLogAnalyzer
from incidentsight.errors import ImageTooLargeError, IncidentSightError, InvalidMetadataError
from incidentsight.interfaces import ImagePayload, TriageOrchestrator
from incidentsight.models import (
    ErrorBody,
    ErrorDetail,
    ErrorResponse,
    HealthResponse,
    IncidentMetadata,
    TriageResponse,
)
from incidentsight.settings import Settings
from incidentsight.triage import BaselineTriageOrchestrator

logger = logging.getLogger(__name__)

MetadataField = Annotated[
    str,
    Form(
        min_length=2,
        max_length=10_000,
        description="A JSON object matching the IncidentMetadata schema.",
    ),
]
LogField = Annotated[
    str,
    Form(
        min_length=1,
        max_length=500_000,
        description="Plain-text log excerpt. Secrets should be redacted before submission.",
    ),
]
ImageField = Annotated[
    UploadFile | None,
    File(
        description=(
            "Optional BMP, GIF, JPEG, PNG, or WebP image. The baseline reads metadata only."
        )
    ),
]


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorBody(code=code, message=message, details=details or []),
    )
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def _safe_location(parts: Sequence[Any]) -> list[str | int]:
    return [part if isinstance(part, (str, int)) else str(part) for part in parts]


def _validation_details(
    errors: Sequence[Mapping[str, Any]], *, prefix: str | None = None
) -> list[ErrorDetail]:
    details: list[ErrorDetail] = []
    for error in errors:
        location = _safe_location(error.get("loc", ()))
        if prefix is not None:
            location.insert(0, prefix)
        details.append(
            ErrorDetail(
                location=location,
                message=str(error.get("msg", "Invalid value.")),
                type=str(error.get("type", "validation_error")),
            )
        )
    return details


def _parse_metadata(raw_metadata: str) -> IncidentMetadata:
    try:
        return IncidentMetadata.model_validate_json(raw_metadata)
    except ValidationError as exc:
        raise InvalidMetadataError(
            _validation_details(exc.errors(include_url=False), prefix="metadata")
        ) from exc


async def _read_image(upload: UploadFile, *, max_bytes: int) -> ImagePayload:
    try:
        content = await upload.read(max_bytes + 1)
    finally:
        await upload.close()

    if len(content) > max_bytes:
        raise ImageTooLargeError(max_bytes)
    return ImagePayload(
        content=content,
        filename=upload.filename,
        content_type=upload.content_type,
    )


def _build_orchestrator(settings: Settings) -> BaselineTriageOrchestrator:
    return BaselineTriageOrchestrator(
        log_analyzer=RegexLogAnalyzer(),
        image_inspector=PillowImageInspector(
            max_bytes=settings.max_image_bytes,
            max_pixels=settings.max_image_pixels,
        ),
    )


def create_app(
    settings: Settings | None = None,
    orchestrator: TriageOrchestrator | None = None,
) -> FastAPI:
    """Create an independently configurable application instance."""

    resolved_settings = settings or Settings()
    resolved_orchestrator = orchestrator or _build_orchestrator(resolved_settings)

    app = FastAPI(
        title="IncidentSight",
        version="0.1.0",
        summary="Honest concept scaffold for incident triage",
        description=(
            "**Status: Concept scaffold.** The current implementation extracts deterministic "
            "log signals and image metadata. It does not understand screenshot contents, call an "
            "LLM, determine root cause, or execute remediation."
        ),
        contact={"name": "IncidentSight maintainers"},
        license_info={"name": "MIT", "identifier": "MIT"},
    )

    @app.exception_handler(IncidentSightError)
    async def handle_incidentsight_error(
        _request: Request,
        exc: IncidentSightError,
    ) -> JSONResponse:
        return _error_response(
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            details=exc.details,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return _error_response(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code="validation_error",
            message="The request did not match the API contract.",
            details=_validation_details(exc.errors()),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled request error for %s", request.url.path, exc_info=exc)
        return _error_response(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            code="internal_error",
            message="An unexpected error occurred.",
        )

    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["service"],
        summary="Check service readiness",
    )
    async def health() -> HealthResponse:
        return HealthResponse()

    @app.post(
        "/api/triage",
        response_model=TriageResponse,
        responses={
            HTTPStatus.UNPROCESSABLE_ENTITY: {"model": ErrorResponse},
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE: {"model": ErrorResponse},
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE: {"model": ErrorResponse},
        },
        tags=["triage"],
        summary="Triage an incident with the deterministic baseline",
    )
    async def triage_incident(
        metadata: MetadataField,
        log_text: LogField,
        image: ImageField = None,
    ) -> TriageResponse:
        parsed_metadata = _parse_metadata(metadata)
        image_payload = (
            await _read_image(image, max_bytes=resolved_settings.max_image_bytes)
            if image is not None
            else None
        )
        return await resolved_orchestrator.triage(
            metadata=parsed_metadata,
            log_text=log_text,
            image=image_payload,
        )

    return app


app = create_app()
