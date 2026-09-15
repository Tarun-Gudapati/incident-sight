"""Application errors that map to stable, non-sensitive API responses."""

from __future__ import annotations

from http import HTTPStatus

from incidentsight.models import ErrorDetail


class IncidentSightError(Exception):
    """Base exception with an HTTP-safe representation."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        details: list[ErrorDetail] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or []


class InvalidMetadataError(IncidentSightError):
    """Raised when the multipart metadata field is not valid JSON/model data."""

    def __init__(self, details: list[ErrorDetail]) -> None:
        super().__init__(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code="invalid_metadata",
            message="The metadata field must contain a valid incident metadata JSON object.",
            details=details,
        )


class InvalidImageError(IncidentSightError):
    """Raised when uploaded bytes are not an accepted raster image."""

    def __init__(self, message: str) -> None:
        super().__init__(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            code="invalid_image",
            message=message,
        )


class UnsupportedImageMediaTypeError(IncidentSightError):
    """Raised when a declared upload type is not image/*."""

    def __init__(self) -> None:
        super().__init__(
            status_code=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            code="unsupported_image_media_type",
            message="The optional image upload must declare an image/* content type.",
        )


class ImageTooLargeError(IncidentSightError):
    """Raised before image decoding when the byte limit is exceeded."""

    def __init__(self, max_bytes: int) -> None:
        super().__init__(
            status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            code="image_too_large",
            message=f"The image exceeds the configured limit of {max_bytes} bytes.",
        )
