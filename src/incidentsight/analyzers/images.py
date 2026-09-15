"""Raster image validation and metadata-only inspection."""

from __future__ import annotations

import warnings
from io import BytesIO

from PIL import Image, UnidentifiedImageError

from incidentsight.errors import (
    ImageTooLargeError,
    InvalidImageError,
    UnsupportedImageMediaTypeError,
)
from incidentsight.interfaces import ImagePayload
from incidentsight.models import ImageMetadata

_SUPPORTED_FORMATS = frozenset({"BMP", "GIF", "JPEG", "PNG", "WEBP"})


class PillowImageInspector:
    """Validate an upload and report metadata without interpreting its pixels."""

    def __init__(self, *, max_bytes: int, max_pixels: int) -> None:
        self._max_bytes = max_bytes
        self._max_pixels = max_pixels

    def inspect(self, image: ImagePayload) -> ImageMetadata:
        """Return dimensions, detected format, and byte size for a raster image."""

        if not image.content:
            raise InvalidImageError("The uploaded image is empty.")
        if len(image.content) > self._max_bytes:
            raise ImageTooLargeError(self._max_bytes)
        if image.content_type is not None and not image.content_type.lower().startswith("image/"):
            raise UnsupportedImageMediaTypeError

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(BytesIO(image.content)) as opened:
                    detected_format = opened.format
                    width, height = opened.size
                    if width * height > self._max_pixels:
                        raise InvalidImageError(
                            f"The image exceeds the configured limit of {self._max_pixels} pixels."
                        )
                    if detected_format is None or detected_format.upper() not in _SUPPORTED_FORMATS:
                        allowed = ", ".join(sorted(_SUPPORTED_FORMATS))
                        raise InvalidImageError(
                            f"Unsupported raster format. Supported formats: {allowed}."
                        )
                    opened.verify()
        except InvalidImageError:
            raise
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            raise InvalidImageError("The image dimensions exceed safe decoding limits.") from exc
        except (OSError, SyntaxError, UnidentifiedImageError) as exc:
            raise InvalidImageError(
                "The uploaded bytes are not a valid supported raster image."
            ) from exc

        filename = None
        if image.filename:
            filename = image.filename.replace("\\", "/").rsplit("/", maxsplit=1)[-1][:255]

        return ImageMetadata(
            filename=filename,
            declared_content_type=image.content_type,
            detected_format=detected_format.upper(),
            width=width,
            height=height,
            size_bytes=len(image.content),
        )
