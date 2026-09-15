"""Tests for metadata-only image inspection."""

from io import BytesIO

import pytest
from PIL import Image

from incidentsight.analyzers.images import PillowImageInspector
from incidentsight.errors import (
    ImageTooLargeError,
    InvalidImageError,
    UnsupportedImageMediaTypeError,
)
from incidentsight.interfaces import ImagePayload


def _image_bytes(image_format: str = "PNG", size: tuple[int, int] = (3, 2)) -> bytes:
    buffer = BytesIO()
    Image.new("RGB", size, color=(20, 40, 60)).save(buffer, format=image_format)
    return buffer.getvalue()


def test_reports_metadata_without_pixel_interpretation() -> None:
    content = _image_bytes()
    inspector = PillowImageInspector(max_bytes=10_000, max_pixels=1_000)

    result = inspector.inspect(
        ImagePayload(
            content=content,
            filename=r"C:\uploads\incident.png",
            content_type="image/png",
        )
    )

    assert result.filename == "incident.png"
    assert result.declared_content_type == "image/png"
    assert result.detected_format == "PNG"
    assert (result.width, result.height) == (3, 2)
    assert result.size_bytes == len(content)


def test_rejects_empty_upload() -> None:
    inspector = PillowImageInspector(max_bytes=100, max_pixels=100)

    with pytest.raises(InvalidImageError, match="empty"):
        inspector.inspect(ImagePayload(content=b"", filename=None, content_type="image/png"))


def test_rejects_oversized_upload() -> None:
    inspector = PillowImageInspector(max_bytes=3, max_pixels=100)

    with pytest.raises(ImageTooLargeError):
        inspector.inspect(ImagePayload(content=b"1234", filename=None, content_type="image/png"))


def test_rejects_non_image_declared_media_type() -> None:
    inspector = PillowImageInspector(max_bytes=100, max_pixels=100)

    with pytest.raises(UnsupportedImageMediaTypeError):
        inspector.inspect(ImagePayload(content=b"image", filename=None, content_type="text/plain"))


def test_rejects_invalid_image_bytes() -> None:
    inspector = PillowImageInspector(max_bytes=100, max_pixels=100)

    with pytest.raises(InvalidImageError, match="not a valid"):
        inspector.inspect(
            ImagePayload(content=b"not-an-image", filename=None, content_type="image/png")
        )


def test_rejects_configured_pixel_limit() -> None:
    inspector = PillowImageInspector(max_bytes=10_000, max_pixels=99)

    with pytest.raises(InvalidImageError, match="99 pixels"):
        inspector.inspect(
            ImagePayload(
                content=_image_bytes(size=(10, 10)),
                filename="large.png",
                content_type="image/png",
            )
        )


def test_rejects_raster_format_outside_allowlist() -> None:
    inspector = PillowImageInspector(max_bytes=10_000, max_pixels=1_000)

    with pytest.raises(InvalidImageError, match="Unsupported raster format"):
        inspector.inspect(
            ImagePayload(
                content=_image_bytes(image_format="TIFF"),
                filename="incident.tiff",
                content_type=None,
            )
        )
