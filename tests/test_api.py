"""HTTP contract tests."""

from __future__ import annotations

import asyncio
import json
from io import BytesIO
from typing import Any

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response
from PIL import Image

from incidentsight.app import create_app
from incidentsight.interfaces import ImagePayload
from incidentsight.models import IncidentMetadata, TriageResponse
from incidentsight.settings import Settings


def _metadata_json(**overrides: str) -> str:
    metadata = {
        "incident_id": "INC-100",
        "title": "Payments degraded",
        "service": "payments",
        "environment": "production",
        "description": "Alert from the synthetic monitor.",
    }
    metadata.update(overrides)
    return json.dumps(metadata)


def _png_bytes(size: tuple[int, int] = (5, 4)) -> bytes:
    buffer = BytesIO()
    Image.new("RGB", size, color=(10, 20, 30)).save(buffer, format="PNG")
    return buffer.getvalue()


class _AppClient:
    """Small synchronous facade over HTTPX's non-deprecated ASGI transport."""

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    def request(self, method: str, path: str, **kwargs: Any) -> Response:
        async def send() -> Response:
            transport = ASGITransport(app=self._app, raise_app_exceptions=False)
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(send())

    def get(self, path: str) -> Response:
        return self.request("GET", path)

    def post(self, path: str, **kwargs: Any) -> Response:
        return self.request("POST", path, **kwargs)


def _client(*, max_image_bytes: int = 10_000, max_image_pixels: int = 10_000) -> _AppClient:
    app = create_app(
        Settings(
            max_image_bytes=max_image_bytes,
            max_image_pixels=max_image_pixels,
        )
    )
    return _AppClient(app)


def test_health_reports_baseline_mode() -> None:
    response = _client().get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "mode": "deterministic-baseline",
        "screenshot_interpretation": "not_configured",
    }


def test_triage_multipart_request_without_image() -> None:
    response = _client().post(
        "/api/triage",
        data={
            "metadata": _metadata_json(),
            "log_text": "ERROR PaymentException request timed out status=503",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "INC-100"
    assert body["severity"] == "high"
    assert all(hypothesis["is_hypothesis"] is True for hypothesis in body["hypotheses"])
    assert body["action_plan"]["human_approval_required"] is True
    assert body["action_plan"]["automation_executed"] is False


def test_triage_reports_only_uploaded_image_metadata() -> None:
    content = _png_bytes()
    response = _client().post(
        "/api/triage",
        data={
            "metadata": _metadata_json(),
            "log_text": "INFO request accepted",
        },
        files={"image": ("screenshot.png", content, "image/png")},
    )

    assert response.status_code == 200
    image_evidence = next(
        item for item in response.json()["evidence"] if item["signal"] == "image_metadata"
    )
    assert image_evidence["observed_values"] == [
        "format=PNG",
        "dimensions=5x4",
        f"size_bytes={len(content)}",
    ]
    assert "did not interpret" in image_evidence["detail"]


def test_invalid_metadata_uses_stable_error_envelope() -> None:
    response = _client().post(
        "/api/triage",
        data={"metadata": '{"incident_id": 7}', "log_text": "INFO started"},
    )

    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "invalid_metadata"
    assert body["error"]["details"]
    assert all(detail["location"][0] == "metadata" for detail in body["error"]["details"])


def test_missing_form_field_uses_stable_validation_error() -> None:
    response = _client().post("/api/triage", data={"log_text": "INFO started"})

    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error"
    assert body["error"]["details"][0]["type"] == "missing"


def test_rejects_non_image_upload_type() -> None:
    response = _client().post(
        "/api/triage",
        data={"metadata": _metadata_json(), "log_text": "INFO started"},
        files={"image": ("notes.txt", b"not an image", "text/plain")},
    )

    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_image_media_type"


def test_rejects_invalid_image_content() -> None:
    response = _client().post(
        "/api/triage",
        data={"metadata": _metadata_json(), "log_text": "INFO started"},
        files={"image": ("fake.png", b"not an image", "image/png")},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_image"


def test_rejects_image_over_byte_limit_before_decoding() -> None:
    response = _client(max_image_bytes=5).post(
        "/api/triage",
        data={"metadata": _metadata_json(), "log_text": "INFO started"},
        files={"image": ("large.png", b"123456", "image/png")},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "image_too_large"


def test_rejects_image_over_pixel_limit() -> None:
    response = _client(max_image_pixels=10).post(
        "/api/triage",
        data={"metadata": _metadata_json(), "log_text": "INFO started"},
        files={"image": ("large.png", _png_bytes((4, 4)), "image/png")},
    )

    assert response.status_code == 422
    assert "10 pixels" in response.json()["error"]["message"]


def test_openapi_documents_health_and_multipart_triage() -> None:
    response = _client().get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "IncidentSight"
    assert "Status: Concept scaffold" in schema["info"]["description"]
    assert "/health" in schema["paths"]
    assert "multipart/form-data" in schema["paths"]["/api/triage"]["post"]["requestBody"]["content"]


class _FailingOrchestrator:
    async def triage(
        self,
        *,
        metadata: IncidentMetadata,
        log_text: str,
        image: ImagePayload | None,
    ) -> TriageResponse:
        del metadata, log_text, image
        raise RuntimeError("private implementation detail")


def test_unexpected_errors_do_not_leak_details() -> None:
    app = create_app(Settings(), orchestrator=_FailingOrchestrator())
    client = _AppClient(app)

    response = client.post(
        "/api/triage",
        data={"metadata": _metadata_json(), "log_text": "INFO started"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_error",
            "message": "An unexpected error occurred.",
            "details": [],
        }
    }
