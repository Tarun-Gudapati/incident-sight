"""Keep checked-in sample inputs valid."""

from pathlib import Path

from incidentsight.analyzers.logs import RegexLogAnalyzer
from incidentsight.models import IncidentMetadata

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_sample_metadata_and_log_fixture_are_valid() -> None:
    metadata = IncidentMetadata.model_validate_json(
        (PROJECT_ROOT / "examples" / "incident-metadata.json").read_text(encoding="utf-8")
    )
    analysis = RegexLogAnalyzer().analyze(
        (PROJECT_ROOT / "examples" / "sample-incident.log").read_text(encoding="utf-8")
    )

    assert metadata.incident_id == "INC-2026-0915"
    assert analysis.exception_counts == {"CheckoutException": 1}
    assert analysis.timeout_count == 1
    assert analysis.http_status_counts == {503: 2}
