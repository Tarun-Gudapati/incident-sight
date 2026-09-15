"""Runtime settings loaded from environment variables or a local .env file."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """IncidentSight settings.

    Multimodal-provider settings are intentionally absent until a real provider
    adapter exists. Setting an API key today would not enable image understanding.
    """

    model_config = SettingsConfigDict(
        env_prefix="INCIDENTSIGHT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    max_image_bytes: int = Field(default=10 * 1024 * 1024, ge=1, le=50 * 1024 * 1024)
    max_image_pixels: int = Field(default=25_000_000, ge=1, le=100_000_000)
