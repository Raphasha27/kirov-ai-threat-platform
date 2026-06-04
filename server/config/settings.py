from pydantic import Field, field_validator
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "Kirov AI Threat Platform"
    app_version: str = "1.0.0"
    debug: bool = False

    database_url: str = Field(
        default="postgresql+asyncpg://kirov:kirov@localhost:5432/kirov_threat",
        description="Database connection string. Must be set in production.",
    )
    redis_url: str = Field(default="redis://localhost:6379/0")

    jwt_secret: str = Field(
        default="",
        description="JWT signing secret. Must be set in production via env var KT_JWT_SECRET.",
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    api_v1_prefix: str = "/api/v1"

    openai_api_key: Optional[str] = None
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    cors_origins: list[str] = ["http://localhost:3000"]

    log_level: str = "INFO"
    max_log_size_mb: int = 10
    retention_days: int = 90

    sentry_dsn: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None

    model_config = {"env_prefix": "KT_", "env_file": ".env"}

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        stripped = v.strip() if v else ""
        if (
            not stripped
            or "placeholder" in stripped.lower()
            or "change" in stripped.lower()
        ):
            raise ValueError(
                "JWT_SECRET must be set and must not be a placeholder. "
                "Set the KT_JWT_SECRET environment variable or add it to your .env file."
            )
        return stripped

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        stripped = v.strip() if v else ""
        if not stripped:
            raise ValueError("DATABASE_URL must be set.")
        return stripped


settings = Settings()
