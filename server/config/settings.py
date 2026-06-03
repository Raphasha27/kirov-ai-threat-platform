from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "Kirov AI Threat Platform"
    app_version: str = "1.0.0"
    debug: bool = False

    database_url: str = "postgresql+asyncpg://kirov:kirov@localhost:5432/kirov_threat"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

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


settings = Settings()
