from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------
# Project base directory
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------
# Application settings
# ---------------------------------------------------------

class Settings(BaseSettings):

    # Application
    app_name: str = "CIPHER-X"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = True

    # API
    api_v1_prefix: str = "/api/v1"

    # Database
    database_url: str = "sqlite:///./cipherx.db"

    # Security
    secret_key: str = "change-this-development-secret"

    # Upload limits
    max_upload_size_mb: int = 25

    # Feature flags
    enable_threat_intel: bool = False
    enable_ai: bool = False
    enable_graph: bool = False

    # -----------------------------------------------------
    # Threat Intelligence
    # -----------------------------------------------------

    ipinfo_token: str | None = None
    abuseipdb_api_key: str | None = None

    threat_intel_timeout_seconds: int = 5
    abuseipdb_max_age_days: int = 90

    # -----------------------------------------------------
    # Environment configuration
    # -----------------------------------------------------

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


# ---------------------------------------------------------
# Cached settings
# ---------------------------------------------------------

@lru_cache
def get_settings() -> Settings:
    return Settings()