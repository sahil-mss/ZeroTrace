from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized application configuration for AegisPT."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application metadata
    APP_NAME: str = "AegisPT"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server configuration
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Storage paths
    STORAGE_DIR: str = "./aegis_data"
    EVIDENCE_STORAGE_PATH: str = "./aegis_data/evidence_blobs"
    DATABASE_URL: str = "sqlite:///./aegis_data/aegispt.db"

    # Default job & rate limits
    DEFAULT_JOB_TIMEOUT_SECONDS: int = 300
    DEFAULT_MAX_CONCURRENCY: int = 3
    DEFAULT_MAX_REQUESTS_PER_MINUTE: int = 60
    ALLOW_INTRUSIVE_TESTS: bool = False


settings = Settings()
