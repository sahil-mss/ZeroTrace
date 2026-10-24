from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized application configuration for ZeroTrace."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application metadata
    APP_NAME: str = "ZeroTrace"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server configuration
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Authentication & Security
    # Shared API Token is a development prototype, not a complete multi-user system.
    # When unset or empty, protected endpoints fail closed unless ZEROTRACE_DEV_OPEN=true.
    API_BEARER_TOKEN: str | None = None
    ZEROTRACE_DEV_OPEN: bool = False

    @property
    def API_AUTH_TOKEN(self) -> str | None:
        return self.API_BEARER_TOKEN

    @API_AUTH_TOKEN.setter
    def API_AUTH_TOKEN(self, val: str | None) -> None:
        self.API_BEARER_TOKEN = val

    def get_auth_token(self) -> str | None:
        """Returns the configured token from API_AUTH_TOKEN or API_BEARER_TOKEN."""
        return self.API_BEARER_TOKEN

    CORS_ALLOWED_ORIGINS: list[str] = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]

    # Storage paths
    STORAGE_DIR: str = "./aegis_data"
    EVIDENCE_STORAGE_PATH: str = "./aegis_data/evidence_blobs"
    DATABASE_URL: str = "sqlite:///./aegis_data/aegispt.db"

    # Default job & rate limits
    DEFAULT_JOB_TIMEOUT_SECONDS: int = 300
    DEFAULT_MAX_CONCURRENCY: int = 3
    DEFAULT_MAX_REQUESTS_PER_MINUTE: int = 60
    ALLOW_INTRUSIVE_TESTS: bool = False

    # Passive OSINT Intelligence Settings
    # Both network-backed adapters are disabled by default for safety and offline compliance.
    OSINT_NETWORK_ENABLED: bool = False
    OSINT_DNS_ENABLED: bool = False
    OSINT_CT_ENABLED: bool = False
    OSINT_REQUEST_TIMEOUT_SECONDS: float = 10.0
    OSINT_MAX_RESPONSE_BYTES: int = 1_000_000  # 1 MB maximum response body
    OSINT_RATE_LIMIT_PER_MINUTE: int = 30
    OSINT_MAX_RECORDS_PER_COLLECTION: int = 100
    OSINT_COLLECTION_TIMEOUT_SECONDS: float = 60.0
    OSINT_USER_AGENT: str = "ZeroTrace-OSINT/1.0 (+https://github.com/sahil-mss/ZeroTrace)"


settings = Settings()
