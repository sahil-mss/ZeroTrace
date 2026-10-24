import os

from pydantic import BaseModel, Field


class AIConfig(BaseModel):
    """Configuration for AI model execution and safety guardrails."""

    provider: str = Field(
        default_factory=lambda: os.getenv("AI_PROVIDER", "deterministic").lower(),
        description="Provider type: deterministic | ollama | openai | mock",
    )
    model_name: str = Field(
        default_factory=lambda: os.getenv("AI_MODEL_NAME", "llama3.2"),
        description="Model identifier for remote/local model execution",
    )
    api_base: str = Field(
        default_factory=lambda: os.getenv("AI_API_BASE", "http://localhost:11434/v1"),
        description="Base URL for OpenAI-compatible or local model endpoints",
    )
    api_key: str | None = Field(
        default_factory=lambda: os.getenv("AI_API_KEY", ""),
        description="API key for authentication (never committed to repository)",
    )
    timeout_seconds: float = Field(
        default_factory=lambda: float(os.getenv("AI_TIMEOUT_SECONDS", "10.0")),
        description="HTTP request timeout in seconds",
    )
    allow_external_calls: bool = Field(
        default_factory=lambda: (
            os.getenv("AI_ALLOW_EXTERNAL_CALLS", "false").lower() in ("true", "1", "yes")
        ),
        description="Explicit consent flag to permit sending assessment data to external endpoints",
    )

    def is_local_endpoint(self) -> bool:
        """Check if api_base points to a local or private address."""
        base = self.api_base.lower()
        return (
            "localhost" in base
            or "127.0.0.1" in base
            or "0.0.0.0" in base
            or "::1" in base
            or base.startswith("http://10.")
            or base.startswith("http://192.168.")
        )
