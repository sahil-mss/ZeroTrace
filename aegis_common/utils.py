import re
import uuid
from datetime import UTC, datetime
from typing import Any


def utc_now() -> datetime:
    """Returns current timezone-aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensures a datetime object is timezone-aware and set to UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def generate_id(prefix: str) -> str:
    """Generates a secure, human-readable prefixed identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|token|secret|authorization|bearer|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)


def sanitize_sensitive_data(data: Any) -> Any:
    """
    Recursively scans and redacts credentials, authorization tokens,
    and private keys from dictionaries and lists.
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if SENSITIVE_KEY_PATTERN.search(str(key)):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_sensitive_data(value)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_sensitive_data(item) for item in data]
    return data
