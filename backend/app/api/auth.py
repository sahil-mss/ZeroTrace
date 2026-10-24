"""
ZeroTrace Authentication Dependency Module.

Provides Bearer Token authentication for protecting REST API endpoints.

SECURITY NOTICE:
One shared API token is a development prototype for Person 1, 2, and 3
integration and test automation, NOT a complete multi-user authorization system.
A production environment requires role-based access control (RBAC), user identities,
token revocation, and short-lived credential exchange.
"""

import logging
import os
import secrets

from fastapi import Header, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.core.config import settings

logger = logging.getLogger("zerotrace.auth")

# Bearer token extractor; auto_error=False allows returning custom secure error responses
bearer_scheme = HTTPBearer(auto_error=False)


def verify_api_token(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """
    Validates caller credentials against configured settings.API_AUTH_TOKEN.

    Fails closed when API_AUTH_TOKEN is not configured or is empty.
    Supports standard Authorization Bearer header as well as X-API-Key header.
    Performs constant-time comparison via secrets.compare_digest.
    Never logs or exposes the token value in logs or audit metadata.
    """
    configured_token = (
        (settings.get_auth_token() or "").strip()
        or os.getenv("API_AUTH_TOKEN", "").strip()
        or os.getenv("API_BEARER_TOKEN", "").strip()
    )

    # Optional development open mode
    if settings.ZEROTRACE_DEV_OPEN and not configured_token:
        return "open_dev_operator"

    # 1. Fail closed if authentication token is unconfigured on the server
    if not configured_token or not configured_token.strip():
        logger.warning(
            "Access denied: API_AUTH_TOKEN is not configured on the server. Failing closed."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is not configured on this server; access denied by policy.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Extract supplied token from Authorization Bearer or X-API-Key
    supplied_token = ""
    if credentials and credentials.credentials:
        supplied_token = credentials.credentials.strip()
    elif x_api_key:
        supplied_token = x_api_key.strip()

    if not supplied_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header with Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Constant-time comparison to prevent timing attacks
    is_valid = secrets.compare_digest(
        supplied_token.encode("utf-8"),
        configured_token.strip().encode("utf-8"),
    )

    if not is_valid:
        logger.warning("Access denied: Invalid bearer token provided.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return "authenticated_operator"
