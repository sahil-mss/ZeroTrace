"""OWASP ZAP scanner integration package.

Provides automated interaction with OWASP ZAP via its REST API,
policy profile enforcement, and structured JSON alert extraction.
"""

from aegispt.security_engine.integrations.zap.config import ZAPConfig
from aegispt.security_engine.integrations.zap.parser import (
    ZAPAlertParser,
    ZAPParserError,
)
from aegispt.security_engine.integrations.zap.scanner import ZAPScanner

__all__ = ["ZAPScanner", "ZAPConfig", "ZAPAlertParser", "ZAPParserError"]
