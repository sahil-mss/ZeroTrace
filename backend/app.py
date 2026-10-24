"""
Backward compatibility re-export.
Canonical app is defined in backend.app.main:app
"""

from backend.app.main import app

__all__ = ["app"]
