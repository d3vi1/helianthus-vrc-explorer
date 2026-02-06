from __future__ import annotations


class ValueParseError(Exception):
    """Raised when response bytes cannot be parsed into a typed value."""
