"""Retail-aware function evidence and mismatch explanation."""

from .analysis import build_analysis
from .model import SCHEMA_NAME, SCHEMA_VERSION

__all__ = ["SCHEMA_NAME", "SCHEMA_VERSION", "build_analysis"]
