"""Intel source adapters.

Each adapter exposes a ``fetch(client)`` callable that returns a tuple
``(url, normalized_items)`` so the IntelCache can store it uniformly.
"""
from __future__ import annotations

from .base import SOURCES, SourceAdapter, register_source
from . import cisa_kev, epss, nvd, osv  # noqa: F401 — side-effect registration

__all__ = ["SOURCES", "SourceAdapter", "register_source"]
