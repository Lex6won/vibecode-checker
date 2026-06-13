"""Abstract base for scanner adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..schema import Finding


class ScannerAdapter(ABC):
    """Pluggable detection engine.

    Implementations should:
    - Set ``name`` to a short identifier (used as the ``engine`` field on findings).
    - Be safe to call on any input; never raise on syntax errors or unknown languages.
    - Honor ``language`` / ``filename`` to skip irrelevant inputs cheaply.
    - Honor ``categories`` to allow callers to narrow the rule set (e.g. secret-only).
    """

    name: str = "base"

    @abstractmethod
    def scan(
        self,
        code: str,
        *,
        filename: str = "<memory>",
        language: str | None = None,
        scenario: str | None = None,
        profile: str = "public-default-strict",
        categories: set[str] | None = None,
    ) -> list[Finding]:
        ...
