"""Scanner adapters — pluggable detection engines.

Each adapter implements ``ScannerAdapter.scan(code, ...)`` and returns a list
of ``Finding``. The orchestrator in ``gvskb.scanner`` runs adapters in order
and de-duplicates overlapping findings (more precise engine wins).

Currently registered:
- ``regex``: original engine — single-line regex patterns from MD ``detection.patterns``
- ``python-ast``: precise Python AST visitor for eval/exec/subprocess/pickle/weak crypto

Planned:
- ``semgrep``: optional Semgrep CE adapter
- ``secret``: dedicated secret-scanner with high-confidence patterns
- ``dependency``: SBOM / requirements scanner that joins with intel cache
"""
from __future__ import annotations

from .ast_scanner import PythonAstScanner
from .base import ScannerAdapter
from .regex_scanner import RegexScanner

__all__ = ["ScannerAdapter", "RegexScanner", "PythonAstScanner"]
