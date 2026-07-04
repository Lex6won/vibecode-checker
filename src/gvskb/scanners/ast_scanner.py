"""Python AST scanner — precise detection of dangerous call sites.

Where the regex adapter sees text, this adapter sees Python's parse tree:
- ``eval(x)`` is detected; ``obj.eval(...)`` is not.
- ``subprocess.run(..., shell=True)`` is detected via keyword argument inspection.
- ``hashlib.md5(...)`` is detected as a *call*, not as a substring match.

Findings emitted here reuse the same ``rule_id`` as the corresponding MD rule
so consumers see a consistent vocabulary across engines. Rule metadata is
looked up from ``regex_scanner.RULES`` to avoid duplicating policy.
"""
from __future__ import annotations

import ast
import re
from typing import Iterable

from ..schema import Finding
from .base import ScannerAdapter
from .regex_scanner import build_finding, lookup_rule, redact_evidence


# Names that, when called bare (e.g. ``eval(x)``), are code-injection sinks.
_BUILTIN_CODE_EXEC = {"eval", "exec"}

# Attribute-call sinks for OS commands. (object_name, attr_name)
_OS_COMMAND_SINKS = {
    ("os", "system"),
    ("os", "popen"),
    ("commands", "getoutput"),
    ("commands", "getstatusoutput"),
}

# subprocess functions whose ``shell=True`` is the risky pattern.
_SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}

# Untrusted deserialization sinks.
_DESERIALIZATION_SINKS = {
    ("pickle", "loads"), ("pickle", "load"),
    ("cPickle", "loads"), ("cPickle", "load"),
    ("marshal", "loads"), ("marshal", "load"),
    ("shelve", "open"),
    ("pandas", "read_pickle"),
    ("joblib", "load"),
}

# Weak hash algorithms via hashlib.
_WEAK_HASH_FUNCS = {"md5", "sha1", "md4"}
_WEAK_HASH_NAMES = {"md5", "sha1", "md4"}
_IGNORE_RE = re.compile(r"gvskb:\s*ignore(?:\s+([A-Za-z0-9_.:-]+))?", re.IGNORECASE)


def _is_ignored(line: str, rule_id: str) -> bool:
    match = _IGNORE_RE.search(line)
    if not match:
        return False
    ignored_rule = match.group(1)
    return ignored_rule is None or ignored_rule == rule_id


def _attr_chain(node: ast.AST) -> str | None:
    """Return ``"a.b.c"`` for an Attribute/Name chain, else None."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map module aliases to their canonical top-level name.

    ``import pandas as pd`` → ``{"pd": "pandas"}`` so that ``pd.read_pickle``
    resolves to the ``("pandas", "read_pickle")`` sink. Bare ``import os`` maps
    ``os`` to itself, keeping non-aliased calls working unchanged.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                aliases[alias.asname or top] = top
    return aliases


def _kw_is_true(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _string_arg(call: ast.Call, index: int) -> str | None:
    if index < len(call.args):
        node = call.args[index]
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


class _Visitor(ast.NodeVisitor):
    """Collects ``(rule_id, line_no, evidence)`` triples while walking the tree."""

    def __init__(self, source_lines: list[str], aliases: dict[str, str] | None = None) -> None:
        self.source_lines = source_lines
        self.aliases = aliases or {}
        self.hits: list[tuple[str, int, str]] = []

    def _evidence(self, line_no: int) -> str:
        if 1 <= line_no <= len(self.source_lines):
            return redact_evidence(self.source_lines[line_no - 1])
        return ""

    def _record(self, rule_id: str, lineno: int) -> None:
        if 1 <= lineno <= len(self.source_lines) and _is_ignored(self.source_lines[lineno - 1], rule_id):
            return
        self.hits.append((rule_id, lineno, self._evidence(lineno)))

    # ------------------------------------------------------------------
    # Call site inspection
    # ------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 (ast API)
        # 1) Bare eval / exec — code injection
        if isinstance(node.func, ast.Name) and node.func.id in _BUILTIN_CODE_EXEC:
            self._record("KISA-PY-INPUT-02", node.lineno)

        # 2) compile(code, file, 'exec'|'eval'|'single')
        if isinstance(node.func, ast.Name) and node.func.id == "compile":
            mode = _string_arg(node, 2)
            if mode in {"exec", "eval", "single"}:
                self._record("KISA-PY-INPUT-02", node.lineno)

        # 3) Attribute calls — OS command, subprocess shell=True, weak hash, deserialization
        chain = _attr_chain(node.func) if isinstance(node.func, ast.Attribute) else None
        if chain:
            parts = chain.split(".")
            # Resolve module alias on the first token (pd → pandas, np → numpy),
            # so aliased sink calls match the canonical (module, attr) sets.
            if parts:
                parts[0] = self.aliases.get(parts[0], parts[0])

            # 3a) os.system / os.popen / commands.getoutput
            if len(parts) >= 2 and (parts[0], parts[1]) in _OS_COMMAND_SINKS:
                self._record("KISA-PY-INPUT-05", node.lineno)

            # 3b) subprocess.<run|call|check_call|check_output|Popen>(shell=True)
            if len(parts) >= 2 and parts[0] == "subprocess" and parts[1] in _SUBPROCESS_FUNCS:
                if _kw_is_true(node, "shell"):
                    self._record("KISA-PY-INPUT-05", node.lineno)

            # 3c) hashlib.md5() / hashlib.sha1() — direct
            if len(parts) >= 2 and parts[0] == "hashlib" and parts[1] in _WEAK_HASH_FUNCS:
                self._record("KISA-PY-SEC-04", node.lineno)

            # 3d) hashlib.new('md5'|'sha1')
            if len(parts) >= 2 and parts[0] == "hashlib" and parts[1] == "new":
                algo = _string_arg(node, 0)
                if algo and algo.lower() in _WEAK_HASH_NAMES:
                    self._record("KISA-PY-SEC-04", node.lineno)

            # 3e) Untrusted deserialization
            if len(parts) >= 2 and (parts[0], parts[1]) in _DESERIALIZATION_SINKS:
                self._record("KISA-PY-CODE-03", node.lineno)

            # 3f) torch.load() without weights_only=True
            if len(parts) >= 2 and parts[0] == "torch" and parts[1] == "load":
                if not _kw_is_true(node, "weights_only"):
                    self._record("KISA-PY-CODE-03", node.lineno)

        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Multi-line SQL injection via variable taint (intra-scope def → use)
#
# The regex engine only catches string-building *inside* the execute() call
# (``execute("..." + x)``). Real AI-generated code overwhelmingly assembles the
# query on one line and runs it on the next::
#
#     query = "SELECT * FROM t WHERE n = '" + name + "'"   # taint source
#     cur.execute(query)                                    # sink → flagged
#
# Per function/module scope, in document order, we track which string variables
# were last assigned a *dynamically built* string (f-string with a non-constant
# field, ``+`` concat mixing a literal with a variable/call, or ``.format(...)``)
# and flag when such a variable — or a dynamic expression — reaches a cursor
# ``execute``/``executemany``/``executescript`` call. A parameterised call
# (constant first arg + params tuple) is never tainted, so the rule's
# ``examples.negative`` stay clean and FP=0 is preserved.
# ---------------------------------------------------------------------------

_SQL_EXEC_METHODS = {"execute", "executemany", "executescript"}


def _fstring_is_dynamic(node: ast.JoinedStr) -> bool:
    """An f-string whose interpolated field is not itself a constant."""
    return any(
        isinstance(v, ast.FormattedValue) and not isinstance(v.value, ast.Constant)
        for v in node.values
    )


def _add_mixes_literal_and_dynamic(node: ast.AST) -> bool:
    """A ``+`` chain concatenating at least one str literal with at least one
    variable/call/subscript (dynamic input) — the classic SQL build shape."""
    has_str = has_dyn = False
    stack: list[ast.AST] = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            stack.append(n.left)
            stack.append(n.right)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            has_str = True
        elif isinstance(n, ast.JoinedStr):
            has_str = True
            if _fstring_is_dynamic(n):
                has_dyn = True
        elif isinstance(n, (ast.Name, ast.Call, ast.Attribute, ast.Subscript, ast.Await)):
            has_dyn = True
    return has_str and has_dyn


def _expr_builds_dynamic_sql(node: ast.AST, tainted: set[str]) -> bool:
    """Is ``node`` a dynamically-built (untrusted) string expression?"""
    if isinstance(node, ast.JoinedStr):
        return _fstring_is_dynamic(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _add_mixes_literal_and_dynamic(node)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = node.func.value
            base_is_str = (
                (isinstance(base, ast.Constant) and isinstance(base.value, str))
                or isinstance(base, ast.JoinedStr)
                or (isinstance(base, ast.Name) and base.id in tainted)
            )
            return base_is_str and bool(node.args or node.keywords)
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted
    return False


def _sub_statement_bodies(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Nested statement blocks (if/for/while/with/try) — NOT def/class bodies."""
    bodies: list[list[ast.stmt]] = []
    for field in ("body", "orelse", "finalbody"):
        block = getattr(stmt, field, None)
        if isinstance(block, list):
            bodies.append(block)
    for handler in getattr(stmt, "handlers", []) or []:
        if isinstance(handler, ast.ExceptHandler):
            bodies.append(handler.body)
    return bodies


def _sink_calls(stmt: ast.stmt) -> list[ast.Call]:
    """execute()-family calls in this statement's own expression (Expr / Assign
    RHS / Return), excluding calls inside nested statement bodies."""
    roots: list[ast.AST] = []
    if isinstance(stmt, ast.Expr):
        roots.append(stmt.value)
    elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return)):
        if getattr(stmt, "value", None) is not None:
            roots.append(stmt.value)
    calls: list[ast.Call] = []
    for root in roots:
        for n in ast.walk(root):
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in _SQL_EXEC_METHODS
                and n.args
            ):
                calls.append(n)
    return calls


def _process_scope(
    stmts: list[ast.stmt],
    tainted: set[str],
    hits: list[tuple[str, int, str]],
    source_lines: list[str],
) -> None:
    for stmt in stmts:
        # Nested def/class opens a new scope; its parameters start untainted.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _process_scope(stmt.body, set(), hits, source_lines)
            continue
        # 1) sinks read the taint state established by earlier statements.
        for call in _sink_calls(stmt):
            arg0 = call.args[0]
            reaches = (isinstance(arg0, ast.Name) and arg0.id in tainted) or \
                _expr_builds_dynamic_sql(arg0, tainted)
            if not reaches:
                continue
            line_no = call.lineno
            src = source_lines[line_no - 1] if 1 <= line_no <= len(source_lines) else ""
            if _is_ignored(src, "GOV-SQL-INJECTION-001"):
                continue
            hits.append(("GOV-SQL-INJECTION-001", line_no, redact_evidence(src)))
        # 2) recurse into compound bodies with the same (flow-insensitive) taint.
        for body in _sub_statement_bodies(stmt):
            _process_scope(body, tainted, hits, source_lines)
        # 3) update taint from this statement's assignment (post-use).
        if isinstance(stmt, ast.Assign):
            is_dyn = _expr_builds_dynamic_sql(stmt.value, tainted)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    (tainted.add if is_dyn else tainted.discard)(target.id)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            (tainted.add if _expr_builds_dynamic_sql(stmt.value, tainted) else tainted.discard)(stmt.target.id)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            if _expr_builds_dynamic_sql(stmt.value, tainted) or isinstance(
                stmt.value, (ast.Name, ast.Call, ast.Subscript, ast.Attribute)
            ):
                tainted.add(stmt.target.id)


def _scan_sql_taint(tree: ast.AST, source_lines: list[str]) -> list[tuple[str, int, str]]:
    """Return ``(rule_id, line_no, evidence)`` for tainted SQL sinks."""
    hits: list[tuple[str, int, str]] = []
    _process_scope(getattr(tree, "body", []), set(), hits, source_lines)
    return hits


def _looks_like_python(filename: str, language: str | None) -> bool:
    if language and language.lower() in {"python", "py"}:
        return True
    return filename.endswith(".py") or filename.endswith(".pyw")


class PythonAstScanner(ScannerAdapter):
    """Precise AST-based detection for Python sources."""

    name = "python-ast"

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
        if not _looks_like_python(filename, language):
            return []
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError):
            # Malformed input or null bytes — let the regex scanner still try.
            return []

        visitor = _Visitor(code.splitlines(), _collect_import_aliases(tree))
        visitor.visit(tree)

        # Precise call-site hits + multi-line SQL taint hits share one pipeline.
        all_hits = visitor.hits + _scan_sql_taint(tree, visitor.source_lines)

        findings: list[Finding] = []
        for rule_id, line_no, evidence in all_hits:
            rule = lookup_rule(rule_id)
            if rule is None:
                continue  # rule not loaded (e.g. testing with empty repo)
            if categories and rule["category"] not in categories:
                continue
            findings.append(build_finding(
                rule, filename=filename, line_no=line_no,
                evidence=evidence, engine=self.name,
            ))
        return findings


def supported_rule_ids() -> Iterable[str]:
    """Rule IDs this adapter can emit. Useful for status_for_mcp."""
    return (
        "KISA-PY-INPUT-02", "KISA-PY-INPUT-05", "KISA-PY-SEC-04", "KISA-PY-CODE-03",
        "GOV-SQL-INJECTION-001",
    )
