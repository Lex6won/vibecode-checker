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
import contextvars
import re
from typing import Iterable

from ..schema import Finding
from .base import ScannerAdapter
from .py_const import (
    ConstEnv,
    collect_constants,
    expr_is_constant,
    literal_only_parameters,
)
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
def _is_ignored(line: str, rule_id: str) -> bool:
    """인라인 무시 판정 — 공용 구현에 위임한다.

    예전에는 여기서 줄 전체를 ``_IGNORE_RE.search`` 로 훑어, **문자열 리터럴 안의
    문구로도** 검사가 꺼졌다(``label = "gvskb: ignore"``). 엔진마다 따로 구현하면
    한쪽만 고쳐져 우회가 남으므로 판정을 한 곳으로 모은다.
    """
    from .regex_scanner import line_ignores_rule

    return line_ignores_rule(line, rule_id, "python")


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


def _argv_spawns_shell_with_dynamic_command(call: ast.Call) -> bool:
    if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
        return False
    elts = call.args[0].elts
    strs = [e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None for e in elts]
    for i, s in enumerate(strs):
        if s is None or s.rsplit("/", 1)[-1] not in {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh"}:
            continue
        rest = strs[i + 1:]
        for j, t in enumerate(rest):
            if t in {"-c", "/c", "/C", "-Command"}:
                # `-c` 바로 뒤의 **명령 문자열 자체**가 동적일 때만 잡는다.
                # `["cmd", "/c", "del", fname]` 처럼 명령어가 상수이고 뒤가 인자인
                # 형태는 코퍼스가 음성으로 고정한 판정이다(g_clean_twins).
                return j + 1 < len(rest) and rest[j + 1] is None
    return False


def _yaml_loader_is_safe(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "Loader":
            name = kw.value.attr if isinstance(kw.value, ast.Attribute) else getattr(kw.value, "id", "")
            return "Safe" in str(name)
    if len(call.args) >= 2:
        node = call.args[1]
        name = node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")
        return "Safe" in str(name)
    return False   # Loader 미지정: PyYAML<6 은 FullLoader 경고, 5.x 이하는 임의 객체


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
        from .regex_scanner import InlineIgnores

        self.source_lines = source_lines
        self._ignores = InlineIgnores("\n".join(source_lines), "python")
        self.aliases = aliases or {}
        self.hits: list[tuple[str, int, str]] = []

    def _evidence(self, line_no: int) -> str:
        if 1 <= line_no <= len(self.source_lines):
            return redact_evidence(self.source_lines[line_no - 1])
        return ""

    def _record(self, rule_id: str, lineno: int, confidence: str | None = None) -> None:
        # 같은 줄 형태와 **바로 윗줄 단독 주석** 형태를 모두 본다. 두 번째 형태는
        # 룰 카드가 안내하는 사용법이면서(주석을 위에 다는 습관) 판정이 모호하지
        # 않아, 다른 언어에서도 같은 규칙을 쓴다.
        if self._ignores.suppresses(lineno, rule_id):
            return
        if confidence:
            self.hits.append((rule_id, lineno, self._evidence(lineno), confidence))
        else:
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

            # 명령 인자에 외부 출처(요청·argv·stdin)가 직접 들어 있으면 '확인됨'.
            cmd_conf = "confirmed" if _expr_mentions_source(node) else None
            # 3a) os.system / os.popen / commands.getoutput
            if len(parts) >= 2 and (parts[0], parts[1]) in _OS_COMMAND_SINKS:
                self._record("KISA-PY-INPUT-05", node.lineno, cmd_conf)

            # 3b) subprocess.<run|call|check_call|check_output|Popen>(shell=True)
            if len(parts) >= 2 and parts[0] == "subprocess" and parts[1] in _SUBPROCESS_FUNCS:
                if _kw_is_true(node, "shell"):
                    self._record("KISA-PY-INPUT-05", node.lineno, cmd_conf)
                # 3b') shell=True 없이 `["sh", "-c", cmd]` — 셸을 직접 띄우는 것과
                # 같다(미탐, eval_corpus s04_privesc.py). 리스트 안에 sh/bash 와 -c 가
                # 있고 그 뒤 원소가 상수가 아니면 잡는다.
                elif _argv_spawns_shell_with_dynamic_command(node):
                    self._record("KISA-PY-INPUT-05", node.lineno)

            # 3b'') yaml.load(...) — Loader 가 Safe 계열이 아니면 임의 객체 생성
            if len(parts) >= 2 and parts[0] == "yaml" and parts[1] == "load":
                if not _yaml_loader_is_safe(node):
                    self._record("KISA-PY-CODE-03", node.lineno)

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

# LLM SDK call sinks (OpenAI/Anthropic/Gemini/…). Matched on the trailing
# attribute chain so ``db.create``/``User.objects.create`` never qualify — only
# the LLM-specific shapes do. A dynamically-built prompt string reaching one of
# these calls is prompt-injection risk (OWASP LLM01) → GOV-LLM-PROMPT-INJECTION-001.
_LLM_SINK_RE = re.compile(
    r"(?:chat\.completions\.create|completions\.create|responses\.create"
    r"|messages\.create|ChatCompletion\.create|generate_content"
    r"|\.chat|\.complete"
    # LangChain 계열 — 공공 챗봇에서 가장 흔한 형태인데 미탐이었다(적대적 검증
    # 2026-08-29). `db.invoke`·`queue.stream` 오탐을 막으려고 수신자 이름을
    # llm/chain/model/chat 계열로 한정한다.
    r"|(?:^|\.)(?:llm|chain|model|chat|chat_model|agent)\w*\.(?:invoke|ainvoke|predict|stream|astream)"
    r")$"
)


# SQL 자리표시자 리터럴: `?` · `%s` · `%(name)s` · `:name` · `$1` · `@p`
_PLACEHOLDER_LITERAL_RE = re.compile(r"^\s*(?:\?|%s|%\(\w+\)s|:\w+|\$\d+|@\w+)\s*$")


def _is_placeholder_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) \
        and bool(_PLACEHOLDER_LITERAL_RE.match(node.value))


_PLACEHOLDER_FUNCS: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "gvskb_placeholder_funcs", default=frozenset(),
)


def _is_placeholder_expr(node: ast.AST, env: ConstEnv | None = None) -> bool:
    """**자리표시자 목록을 늘려 넣는 식** — 값은 바인딩으로 가므로 동적 SQL 이 아니다.

    실측(2026-10-13 safe_check): `','.join('?' * len(xs))` · `", ".join("?" for _ in rows)` 를
    f-string 에 넣고 값은 params 로 넘기는 안전한 코드 36곳 중 대부분이 "확인된 SQL 삽입"
    으로 차단됐다. 인정하는 모양만 좁게 둔다 — 구분자 리터럴 `.join(` 의 인자가
    자리표시자 리터럴의 반복·내포·리스트일 때, 그리고 그런 식과 상수만 보간한 f-string.
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" \
            and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str) \
            and len(node.args) == 1 and not node.keywords:
        arg = node.args[0]
        if isinstance(arg, (ast.GeneratorExp, ast.ListComp)):
            return _is_placeholder_literal(arg.elt)
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mult):
            return _is_placeholder_literal(arg.left) or _is_placeholder_literal(arg.right) \
                or (isinstance(arg.left, ast.List) and all(_is_placeholder_literal(e) for e in arg.left.elts))
        if isinstance(arg, (ast.List, ast.Tuple)):
            return bool(arg.elts) and all(_is_placeholder_literal(e) for e in arg.elts)
        return False
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _PLACEHOLDER_FUNCS.get():
        return True
    if isinstance(node, ast.JoinedStr):
        return all(
            not isinstance(v, ast.FormattedValue)
            or isinstance(v.value, ast.Constant)
            or (env is not None and expr_is_constant(v.value, env))
            or _is_placeholder_expr(v.value, env)
            for v in node.values
        )
    return False


def _fstring_is_dynamic(node: ast.JoinedStr, env: ConstEnv | None = None) -> bool:
    """An f-string whose interpolated field is not itself a constant.

    ``env`` 가 주어지면 **개발자 상수로 증명된 이름**(리터럴 리스트 순회 변수 등)
    은 동적으로 보지 않는다 — 실측에서 이 구분 하나가 SQL 오탐 8건을 만들었다.
    """
    for v in node.values:
        if not isinstance(v, ast.FormattedValue):
            continue
        if isinstance(v.value, ast.Constant):
            continue
        if env is not None and expr_is_constant(v.value, env):
            continue
        if _is_placeholder_expr(v.value, env):
            continue
        return True
    return False


def _add_mixes_literal_and_dynamic(node: ast.AST, env: ConstEnv | None = None) -> bool:
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
            if _fstring_is_dynamic(n, env):
                has_dyn = True
        elif isinstance(n, (ast.Name, ast.Call, ast.Attribute, ast.Subscript, ast.Await)):
            # 상수로 증명된 이름·리터럴 컨테이너 join·자리표시자 확장은 동적 입력이 아니다.
            if (env is not None and expr_is_constant(n, env)) or _is_placeholder_expr(n, env):
                has_str = True
            else:
                has_dyn = True
    return has_str and has_dyn


def _expr_builds_dynamic_sql(node: ast.AST, tainted: set[str], env: ConstEnv | None = None) -> bool:
    """Is ``node`` a dynamically-built (untrusted) string expression?"""
    if env is not None and expr_is_constant(node, env):
        return False
    if isinstance(node, ast.JoinedStr):
        return _fstring_is_dynamic(node, env)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _add_mixes_literal_and_dynamic(node, env)
    # `"… %s" % value` — % 포맷도 문자열 조립이다(SQL·프롬프트 공통 미탐, 2026-08-29).
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)):
        right = node.right
        if env is not None and expr_is_constant(right, env):
            return False
        return not isinstance(right, ast.Constant)
    if isinstance(node, ast.IfExp):
        return _expr_builds_dynamic_sql(node.body, tainted, env) or \
            _expr_builds_dynamic_sql(node.orelse, tainted, env)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = node.func.value
            base_is_str = (
                (isinstance(base, ast.Constant) and isinstance(base.value, str))
                or isinstance(base, ast.JoinedStr)
                or (isinstance(base, ast.Name) and base.id in tainted)
            )
            if not (base_is_str and (node.args or node.keywords)):
                return False
            # 인자가 전부 상수면 결과도 상수 — 동적 SQL 이 아니다.
            if env is not None and all(expr_is_constant(a, env) for a in node.args) \
                    and all(expr_is_constant(k.value, env) for k in node.keywords):
                return False
            return True
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted
    return False


# DDL·PRAGMA 는 파라미터 바인딩이 **문법적으로 불가능**하다(테이블·컬럼명은
# placeholder 로 넘길 수 없음). 따라서 f-string 조립 자체를 SQL 삽입(critical)
# 으로 판정하면 정상 마이그레이션 코드가 전부 차단된다. 별도 룰로 분리해
# "값의 출처가 화이트리스트인지 확인하라"는 검토 요청(medium)으로 낮춘다.
_DDL_PREFIX_RE = re.compile(
    r"^\s*(?:ALTER|CREATE|DROP|TRUNCATE|RENAME|PRAGMA|ATTACH|DETACH|REINDEX|VACUUM|ANALYZE)\b",
    re.IGNORECASE,
)


def _leading_sql_text(node: ast.AST) -> str:
    """표현식이 만들어낼 SQL 의 앞부분 리터럴을 최대한 복원한다."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                return v.value
            return ""       # 첫 조각이 삽입 필드면 판단 불가
        return ""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _leading_sql_text(node.left)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        return _leading_sql_text(node.func.value)
    return ""


def _sql_rule_for(node: ast.AST, tainted_name_src: str = "") -> str:
    """이 SQL 표현식에 맞는 룰 ID — DDL/PRAGMA 면 별도 룰."""
    head = _leading_sql_text(node) or tainted_name_src
    if head and _DDL_PREFIX_RE.match(head):
        return "GOV-SQL-DDL-DYNAMIC-001"
    return "GOV-SQL-INJECTION-001"


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


def _llm_sink_calls(stmt: ast.stmt) -> list[ast.Call]:
    """LLM SDK calls (``…chat.completions.create``, ``…messages.create``,
    ``…generate_content`` …) in this statement's own expression."""
    roots: list[ast.AST] = []
    if isinstance(stmt, ast.Expr):
        roots.append(stmt.value)
    elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return)):
        if getattr(stmt, "value", None) is not None:
            roots.append(stmt.value)
    calls: list[ast.Call] = []
    for root in roots:
        for n in ast.walk(root):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                chain = _attr_chain(n.func)
                if chain and _LLM_SINK_RE.search(chain):
                    calls.append(n)
    return calls


def _call_passes_dynamic_prompt(call: ast.Call, tainted: set[str]) -> bool:
    """Does any *argument* of this LLM call carry a dynamically-built string —
    a tainted variable or an inline literal+variable concat / dynamic f-string?

    Only args/keywords are inspected (never the ``.func`` chain), so the SDK
    object names themselves can't be mistaken for tainted data. A bare untrusted
    variable passed as data (``content=user_input``) is *not* flagged — only the
    concat-into-instructions shape is (that is the injection signal)."""
    roots: list[ast.AST] = list(call.args) + [kw.value for kw in call.keywords]
    for root in roots:
        for node in ast.walk(root):
            if isinstance(node, ast.Name) and node.id in tainted:
                return True
            if isinstance(node, (ast.BinOp, ast.JoinedStr)) and _expr_builds_dynamic_sql(node, tainted):
                return True
            # `SYSTEM_PROMPT + user_input` — 리터럴이 없어 위 판정을 비껴간다.
            # 대문자 상수 이름(지시문 상수의 관례)과 동적 값의 결합은 같은 모양이다.
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and _adds_instruction_constant(node):
                return True
            # `"요약: %s" % user_input` — % 포맷도 결합이다.
            if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
                    and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
                    and not isinstance(node.right, ast.Constant)):
                return True
    return False


_INSTRUCTION_CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")


def _adds_instruction_constant(node: ast.BinOp) -> bool:
    """`+` 체인에 대문자 상수 이름(SYSTEM_PROMPT 류)과 비상수 값이 함께 있는가."""
    has_const = has_dyn = False
    stack: list[ast.AST] = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            stack.extend((n.left, n.right))
        elif isinstance(n, ast.Name) and _INSTRUCTION_CONST_RE.match(n.id):
            has_const = True
        elif isinstance(n, (ast.Name, ast.Call, ast.Attribute, ast.Subscript, ast.Await)):
            has_dyn = True
    return has_const and has_dyn


def _scope_env(
    stmts: list[ast.stmt],
    const_params: set[str],
) -> ConstEnv:
    """스코프 상수 환경에 **호출부에서 증명된 매개변수**를 얹는다.

    매개변수는 스코프 안만 봐서는 출처를 알 수 없어 늘 동적으로 취급됐다.
    모듈 안 모든 호출부가 리터럴을 넘긴다는 것이 증명된 이름만 상수로 올린다
    (증명 조건은 ``literal_only_parameters`` 참조).
    """
    env = collect_constants(stmts)
    if const_params:
        env.names |= const_params
    return env


def _inherit_outer_constants(inner: ConstEnv, outer: ConstEnv, node: ast.AST) -> None:
    """바깥 범위(모듈)에서 상수로 증명된 이름을 함수 안에서도 상수로 본다.

    함수 범위 환경은 함수 본문만 보고 만들어져 `COLS = [...]`·`VIEW = "v"` 같은 모듈
    상수가 함수 안에서는 동적으로 취급됐다(실측 2026-10-13 safe_check `etl/read_facilities.py`
    `f"SELECT {', '.join(COLS)} FROM {VIEW}"` 가 "확인된 SQL 삽입"). 함수 안에서 다시
    대입·순회·삭제하거나 매개변수·global 로 가리는 이름은 물려받지 않는다.
    """
    shadow: set[str] = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        a = node.args
        shadow |= {p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)}
        if a.vararg:
            shadow.add(a.vararg.arg)
        if a.kwarg:
            shadow.add(a.kwarg.arg)
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            shadow.add(n.id)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            shadow |= set(n.names)
    inner.names |= outer.names - shadow
    inner.containers |= outer.containers - shadow


def _dynamic_part_is_a_parameter(node: ast.AST, params: set[str], env: ConstEnv) -> bool:
    """동적으로 판정된 부분이 **이 함수의 매개변수**뿐인가.

    매개변수의 값이 어디서 오는지는 이 스코프 밖의 일이라 **추적한 적이 없다.**
    그런데도 판정 근거를 `confirmed`(확인됨 · 데이터 흐름 추적)로 찍고 있었다 —
    보고서를 읽는 담당자에게는 "흐름을 따라가 확인했다"로 읽힌다.

    같은 스코프 안에서 조립된 문자열은 실제로 대입을 따라가 확인한 것이므로
    `confirmed` 가 맞다. 둘을 갈라 각자에게 맞는 이름을 붙인다.
    """
    if not params:
        return False
    found_param = False
    for n in ast.walk(node):
        if not isinstance(n, ast.Name) or isinstance(n.ctx, ast.Store):
            continue
        if expr_is_constant(n, env):
            continue
        if n.id in params:
            found_param = True
        else:
            return False   # 매개변수 아닌 동적 이름이 섞였다 → 스코프 안에서 추적된 것
    return found_param


def _prompt_dynamic_part_is_a_parameter(node: ast.AST, params: set[str], env: ConstEnv) -> bool:
    """프롬프트 인자 판 — `SYSTEM_PROMPT` 같은 대문자 지시문 상수는 동적 이름으로 세지 않는다."""
    if not params:
        return False
    found_param = False
    for n in ast.walk(node):
        if not isinstance(n, ast.Name) or isinstance(n.ctx, ast.Store):
            continue
        if expr_is_constant(n, env) or _INSTRUCTION_CONST_RE.match(n.id):
            continue
        if n.id in params:
            found_param = True
        else:
            return False
    return found_param


# ── 외부 출처 ────────────────────────────────────────────────────────────────
# "동적으로 조립됐다"와 "외부 입력이 닿았다"는 다르다. 실측(2026-10-13 safe_check):
# 자리표시자·모듈 상수·DB 메타데이터로 조립한 SQL 36건이 전부 '확인됨(데이터 흐름 추적)'
# 으로 차단됐지만 외부 입력이 닿은 곳은 없었다. 여기서 말하는 출처는 공격자가 값을 정할
# 수 있는 자리뿐이다 — 요청(Flask/Django/FastAPI), 명령행 인자, 표준입력, 라우트 매개변수.
# 환경변수·설정 파일은 운영자 통제라 넣지 않는다.
_SOURCE_PY_RE = re.compile(
    r"^(?:request\.(?:args|form|json|values|data|files|headers|cookies|get_json|get_data|GET|POST|body|query_params|path_params)"
    r"|req\.(?:args|form|json|body|query|params|headers|cookies)"
    r"|sys\.argv|sys\.stdin|input|raw_input|flask\.request|self\.request\.(?:args|form|json|data|GET|POST))$",
)
_ROUTE_DECORATOR_RE = re.compile(r"(?:^|\.)(?:route|get|post|put|patch|delete|api_route|websocket)$")


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _expr_mentions_source(node: ast.AST) -> bool:
    """식 안에 외부 출처(요청·argv·stdin)가 **직접** 있는가."""
    for n in ast.walk(node):
        if isinstance(n, (ast.Attribute, ast.Name)):
            d = _dotted(n)
            if d and _SOURCE_PY_RE.match(d):
                return True
        if isinstance(n, ast.Call):
            d = _dotted(n.func)
            if d and _SOURCE_PY_RE.match(d):
                return True
    return False


def _load_names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and not isinstance(n.ctx, ast.Store)}


def _reaches_source(node: ast.AST, sourced: set[str]) -> bool:
    return _expr_mentions_source(node) or bool(_load_names(node) & sourced)


_TOOL_DECORATOR_RE = re.compile(r"(?:^|\.)(?:tool|function_tool|call_tool|register_tool|mcp_tool|ai_function|kernel_function)$")
_TOOL_REGISTRY_NAME_RE = re.compile(r"(?i)^_?(?:tools?|tool_?(?:list|map|registry|specs?|defs?|schemas?)|functions|function_?(?:list|map|specs?|schemas?)|available_?tools)$")
_TOOL_FUNCS: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar("gvskb_tool_funcs", default=frozenset())
_NON_DATA_PARAMS = frozenset({"self", "cls", "con", "conn", "connection", "cur", "cursor", "db", "session", "engine", "ctx", "context"})


def _tool_functions(tree: ast.AST) -> frozenset[str]:
    """LLM·MCP 도구로 노출된 함수 이름 — 그 매개변수는 **모델이 정한 값**이다.

    실측(2026-10-13 safe_check `analyzer/rep20/v4_tools.py`): `TOOLS = [{"name": "run_sql", …}]`
    로 에이전트에 노출된 `run_sql(con, sql)` 이 받은 SQL 을 정규식 검사만 하고 실행했다.
    근거 정책 뒤로 이 진짜 위험이 '유력·검토'로 내려갔다 — 매개변수를 출처로 몰랐기 때문이다.
    두 가지를 인정한다: 도구 데코레이터(`@tool`·`@mcp.tool()`·`@function_tool` …)와,
    모듈 수준 도구 목록(`TOOLS`·`tool_map`·`FUNCTIONS` …)에 이름(`"name": "fn"`)이나 함수 자체로 실린 것.
    """
    names: set[str] = set()
    defs: set[str] = set()
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.add(node.name)
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if _TOOL_DECORATOR_RE.search(_dotted(target) or ""):
                    names.add(node.name)
    for node in getattr(tree, "body", []):
        targets: list[ast.AST] = []
        value = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None or not any(isinstance(t, ast.Name) and _TOOL_REGISTRY_NAME_RE.match(t.id) for t in targets):
            continue
        for n in ast.walk(value):
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and k.value in ("name", "function") \
                            and isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value in defs:
                        names.add(v.value)
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value in defs \
                            and isinstance(v, ast.Name) and v.id == k.value:
                        names.add(k.value)
            if isinstance(n, ast.Name) and n.id in defs:
                names.add(n.id)
    return frozenset(names)


def _route_params(fn: ast.AST) -> set[str]:
    """`@app.route("/u/<name>")`·`@router.get(...)` 핸들러의 매개변수는 요청에서 온다."""
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return set()
    if fn.name in _TOOL_FUNCS.get():
        a = fn.args
        return {p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)} - _NON_DATA_PARAMS
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        d = _dotted(target) or ""
        if _ROUTE_DECORATOR_RE.search(d):
            a = fn.args
            return {p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)} - {"self", "cls"}
    return set()


def _process_scope(
    stmts: list[ast.stmt],
    tainted: set[str],
    hits: list[tuple, ...] | list,
    source_lines: list[str],
    env: ConstEnv | None = None,
    literal_params: dict[str, set[str]] | None = None,
    scope_params: set[str] | None = None,
    sourced: set[str] | None = None,
) -> None:
    literal_params = literal_params or {}
    scope_params = scope_params or set()
    sourced = set() if sourced is None else sourced
    if env is None:
        env = collect_constants(stmts)
    for stmt in stmts:
        # Nested def/class opens a new scope; its parameters start untainted.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            proven = literal_params.get(getattr(stmt, "name", ""), set())
            inner = _scope_env(stmt.body, proven)
            _inherit_outer_constants(inner, env, stmt)
            inner_params: set[str] = set()
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = stmt.args
                inner_params = {
                    p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)
                } - proven
            _process_scope(stmt.body, set(), hits, source_lines, inner,
                           literal_params, inner_params, sourced=_route_params(stmt))
            continue
        # 1) sinks read the taint state established by earlier statements.
        for call in _sink_calls(stmt):
            arg0 = call.args[0]
            reaches = (isinstance(arg0, ast.Name) and arg0.id in tainted) or \
                _expr_builds_dynamic_sql(arg0, tainted, env) or \
                (isinstance(arg0, ast.Name) and arg0.id in sourced)   # 쿼리 전체가 외부 입력(LLM 도구 인자 등)
            if not reaches:
                continue
            rule_id = _sql_rule_for(arg0)
            line_no = call.lineno
            src = source_lines[line_no - 1] if 1 <= line_no <= len(source_lines) else ""
            if _is_ignored(src, rule_id):
                continue
            # 근거 강도: 외부 출처(요청·argv·stdin·라우트 매개변수)가 이 식에 닿았으면
            # '확인됨', 동적으로 조립됐을 뿐 출처를 못 봤으면 '유력'. 매개변수만 동적인 것도 유력.
            # 룰이 상한을 두면(DDL 은 조립 사실만 확인 — likely) 그 위로 올리지 않는다.
            cap = _CONFIDENCE_BY_RULE.get(rule_id, "confirmed")
            conf = "confirmed" if cap == "confirmed" and _reaches_source(arg0, sourced) else "likely"
            hits.append((rule_id, line_no, redact_evidence(src), conf))
        # 1b) LLM prompt-injection sinks: a dynamically-built prompt string
        #     reaching an LLM SDK call (OWASP LLM01).
        for call in _llm_sink_calls(stmt):
            if not _call_passes_dynamic_prompt(call, tainted):
                continue
            line_no = call.lineno
            src = source_lines[line_no - 1] if 1 <= line_no <= len(source_lines) else ""
            if _is_ignored(src, "GOV-LLM-PROMPT-INJECTION-001"):
                continue
            # SQL 과 같은 규약: 동적 부분이 매개변수뿐이면 출처를 추적한 적이 없다.
            args_root = ast.Tuple(elts=list(call.args) + [kw.value for kw in call.keywords])
            conf = "confirmed" if _reaches_source(args_root, sourced) else "likely"
            hits.append(("GOV-LLM-PROMPT-INJECTION-001", line_no, redact_evidence(src), conf))
        # 2) recurse into compound bodies with the same (flow-insensitive) taint.
        if isinstance(stmt, (ast.For, ast.AsyncFor)) and _reaches_source(stmt.iter, sourced):
            sourced |= _load_names(stmt.target) | {n.id for n in ast.walk(stmt.target) if isinstance(n, ast.Name)}
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None and _reaches_source(item.context_expr, sourced):
                    sourced |= {n.id for n in ast.walk(item.optional_vars) if isinstance(n, ast.Name)}
        for body in _sub_statement_bodies(stmt):
            _process_scope(body, tainted, hits, source_lines, env, literal_params, scope_params, sourced)
        # 3) update taint from this statement's assignment (post-use).
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and stmt.value is not None:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            names = {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}
            if _reaches_source(stmt.value, sourced) or (isinstance(stmt, ast.AugAssign) and names & sourced):
                sourced |= names
            elif not isinstance(stmt, ast.AugAssign):
                sourced -= names          # 다른 값으로 덮어쓰면 출처가 끊긴다
        if isinstance(stmt, ast.Assign):
            is_dyn = _expr_builds_dynamic_sql(stmt.value, tainted, env)
            # `ph = ",".join("?" * n)` · `clause = f"AND x IN ({ph})"` — 이 이름은 뒤에서 상수처럼 쓰인다.
            is_ph = _is_placeholder_expr(stmt.value, env)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    (tainted.add if is_dyn else tainted.discard)(target.id)
                    if is_ph:
                        env.names.add(target.id)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            (tainted.add if _expr_builds_dynamic_sql(stmt.value, tainted, env) else tainted.discard)(stmt.target.id)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            if _expr_builds_dynamic_sql(stmt.value, tainted, env) or (
                isinstance(stmt.value, (ast.Name, ast.Call, ast.Subscript, ast.Attribute))
                and not expr_is_constant(stmt.value, env)
            ):
                tainted.add(stmt.target.id)


def _scan_taint_flows(tree: ast.AST, source_lines: list[str]) -> list[tuple[str, int, str]]:
    """Return ``(rule_id, line_no, evidence)`` for tainted SQL and LLM-prompt sinks.

    A single scope walk feeds both flows: the same dynamically-built-string taint
    that catches multi-line SQL injection also catches a prompt assembled by
    concatenation that reaches an LLM SDK call (prompt injection)."""
    hits: list[tuple[str, int, str]] = []
    # 모듈 전체를 먼저 훑어 '호출부가 전부 리터럴인 매개변수'를 증명해 둔다 —
    # 스코프 안만 보는 상수 판정으로는 매개변수의 출처를 알 수 없다.
    token = _PLACEHOLDER_FUNCS.set(_placeholder_functions(tree))
    tool_token = _TOOL_FUNCS.set(_tool_functions(tree))
    try:
        _process_scope(
            getattr(tree, "body", []), set(), hits, source_lines,
            literal_params=literal_only_parameters(tree),
        )
    finally:
        _TOOL_FUNCS.reset(tool_token)
        _PLACEHOLDER_FUNCS.reset(token)
    return hits


def _placeholder_functions(tree: ast.AST) -> frozenset[str]:
    """모든 ``return`` 이 자리표시자 확장인 모듈 함수 이름 — `_ph(codes)` 호출도 자리표시자다.

    실측(2026-10-13 safe_check `soosiro_mcp_server.py`): `def _fact_placeholders(xs): return
    ",".join("?" * len(xs))` 를 9곳의 f-string 이 썼고 전부 "확인된 SQL 삽입"이 됐다.
    """
    out: set[str] = set()
    for node in getattr(tree, "body", []):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
        if returns and all(r.value is not None and _is_placeholder_expr(r.value) for r in returns):
            out.add(node.name)
    return frozenset(out)


def _looks_like_python(filename: str, language: str | None) -> bool:
    if language and language.lower() in {"python", "py"}:
        return True
    return filename.endswith(".py") or filename.endswith(".pyw")


# 판정 근거 강도 — AST 엔진이 발행하는 룰별 기본값.
# confirmed: 값의 흐름(테인트)이나 문장 구조를 실제로 확인한 것.
# likely   : 구조 분석 기반이지만 문맥(의도)까지는 단정하지 못하는 것.
_CONFIDENCE_BY_RULE: dict[str, str] = {
    # 같은 스코프 안에서 대입을 따라가 조립을 확인한 동적 SQL.
    # **주의**: 동적 부분이 함수 매개변수뿐이면 출처가 스코프 밖이라 추적한 적이
    # 없다. 그런 발견은 여기 값이 아니라 `likely` 로 내려 보낸다
    # (_dynamic_part_is_a_parameter). 예전에는 구분 없이 confirmed 를 찍어
    # "데이터 흐름 추적"을 하지 않고도 했다고 말하고 있었다.
    "GOV-SQL-INJECTION-001": "confirmed",
    "GOV-LLM-PROMPT-INJECTION-001": "confirmed",
    # DDL 은 조립 사실만 확인했을 뿐, 값이 외부 입력인지는 사람이 봐야 한다.
    "GOV-SQL-DDL-DYNAMIC-001": "likely",
    # 탈출 경로·대기 부재는 구조로 확인했으나 '의도된 상주'일 여지가 남는다.
    "KISA-PY-TIME-02": "likely",
}


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

        # Precise call-site hits + multi-line taint hits (SQL + LLM) share one pipeline.
        all_hits = (
            visitor.hits
            + _scan_taint_flows(tree, visitor.source_lines)
            + _scan_infinite_loops(tree, visitor.source_lines)
        )

        findings: list[Finding] = []
        for hit in all_hits:
            # 3-튜플(룰별 기본 근거) 과 4-튜플(현장에서 판정한 근거)을 함께 받는다.
            rule_id, line_no, evidence = hit[0], hit[1], hit[2]
            confidence = hit[3] if len(hit) > 3 else _CONFIDENCE_BY_RULE.get(rule_id, "likely")
            rule = lookup_rule(rule_id)
            if rule is None:
                continue  # rule not loaded (e.g. testing with empty repo)
            if categories and rule["category"] not in categories:
                continue
            findings.append(build_finding(
                rule, filename=filename, line_no=line_no,
                evidence=evidence, engine=self.name,
                confidence=confidence,
            ))
        return findings


# ---------------------------------------------------------------------------
# 무한 반복문(KISA-PY-TIME-02) — 줄 단위 regex 는 `while True:` 만 보고 본문을
# 못 본다. 실측에서 정상 코드가 전부 걸렸다:
#   · `while True: _backup(); time.sleep(24*3600)`  → 의도된 백그라운드 스케줄러
#   · `while True: code = token(); if not dup: break` → 재시도 후 탈출
# 그래서 **본문에 탈출 경로도 없고 대기(sleep)도 없는** 진짜 busy-loop 만
# 남긴다. 탈출 판정은 이 while 문에 실제로 적용되는 것만 센다(중첩 루프의
# break 는 바깥 while 을 끝내지 못하므로 세지 않는다).
# ---------------------------------------------------------------------------

_SLEEP_RE = re.compile(r"(?:^|\.)(?:sleep|wait|join|select|poll|recv|accept)$")


def _stmts_for_this_loop(body: list[ast.stmt]) -> list[ast.stmt]:
    """이 루프에 직접 속한 문장들 — 중첩 루프·함수 정의 안쪽은 제외한다."""
    out: list[ast.stmt] = []
    stack = list(body)
    while stack:
        s = stack.pop()
        out.append(s)
        if isinstance(s, (ast.For, ast.AsyncFor, ast.While,
                          ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue      # 별도 루프/스코프 — 여기 break 는 바깥을 끝내지 않는다
        for fld in ("body", "orelse", "finalbody"):
            blk = getattr(s, fld, None)
            if isinstance(blk, list):
                stack.extend(blk)
        for h in getattr(s, "handlers", []) or []:
            if isinstance(h, ast.ExceptHandler):
                stack.extend(h.body)
    return out


def _loop_has_exit(node: ast.While) -> bool:
    """이 while 을 벗어날 수 있는 경로가 있는가(break/return/raise)."""
    for s in _stmts_for_this_loop(node.body):
        if isinstance(s, (ast.Break, ast.Return, ast.Raise)):
            return True
    # return/raise 는 중첩 블록 안이라도 함수를 벗어나므로 전체를 한 번 더 본다.
    for s in node.body:
        for n in ast.walk(s):
            if isinstance(n, (ast.Return, ast.Raise)):
                return True
    return False


def _loop_has_wait(node: ast.While) -> bool:
    """본문에 대기(sleep/wait/poll)가 있는가 — 의도된 상주 루프 신호."""
    for s in node.body:
        for n in ast.walk(s):
            if isinstance(n, ast.Call):
                chain = _attr_chain(n.func) if isinstance(n.func, ast.Attribute) else (
                    n.func.id if isinstance(n.func, ast.Name) else None
                )
                if chain and _SLEEP_RE.search(chain):
                    return True
    return False


def _is_literal_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _scan_infinite_loops(tree: ast.AST, source_lines: list[str]) -> list[tuple[str, int, str]]:
    """탈출 경로도 대기도 없는 ``while True:`` 만 보고한다."""
    hits: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.While) and _is_literal_true(node.test)):
            continue
        if _loop_has_exit(node) or _loop_has_wait(node):
            continue
        line_no = node.lineno
        src = source_lines[line_no - 1] if 1 <= line_no <= len(source_lines) else ""
        if _is_ignored(src, "KISA-PY-TIME-02"):
            continue
        hits.append(("KISA-PY-TIME-02", line_no, redact_evidence(src)))
    return hits


def python_ast_parsed(code: str, filename: str, language: str | None) -> bool:
    """이 입력을 AST 엔진이 실제로 분석했는가(= regex 예비 수단이 불필요한가)."""
    if not _looks_like_python(filename, language):
        return False
    try:
        ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    return True


def supported_rule_ids() -> Iterable[str]:
    """Rule IDs this adapter can emit. Useful for status_for_mcp."""
    return (
        "KISA-PY-INPUT-02", "KISA-PY-INPUT-05", "KISA-PY-SEC-04", "KISA-PY-CODE-03",
        "KISA-PY-TIME-02",
        "GOV-SQL-INJECTION-001", "GOV-SQL-DDL-DYNAMIC-001", "GOV-LLM-PROMPT-INJECTION-001",
    )
