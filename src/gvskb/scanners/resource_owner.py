"""자원을 **넘겨주는 자리**에는 `with` 를 요구할 수 없다.

`KISA-PY-CODE-02`(파일·DB연결·소켓을 with 없이 변수에 담음)는 정규식 룰이라
한 줄만 본다. 그래서 파이썬에서 가장 흔한 관용구 하나를 통째로 오탐한다::

    def _connect(path):
        conn = sqlite3.connect(path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn                      # ← 자원의 주인이 호출자로 넘어간다

    conn = _connect(path)
    try:
        ...
    finally:
        conn.close()                     # ← 해제는 여기서 한다

룰이 걱정하는 것은 *"예외가 나면 자원이 안 닫힌다"* 인데, 생성 함수는 애초에
`with` 를 쓸 수 없다 — 블록을 벗어나는 순간 닫혀서 반환값이 쓸모없어진다.
**해제 책임이 있는 곳에 요구해야 하는 규칙을, 책임이 없는 곳에 요구하고 있었다.**

그렇다고 발견을 지우지는 않는다. 호출자가 정말 닫는지는 이 자리에서 알 수 없다.
`low` 로 낮추고 **어디를 봐야 하는지**를 사유로 남긴다 — 실측(koica-reg-mcp)에서
호출부 둘 다 `try/finally` 로 닫고 있었지만, 그것은 사람이 확인한 사실이다.
"""

from __future__ import annotations

import ast

from ..schema import Decision, Finding, Severity

#: 이 관용구가 적용되는 룰. 자원 생성/해제 계열만 손댄다.
_RESOURCE_RULES = {"KISA-PY-CODE-02"}

_REASON = (
    "자원을 호출자에게 반환하는 생성 함수 — 이 자리에서는 with 를 쓸 수 없고 "
    "해제 책임은 호출부에 있습니다. 호출부가 close()/with 로 닫는지 확인하세요"
)


def _returned_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """이 함수가 밖으로 내보내는 이름들(중첩 함수의 return 은 세지 않는다)."""
    out: set[str] = set()
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue                      # 중첩 스코프는 그쪽의 일이다
        if isinstance(node, ast.Return) and node.value is not None:
            for n in ast.walk(node.value):
                if isinstance(n, ast.Name):
                    out.add(n.id)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _handoff_lines(code: str) -> set[int]:
    """자원을 만들고 **그대로 반환**하는 대입문의 줄 번호."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return set()

    lines: set[int] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        returned = _returned_names(fn)
        if not returned:
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target.id]
            else:
                continue
            if any(t in returned for t in targets) and node.lineno:
                lines.add(node.lineno)
    return lines


def attenuate_returned_resource_findings(
    findings: list[Finding], code: str, filename: str,
) -> list[Finding]:
    """생성 후 반환하는 자원의 `with` 미사용 지적을 low 로 낮춘다(삭제하지 않음)."""
    if not filename.endswith((".py", ".pyw")):
        return findings
    if not any(f.rule_id in _RESOURCE_RULES for f in findings):
        return findings

    handoff = _handoff_lines(code)
    if not handoff:
        return findings

    adjusted: list[Finding] = []
    for finding in findings:
        if (
            finding.rule_id not in _RESOURCE_RULES
            or finding.location.line not in handoff
            or finding.severity == Severity.low
        ):
            adjusted.append(finding)
            continue
        adjusted.append(finding.model_copy(update={
            "severity": Severity.low,
            "decision": Decision.warn if finding.decision == Decision.block else finding.decision,
            "requires_approval_to_bypass": False,
            "severity_adjusted": f"{finding.severity.value} → low · {_REASON}",
        }))
    return adjusted
