"""JS/TS 다줄 taint 스캐너 — "윗줄에서 조립, 아랫줄에서 실행" 격차 해소.

regex 엔진은 한 줄 안에서 조립과 sink가 함께 있어야 잡는다. 그러나 AI 생성
JS 코드의 흔한 형태는::

    const q = "SELECT * FROM users WHERE name = '" + name + "'";  // 조립
    db.query(q);                                                   // 실행 ← 여기서 발화

의존성 없이(라인 기반 변수추적) 동작하도록 설계했다 — 망분리 공공 PC에
tree-sitter 같은 네이티브 휠을 반입시키지 않기 위한 의도적 선택이다. 파싱이
아니라 휴리스틱이므로 **오염 판정은 좁게** 잡아 FP=0 원칙을 지킨다:

- 오염: 문자열 리터럴과 식별자의 ``+`` 결합, 또는 ``${...}`` 템플릿 리터럴
- 해제: 순수 상수 재할당, ``DOMPurify.sanitize(...)`` 정화
- sink: ``eval/Function(v)`` → KISA-JS-INPUT-02 · ``.query/.execute(v)`` →
  KISA-JS-INPUT-01 · ``.innerHTML/.outerHTML = v`` → KISA-JS-INPUT-04

파일 단위 추적(함수 스코프 미구분)이지만 재할당 해제가 있어, 실측 negative
(파라미터 바인딩·상수 쿼리·sanitize)에서 오탐이 나지 않음을 테스트로 고정한다.
"""
from __future__ import annotations

import re

from ..schema import Finding
from .base import ScannerAdapter
from .regex_scanner import _IGNORE_RE, build_finding, lookup_rule, redact_evidence

_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte")
_JS_LANGS = {"javascript", "typescript", "js", "ts"}

# 할당: [const|let|var] name = RHS   (== 비교는 제외)
_ASSIGN_RE = re.compile(
    r"^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(\+?=)(?![=>])\s*(.+?);?\s*$"
)

# 오염 RHS: '문자열' + 식별자  |  식별자 + '문자열'  |  `...${...}...`
_CONCAT_DYN = re.compile(
    r"""(['"][^'"]*['"]\s*\+\s*[A-Za-z_$])|([A-Za-z_$][\w$]*\s*\+\s*['"])"""
)
_TEMPLATE_DYN = re.compile(r"`[^`]*\$\{[^}]+\}[^`]*`")
# 순수 상수 RHS: 따옴표 문자열 하나 또는 ${} 없는 백틱 하나
_CONST_STR = re.compile(r"""^(?:(['"])(?:(?!\1).)*\1|`[^`$]*`)$""")

# sink → 재사용할 기존 룰 ID
_EVAL_SINK = re.compile(r"\b(?:eval|Function)\s*\(\s*([A-Za-z_$][\w$]*)\s*[\),]")
_SQL_SINK = re.compile(r"\.\s*(?:query|execute)\s*\(\s*([A-Za-z_$][\w$]*)\s*[\),]")
_HTML_SINK = re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$")
_SINKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_EVAL_SINK, "KISA-JS-INPUT-02"),
    (_SQL_SINK, "KISA-JS-INPUT-01"),
    (_HTML_SINK, "KISA-JS-INPUT-04"),
)


def _is_js(filename: str, language: str | None) -> bool:
    if language and language.lower() in _JS_LANGS:
        return True
    return filename.lower().endswith(_JS_SUFFIXES)


def _rhs_is_tainted(rhs: str, tainted: set[str]) -> bool:
    if "DOMPurify.sanitize" in rhs:
        return False  # 정화된 값
    if _CONCAT_DYN.search(rhs) or _TEMPLATE_DYN.search(rhs):
        return True
    # 오염 변수의 단순 전파: v2 = v1  /  v2 = v1 + "..."
    return any(re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted)


class JsTaintScanner(ScannerAdapter):
    """라인 기반 JS/TS 변수 taint — 다줄 SQL·eval·innerHTML 결합 탐지."""

    name = "js-taint"

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
        if not _is_js(filename, language):
            return []

        findings: list[Finding] = []
        tainted: set[str] = set()
        for line_no, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "/*", "*")):
                continue  # 주석 줄 — 살아있는 코드가 아니다

            # 1) sink 검사 — 이 줄 이전까지의 오염 상태 기준
            for pattern, rule_id in _SINKS:
                m = pattern.search(line)
                if not m or m.group(1) not in tainted:
                    continue
                if _IGNORE_RE.search(line):
                    ignore = _IGNORE_RE.search(line)
                    if ignore and (ignore.group(1) is None or ignore.group(1) == rule_id):
                        continue
                rule = lookup_rule(rule_id)
                if rule is None:
                    continue
                if categories and rule["category"] not in categories:
                    continue
                findings.append(build_finding(
                    rule, filename=filename, line_no=line_no,
                    evidence=redact_evidence(line), engine=self.name,
                ))

            # 2) 할당으로 오염 상태 갱신 (사용 후 갱신 — 자기 줄 sink는 regex가 담당)
            m = _ASSIGN_RE.match(line)
            if not m:
                continue
            name, op, rhs = m.group(1), m.group(2), m.group(3).strip()
            if op == "+=":
                if _rhs_is_tainted(rhs, tainted) or name in tainted:
                    tainted.add(name)
                continue
            if _CONST_STR.match(rhs):
                tainted.discard(name)  # 상수 재할당 → 해제
            elif _rhs_is_tainted(rhs, tainted):
                tainted.add(name)
            else:
                tainted.discard(name)  # 알 수 없는 값 — 보수적으로 비오염 처리(FP 방지)
        return findings


def supported_rule_ids() -> tuple[str, ...]:
    return ("KISA-JS-INPUT-01", "KISA-JS-INPUT-02", "KISA-JS-INPUT-04")
