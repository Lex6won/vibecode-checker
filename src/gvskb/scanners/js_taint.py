"""JS/TS 다줄 taint 스캐너 — "윗줄에서 조립, 아랫줄에서 실행" 격차 해소.

regex 엔진은 한 줄 안에서 조립과 sink가 함께 있어야 잡는다. 그러나 AI 생성
JS 코드의 흔한 형태는::

    const q = "SELECT * FROM users WHERE name = '" + name + "'";  // 조립
    db.query(q);                                                   // 실행 ← 여기서 발화

의존성 없이(라인 기반 변수추적) 동작하도록 설계했다 — 망분리 공공 PC에
tree-sitter 같은 네이티브 휠을 반입시키지 않기 위한 의도적 선택이다. 파싱이
아니라 휴리스틱이므로 **오염 판정은 좁게** 잡아 FP=0 원칙을 지킨다.

SQL·eval sink (변경 없음)
-------------------------
- 오염: 문자열 리터럴과 식별자의 ``+`` 결합, 또는 ``${...}`` 템플릿 리터럴
- 해제: 순수 상수 재할당, ``DOMPurify.sanitize(...)`` 정화
- sink: ``eval/Function(v)`` → KISA-JS-INPUT-02 · ``.query/.execute(v)`` → KISA-JS-INPUT-01

HTML sink — 출처 4단계 (2026-09-18, 실측 999건 사례)
----------------------------------------------------
실측(공공 업무 앱, 발견 999건)에서 ``innerHTML`` 873건 중 817건이 "패턴만 일치"
차단이었고, 그중 211건은 **상수 문자열 대입**, 대다수는 프로젝트 자체 정화 함수
``esc()`` 를 거친 템플릿이었다. 진짜 저장형 XSS 한 건(``f.note``)은 그 873건
안에 **있었지만 구분되지 않았다** — 미탐이 아니라 구분 없는 과탐이 문제였다.

그래서 HTML sink 는 "${} 가 있으면 오염" 대신 값의 **출처**를 네 단계로 나눈다::

    CONST      보간·결합 없는 상수                → 발견 없음(주입할 값이 없다)
    SANITIZED  모든 보간이 정화 호출로 감싸임      → regex 발견을 warn 으로 낮춤(추론)
    TAINTED    외부 출처(location·req.body·입력값…) → js-taint 발견 · 차단
    UNKNOWN    출처를 추적하지 못함               → regex 발견을 warn(정밀 검토)으로

UNKNOWN 을 차단에서 내리는 것은 **이 엔진이 실제로 그 sink 를 보고 출처를 찾지
못했을 때만**이다. 엔진이 돌지 않았거나(실패) 모르는 sink 모양이면 regex 차단이
그대로 남는다(fail-closed). 정화 함수는 이름이 아니라 **본문**으로 인정한다
(``html_sink_context.ProjectSanitizers``) — ``sanitizeMaybe(h){return h.trim()}``
같은 이름만 정화인 함수는 인정하지 않는다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..schema import Finding
from .base import ScannerAdapter
from .regex_scanner import InlineIgnores, build_finding, lookup_rule, redact_evidence

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

# sink → 재사용할 기존 룰 ID (SQL·eval 은 종전과 같다)
_EVAL_SINK = re.compile(r"\b(?:eval|Function)\s*\(\s*([A-Za-z_$][\w$]*)\s*[\),]")
_SQL_SINK = re.compile(r"\.\s*(?:query|execute)\s*\(\s*([A-Za-z_$][\w$]*)\s*[\),]")
_SINKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_EVAL_SINK, "KISA-JS-INPUT-02"),
    (_SQL_SINK, "KISA-JS-INPUT-01"),
)

_HTML_RULE_ID = "KISA-JS-INPUT-04"
# 분류기를 돌릴 가치가 있는 파일인가 — sink 토큰이 하나도 없으면 건너뛴다(성능 가드).
_HTML_SINK_HINT_RE = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write|\.html\s*\(")

# ── HTML sink 출처 분류 ──────────────────────────────────────────────────────
CONST, SANITIZED, TAINTED, UNKNOWN = "const", "sanitized", "tainted", "unknown"
UNPARSED = "unparsed"       # 식을 읽지 못함 — 판정을 내지 않는다(regex 차단 유지)

# 외부 출처 — 공격자가 값을 정할 수 있는 자리. 브라우저와 Node 양쪽. 서버 응답
# (fetch·axios·res.data)도 넣는다: 저장형 XSS 는 바로 그 경로로 들어온다(실측 f.note).
_SOURCE_RE = re.compile(
    r"\blocation\s*\.\s*(?:search|hash|href|pathname)\b|\bwindow\s*\.\s*location\b"
    r"|\bdocument\s*\.\s*(?:URL|referrer|cookie)\b|\bwindow\s*\.\s*name\b"
    r"|\bURLSearchParams\b|\.searchParams\s*\.\s*get\s*\("
    r"|\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies)\b"
    r"|\bctx\s*\.\s*request\b"
    r"|\.value\b|\bprompt\s*\("
    r"|\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\("
    r"|\b(?:event|e|ev|msg)\s*\.\s*data\b|\b(?:res|resp|response)\s*\.\s*data\b"
    r"|\bJSON\s*\.\s*parse\s*\(|\.responseText\b|\b(?:res|resp|response|r)\s*\.\s*(?:json|text)\s*\(\s*\)"
    r"|\bawait\s+(?:fetch|axios)\b|\bfetch\s*\(|\baxios\s*[.(]"
    r"|\breader\s*\.\s*result\b|\bFileReader\b|\bdecodeURIComponent\s*\(|\batob\s*\("
    r"|\.(?:textContent|innerText)\b(?!\s*=[^=])",
)
# 이름이 "입력값"이라고 말하는 식별자 — 개발자가 스스로 붙인 표지다. 출처를 못
# 찾았을 때 이 이름이면 UNKNOWN 이 아니라 TAINTED(유력)로 본다. `html`·`data`·
# `content` 같은 일반 이름은 넣지 않는다 — 실측 사례의 정상 템플릿 변수들이다.
_TAINTED_NAME_RE = re.compile(
    r"(?i)^(?:[\w$]*?)(?:user\w*|input\w*|untrusted\w*|raw\w*|llm\w*|model_?output|prompt\w*"
    r"|payload|params?|query|body|req|request)$",
)
# HTML 이 될 수 없는 값(숫자·길이·불리언) — 정화 없이도 안전.
_SAFE_EXPR_RE = re.compile(
    r"^(?:\d+(?:\.\d+)?|true|false|null|undefined|[\w$.]+\s*\.\s*length"
    r"|Number\s*\([^()]*\)|parseInt\s*\([^()]*\)|parseFloat\s*\([^()]*\)|Math\s*\.\s*\w+\s*\([^()]*\)"
    r"|[\w$.]+\s*\.\s*toFixed\s*\([^()]*\)|[\w$.]+\s*\.\s*toLocaleString\s*\([^()]*\))"
    r"(?:\s*[+\-*/%]\s*(?:\d+|[\w$.]+\s*\.\s*length))*$",
)
# 문자열 리터럴만 있는 삼항: cond ? 'a' : "b"
_LITERAL_TERNARY_RE = re.compile(
    r"""^[^?]+\?\s*(['"])(?:(?!\1).)*\1\s*:\s*(['"])(?:(?!\2).)*\2\s*$""",
)
# 여러 줄 템플릿을 따라갈 상한 — 실측 최장 템플릿은 수십 줄이었다.
_TEMPLATE_MAX_LINES = 400
_FUNC_BODY_MAX_LINES = 200

# HTML sink 모양 — 인자 식을 뽑아 분류한다. JSX `dangerouslySetInnerHTML` 은
# 이 범위 밖이다(그쪽은 html_sink_context 가 헬퍼 본문을 본다).
_HTML_ASSIGN_SINK = re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*(\+?=)(?!=)\s*(.*)$")
_HTML_CALL_SINK = re.compile(
    r"(?:\.insertAdjacentHTML\s*\(\s*['\"][A-Za-z]+['\"]\s*,\s*|\bdocument\s*\.\s*write(?:ln)?\s*\(\s*"
    r"|\$\([^)]*\)\s*\.\s*html\s*\(\s*)(.*)$",
)
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*\(([^)]*)\)|\(([^)]*)\)\s*=>|([A-Za-z_$][\w$]*)\s*=>))",
)
_RETURN_RE = re.compile(r"^\s*return\s+(.*)$")
# 컬렉션 순회에서 요소 변수는 컬렉션의 출처를 물려받는다: rows.map(r => …) · for (const m of MEMBERS)
# 첫 그룹은 멤버 사슬의 **뿌리**다(`data.files.map(f => …)` → data). 바로 앞 이름(files)만
# 잡으면 fetch 응답 변수의 출처가 순회 변수로 이어지지 않는다(적대적 검증 2026-09-18).
_CALLBACK_BIND_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]]*\])*?"
    r"\s*\.\s*(?:map|forEach|flatMap|filter|some|every|find|reduce)\s*\(\s*(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)",
)
_FOR_OF_RE = re.compile(r"\bfor\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+([A-Za-z_$][\w$]*)")
_STRING_LITERAL_RE = re.compile(r"""^(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")$""", re.S)
_PASSTHROUGH_CALLS = {"String", "str", "trim", "toString"}
_NUMERIC_CALLS = {"Number", "parseInt", "parseFloat", "Boolean"}


@dataclass
class SinkVerdict:
    state: str
    reason: str
    direct_source: bool = False     # sink 식 자체에 외부 출처가 있다(confirmed)


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


# ── 문자열 도구 ─────────────────────────────────────────────────────────────

def _find_backtick_end(text: str, start: int) -> int:
    """``start`` 부터 시작하는 템플릿 본문의 닫는 백틱 위치(중첩 ``${`…`}`` 인식). 없으면 -1."""
    depth = 0
    i, n = start, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if depth:
            if ch == "`":
                j = _find_backtick_end(text, i + 1)
                if j == -1:
                    return -1
                i = j + 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "{":
            depth = 1
            i += 2
            continue
        if ch == "`":
            return i
        i += 1
    return -1


def _split_template(body: str) -> list[str]:
    """템플릿 본문의 ``${…}`` 식들. 중첩 템플릿(``${rows.map(r => `…${x}…`)}``)은
    **안쪽 식만** 취한다 — HTML 이 되는 값은 안쪽 보간이지 바깥 배열이 아니다.
    정규식 ``\\$\\{[^}]+\\}`` 는 중첩에서 잘못 끊긴다."""
    exprs: list[str] = []
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "$" and i + 1 < n and body[i + 1] == "{":
            start = i + 2
            depth = 1
            j = start
            has_nested = False
            in_str: str | None = None
            while j < n and depth:
                c = body[j]
                if in_str:
                    if c == "\\":
                        j += 2
                        continue
                    if c == in_str:
                        in_str = None
                elif c in ("'", '"'):
                    in_str = c
                elif c == "`":
                    end = _find_backtick_end(body, j + 1)
                    if end == -1:
                        return exprs
                    exprs.extend(_split_template(body[j + 1:end]))
                    has_nested = True
                    j = end
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                j += 1
            if not has_nested:
                exprs.append(body[start:j - 1].strip())
            i = j
            continue
        i += 1
    return exprs


def _strip_call_wrapper(expr: str) -> tuple[str | None, str]:
    """``esc(x)`` → ('esc', 'x'). 호출 하나가 식 전체를 감싸야 한다.

    ``esc(a) + b`` 처럼 감싸지 않은 꼬리가 있으면 None — 감싸지 않은 부분이 주입 지점이다.
    """
    m = re.match(r"^\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(", expr)
    if not m:
        return None, expr
    open_idx = m.end() - 1
    depth = 0
    in_str: str | None = None
    i = open_idx
    while i < len(expr):
        ch = expr[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(expr, i + 1)
            if j == -1:
                return None, expr
            i = j
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                if expr[i + 1:].strip():
                    return None, expr
                return re.sub(r"\s+", "", m.group(1)), expr[open_idx + 1:i]
        i += 1
    return None, expr


def _split_statements(line: str) -> list[str]:
    """한 줄을 최상위 ``;``·``{``·``}`` 에서 문장으로 나눈다(문자열·템플릿·괄호 안은 건너뜀).

    `function load(){ html = await fetch(…); render(); }` 처럼 한 줄에 여러 문장이 있으면
    줄 머리 정규식은 안쪽 할당을 못 본다 — 적대적 검증(2026-09-18)에서 sink 앞의
    상수 할당만 보이고 나중 함수 안의 오염이 무시됐다.
    """
    out: list[str] = []
    depth = 0
    in_str: str | None = None
    start = 0
    i = 0
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(line, i + 1)
            if j == -1:
                out.append(line[start:])
                return [s for s in out if s.strip()]
            i = j
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch in ";{}" and depth <= 0:
            out.append(line[start:i])
            start = i + 1
        i += 1
    out.append(line[start:])
    return [s for s in out if s.strip()]


def _cut_at_statement_end(expr: str) -> str:
    """``html; }`` → ``html`` — 최상위 ``;`` 또는 짝 없는 ``}`` 앞까지."""
    depth = 0
    in_str: str | None = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(expr, i + 1)
            if j == -1:
                return expr
            i = j
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return expr[:i]
            depth -= 1
        elif ch == ";" and depth == 0:
            return expr[:i]
        i += 1
    return expr


def _split_concat(expr: str) -> list[str]:
    """최상위 ``+`` 로 나눈다(괄호·문자열·템플릿 안은 건너뜀)."""
    parts: list[str] = []
    depth = 0
    in_str: str | None = None
    start = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(expr, i + 1)
            if j == -1:
                break
            i = j
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0:
            if expr[i + 1:i + 2] in ("+", "="):
                i += 2
                continue
            parts.append(expr[start:i].strip())
            start = i + 1
        i += 1
    parts.append(expr[start:].strip())
    return [p for p in parts if p]


def _strip_trailing_call_paren(expr: str) -> str:
    """``document.write(html);`` 에서 뽑은 ``html);`` → ``html``."""
    expr = expr.strip().rstrip(";").strip()
    depth = 0
    in_str: str | None = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(expr, i + 1)
            if j == -1:
                break
            i = j
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return expr[:i].strip()
            depth -= 1
        i += 1
    return expr


# ── 분류기 ──────────────────────────────────────────────────────────────────

def _block_comment_mask(lines: list[str]) -> list[bool]:
    """줄이 ``/* … */`` 블록 주석 **안**에 있는가. 벤치마크 음성 대조군(`comments_tricky.js`)의
    주석 속 `element.innerHTML = userInput` 이 오염 발견으로 올라왔다(2026-09-18)."""
    mask: list[bool] = []
    inside = False
    for line in lines:
        starts_inside = inside
        i = 0
        while i < len(line):
            if inside:
                j = line.find("*/", i)
                if j == -1:
                    break
                inside = False
                i = j + 2
            else:
                j = line.find("/*", i)
                if j == -1:
                    break
                # 같은 줄에서 닫히는 주석은 줄 전체를 가리지 않는다
                k = line.find("*/", j + 2)
                if k == -1:
                    inside = True
                    break
                i = k + 2
        mask.append(starts_inside or (inside and line.strip().startswith("/*")))
    return mask


class _Classifier:
    def __init__(self, lines: list[str], project, local_defs: set[str], local_safe: set[str]) -> None:
        self.lines = lines
        self.project = project
        self.local_defs = local_defs
        self.local_safe = local_safe
        self.state: dict[str, tuple[str, bool]] = {}       # 식별자 → (state, direct_source)
        self.comment = _block_comment_mask(lines)
        self.func_returns = self._index_function_returns()

    def _is_comment_line(self, i: int) -> bool:
        return self.comment[i] or self.lines[i].strip().startswith(("//", "/*", "*"))

    def _accepts(self, name: str) -> bool:
        from .html_sink_context import sanitizer_name_ok
        return sanitizer_name_ok(name, self.local_defs, self.local_safe, self.project)

    # ── 함수 → return 식(한 홉) ────────────────────────────────────────────
    def _index_function_returns(self) -> dict[str, tuple[list[str], set[str]]]:
        """지역 함수 이름 → (return 식들, 매개변수 이름). sink 인자가 ``rowHtml(x)`` 일 때 한 홉 본다."""
        out: dict[str, tuple[list[str], set[str]]] = {}
        for i, line in enumerate(self.lines):
            if self.comment[i]:
                continue
            m = _FUNC_DEF_RE.match(line)
            if not m:
                continue
            name = m.group(1) or m.group(3)
            params_raw = m.group(2) or m.group(4) or m.group(5) or m.group(6) or ""
            params = {p.strip().split("=")[0].strip().lstrip(".") for p in params_raw.split(",") if p.strip()}
            returns: list[str] = []
            indent = len(line) - len(line.lstrip())
            # 한 줄 함수: `function f(a){ return `…`; }` — 정의 줄 자체의 return 도 본다.
            same = re.search(r"\{\s*return\s+(.*)$", line[m.end():])
            if same:
                expr, _c = self._collect_expr(same.group(1).rstrip().rstrip("}").rstrip().rstrip(";"), i)
                returns.append(expr)
            j = i + 1
            end = min(len(self.lines), i + _FUNC_BODY_MAX_LINES)
            while j < end:
                cur = self.lines[j]
                # 같거나 바깥 들여쓰기의 다음 정의 = 본문 끝(대략적 경계)
                if _FUNC_DEF_RE.match(cur) and (len(cur) - len(cur.lstrip())) <= indent:
                    break
                rm = _RETURN_RE.match(cur)
                if rm:
                    expr, consumed = self._collect_expr(rm.group(1), j)
                    returns.append(expr)
                    j += consumed
                    continue
                j += 1
            if name and returns:
                out[name] = (returns, params)
        return out

    def _collect_expr(self, head: str, idx: int) -> tuple[str, int]:
        """줄 idx 에서 시작한 식이 여러 줄 템플릿이면 닫힐 때까지 이어 붙인다. (식, 소비한 줄 수)."""
        first = head.find("`")
        if first == -1 or _find_backtick_end(head, first + 1) != -1:
            return head.rstrip(";").strip(), 1
        buf = [head]
        j = idx + 1
        while j < len(self.lines) and j - idx <= _TEMPLATE_MAX_LINES:
            buf.append(self.lines[j])
            joined = "\n".join(buf)
            if _find_backtick_end(joined, first + 1) != -1:
                return joined.rstrip(";").strip(), j - idx + 1
            j += 1
        return "\n".join(buf), j - idx      # 닫히지 않음 — 보수적으로 그대로

    def _set_state(self, name: str, state: str, direct: bool) -> None:
        """이름의 상태를 **합친다**(덮어쓰지 않는다) — 파일 전체 기준, 오염이 우선.

        줄 순서대로 덮어쓰면 뚫린다(적대적 검증 2026-09-18)::

            let html = '';                                   // CONST
            function render(){ el.innerHTML = html; }        // sink 가 먼저 나온다
            function load(){ html = await fetch(…).then(r => r.json()); render(); }

        sink 시점의 상태는 CONST 라 발견이 **삭제**됐다. 같은 파일에서 그 이름에 한 번이라도
        외부 값이 들어오면 오염으로 본다(TAINTED > UNKNOWN > SANITIZED > CONST).
        상수 재할당으로 오염을 해제하는 SQL 쪽 규칙은 여기 적용하지 않는다 — 이쪽은
        삭제(CONST)가 걸린 판정이라 보수적이어야 한다.
        """
        prev = self.state.get(name)
        if prev is None:
            self.state[name] = (state, direct)
            return
        merged = self._merge([SinkVerdict(prev[0], "", prev[1]), SinkVerdict(state, "", direct)])
        self.state[name] = (merged.state, prev[1] or direct)

    def _bind_iteration_vars(self, text: str) -> None:
        """``rows.map(r => …)`` 의 ``r`` 은 ``rows`` 의 출처를 물려받는다."""
        for m in _CALLBACK_BIND_RE.finditer(text):
            root, param = m.group(1), m.group(2)
            st = self.state.get(root)
            if st is not None:
                self._set_state(param, st[0], st[1])
            elif _TAINTED_NAME_RE.search(root):
                self._set_state(param, TAINTED, False)

    # ── 식 분류 ───────────────────────────────────────────────────────────
    def classify_expr(self, expr: str, depth: int = 0, params: set[str] | None = None) -> SinkVerdict:
        expr = expr.strip().rstrip(";").strip()
        if expr.startswith("(") and expr.endswith(")"):
            expr = expr[1:-1].strip()
        if expr in ("''", '""', "``"):
            return SinkVerdict(CONST, "상수")
        if not expr:
            # 값이 없다 = 이 줄에서 인자를 읽지 못했다(줄바꿈으로 넘긴 인자 등). 상수가 아니다.
            return SinkVerdict(UNPARSED, "인자를 읽지 못함")
        if depth > 6:
            return SinkVerdict(UNKNOWN, "식이 너무 깊음")
        if _STRING_LITERAL_RE.match(expr):
            return SinkVerdict(CONST, "상수 문자열")
        # 템플릿 리터럴
        if expr.startswith("`"):
            end = _find_backtick_end(expr, 1)
            if end == -1:
                return SinkVerdict(UNPARSED, "닫히지 않은 템플릿")
            self._bind_iteration_vars(expr[1:end])
            verdict = self._classify_parts(_split_template(expr[1:end]), depth, params)
            tail = expr[end + 1:].strip()
            if tail and tail[0] == "+":
                verdict = self._merge([verdict, self.classify_expr(tail[1:], depth + 1, params)])
            elif tail and not tail.startswith((";", ")", ".trim(", ".replace(")):
                verdict = SinkVerdict(UNKNOWN, "템플릿 뒤에 해석하지 못한 식")
            return verdict
        # 호출로 전체를 감쌈
        wrapper, inner = _strip_call_wrapper(expr)
        if wrapper:
            if self._accepts(wrapper):
                return SinkVerdict(SANITIZED, f"정화 호출 {wrapper}() 로 감쌈")
            base = wrapper.split(".")[0]
            last = wrapper.split(".")[-1]
            if last in _NUMERIC_CALLS and "." not in wrapper:
                return SinkVerdict(CONST, "숫자·불리언 변환값")
            if last in _PASSTHROUGH_CALLS:
                return self.classify_expr(inner, depth + 1, params)
            if base in self.func_returns and depth < 2:
                returns, fparams = self.func_returns[base]
                args = _split_args(inner)
                if any(self.classify_expr(a, depth + 1, params).state == TAINTED for a in args):
                    return SinkVerdict(TAINTED, f"{base}() 인자에 외부 출처가 있음")
                verdict = self._merge([self.classify_expr(r, depth + 1, fparams) for r in returns])
                verdict.reason = f"{base}() 반환식 — {verdict.reason}"
                return verdict
            if _SOURCE_RE.search(expr):
                return SinkVerdict(TAINTED, "외부 출처(URL·요청·입력값·응답)가 식에 직접 있음", direct_source=True)
            self._bind_iteration_vars(expr)
            if base in self.state and "." in wrapper:
                st = self.state[base]
                return SinkVerdict(st[0], f"변수 {base} 의 출처", st[1])
            if "." in wrapper and (params is None or base not in params) and _TAINTED_NAME_RE.search(base):
                return SinkVerdict(TAINTED, f"이름이 입력값을 뜻함({base})")
            return SinkVerdict(UNKNOWN, f"{wrapper}() 반환값 — 출처 추적 불가")
        # 결합
        if "+" in expr:
            parts = _split_concat(expr)
            if len(parts) > 1:
                return self._merge([self.classify_expr(p, depth + 1, params) for p in parts])
        # 메서드 사슬 속 템플릿 — `rows.map(r => `…${esc(r.a)}…`).join('')`. HTML 이 되는
        # 값은 안쪽 보간이지 바깥 배열이 아니다. 순회 변수는 컬렉션의 출처를 물려받는다.
        if "`" in expr:
            self._bind_iteration_vars(expr)
            inner: list[str] = []
            pos = 0
            while True:
                b = expr.find("`", pos)
                if b == -1:
                    break
                end = _find_backtick_end(expr, b + 1)
                if end == -1:
                    return SinkVerdict(UNPARSED, "닫히지 않은 템플릿")
                inner.extend(_split_template(expr[b + 1:end]))
                pos = end + 1
            return self._classify_parts(inner, depth, params)
        # HTML 이 될 수 없는 값, 리터럴 삼항
        if _SAFE_EXPR_RE.match(expr) or _LITERAL_TERNARY_RE.match(expr):
            return SinkVerdict(CONST, "HTML 이 될 수 없는 값")
        # 삼항은 두 가지(조건은 값이 아니다), 논리식(`a || ''`·`a ?? b`·`a && b`)은 모든 피연산자를 본다
        if " ? " in expr and " : " in expr:
            _cond, _, rest = expr.partition(" ? ")
            left, _, right = rest.rpartition(" : ")
            if left.strip() and right.strip():
                return self._merge([self.classify_expr(left, depth + 1, params),
                                    self.classify_expr(right, depth + 1, params)])
        if "||" in expr or "??" in expr or "&&" in expr:
            pieces = [p for p in re.split(r"\|\||\?\?|&&", expr) if p.strip()]
            if len(pieces) > 1:
                return self._merge([self.classify_expr(p, depth + 1, params) for p in pieces])
        if _SOURCE_RE.search(expr):
            return SinkVerdict(TAINTED, "외부 출처(URL·요청·입력값·응답)가 식에 직접 있음", direct_source=True)
        # 식별자(멤버 접근 포함)
        m = re.match(r"^([A-Za-z_$][\w$]*)(?:\s*[.\[(]|$)", expr)
        if m:
            root = m.group(1)
            if params is not None and root in params:
                return SinkVerdict(UNKNOWN, f"매개변수 {root} — 호출자에 따라 다름")
            st = self.state.get(root)
            if st is not None:
                return SinkVerdict(st[0], f"변수 {root} 의 출처", st[1])
            if _TAINTED_NAME_RE.search(root):
                return SinkVerdict(TAINTED, f"이름이 입력값을 뜻함({root})")
            return SinkVerdict(UNKNOWN, f"변수 {root} 의 출처를 찾지 못함")
        return SinkVerdict(UNKNOWN, "식 해석 불가")

    def _classify_parts(self, exprs: list[str], depth: int, params: set[str] | None) -> SinkVerdict:
        if not exprs:
            return SinkVerdict(CONST, "보간 없는 템플릿")
        return self._merge([self.classify_expr(e, depth + 1, params) for e in exprs])

    @staticmethod
    def _merge(verdicts: list[SinkVerdict]) -> SinkVerdict:
        if not verdicts:
            return SinkVerdict(CONST, "상수")
        for v in verdicts:
            if v.state == TAINTED:
                return v
        for v in verdicts:
            if v.state in (UNKNOWN, UNPARSED):
                return SinkVerdict(UNKNOWN, v.reason)
        if any(v.state == SANITIZED for v in verdicts):
            return SinkVerdict(SANITIZED, "모든 보간이 정화 호출 또는 상수")
        return SinkVerdict(CONST, "상수·안전한 값만 결합")

    # ── 줄 순회 ───────────────────────────────────────────────────────────
    def _sink_at(self, i: int) -> tuple[str, int] | None:
        """줄 i 가 HTML sink 면 (인자 식, 소비한 줄 수). 아니면 None."""
        line = self.lines[i]
        n = len(self.lines)
        m = _HTML_ASSIGN_SINK.search(line)
        call = None if m else _HTML_CALL_SINK.search(line)
        if not (m or call):
            return None
        raw = (m.group(2) if m else call.group(1)).strip()
        start = i
        if not raw and i + 1 < n:
            # `el.innerHTML =` 로 줄이 끝나고 값은 다음 줄 — 실측 dashboard.html:12
            start = i + 1
            raw = self.lines[start].strip()
        expr, used = self._collect_expr(raw, start)
        if call:
            expr = _strip_trailing_call_paren(expr)
        return _cut_at_statement_end(expr), (start - i) + used

    def _collect_states(self) -> None:
        """1차: 파일 전체의 할당·순회 바인딩으로 이름 → 상태를 모은다(합침, 덮어쓰기 아님).

        두 번 돈다 — 나중 줄의 변수를 참조하는 앞 줄의 할당이 첫 바퀴에서 UNKNOWN 으로
        남는 것을 두 번째 바퀴가 메운다. 상태는 합쳐지므로 바퀴가 늘어도 나빠지지 않는다.
        """
        n = len(self.lines)
        for _round in range(2):
            i = 0
            while i < n:
                line = self.lines[i]
                if self._is_comment_line(i):
                    i += 1
                    continue
                consumed = 1
                fo = _FOR_OF_RE.search(line)
                if fo:
                    st = self.state.get(fo.group(2))
                    if st is not None:
                        self._set_state(fo.group(1), st[0], st[1])
                sink = self._sink_at(i)
                if sink is not None:
                    i += sink[1]
                    continue
                a = _ASSIGN_RE.match(line)
                if a:
                    # 줄 머리의 할당 — 여러 줄 템플릿을 따라간다
                    name, rhs = a.group(1), a.group(3).strip()   # `=`·`+=` 모두 합침(덮어쓰기 없음)
                    rhs, consumed = self._collect_expr(rhs, i)
                    v = self.classify_expr(_cut_at_statement_end(rhs))
                    if v.state == UNPARSED:
                        v = SinkVerdict(UNKNOWN, v.reason)
                    self._set_state(name, v.state, v.direct_source)
                else:
                    # 한 줄 안의 문장들(`function f(){ html = …; }`) — 같은 줄 안에서만 본다
                    for stmt in _split_statements(line)[1:] if line.count("`") % 2 == 0 else []:
                        a2 = _ASSIGN_RE.match(stmt)
                        if not a2:
                            continue
                        v = self.classify_expr(a2.group(3).strip())
                        if v.state == UNPARSED:
                            v = SinkVerdict(UNKNOWN, v.reason)
                        self._set_state(a2.group(1), v.state, v.direct_source)
                i += consumed

    def run(self) -> dict[int, SinkVerdict]:
        self._collect_states()
        verdicts: dict[int, SinkVerdict] = {}
        i = 0
        n = len(self.lines)
        while i < n:
            if self._is_comment_line(i):
                i += 1
                continue
            sink = self._sink_at(i)
            if sink is None:
                i += 1
                continue
            expr, consumed = sink
            v = self.classify_expr(expr)
            if v.state != UNPARSED:          # 읽지 못한 것은 판정하지 않는다 — regex 차단이 남는다
                verdicts[i + 1] = v
            i += consumed
        return verdicts


def _split_args(inner: str) -> list[str]:
    """호출 인자를 최상위 쉼표로 나눈다."""
    args: list[str] = []
    depth = 0
    in_str: str | None = None
    start = 0
    i = 0
    while i < len(inner):
        ch = inner[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(inner, i + 1)
            if j == -1:
                break
            i = j
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(inner[start:i].strip())
            start = i + 1
        i += 1
    args.append(inner[start:].strip())
    return [a for a in args if a]


_memo: dict[tuple[int, int], dict[int, SinkVerdict]] = {}


def classify_html_sinks(code: str, project=None) -> dict[int, SinkVerdict]:
    """파일의 HTML sink 줄 → 출처 판정. scan_code 가 regex 발견 감쇄에 쓴다.

    같은 코드에 두 번 불리므로(어댑터 · 감쇄) 마지막 결과 하나를 기억한다.
    """
    from .html_sink_context import current_project, local_sanitizer_index
    if not _HTML_SINK_HINT_RE.search(code):
        return {}
    if project is None:
        project = current_project()
    key = (hash(code), id(project))
    cached = _memo.get(key)
    if cached is not None:
        return cached
    lines = code.splitlines()
    local_safe, _helpers, local_defs = local_sanitizer_index(lines, project)
    result = _Classifier(lines, project, local_defs, local_safe).run()
    _memo.clear()
    _memo[key] = result
    return result


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
        # JS 는 같은 줄 무시를 인정하지 않는다(정규식 리터럴과 나눗셈을 문맥 없이
        # 구분할 수 없어, 주석 위치 판정이 원리적으로 불안하다). 단독 주석 줄의
        # 지시만 본다 — 판정이 모호하지 않은 형태다.
        ignores = InlineIgnores(code, "javascript")
        for line_no, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "/*", "*")):
                continue  # 주석 줄 — 살아있는 코드가 아니다

            # 1) sink 검사 — 이 줄 이전까지의 오염 상태 기준
            for pattern, rule_id in _SINKS:
                m = pattern.search(line)
                if not m or m.group(1) not in tainted:
                    continue
                if ignores.suppresses(line_no, rule_id):
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

        # 3) HTML sink — 출처가 외부로 확인된 것만 이 엔진이 발행한다.
        rule = lookup_rule(_HTML_RULE_ID)
        if rule is not None and not (categories and rule["category"] not in categories):
            lines = code.splitlines()
            for line_no, verdict in classify_html_sinks(code).items():
                if verdict.state != TAINTED or ignores.suppresses(line_no, _HTML_RULE_ID):
                    continue
                f = build_finding(
                    rule, filename=filename, line_no=line_no,
                    evidence=redact_evidence(lines[line_no - 1]), engine=self.name,
                )
                findings.append(f.model_copy(update={
                    "confidence": "confirmed" if verdict.direct_source else "likely",
                    "why_it_matters": f.why_it_matters + f"\n\n**출처 추적:** {verdict.reason}",
                }))
        return findings


def supported_rule_ids() -> tuple[str, ...]:
    return ("KISA-JS-INPUT-01", "KISA-JS-INPUT-02", "KISA-JS-INPUT-04")
