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
from ..policy import split_lines
from dataclasses import dataclass

from ..schema import Finding
from .base import ScannerAdapter
from .regex_scanner import InlineIgnores, build_finding, lookup_rule, redact_evidence

_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte")
_JS_LANGS = {"javascript", "typescript", "js", "ts"}

# 할당: [const|let|var] name = RHS   (== 비교는 제외)
# 키워드 뒤에 공백을 요구한다 — `letter = location.hash` 의 이름이 `ter` 로 잡혔다(전면 점검 §3-3).
# `export const` · TS 타입 주석(`let html: string = …`)도 받는다.
_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)(?:\s*:\s*[\w$<>\[\]|&, .?]+?)?\s*(\+?=)(?![=>])\s*(.+?);?\s*$"
)
# `const { note, user: u } = req.body` — 구조분해 선언. 이름마다 RHS 의 출처를 물려받는다.
_DESTRUCT_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+?);?\s*$"
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
_HTML_SINK_HINT_RE = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|document\s*\.\s*write|\.html\s*\(")

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
# 키워드는 이름의 **시작** 또는 `_`·`$`·camelCase 경계 뒤에서만 센다 — `draw`(raw)·`tbody`(body)·
# `freq`(req)·`jQuery`(query) 가 부분 문자열로 걸려 '유력'을 과잉 생산했다(전면 점검 §3-3).
# `body`·`req` 는 접두어 없이 단독일 때만(`tableBody` 는 요소다).
_TAINTED_NAME_RE = re.compile(
    r"(?i)^(?!.*(?:cnt|count|len|length|idx|index|num|total|sum|size|width|height)$)(?!jquery$)"   # userHiddenCnt 는 숫자다(실측)
    r"(?:(?:[\w$]*?(?:[_$]|(?-i:(?<=[a-z0-9])(?=[A-Z]))))?"
    r"(?:user\w*|input\w*|untrusted\w*|raw\w*|llm\w*|model_?output|prompt\w*|payload|params?|query|req\w*|request\w*)"
    r"|body)$",
)
# HTML 이 될 수 없는 값(숫자·길이·불리언) — 정화 없이도 안전.
_SAFE_EXPR_RE = re.compile(
    r"^(?:\d+(?:\.\d+)?|true|false|null|undefined|[\w$.]+\s*\.\s*length"
    r"|Number\s*\([^()]*\)|parseInt\s*\([^()]*\)|parseFloat\s*\([^()]*\)|Math\s*\.\s*\w+\s*\([^()]*\)"
    r"|[\w$.]+\s*\.\s*toFixed\s*\([^()]*\)|[\w$.]+\s*\.\s*toLocaleString\s*\([^()]*\))"
    r"(?:\s*[+\-*/%]\s*(?:\d+|[\w$.]+\s*\.\s*length))*$",
)
# 이름이 숫자를 뜻하는 멤버 — `f.id`·`f.size_bytes`·`row.count`. 실측(2026-09-19)에서 fetch 응답의
# `${f.id}`·`_fmtSize(f.size_bytes)` 가 "확인된 XSS" 로 올라왔다(LLM 검증은 안전). 서버가 매기는
# 숫자 필드는 HTML 이 되지 않는다. `menu_id` 같은 `_id` 는 넣되 `user_id`·`login_id` 는 사용자 문자열일 수 있어 뺀다.
_NUMERIC_MEMBER_RE = re.compile(
    r"^(?!.*\.\s*(?:user|login|member|account|email|mail)_id$)"       # 사용자 문자열일 수 있는 _id 는 제외
    r"[\w$]+(?:\s*\.\s*[\w$]+)*\s*\.\s*(?:id|[a-z]+_id|size(?:_bytes)?|bytes|count|cnt|len|length|idx|index|num|total|qty"
    r"|quantity|amount|seq|year|month|day|page|limit|offset|rank|width|height|ts|timestamp"
    # 서버가 매기는 날짜·시각·프로세스 번호: `s.ended_at`·`row.reg_date`·`job.createdAt`·`d.pid`
    # (실측 2026-10-13 safe_check: XSS '확인됨' 차단 19건 중 7건이 이 값만 넣는 자리였다)
    r"|pid|ppid|port|date|time|datetime|[a-z]+_(?:at|date|time|dt|ts)|[a-z]+(?:At|Date|Time|Dt)"
    # camelCase 도 같은 뜻이다: `item.pageNumber`·`row.rowCount` (실측 2026-10-13 약관검색기)
    r"|[a-z]+(?:Number|Num|No|Count|Cnt|Index|Idx|Size|Length|Len|Total|Qty|Seq|Width|Height))$",
)
# 이름이 숫자를 뜻하는 **단독 식별자** — `pageNumber`·`rowCount`·`i`. 출처를 못 찾았을 때
# UNKNOWN 대신 CONST 로 본다. 입력값 이름(`userNumber`)은 먼저 TAINTED 로 잡히므로 여기 오지 않는다.
_NUMERIC_NAME_RE = re.compile(
    r"^(?:[ijkn]|idx|index|count|cnt|total|len|length|size|num"
    r"|[a-z]+(?:Number|Num|No|Count|Cnt|Index|Idx|Size|Length|Len|Total|Qty|Seq|Width|Height)"
    r"|[a-z]+_(?:number|num|no|count|cnt|index|idx|size|length|len|total|qty|seq|width|height))$",
)
# URL 인코딩 — 출력에 `< > " &` 가 나올 수 없어 HTML 본문·큰따옴표 속성에서는 주입이 되지 않는다.
# (`'` 는 남으므로 작은따옴표 속성은 사람이 본다 — 정화 추론과 같은 등급으로 둔다.)
_URL_ENCODE_CALLS = {"encodeURIComponent", "encodeURI"}
# `arr.map(esc)` · `arr.map(x => esc(x)).join('')` — 정화 함수를 인자로 넘기는 형태.
_MAP_SANITIZER_RE = re.compile(
    r"^(?P<recv>[^`]+?)\.\s*map\s*\(\s*(?:(?P<fn>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
    r"|\(?\s*(?P<param>[A-Za-z_$][\w$]*)\s*\)?\s*=>\s*(?P<body>[^{][^()]*\([^()]*\)))\s*\)"
    r"(?:\s*\.\s*join\s*\([^)]*\))?$",
)
# 식 전체가 길이·숫자 서식으로 끝난다: `pool.filter(…).length` · `(a/1024).toFixed(0)`
_NUMERIC_TAIL_RE = re.compile(r"\.\s*(?:length|size)$|\.\s*(?:toFixed|toLocaleString|toPrecision)\s*\([^()]*\)$")
# 문자열 리터럴만 있는 삼항: cond ? 'a' : "b"
_LITERAL_TERNARY_RE = re.compile(
    r"""^[^?]+\?\s*(['"])(?:(?!\1).)*\1\s*:\s*(['"])(?:(?!\2).)*\2\s*$""",
)
# 여러 줄 템플릿을 따라갈 상한 — 실측 최장 템플릿은 수십 줄이었다.
_TEMPLATE_MAX_LINES = 400
_FUNC_BODY_MAX_LINES = 200
# 선언의 RHS 가 다음 줄로 이어지는 끝 모양과, 그것을 따라갈 상한(선언 한 개는 짧다).
_DECL_CONTINUES = ("=>", "(", ",", "||", "&&", "+")
_DECL_CONT_MAX_LINES = 20
_LITERAL_CONT_MAX_LINES = 120

# HTML sink 모양 — 인자 식을 뽑아 분류한다. JSX `dangerouslySetInnerHTML` 은
# 이 범위 밖이다(그쪽은 html_sink_context 가 헬퍼 본문을 본다).
_HTML_ASSIGN_SINK = re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*(\+?=)(?!=)\s*(.*)$")
_HTML_CALL_SINK = re.compile(
    r"(?:\.insertAdjacentHTML\s*\(\s*['\"][A-Za-z]+['\"]\s*,\s*|\bdocument\s*\.\s*write(?:ln)?\s*\(\s*"
    r"|\$\([^)]*\)\s*\.\s*html\s*\(\s*)(.*)$",
)
# JSX sink — `dangerouslySetInnerHTML={{ __html: X }}`. 정규식 룰은 보지만 이 엔진에 sink 가 없어
# 상수·정화 분류를 한 번도 받지 못했다(실측 2026-10-15 챗봇: 고정 sampleData 44건 + 고정 스크립트 1건).
_JSX_HTML_SINK = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{")
_JSX_HTML_KEY_RE = re.compile(r"^\s*__html\s*:\s*")
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*\(([^)]*)\)|\(([^)]*)\)\s*=>|([A-Za-z_$][\w$]*)\s*=>))",
)
_RETURN_RE = re.compile(r"^\s*return\s+(.*)$")
# 컬렉션 순회에서 요소 변수는 컬렉션의 출처를 물려받는다: rows.map(r => …) · for (const m of MEMBERS)
# 첫 그룹은 멤버 사슬의 **뿌리**다(`data.files.map(f => …)` → data). 바로 앞 이름(files)만
# 잡으면 fetch 응답 변수의 출처가 순회 변수로 이어지지 않는다(적대적 검증 2026-09-18).
# ES5 `rows.map(function(f, i){ … })` 도 같다 — 예전 정규식은 매개변수 자리에서 단어 `function`
# 을 잡아 `f` 가 출처를 못 물려받았다(실측 2026-10-13 safe_check app.js: 추적 불가 23건, 한 줄
# `forEach(function(f){ h+=… })` 누적은 발견 자체가 사라짐).
_CALLBACK_BIND_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]]*\])*?"
    r"\s*\.\s*(?:map|forEach|flatMap|filter|some|every|find|reduce)\s*\(\s*(?:async\s*)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)"
    r"(?:\s*,\s*([A-Za-z_$][\w$]*))?",      # 두 번째 매개변수 = 인덱스(숫자) — 실측 `${i}` 가 출처 미상으로 남았다
)
# `(data.items || []).map((item) => …)` · `(rows ?? []).forEach(r => …)` — 빈 배열 폴백으로 감싼
# 컬렉션. 위 규칙은 괄호 앞의 이름을 못 잡아 요소가 출처를 물려받지 못했다(실측 2026-10-13).
_CALLBACK_BIND_PAREN_RE = re.compile(
    r"\(\s*([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]]*\])*\s*(?:\|\||\?\?)\s*\[\s*\]\s*\)"
    r"\s*\.\s*(?:map|forEach|flatMap|filter|some|every|find|reduce)\s*\(\s*(?:async\s*)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)"
    r"(?:\s*,\s*([A-Za-z_$][\w$]*))?",
)
_FOR_OF_RE = re.compile(r"\bfor\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+([A-Za-z_$][\w$]*)")
_STRING_LITERAL_RE = re.compile(r"""^(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")$""", re.S)
_PASSTHROUGH_CALLS = {"String", "str", "trim", "toString"}
_NUMERIC_CALLS = {"Number", "parseInt", "parseFloat", "Boolean"}
#: 숫자 서식 메서드 — 결과는 숫자 문자열이라 HTML 이 되지 않는다(`missing.toLocaleString("ko-KR")`).
_NUMERIC_FORMAT_CALLS = {"toFixed", "toLocaleString", "toPrecision"}
#: 산술식 — `+` 가 없는 `- * / %` 연산은 JS 에서 문자열을 만들지 못한다(`total - linked`).
_ARITHMETIC_RE = re.compile(r"^[\w$.\s()\[\]]+(?:[-*/%](?![/*])[\w$.\s()\[\]]+)+$")


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


def _paren_balance(text: str) -> int:
    """괄호 깊이(문자열·템플릿·주석 제외). 0 이면 닫혔다."""
    depth = 0
    in_str: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str or (in_str == "\n" and ch == "\n"):
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(text, i + 1)
            if j == -1:
                return 1
            i = j
        elif ch == "/" and text[i + 1:i + 2] == "/":
            in_str = "\n"                        # 줄 주석 — 줄 끝까지 건너뛴다
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        i += 1
    return depth


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


_FUNC_OPEN_HINT_RE = re.compile(r"(?:\)\s*(?::\s*[\w<>\[\]|, .]+)?|=>|\bfunction\b[^{]*|\bcatch\b[^{]*)\s*$")
# `if (…) {`·`for (…) {`·`} else {`·`try {` — 괄호로 끝나지만 **블록**이다. 함수로 보면 같은 함수 안
# 순서 규칙이 깨져 상수 재할당까지 차단됐다(전면 점검 §3-3).
_CONTROL_OPEN_RE = re.compile(
    r"(?:^\s*|[;{}]\s*|\)\s*)(?:else\s+)?(?:if|for|while|switch|with)\s*\([^{]*$|(?:^\s*|[;{}]\s*)(?:else|try|do|finally)\s*$"
)
_DECL_RE = re.compile(r"(?<![\w$.])(const|let|var)\s+([A-Za-z_$][\w$]*)")


class _ScopeMap:
    """줄 → 스코프 사슬. 중괄호를 세어 함수·블록 범위를 만든다(문자열·템플릿·주석은 건너뜀).

    변수 상태를 **범위 + 이름**으로 나누기 위한 것이다. 파일 전체를 한 이름으로 합치면
    `function bad(req){ let html = req.body.x }` 의 html 이 `function safe(){ const html = '…' }`
    의 html 을 오염시킨다(Codex 재현 2026-09-19). 반대로 줄 순서만 따르면 sink 뒤의
    다른 함수에서 일어나는 오염을 놓친다(적대적 검증 2026-09-18). 그래서:

    - 같은 함수 안에서만 쓰이는 변수 → **순서대로**(마지막 할당이 이긴다, `+=` 는 합침)
    - 다른 함수에서도 할당되는 변수(모듈 변수·클로저) → **모든 할당을 합침**(오염이 우선)
    """

    def __init__(self, lines: list[str], comment: list[bool]) -> None:
        self.chain: list[tuple[int, ...]] = []
        self.kind: dict[int, str] = {0: "function"}          # 모듈도 하나의 함수 범위로 본다
        self.parent: dict[int, int] = {0: 0}
        # 줄 **시작** 시점의 범위 — 선언은 여기에 묶는다. `const cfg = { title: location.hash }` 처럼
        # 같은 줄에서 연 `{` 안으로 선언이 들어가 뒤 줄에서 못 찾던 결함(전면 점검 §3-3).
        self.chain_start: list[tuple[int, ...]] = []
        stack = [0]
        next_id = 1
        tmpl_open = False
        for i, line in enumerate(lines):
            if comment[i] or line.strip().startswith(("//", "*")):
                self.chain.append(tuple(stack))
                self.chain_start.append(tuple(stack))
                continue
            scan = line
            if tmpl_open:
                # 여러 줄 템플릿 안 — 닫는 백틱 뒤의 중괄호만 센다. 예전엔 닫는 줄의 `}` 가 유실돼
                # 이후 함수가 전부 중첩으로 잡혔다.
                j = _find_backtick_end(line, 0)
                if j == -1:
                    self.chain.append(tuple(stack))
                    self.chain_start.append(tuple(stack))
                    continue
                scan = line[j + 1:]
                tmpl_open = False
            self.chain_start.append(tuple(stack))
            deepest = tuple(stack)
            braces, tmpl_open = self._braces(scan)
            for kind_hint, ch in braces:
                if ch == "{":
                    sid = next_id
                    next_id += 1
                    self.kind[sid] = "function" if kind_hint else "block"
                    self.parent[sid] = stack[-1]
                    stack.append(sid)
                    if len(stack) > len(deepest):
                        deepest = tuple(stack)
                elif len(stack) > 1:
                    stack.pop()
            self.chain.append(deepest)

    @staticmethod
    def _braces(line: str):
        """줄의 최상위 중괄호들을 (함수 여는 괄호인가, 문자) 순서로 낸다. (목록, 템플릿이 열린 채 끝났는가)."""
        out = []
        in_str: str | None = None
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
                    return out, True            # 여러 줄 템플릿 — 다음 줄들은 닫는 백틱까지 건너뛴다
                i = j
            elif ch == "/" and line[i + 1:i + 2] == "/":
                break
            elif ch == "{":
                before = line[:i].rstrip()
                is_func = (bool(_FUNC_OPEN_HINT_RE.search(before)) or before.endswith(("=>",))) \
                    and not _CONTROL_OPEN_RE.search(before)
                out.append((is_func, "{"))
            elif ch == "}":
                out.append((False, "}"))
            i += 1
        return out, False

    def func_of(self, sid: int) -> int:
        while self.kind.get(sid) != "function":
            sid = self.parent[sid]
        return sid


class _Classifier:
    def __init__(self, lines: list[str], project, local_defs: set[str], local_safe: set[str]) -> None:
        self.lines = lines
        self.project = project
        self.local_defs = local_defs
        self.local_safe = local_safe
        self.comment = _block_comment_mask(lines)
        self.scopes = _ScopeMap(lines, self.comment)
        # (범위 id, 이름) → [(줄 index, 연산, 상태, direct)] — 할당 이력
        self.vars: dict[tuple[int, str], list[tuple[int, str, str, bool]]] = {}
        self.cur = 0                                  # 지금 분류 중인 줄 index
        self.func_returns = self._index_function_returns()

    # ── 범위 인식 변수 상태 ───────────────────────────────────────────────
    def _declaring_scope(self, name: str, line: int, declared: bool, head: bool = False) -> int:
        """이름이 속한 범위. 선언이면 현재 범위, 아니면 사슬에서 찾고 없으면 모듈.

        ``head`` = 선언이 줄 **머리**에 있다 → 이 줄에서 연 `{`(객체 리터럴·콜백 본문) 안이 아니라
        줄 시작 시점의 범위다(`const cfg = { title: location.hash }`). 줄 안쪽 문장의 선언
        (`function render(){ const html = '…'; … }`)은 그 줄에서 연 함수 범위에 속한다.
        """
        chain = self.scopes.chain[line]
        if declared:
            return (self.scopes.chain_start if head else self.scopes.chain)[line][-1]
        for sid in reversed(chain):
            if (sid, name) in self.vars:
                return sid
        return 0

    def _record(self, name: str, line: int, op: str, state: str, direct: bool, declared: bool = False,
                head: bool = False) -> None:
        sid = self._declaring_scope(name, line, declared, head)
        hist = self.vars.setdefault((sid, name), [])
        if not any(h[0] == line and h[1] == op and h[2] == state for h in hist):   # 2바퀴 중복 방지
            hist.append((line, op, state, direct))

    def _lookup(self, name: str, line: int | None = None) -> tuple[str, bool] | None:
        line = self.cur if line is None else line
        chain = self.scopes.chain[line]
        sid = next((s for s in reversed(chain) if (s, name) in self.vars), None)
        if sid is None:
            return None
        hist = self.vars[(sid, name)]
        my_func = self.scopes.func_of(chain[-1])
        same_func = all(self.scopes.func_of(self.scopes.chain[h[0]][-1]) == my_func for h in hist)
        if same_func:
            before = [h for h in hist if h[0] <= line]
            if before:
                state: tuple[str, bool] | None = None
                for _ln, op, st, direct in before:
                    if op == "+=" and state is not None:
                        m = self._merge([SinkVerdict(state[0], "", state[1]), SinkVerdict(st, "", direct)])
                        state = (m.state, state[1] or direct)
                    else:
                        state = (st, direct)
                return state
        # 다른 함수에서도 할당된다(또는 사용 뒤에 선언) — 모든 할당을 합친다. 오염이 우선.
        merged: tuple[str, bool] | None = None
        for _ln, _op, st, direct in hist:
            if merged is None:
                merged = (st, direct)
            else:
                m = self._merge([SinkVerdict(merged[0], "", merged[1]), SinkVerdict(st, "", direct)])
                merged = (m.state, merged[1] or direct)
        return merged

    def _is_comment_line(self, i: int) -> bool:
        return self.comment[i] or self.lines[i].strip().startswith(("//", "/*", "*"))

    def _accepts(self, name: str) -> bool:
        from .html_sink_context import sanitizer_name_ok
        return sanitizer_name_ok(name, self.local_defs, self.local_safe, self.project)

    # ── 함수 → return 식(한 홉) ────────────────────────────────────────────
    def _index_function_returns(self) -> dict[str, tuple[list[tuple[str, int]], list[str]]]:
        """지역 함수 이름 → ([(return 식, 줄 index)], 매개변수 이름). sink 인자가 ``rowHtml(x)`` 일 때 한 홉 본다.

        줄 index 를 함께 두는 이유: 반환식 안의 지역 변수(`const suffix = …; return `…${suffix}``)는
        **그 함수의 범위**에서 찾아야 한다. 실측(2026-10-13 약관검색기 pdfUrl)에서 sink 줄의 범위로
        찾다가 못 찾아 출처 미상이 됐다.
        """
        out: dict[str, tuple[list[tuple[str, int]], list[str]]] = {}
        for i, line in enumerate(self.lines):
            if self.comment[i]:
                continue
            m = _FUNC_DEF_RE.match(line)
            if not m:
                continue
            name = m.group(1) or m.group(3)
            params_raw = m.group(2) or m.group(4) or m.group(5) or m.group(6) or ""
            params: list[str] = []
            for raw_p in params_raw.split(","):
                nm = raw_p.strip().split("=")[0].split(":")[0].strip().lstrip(".")
                if nm and nm not in params:
                    params.append(nm)
            returns: list[tuple[str, int]] = []
            indent = len(line) - len(line.lstrip())
            # 한 줄 함수: `function f(a){ return `…`; }` — 정의 줄 자체의 return 도 본다.
            same = re.search(r"\breturn\s+(.*)$", line[m.end():])
            if same:
                expr, _c = self._collect_expr(same.group(1).rstrip().rstrip("}").rstrip().rstrip(";"), i)
                returns.append((expr, i))
            concise = False
            if not same and (m.group(5) is not None or m.group(6) is not None) and line[m.end():].strip() \
                    and not line[m.end():].lstrip().startswith("{"):
                # `const fmt = (t) => t.replace(…)` — 블록 없는 화살표는 본문이 곧 반환값이다.
                expr, _c = self._collect_expr(line[m.end():].strip().rstrip(";"), i)
                returns.append((expr, i))
                concise = True
            j = i + 1
            # 간결 화살표는 본문이 한 식뿐이다 — 뒤 줄의 `return` 은 다른 함수 것이다(실측 2026-10-15:
            # `export default function Page()` 의 JSX return 이 `fmt` 의 반환식으로 섞여 들어갔다).
            end = i + 1 if concise else min(len(self.lines), i + _FUNC_BODY_MAX_LINES)
            while j < end:
                cur = self.lines[j]
                # 같거나 바깥 들여쓰기의 다음 정의 = 본문 끝(대략적 경계)
                if _FUNC_DEF_RE.match(cur) and (len(cur) - len(cur.lstrip())) <= indent:
                    break
                rm = _RETURN_RE.match(cur)
                if rm:
                    expr, consumed = self._collect_expr(rm.group(1), j)
                    returns.append((expr, j))
                    j += consumed
                    continue
                j += 1
            if name and returns:
                out[name] = (returns, params)
        return out

    def _collect_expr(self, head: str, idx: int) -> tuple[str, int]:
        """줄 idx 에서 시작한 식이 여러 줄이면 닫힐 때까지 이어 붙인다. (식, 소비한 줄 수).

        여러 줄 템플릿뿐 아니라 **화살표 본문이 다음 줄로 넘어간 선언**도 따라간다 — 실측
        (2026-10-13 약관검색기 app.js:79) `const validities = (…).map((item) =>` 줄바꿈 뒤 템플릿.
        예전엔 첫 줄만 보고 출처 미상으로 남겨 정화된 값이 '높음'으로 올라갔다.
        """
        first = head.find("`")
        open_template = first != -1 and _find_backtick_end(head, first + 1) == -1
        stripped = head.rstrip().rstrip(";").rstrip()
        # 줄 끝이 명백히 이어지는 모양일 때만 따라간다. 괄호 계산만 믿으면 정규식 리터럴
        # 속 따옴표(`/[&<>"']/g`)에 속아 멀쩡한 한 줄 선언을 "안 닫힘"으로 보고 뒤 줄을 삼킨다.
        open_literal = (not open_template) and stripped.endswith(("{", "[")) and _paren_balance(stripped) > 0
        open_arrow = (not open_template) and (stripped.endswith(_DECL_CONTINUES) or open_literal)
        if not open_template and not open_arrow:
            return head.rstrip(";").strip(), 1
        buf = [head]
        j = idx + 1
        # 객체·배열 리터럴(`const sampleData = {`)은 선언보다 길다 — 실측 2026-10-15 챗봇 style-preview.
        limit = _TEMPLATE_MAX_LINES if open_template else (_LITERAL_CONT_MAX_LINES if open_literal else _DECL_CONT_MAX_LINES)
        while j < len(self.lines) and j - idx <= limit:
            buf.append(self.lines[j])
            joined = "\n".join(buf)
            if open_template:
                if _find_backtick_end(joined, first + 1) != -1:
                    return joined.rstrip(";").strip(), j - idx + 1
            else:
                tail = joined.rstrip().rstrip(";").rstrip()
                if not tail.endswith(_DECL_CONTINUES) and _paren_balance(tail) <= 0 and joined.count("`") % 2 == 0:
                    return joined.rstrip(";").strip(), j - idx + 1
            j += 1
        if not open_template:
            return head.rstrip(";").strip(), 1          # 몇 줄 안에 안 닫힘 — 첫 줄만(예전 동작)
        return "\n".join(buf), j - idx      # 닫히지 않음 — 보수적으로 그대로

    def _bind_iteration_vars(self, text: str) -> None:
        """``rows.map(r => …)`` 의 ``r`` 은 ``rows`` 의 출처를 물려받는다(현재 줄의 범위에 선언)."""
        matches = list(_CALLBACK_BIND_RE.finditer(text)) + list(_CALLBACK_BIND_PAREN_RE.finditer(text))
        for m in matches:
            root, param, index = m.group(1), m.group(2), m.group(3)
            st = self._lookup(root)
            if st is not None:
                self._record(param, self.cur, "=", st[0], st[1], declared=True)
            elif _TAINTED_NAME_RE.search(root):
                self._record(param, self.cur, "=", TAINTED, False, declared=True)
            if index and index != "_":
                self._record(index, self.cur, "=", CONST, False, declared=True)

    def _bind_callback_params(self, recv: str, cb_params: list[str]) -> None:
        """콜백 첫 매개변수 = 컬렉션 요소(컬렉션의 출처를 물려받음), 둘째 = 인덱스(숫자)."""
        if not cb_params:
            return
        root = re.match(r"^\(?\s*([A-Za-z_$][\w$]*)", recv.strip())
        st = self._lookup(root.group(1)) if root else None
        if st is not None:
            self._record(cb_params[0], self.cur, "=", st[0], st[1], declared=True)
        elif root and _TAINTED_NAME_RE.search(root.group(1)):
            self._record(cb_params[0], self.cur, "=", TAINTED, False, declared=True)
        else:
            self._record(cb_params[0], self.cur, "=", UNKNOWN, False, declared=True)
        for extra in cb_params[1:2]:
            if extra and extra != "_":
                self._record(extra, self.cur, "=", CONST, False, declared=True)

    # ── 식 분류 ───────────────────────────────────────────────────────────
    def classify_expr(self, expr: str, depth: int = 0, params=None) -> SinkVerdict:
        expr = expr.strip().rstrip(";").strip()
        # TS/ES2020 표기 정규화 — `res?.data?.note`·`data!.note` 는 `res.data.note`·`data.note` 와 같은 값이다.
        expr = expr.replace("?.", ".").replace("!.", ".")
        if expr.startswith("(") and expr.endswith(")") and _matching_close(expr, 0) == len(expr) - 1:
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
        # 최상위 삼항·논리식은 **템플릿보다 먼저** 가른다 — `data.html || \`<p>없음</p>\`` 가 "보간 없는
        # 템플릿"으로 상수가 됐다(전면 점검 §3-3). 피연산자마다 따로 분류해 합친다.
        split = _split_top_level(expr)
        if split is not None:
            return self._merge([self.classify_expr(piece, depth + 1, params) for piece in split])
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
        # `arr.map(esc).join('')` · `arr.map(x => esc(x))` — 요소마다 정화 함수를 거친다.
        # 실측(2026-10-13 약관검색기 app.js:85) `evidence.map(escapeHtml).join("<br>")`.
        mm = _MAP_SANITIZER_RE.match(expr)
        if mm and "`" not in expr:
            fn = mm.group("fn")
            if fn and self._accepts(fn):
                return SinkVerdict(SANITIZED, f"map({fn}) — 요소마다 정화 호출")
            # `rows.map(rowHtml)` — 지역 헬퍼를 요소마다 부른다. 요소의 출처를 매개변수에 묶고 반환식으로 판정.
            if fn and fn.split(".")[0] in self.func_returns and depth < 4:
                elem = self._element_verdict(mm.group("recv"))
                verdict = self._classify_helper_call(fn.split(".")[0], [elem], depth)
                verdict.reason = f"map({fn}) — {verdict.reason}"
                return verdict
            if mm.group("body"):
                # 콜백 매개변수는 컬렉션 요소다 — 컬렉션의 출처를 물려받는다(예전엔 무조건 미상이라
                # `rows.map(r => rawHtml(r))` 의 저장형 XSS 가 '검토'에 머물렀다).
                self._bind_callback_params(mm.group("recv"), [mm.group("param")])
                body = self.classify_expr(mm.group("body"), depth + 1, params)
                if body.state == SANITIZED:
                    return SinkVerdict(SANITIZED, f"map(…) 본문 — {body.reason}")
                if body.state == TAINTED:
                    return SinkVerdict(TAINTED, f"map(…) 본문 — {body.reason}", body.direct_source)
        # `rows.map(function(f, i){ … return X; }).join('')` · `rows.map(f => { … return X })` ·
        # `rows.map(f => X)` — HTML 이 되는 것은 콜백이 **돌려주는 값**이지 바깥 배열이 아니다.
        # 실측(2026-10-13 safe_check app.js:1574): 모든 값이 esc() 를 거친 ES5 콜백이 배열 변수의
        # 출처만으로 '확인된 XSS' 차단이 됐다. 템플릿 본문은 아래 기존 경로가 맡는다.
        cb = _map_callback_parts(expr)
        if cb is not None and "`" not in expr:
            recv, cb_params, returns = cb
            self._bind_callback_params(recv, cb_params)
            if not returns:
                return SinkVerdict(UNKNOWN, "map 콜백의 반환값을 찾지 못함")
            verdict = self._merge([self.classify_expr(r, depth + 1, params) for r in returns])
            if verdict.state in (SANITIZED, CONST):
                verdict.reason = f"map 콜백 반환값 — {verdict.reason}"
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
            if last in _NUMERIC_FORMAT_CALLS and "." in wrapper:
                return SinkVerdict(CONST, "HTML 이 될 수 없는 값(숫자 서식)")
            if last in _PASSTHROUGH_CALLS:
                if not inner.strip() and "." in wrapper:
                    # `el.textContent.trim()` — 값은 수신자(el.textContent)다
                    return self.classify_expr(wrapper.rsplit(".", 1)[0], depth + 1, params)
                return self.classify_expr(inner, depth + 1, params)
            if wrapper in _URL_ENCODE_CALLS:
                return SinkVerdict(SANITIZED, f"{wrapper}() — URL 인코딩 결과에는 HTML 메타문자가 없음")
            if base in self.func_returns and depth < 4:      # 배열 → 함수 → 객체 → 헬퍼 호출까지(실측 _rtReadSingleRow)
                args = _split_args(inner)
                arg_verdicts = [self.classify_expr(a, depth + 1, params) for a in args]
                return self._classify_helper_call(base, arg_verdicts, depth)
            if _SOURCE_RE.search(expr):
                return SinkVerdict(TAINTED, "외부 출처(URL·요청·입력값·응답)가 식에 직접 있음", direct_source=True)
            self._bind_iteration_vars(expr)
            st_base = self._lookup(base) if "." in wrapper else None
            if st_base is not None:
                return SinkVerdict(st_base[0], f"변수 {base} 의 출처", st_base[1])
            if "." in wrapper and (params is None or base not in params) and _TAINTED_NAME_RE.search(base):
                return SinkVerdict(TAINTED, f"이름이 입력값을 뜻함({base})")
            return SinkVerdict(UNKNOWN, f"{wrapper}() 반환값 — 출처 추적 불가")
        # 배열·객체 리터럴 — 요소(값)들의 출처를 합친다. 실측: `RT_FIELDS = [_readRow()]` 가
        # "식 해석 불가"로 남아 그 요소의 저장형 XSS 가 출처 미상에 머물렀다.
        if expr.startswith("[") and expr.endswith("]"):
            items = _split_args(expr[1:-1])
            return self._merge([self.classify_expr(x, depth + 1, params) for x in items]) if items else SinkVerdict(CONST, "빈 배열")
        if expr.startswith("{") and expr.endswith("}"):
            values = []
            for item in _split_args(expr[1:-1]):
                k, sep, v = item.partition(":")
                values.append(v if sep else k)          # `{a}` 축약은 변수 a 자체
            return self._merge([self.classify_expr(x, depth + 1, params) for x in values]) if values else SinkVerdict(CONST, "빈 객체")
        # 결합
        if "+" in expr:
            parts = _split_concat(expr)
            if len(parts) > 1:
                return self._merge([self.classify_expr(p, depth + 1, params) for p in parts])
        if _ARITHMETIC_RE.match(expr) and _paren_balance(expr) == 0:
            return SinkVerdict(CONST, "HTML 이 될 수 없는 값(산술식)")
        # 길이·숫자 서식 꼬리는 **피연산자 하나**에만 적용한다 — 식 전체(`'<p>' + req.body.note + …
        # + items.length`)가 `.length` 로 끝난다고 상수가 됐다(전면 점검 §3-3).
        if _NUMERIC_TAIL_RE.search(expr) and _paren_balance(expr) == 0 and "`" not in expr:
            return SinkVerdict(CONST, "HTML 이 될 수 없는 값(길이·숫자 서식)")
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
        # 외부 출처가 식에 직접 있으면 멤버 이름이 숫자처럼 보여도 공격자 값이다 — `req.query.id`·
        # `req.body.date` 가 숫자 멤버 규칙에 먼저 걸려 **발견이 지워졌다**(전면 점검 §3-3). 진짜 숫자
        # (`.length`·`Number(…)`)만 예외.
        if _SOURCE_RE.search(expr) and not _SAFE_EXPR_RE.match(expr):
            return SinkVerdict(TAINTED, "외부 출처(URL·요청·입력값·응답)가 식에 직접 있음", direct_source=True)
        # HTML 이 될 수 없는 값, 리터럴 삼항, 숫자 이름의 멤버
        if _SAFE_EXPR_RE.match(expr) or _LITERAL_TERNARY_RE.match(expr) or _NUMERIC_MEMBER_RE.match(expr):
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
            st = self._lookup(root)
            if st is not None:
                return SinkVerdict(st[0], f"변수 {root} 의 출처", st[1])
            if _TAINTED_NAME_RE.search(root):
                return SinkVerdict(TAINTED, f"이름이 입력값을 뜻함({root})")
            if expr == root and _NUMERIC_NAME_RE.match(root):
                return SinkVerdict(CONST, f"이름이 숫자를 뜻함({root})")
            return SinkVerdict(UNKNOWN, f"변수 {root} 의 출처를 찾지 못함")
        return SinkVerdict(UNKNOWN, "식 해석 불가")

    def _element_verdict(self, recv: str) -> SinkVerdict:
        """컬렉션 식의 **요소** 상태 — 뿌리 변수의 출처를 물려받는다(`data.rows` → data)."""
        root = re.match(r"^\(?\s*([A-Za-z_$][\w$]*)", recv.strip())
        st = self._lookup(root.group(1)) if root else None
        if st is not None:
            return SinkVerdict(st[0], f"변수 {root.group(1)} 의 출처", st[1])
        if root and _TAINTED_NAME_RE.search(root.group(1)):
            return SinkVerdict(TAINTED, f"이름이 입력값을 뜻함({root.group(1)})")
        return SinkVerdict(UNKNOWN, "컬렉션의 출처를 찾지 못함")

    def _classify_helper_call(self, base: str, arg_verdicts: list[SinkVerdict], depth: int) -> SinkVerdict:
        """지역 헬퍼 호출 — 매개변수를 **인자의 상태로 묶고** 반환식을 그 함수의 줄에서 분류한다.

        예전(2026-10-13)에는 인자가 출처면 무조건 오염으로 봐 본문에서 `esc()` 하는 정화 헬퍼
        (`rowHtml(data.row)`)까지 차단했다(전면 점검 §3-3 회귀). 그대로 돌려주는 헬퍼는 여전히 오염·확인됨.
        """
        returns, fparams = self.func_returns[base]
        caller_line = self.cur
        saved: dict[tuple[int, str], list | None] = {}
        verdicts = []
        try:
            for r, r_line in returns:
                func_sid = self.scopes.func_of(self.scopes.chain[r_line][-1])
                for pname, v in zip(fparams, arg_verdicts):
                    key = (func_sid, pname)
                    if key not in saved:
                        saved[key] = self.vars.get(key)
                    self.vars[key] = [(r_line, "=", v.state, v.direct_source)]
                self.cur = r_line
                verdicts.append(self.classify_expr(r, depth + 1, None))
        finally:
            self.cur = caller_line
            for key, prev in saved.items():
                if prev is None:
                    self.vars.pop(key, None)
                else:
                    self.vars[key] = prev
        verdict = self._merge(verdicts)
        verdict.reason = f"{base}() 반환식 — {verdict.reason}"
        return verdict

    def _classify_parts(self, exprs: list[str], depth: int, params) -> SinkVerdict:
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
        jsx = _JSX_HTML_SINK.search(line)
        if jsx:
            return self._jsx_sink_at(i, jsx.end())
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
        # `list.innerHTML = rows.map(f => {` — 블록 본문 화살표. 줄이 여는 괄호로 끝나면 괄호가
        # 닫힐 때까지 이어 붙인다(실측: 본문 안 `return `…${esc(x)}…`` 를 못 보고 배열 변수의
        # 출처만으로 '확인된 XSS' 를 냈다).
        if expr.rstrip().endswith(("{", "(", "[")):
            depth = 0
            buf = [expr]
            j = start + used
            while j < n and j - start <= _TEMPLATE_MAX_LINES:
                buf.append(self.lines[j])
                joined = "\n".join(buf)
                depth = _paren_balance(joined)
                j += 1
                if depth <= 0:
                    break
            expr, used = "\n".join(buf), j - start
        if call:
            expr = _strip_trailing_call_paren(expr)
        return _cut_at_statement_end(expr), (start - i) + used

    def _jsx_sink_at(self, i: int, after: int) -> tuple[str, int] | None:
        """`dangerouslySetInnerHTML={{ __html: X }}` 의 X 를 (여러 줄이면 이어) 돌려준다."""
        n = len(self.lines)
        rest = self.lines[i][after:]
        start = i
        if not rest.strip() and i + 1 < n:
            start = i + 1
            rest = self.lines[start]
        km = _JSX_HTML_KEY_RE.match(rest)
        if not km:
            return None
        buf = [rest[km.end():]]
        j = start
        # 닫는 `}}` 까지 — 괄호 깊이가 -1 이 되는 `}` 가 식의 끝이다(문자열·템플릿 제외).
        while True:
            joined = "\n".join(buf)
            cut = _cut_at_depth(joined, -1)
            if cut is not None:
                return cut.strip().rstrip(","), (j - i) + 1
            j += 1
            if j >= n or j - start > _TEMPLATE_MAX_LINES:
                return None
            buf.append(self.lines[j])

    def _collect_states(self) -> None:
        """1차: 파일 전체의 할당·순회 바인딩으로 (범위, 이름) → 할당 이력을 모은다.

        두 번 돈다 — 나중 줄의 변수를 참조하는 앞 줄의 할당이 첫 바퀴에서 UNKNOWN 으로
        남는 것을 두 번째 바퀴가 메운다(같은 줄·같은 상태의 이력은 중복 기록하지 않는다).
        """
        n = len(self.lines)
        for _round in range(2):
            i = 0
            while i < n:
                line = self.lines[i]
                if self._is_comment_line(i):
                    i += 1
                    continue
                self.cur = i
                consumed = 1
                # `RT_FIELDS.forEach((f, i) => {` 처럼 문장 머리의 순회 — 콜백 매개변수를 이 줄의 범위에 묶는다
                self._bind_iteration_vars(line)
                fo = _FOR_OF_RE.search(line)
                if fo:
                    st = self._lookup(fo.group(2))
                    if st is not None:
                        self._record(fo.group(1), i, "=", st[0], st[1], declared=True)
                # sink 줄도 할당은 모은다(`function r(){ const html = '…'; el.innerHTML = html; }`).
                # 다만 sink 의 여러 줄 템플릿 본문은 건너뛴다.
                sink = self._sink_at(i)
                d = _DESTRUCT_RE.match(line)
                if d:
                    rhs, consumed = self._collect_expr(d.group(2).strip(), i)
                    v = self.classify_expr(_cut_at_statement_end(rhs))
                    if v.state == UNPARSED:
                        v = SinkVerdict(UNKNOWN, v.reason)
                    for item in d.group(1).split(","):
                        nm = item.split("=")[0]
                        nm = (nm.split(":")[-1] if ":" in nm else nm).strip().lstrip(".")
                        if re.match(r"^[A-Za-z_$][\w$]*$", nm):
                            self._record(nm, i, "=", v.state, v.direct_source, declared=True, head=True)
                a = None if d else _ASSIGN_RE.match(line)
                if a:
                    # 줄 머리의 할당 — 여러 줄 템플릿을 따라간다
                    name, op, rhs = a.group(1), a.group(2), a.group(3).strip()
                    declared = bool(_DECL_RE.match(line.strip()))
                    rhs, consumed = self._collect_expr(rhs, i)
                    v = self.classify_expr(_cut_at_statement_end(rhs))
                    if v.state == UNPARSED:
                        v = SinkVerdict(UNKNOWN, v.reason)
                    self._record(name, i, op, v.state, v.direct_source, declared, head=True)
                # 한 줄 안의 나머지 문장들(`const load = () => { html = …; }`) — 같은 줄 안에서만 본다.
                # 줄 머리 할당의 RHS 안쪽(화살표 함수 본문)에 든 할당도 여기서 잡힌다.
                if line.count("`") % 2 == 0:
                    # 괄호 안 콜백 본문(`rows.forEach(function(f){ h+=…; })`)의 문장도 모은다 —
                    # 문장 분리기는 괄호 안을 보지 않아, 한 줄 누적이 통째로 빠져 sink 의 `h` 가
                    # 빈 문자열 상수로 남고 **발견 자체가 지워졌다**(실측 2026-10-13 safe_check).
                    inline_stmts = [st for body in _inline_callback_bodies(line) for st in _split_statements(body)]
                    for stmt in _split_statements(line)[1:] + inline_stmts:
                        a2 = _ASSIGN_RE.match(stmt)
                        if not a2:
                            continue
                        v = self.classify_expr(a2.group(3).strip())
                        if v.state == UNPARSED:
                            v = SinkVerdict(UNKNOWN, v.reason)
                        self._record(a2.group(1), i, a2.group(2), v.state, v.direct_source,
                                     bool(_DECL_RE.match(stmt.strip())))
                if sink is not None:
                    consumed = max(consumed, sink[1])
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
            self.cur = i
            expr, consumed = sink
            v = self.classify_expr(expr)
            if v.state != UNPARSED:          # 읽지 못한 것은 판정하지 않는다 — regex 차단이 남는다
                verdicts[i + 1] = v
            i += consumed
        return verdicts


def _split_top_level(expr: str) -> list[str] | None:
    """최상위(괄호·문자열·템플릿 밖)의 삼항 `a ? b : c` → [b, c], 논리 `a || b`·`??`·`&&` → 피연산자들.
    없으면 None. 화살표 본문·호출 인자 안의 연산자는 보지 않는다."""
    depth = 0
    in_str: str | None = None
    i = 0
    n = len(expr)
    logical_cuts: list[int] = []
    q_pos: int | None = None
    colon_pos: int | None = None
    ternary_depth = 0
    while i < n:
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
                return None
            i = j
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0:
            two = expr[i:i + 2]
            if two in ("||", "??", "&&") and q_pos is None:
                logical_cuts.append(i)
                i += 2
                continue
            if ch == "?" and expr[i + 1:i + 2] not in (".", "?", ":"):
                if q_pos is None:
                    q_pos = i
                else:
                    ternary_depth += 1
            elif ch == ":" and q_pos is not None:
                if ternary_depth:
                    ternary_depth -= 1
                elif colon_pos is None:
                    colon_pos = i
        i += 1
    if q_pos is not None and colon_pos is not None and not logical_cuts:
        left, right = expr[q_pos + 1:colon_pos].strip(), expr[colon_pos + 1:].strip()
        if left and right and expr[:q_pos].strip():
            return [left, right]
    if logical_cuts and q_pos is None:
        pieces: list[str] = []
        start = 0
        for cut in logical_cuts:
            pieces.append(expr[start:cut].strip())
            start = cut + 2
        pieces.append(expr[start:].strip())
        pieces = [p for p in pieces if p]
        if len(pieces) > 1:
            return pieces
    if q_pos is not None and colon_pos is not None and logical_cuts:
        # `a || b ? c : d` — 삼항의 조건에 논리식: 값은 c·d 다.
        left, right = expr[q_pos + 1:colon_pos].strip(), expr[colon_pos + 1:].strip()
        if left and right and all(c < q_pos for c in logical_cuts):
            return [left, right]
    return None


_MAP_HEAD_RE = re.compile(r"\.\s*(?:map|flatMap)\s*\(")
_FUNC_CB_RE = re.compile(r"^\s*(?:async\s+)?function\b\s*[\w$]*\s*\(([^()]*)\)\s*\{")
_ARROW_CB_RE = re.compile(r"^\s*(?:async\s+)?(?:\(([^()]*)\)|([A-Za-z_$][\w$]*))\s*=>\s*")
_JOIN_TAIL_RE = re.compile(r"^\s*(?:\.\s*join\s*\([^()]*\))?\s*$")


def _cut_at_depth(text: str, target: int) -> str | None:
    """괄호 깊이가 ``target`` 에 **처음** 도달하는 위치 앞까지의 텍스트. 못 찾으면 None."""
    depth = 0
    in_str: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(text, i + 1)
            if j == -1:
                return None
            i = j
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == target:
                return text[:i]
        i += 1
    return None


def _matching_close(text: str, open_idx: int, open_ch: str = "(", close_ch: str = ")") -> int:
    """text[open_idx] 의 짝 괄호 위치(문자열·템플릿 건너뜀). 못 찾으면 -1."""
    depth = 0
    in_str: str | None = None
    i = open_idx
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "`":
            j = _find_backtick_end(text, i + 1)
            if j == -1:
                return -1
            i = j
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _top_level_returns(body: str) -> list[str]:
    """블록 본문에서 콜백 자신의 `return X` 식들(중첩 함수 안의 return 은 제외)."""
    out: list[str] = []
    for m in re.finditer(r"\breturn\b", body):
        before = body[:m.start()]
        # 중첩 함수 본문 안이면 건너뛴다 — 앞쪽에서 열린 중괄호 수로 대략 판정
        if _paren_balance(before.replace("{", "(").replace("}", ")")) != 0:
            continue
        rest = body[m.end():]
        end = len(rest)
        depth = 0
        in_str: str | None = None
        i = 0
        while i < len(rest):
            ch = rest[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
            elif ch in ("'", '"'):
                in_str = ch
            elif ch == "`":
                j = _find_backtick_end(rest, i + 1)
                if j == -1:
                    break
                i = j
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    end = i
                    break
                depth -= 1
            elif ch == ";" and depth == 0:
                end = i
                break
            i += 1
        expr = rest[:end].strip()
        if expr:
            out.append(expr)
    return out


_INLINE_CB_OPEN_RE = re.compile(r"(?:\bfunction\b\s*[\w$]*\s*\([^()]*\)|=>)\s*\{")


def _inline_callback_bodies(line: str) -> list[str]:
    """한 줄 안의 콜백 본문(`function(…){ … }`·`=> { … }`) — 괄호 **안**에 있는 것만."""
    out: list[str] = []
    for m in _INLINE_CB_OPEN_RE.finditer(line):
        if _paren_balance(line[:m.start()]) <= 0:
            continue                      # 줄 머리 문장의 본문 — 기존 분리기가 본다
        brace = m.end() - 1
        end = _matching_close(line, brace, "{", "}")
        if end != -1:
            out.append(line[brace + 1:end])
    return out


def _map_callback_parts(expr: str) -> tuple[str, list[str], list[str]] | None:
    """``recv.map(<콜백>)(.join(…))?`` → (수신자, 콜백 매개변수, 반환식들). 모양이 아니면 None."""
    m = _MAP_HEAD_RE.search(expr)
    if not m:
        return None
    open_idx = m.end() - 1
    close_idx = _matching_close(expr, open_idx)
    if close_idx == -1 or not _JOIN_TAIL_RE.match(expr[close_idx + 1:]):
        return None
    recv = expr[:m.start()]
    if _paren_balance(recv) != 0:
        return None
    cb = expr[open_idx + 1:close_idx]
    fm = _FUNC_CB_RE.match(cb)
    if fm:
        params = [x.strip().split("=")[0].strip() for x in fm.group(1).split(",") if x.strip()]
        brace = fm.end() - 1
        bend = _matching_close(cb, brace, "{", "}")
        if bend == -1:
            return None
        return recv, params, _top_level_returns(cb[brace + 1:bend])
    am = _ARROW_CB_RE.match(cb)
    if am:
        raw = am.group(1) if am.group(1) is not None else am.group(2)
        params = [x.strip().split("=")[0].strip() for x in raw.split(",") if x.strip()]
        body = cb[am.end():].strip()
        if body.startswith("{"):
            bend = _matching_close(body, 0, "{", "}")
            if bend == -1:
                return None
            return recv, params, _top_level_returns(body[1:bend])
        return recv, params, [body] if body else []
    return None


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
    lines = split_lines(code)
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
        for line_no, line in enumerate(split_lines(code), start=1):
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
            lines = split_lines(code)
            for line_no, verdict in classify_html_sinks(code).items():
                if verdict.state != TAINTED or ignores.suppresses(
                    line_no, _HTML_RULE_ID, "confirmed" if verdict.direct_source else "likely",
                ):
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
