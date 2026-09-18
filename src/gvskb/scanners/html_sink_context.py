"""HTML 주입 sink 의 **문맥**을 보고 차단을 감쇄한다 — 지우지는 않는다.

왜 감쇄이고 삭제가 아닌가
-------------------------
줄 단위 regex 는 `dangerouslySetInnerHTML={{ __html: processHtml(x) }}` 를 보고
`processHtml` 이 무엇을 하는지 모른다. 실측(2026-08-08, lexdiff)에서 차단 9건 중
7건이 이런 모양이었고, 그중 6건은 `processHtml` 본문이 `sanitizeForRender(...)`
로 끝나는 **정상 방어**였다.

그런데 나머지 1건은 달랐다::

    // 법제처 API 법령 본문 = 신뢰 소스. sanitize 생략으로 조당 ~30ms 절감.
    const html = extractArticleText(article, false, lawTitle)
    return <div dangerouslySetInnerHTML={{ __html: html }} />

개발자가 **의도적으로 정화를 껐다.** 이것은 오탐이 아니라 검토가 필요한 실제
판단이다. 순진하게 "한 홉 따라가서 함수면 통과" 로 만들었다면 이 진짜 위험이
함께 사라졌을 것이다. 그래서 이 모듈은 두 가지를 지킨다:

1. **함수 이름이 아니라 함수 본문**을 본다. 본문에 정화 호출이 없으면 그대로 둔다.
2. 확신의 정도에 따라 결과를 나눈다. 전부 지우면 위험이 사라지고, 전부 남기면
   표준 정상 패턴 11건이 목록을 덮어 아무도 읽지 않는다. 둘 다 실패다.

   ===================  ==========================================
   정황                 결과
   ===================  ==========================================
   주입 지점의 정화 호출  발견을 내린다(*관찰*). 단 그 이름이 이 파일에서
                        정화하지 않는 지역 함수면 내리지 않는다.
   지역 헬퍼 1홉         medium · warn 으로 낮추고 이유를 남긴다(*추론*).
   `<style>` 요소        medium · warn (CSS 라 즉시 XSS 는 아니지만
                        `</style>` 탈출이 가능해 '안전'은 아니다).
   그 밖                 그대로 차단.
   ===================  ==========================================

   예전 룰도 정화가 보이면 지웠지만 근거가 달랐다: 그쪽은 줄에 `sanitize` 라는
   **글자**가 있으면 지웠고, 그래서 적대적 검증에서
   `function sanitizeMaybe(h){ return h.trim() }` 에 그대로 뚫렸다 — 발견이
   조용히 사라졌다. 이쪽은 그 이름이 **이 파일에서 정화하지 않는 함수인지
   확인**한 뒤에만 내린다. 확인할 수 없는 것(import 된 `DOMPurify.sanitize`)은
   믿는다. 볼 수 없다는 이유로 전부 차단하면 아무도 이 도구를 쓰지 않는다.

프로젝트 정화 함수 (2026-09-18)
------------------------------
실측(999건 사례)에서 프로젝트는 ``esc()`` 라는 자체 정화 함수를 썼고, 위 표의
어휘(``sanitize*``·``escapeHtml``)에 없어 감쇄가 **한 번도** 작동하지 않았다 —
이름 목록 하나가 차단 817건을 만들었다. 그래서 두 가지를 더한다:

- **본문 판정**: 이름과 무관하게 본문이 ``replace(…)`` 로 ``&lt;``·``&amp;`` 를 만들거나
  ``createTextNode``·``textContent → innerHTML`` 우회를 하면 정화 함수다(``_body_escapes``).
- **트리 전체 색인**(``ProjectSanitizers``): 다른 파일에 정의된 함수도 본문을 본다.
  같은 이름이 트리 안에서 정화하지 않는 것으로 확인되면 어휘에 맞아도 인정하지 않는다.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from ..schema import Decision, Finding, Severity

# 정화로 인정하는 호출 어휘. `sanitiz\w*` 가 sanitizeForRender·sanitizeHtml 을 덮는다.
# 어휘 일치는 **후보**일 뿐이다 — 정의를 볼 수 있으면 본문이 결정한다(`sanitizer_name_ok`).
#
# `escape\w*` 로 넓히지 않는다 — `escapeRegExp`·`escapeURL` 은 HTML 을 정화하지 않는다.
_SANITIZER_VOCAB = (
    r"DOMPurify|sanitiz\w*|escape(?:html|attr(?:ibute)?|text|str(?:ing)?|value)?|esc|escHtml|escAttr"
    r"|htmlEscape|html_escape|htmlspecialchars|encodeHtml|encodeForHTML|purify|xss|filterXSS"
)
_SANITIZER_RE = re.compile(rf"(?i)\b(?:{_SANITIZER_VOCAB}|he\.encode|he\.escape)\s*\(")
_SANITIZER_NAME_RE = re.compile(rf"(?i)^(?:{_SANITIZER_VOCAB})$")

# 본문이 **직접** 정화하는 형태 — `replace(…)` 로 엔티티 치환, 텍스트 노드 경유.
# 주석·문자열에 `&lt;` 라고 적어 둔 가짜(`function esc(s){ /* &lt; */ return s }`)를
# 막기 위해 주석을 지운 본문에서 `replace` 호출과 엔티티가 **함께** 있어야 한다.
_ENTITY_RE = re.compile(r"&lt;|&amp;|&#60;|&#x3c;", re.IGNORECASE)
_REPLACE_CALL_RE = re.compile(r"\.replace(?:All)?\s*\(")
_TEXTNODE_RE = re.compile(r"createTextNode\s*\(")
_TEXTCONTENT_TRICK_RE = re.compile(r"\.(?:textContent|innerText)\s*=[^=][\s\S]{0,200}?\.innerHTML\b")
_JS_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/|(?<![:\\])//[^\n]*")


def _body_escapes(body: str) -> bool:
    """함수 본문이 스스로 HTML 을 이스케이프하는가(주석 제외)."""
    code = _JS_COMMENT_RE.sub("", body)
    if _TEXTNODE_RE.search(code) or _TEXTCONTENT_TRICK_RE.search(code):
        return True
    return bool(_REPLACE_CALL_RE.search(code) and _ENTITY_RE.search(code))

# 이 모듈이 손대는 sink. 값의 출처를 줄 하나로는 알 수 없는 것들.
_SINK_RE = re.compile(r"dangerouslySetInnerHTML|\.(?:inner|outer)HTML\s*\+?=(?!=)|insertAdjacentHTML\s*\(")

# 지역 **함수** 정의 — `function foo(` · `const foo = (…) =>` · `const foo = useCallback(…)`.
# `const html = rows.map(…)` 같은 **값 변수는 정의가 아니다** — 실측(2026-09-18)에서
# 그 변수의 "본문"(다음 정의까지의 줄들)에 `esc(` 가 있다는 이유로 정화 헬퍼로 잡혀,
# fetch 응답을 그대로 넣은 진짜 XSS 가 warn 으로 내려갔다. 변수의 출처는 js-taint 가 본다.
_DEF_RE = re.compile(
    r"^(\s*)(?:export\s+)?(?:default\s+)?(?:async\s+)?"
    r"(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::\s*[\w<>\[\]|, ]+)?\s*=>|[A-Za-z_$][\w$]*\s*=>"
    r"|(?:React\.)?(?:useCallback|useMemo|forwardRef|memo)\s*\())"
)
# 본문이 정화 호출을 **반환**하는 함수 — 이름과 무관하게 정화 함수다(`return sanitizeForRender(x)`).
_RETURN_SANITIZER_RE = re.compile(r"\breturn\s+(?:[\w$]+\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(")
_CALL_NAME_RE = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\(")

# `__html:` 뒤의 식에서 **머리 식별자**만 뽑는다(`processHtml(` → processHtml).
_HTML_VALUE_RE = re.compile(r"__html\s*:\s*([A-Za-z_$][\w$]*)")

# JSX 여는 태그가 style 인지 — 여러 줄에 걸쳐 열리므로 위쪽도 본다.
_STYLE_OPEN_RE = re.compile(r"<style\b")

_MAX_DEF_BODY_LINES = 120     # 한 함수 본문으로 인정할 최대 길이(방어적 상한)
_SINK_WINDOW = 4              # 다줄 JSX 에서 `__html:` 과 정화 호출을 찾을 범위
_STYLE_LOOKBACK = 3           # `<style` 여는 줄을 거슬러 볼 범위

# 근거의 강도가 다르면 등급도 달라야 한다. 셋을 한 등급으로 뭉치면, 표준
# 정상 패턴 11건이 추론 7건과 같은 무게로 올라와 목록이 읽히지 않는다.
_HELPER_REASON = (
    "지역 함수 본문에 정화 호출이 있어 차단에서 경고로 낮춤 — "
    "이 판단은 **추론**입니다. 그 함수가 모든 경로에서 정화하는지 확인하세요"
)
_STYLE_REASON = (
    "<style> 요소라 주입되는 것이 HTML 이 아니라 CSS — 차단에서 경고로 낮춤. "
    "다만 내용에 </style> 이 들어가면 탈출이 가능하니 값의 출처를 확인하세요"
)


# ── 프로젝트 정화 함수 색인 ─────────────────────────────────────────────────

def _norm_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./").lower()


_IMPORT_NAMED_RE = re.compile(r"""import\s*(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]""")
_IMPORT_NS_RE = re.compile(r"""import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*['"]([^'"]+)['"]""")
_REQUIRE_NAMED_RE = re.compile(r"""(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""")
_REQUIRE_NS_RE = re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)""")
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_MODULE_SUFFIXES = ("", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts", "/index.js", "/index.ts", "/index.mjs")


@dataclass
class _ImportMap:
    names: dict[str, str | None]        # 지역 이름 → 모듈 키(트리 안) · None(패키지·미해결)
    namespaces: dict[str, str | None]   # `import * as u` / `const u = require()` 별칭 → 모듈 키
    scripts: list[str]                  # HTML `<script src>` 로 같은 전역을 공유하는 모듈 키


@dataclass
class ProjectSanitizers:
    """검사 트리 전체에서 찾은 정화 함수 정의 — 파일 경계를 넘어 본문을 본다.

    파일별로 (정화 함수, 모든 정의)를 기억하고, 호출한 쪽의 ``import``·``require``·
    ``<script src>`` 를 따라 **실제로 연결된 정의**를 본다. 연결을 알 수 없을 때만
    트리 전체 이름으로 떨어지는데, 그때도 같은 이름이 어느 파일에서는 정화하고 어느
    파일에서는 정화하지 않으면(``ambiguous``) 인정하지 않는다.

    왜 이렇게까지 하나 — 적대적 검증(Codex, 2026-09-19): ``safe-helper.js`` 의 정상
    ``esc()`` 와 ``unsafe-helper.js`` 의 ``return s`` 짜리 ``esc()`` 가 공존할 때, 후자를
    import 한 페이지의 ``el.innerHTML = esc(location.hash)`` 가 **발견 0건**이 됐다.
    "안전한 정의가 하나라도 있으면 믿는다"는 규칙이 진짜 XSS 를 지웠다.
    """

    verified: set[str] = field(default_factory=set)
    unverified: set[str] = field(default_factory=set)
    ambiguous: set[str] = field(default_factory=set)
    by_file: dict[str, tuple[set[str], set[str]]] = field(default_factory=dict)
    files_indexed: int = 0
    _imports: dict[str, _ImportMap] = field(default_factory=dict, repr=False)

    def add_file(self, code: str, path: str = "") -> None:
        # 정화 함수가 있을 리 없는 파일은 색인하지 않는다(성능 가드) — 어휘 이름·엔티티·
        # 텍스트 노드 어느 것도 없으면 본문 판정이 참이 될 수 없다.
        if not _INDEX_HINT_RE.search(code):
            return
        lines = code.splitlines()
        if not lines:
            return
        sanitizers, _helpers, defs = local_sanitizer_index(lines, None)
        self.files_indexed += 1
        if path:
            self.by_file[_norm_path(path)] = (set(sanitizers), set(defs))
        non = {d for d in defs if d not in sanitizers}
        # 한 이름이 여기서는 정화, 저기서는 비정화 → 모호. 어느 쪽도 믿지 않는다.
        self.ambiguous |= (sanitizers & self.unverified) | (non & self.verified)
        self.verified |= sanitizers
        self.unverified |= non
        self.verified -= self.ambiguous
        self.unverified -= self.ambiguous

    # ── import 연결 ────────────────────────────────────────────────────────
    def _resolve_module(self, spec: str, from_file: str) -> str | None:
        """모듈 지정자 → 트리 안 파일 키. 패키지(`lodash`)나 못 찾으면 None."""
        if not spec.startswith((".", "/")) and not from_file.lower().endswith((".html", ".htm")):
            return None                                   # 패키지 — 트리 밖
        base_dir = _norm_path(from_file).rsplit("/", 1)[0] if "/" in _norm_path(from_file) else ""
        candidates: list[str] = []
        if spec.startswith("/"):
            candidates.append(_norm_path(spec))
        else:
            joined = (base_dir + "/" + spec) if base_dir else spec
            parts: list[str] = []
            for seg in joined.replace("\\", "/").split("/"):
                if seg in ("", "."):
                    continue
                if seg == "..":
                    if parts:
                        parts.pop()
                    continue
                parts.append(seg)
            candidates.append("/".join(parts).lower())
            candidates.append(_norm_path(spec))            # HTML 의 src 는 사이트 루트 기준일 수 있다
        for cand in candidates:
            for sfx in _MODULE_SUFFIXES:
                key = cand + sfx
                if key in self.by_file:
                    return key
        # 마지막 수단: 경로 꼬리 일치(`/js/util.js` ↔ `public/js/util.js`)
        tail = candidates[-1].lstrip("/")
        for key in self.by_file:
            if key.endswith("/" + tail) or key.endswith("/" + tail + ".js"):
                return key
        return None

    def imports_of(self, filename: str, code: str) -> _ImportMap:
        cached = self._imports.get(filename)
        if cached is not None:
            return cached
        names: dict[str, str | None] = {}
        namespaces: dict[str, str | None] = {}
        scripts: list[str] = []
        for rx in (_IMPORT_NAMED_RE, _REQUIRE_NAMED_RE):
            for m in rx.finditer(code):
                target = self._resolve_module(m.group(2), filename)
                for item in m.group(1).split(","):
                    item = item.strip()
                    if not item:
                        continue
                    parts = re.split(r"\s+as\s+|\s*:\s*", item)
                    local = parts[-1].strip()
                    if local:
                        names[local] = target
        for rx in (_IMPORT_NS_RE, _REQUIRE_NS_RE):
            for m in rx.finditer(code):
                namespaces[m.group(1)] = self._resolve_module(m.group(2), filename)
        if filename.lower().endswith((".html", ".htm", ".xhtml")):
            for m in _SCRIPT_SRC_RE.finditer(code):
                target = self._resolve_module(m.group(1), filename)
                if target:
                    scripts.append(target)
        result = _ImportMap(names, namespaces, scripts)
        self._imports[filename] = result
        return result

    def resolve(self, name: str, filename: str | None, code: str | None) -> bool | None:
        """이 파일에서 ``name`` 호출이 가리키는 정의가 정화하는가. 모르면 None(어휘로 판단)."""
        short = name.rsplit(".", 1)[-1]
        if filename and code is not None:
            imp = self.imports_of(filename, code)
            if "." in name:
                ns = name.split(".", 1)[0]
                if ns in imp.namespaces:
                    target = imp.namespaces[ns]
                    return None if target is None else self._lookup_in(target, short)
            if short in imp.names:
                target = imp.names[short]
                return None if target is None else self._lookup_in(target, short)
            for target in imp.scripts:
                found = self._lookup_in(target, short)
                if found is not None:
                    return found
        if short in self.ambiguous:
            return False
        if short in self.verified:
            return True
        if short in self.unverified:
            return False
        return None

    def _lookup_in(self, key: str, short: str) -> bool | None:
        entry = self.by_file.get(key)
        if entry is None:
            return None
        sanitizers, defs = entry
        if short in sanitizers:
            return True
        if short in defs:
            return False
        return None                                        # 재수출 등 — 모른다


_INDEX_HINT_RE = re.compile(
    rf"(?i)\b(?:{_SANITIZER_VOCAB})\s*\(|&lt;|&amp;|&#60;|&#x3c;|createTextNode|\.textContent\s*=|\.innerText\s*=",
)
_PROJECT: ContextVar[ProjectSanitizers | None] = ContextVar("gvskb_project_sanitizers", default=None)
_FILE: ContextVar[tuple[str, str] | None] = ContextVar("gvskb_current_file", default=None)


def current_project() -> ProjectSanitizers | None:
    return _PROJECT.get()


@contextmanager
def use_file(filename: str, code: str):
    """지금 판정 중인 파일 — 정화 함수 이름을 import 로 연결할 때 쓴다."""
    token = _FILE.set((filename, code))
    try:
        yield
    finally:
        _FILE.reset(token)


@contextmanager
def use_project(project: ProjectSanitizers | None):
    token = _PROJECT.set(project)
    try:
        yield
    finally:
        _PROJECT.reset(token)


def sanitizer_name_ok(
    name: str, local_defs: set[str], local_safe: set[str], project: ProjectSanitizers | None,
) -> bool:
    """이 이름의 호출을 정화로 인정하는가.

    우선순위: 이 파일의 본문 판정 → 트리의 본문 판정 → 어휘. 정의를 볼 수 있는데
    본문에 정화가 없으면 어휘에 맞아도 **거부**한다(``sanitizeMaybe`` 교훈).
    """
    short = name.rsplit(".", 1)[-1]
    if name in local_safe or short in local_safe:
        return True
    if name in local_defs or short in local_defs:
        return False
    if project is not None:
        cur = _FILE.get()
        resolved = project.resolve(name, cur[0] if cur else None, cur[1] if cur else None)
        if resolved is not None:
            return resolved
    if name.startswith(("DOMPurify.", "he.", "_.", "lodash.")):
        return True
    return bool(_SANITIZER_NAME_RE.match(short))


def is_vocab_sanitizer(name: str) -> bool:
    """이름이 표준 정화 어휘인가(`sanitize*`·`escapeHtml`·`esc`·`DOMPurify.*`).

    "direct"(발견을 내림)는 어휘 이름 + 본문 확인을 **둘 다** 요구한다. 본문만으로
    인정된 지역 함수(`processHtml` 이 `return sanitizeForRender(x)`)는 *추론*이라
    warn 까지만 내린다 — 그 함수가 모든 경로에서 정화하는지는 사람이 본다.
    """
    short = name.rsplit(".", 1)[-1]
    return name.startswith(("DOMPurify.", "he.", "_.", "lodash.")) or bool(_SANITIZER_NAME_RE.match(short))


def local_sanitizer_index(
    lines: list[str], project: ProjectSanitizers | None,
) -> tuple[set[str], set[str]]:
    """(정화 함수, 정화를 부르는 헬퍼 ⊇ 정화 함수, 모든 지역 함수 정의) 이름 집합.

    '모든 지역 정의'가 왜 필요한가: sink 바로 옆에 `sanitizeMaybe(x)` 처럼
    **이름만 정화인 호출**이 있을 때, 그것이 이 파일에 정의돼 있고 본문에
    정화가 없으면 정화로 쳐 주면 안 된다. 반대로 `DOMPurify.sanitize` 나
    import 된 `sanitizeForRender` 는 본문을 볼 수 없으므로 믿는다 —
    볼 수 없는 것을 의심해 전부 차단하면 아무도 쓰지 않는다.

    이름(`sanitizeX`)이 아니라 **본문**을 본다 — 이름은 아무 뜻이 없고,
    본문에 정화가 없는 헬퍼(실측의 `getCachedArticleHtml`)를 통과시키면
    의도적으로 정화를 끈 진짜 위험이 사라진다. 본문이 다른 정화 헬퍼를 부르는
    경우를 위해 고정점까지 반복한다(헬퍼가 헬퍼를 부르는 사슬).
    """
    defs: list[tuple[str, int, int]] = []          # (이름, 들여쓰기, 시작줄 index)
    for i, line in enumerate(lines):
        m = _DEF_RE.match(line)
        if m:
            defs.append((m.group(2) or m.group(3), len(m.group(1)), i))

    bodies: dict[str, str] = {}
    for idx, (name, indent, start) in enumerate(defs):
        # 본문 끝 = 같거나 더 바깥 들여쓰기의 다음 정의 직전(없으면 상한까지).
        end = min(start + _MAX_DEF_BODY_LINES, len(lines))
        for other_name, other_indent, other_start in defs[idx + 1:]:
            if other_start > start and other_indent <= indent:
                end = min(end, other_start)
                break
        body = "\n".join(lines[start:end])
        # **자기 이름은 지우고 본다.** 적대적 검증(2026-08-08)에서
        # `function sanitizeMaybe(h) { return h.trim() }` 가 통과했다 — 정의 줄의
        # `sanitizeMaybe(` 가 정화 호출로 읽힌 것이다. 이름은 아무것도 보장하지
        # 않는데, 이름만으로 통과시키면 '정화하는 척하는 헬퍼'가 게이트를 연다.
        bodies.setdefault(name, re.sub(rf"\b{re.escape(name)}\b", "", body))
    all_names = set(bodies)

    # 두 집합을 구분한다. **정화 함수**(sanitizers)는 본문이 직접 이스케이프하거나 정화
    # 호출을 반환한다 — 이 이름으로 감싼 값은 정화된 값이다. **헬퍼**(helpers)는 본문
    # 어딘가에서 정화를 부를 뿐이다(`_row()` 가 `${esc(m.name)}…${field}` 를 반환) —
    # 그 반환값 전체가 정화됐다고는 말할 수 없다. 헬퍼는 warn(추론)까지만 내린다.
    # 본문마다 "반환하는 호출 이름"과 "부르는 호출 이름"을 **한 번만** 뽑아 둔다. 예전에는
    # 본문 × 알려진 정화 함수 수만큼 정규식을 돌려 정화 함수 3천 + 일반 함수 3천인
    # 0.27MB 파일이 329초 걸렸다(적대적 검증 2026-09-19). 지금은 워크리스트로 선형이다.
    returns_of: dict[str, set[str]] = {n: {m.group(1) for m in _RETURN_SANITIZER_RE.finditer(b)} for n, b in bodies.items()}
    calls_of: dict[str, set[str]] = {n: set(_CALL_NAME_RE.findall(b)) for n, b in bodies.items()}
    sanitizers: set[str] = {n for n, b in bodies.items() if _body_escapes(b)}
    # 반환 호출이 (지역 정의가 아닌) 어휘·트리 정화 함수면 바로 정화 함수다.
    for name, rets in returns_of.items():
        if name in sanitizers:
            continue
        if any(r not in all_names and sanitizer_name_ok(r, all_names, sanitizers, project) for r in rets):
            sanitizers.add(name)
    # 지역 정화 함수를 반환하는 사슬 — 역방향 의존으로 전파(각 간선 한 번씩).
    dependents: dict[str, list[str]] = {}
    for name, rets in returns_of.items():
        for r in rets:
            if r in all_names:
                dependents.setdefault(r, []).append(name)
    work = list(sanitizers)
    while work:
        s = work.pop()
        for dep in dependents.get(s, ()):
            if dep not in sanitizers:
                sanitizers.add(dep)
                work.append(dep)
    helpers: set[str] = set(sanitizers)
    external_ok: dict[str, bool] = {}
    for name, calls in calls_of.items():
        if name in helpers:
            continue
        for c in calls:
            if c == name:
                continue
            if c in sanitizers:
                helpers.add(name)
                break
            if c in all_names:
                continue
            if c not in external_ok:
                external_ok[c] = bool(_SANITIZER_RE.match(c + "(")) and sanitizer_name_ok(c, all_names, sanitizers, project)
            if external_ok[c]:
                helpers.add(name)
                break
    return sanitizers, helpers, all_names


def _local_sanitizing_helpers(lines: list[str]) -> tuple[set[str], set[str], set[str]]:
    return local_sanitizer_index(lines, current_project())


def _is_style_element(lines: list[str], idx: int) -> bool:
    """sink 가 `<style ...>` 여는 태그 안에 있는가(여는 줄이 위에 있을 수 있다)."""
    for j in range(max(0, idx - _STYLE_LOOKBACK), idx + 1):
        if _STYLE_OPEN_RE.search(lines[j]):
            # 사이에 다른 태그가 열렸으면 style 이 아니다(보수적).
            between = "".join(lines[j:idx + 1])
            if not re.search(r"<(?!style\b)[A-Za-z]", between[between.index("<style") + 6:]):
                return True
    return False


_DIRECT_WRAP_RE = re.compile(
    r"\.(?:inner|outer)HTML\s*\+?=\s*(?:[\w$]+\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\("
    r"|insertAdjacentHTML\s*\(\s*['\"][A-Za-z]+['\"]\s*,\s*(?:[\w$]+\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\("
    r"|__html\s*:\s*\n?\s*(?:[\w$]+\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(",
)


def _sanitize_evidence(
    lines: list[str], idx: int, sanitizers: set[str], helpers: set[str], local_defs: set[str],
) -> str | None:
    """정화 정황의 **종류** — "direct" · "helper" · None.

    종류를 구분하는 이유: 주입 지점에 정화 호출이 그대로 있는 것은 *관찰*이고,
    헬퍼 본문을 보고 판단한 것은 *추론*이다. 확신의 정도가 다르면 등급도 달라야
    한다(실측 lexdiff: 직접 11건 · 추론 7건).
    """
    project = current_project()
    window = "\n".join(lines[idx:min(idx + _SINK_WINDOW, len(lines))])
    # "direct" 는 정화 호출이 값 **전체**를 감쌀 때만이다: `= esc(x)` · `__html: sanitize(`.
    # 예전에는 창(4줄) 안에 정화 호출이 하나라도 있으면 내렸다 — 여러 줄 템플릿에서
    # `${esc(title)}` 한 칸 때문에 `${f.note}` 가 함께 사라진다(적대적 검증 2026-09-18).
    for m0 in _DIRECT_WRAP_RE.finditer(window):
        name = m0.group(1) or m0.group(2) or m0.group(3) or ""
        # `이름만 정화`인 지역 함수는 인정하지 않는다. 적대적 검증에서
        # `sanitizeMaybe(h) { return h.trim() }` 가 그대로 통과했다.
        if is_vocab_sanitizer(name) and sanitizer_name_ok(name, local_defs, sanitizers, project):
            return "direct"             # 같은 줄 또는 바로 아래(다줄 JSX)
        if name in helpers:
            return "helper"             # 본문에 정화가 있는 지역 헬퍼로 감쌌다(추론)
    m = _HTML_VALUE_RE.search(window)
    if m and m.group(1) in helpers:
        return "helper"                 # 본문에 정화가 있는 지역 헬퍼를 거친다
    # `.innerHTML = name` 형태의 변수 경유도 같은 기준으로 본다.
    m2 = re.search(r"\.(?:inner|outer)HTML\s*\+?=\s*([A-Za-z_$][\w$]*)", lines[idx])
    return "helper" if (m2 and m2.group(1) in helpers) else None


_CONST_RHS_RE = re.compile(
    r"\.(?:inner|outer)HTML\s*\+?=(?!=)\s*(.*)$|insertAdjacentHTML\s*\(\s*['\"][A-Za-z]+['\"]\s*,\s*(.*)$",
)
_TEMPLATE_MAX_LINES = 80      # 다줄 템플릿 리터럴을 따라갈 상한(방어적)


def _tail_is_statement_end(tail: str) -> bool:
    """닫는 따옴표 뒤가 문장 끝인가 — ``;`` 로 시작하면 뒤는 **다른 문장**이다.

    실측(999건 사례): ``if (!x) { bar.innerHTML = ''; return; }`` 한 줄 블록 211건이
    "뒤에 뭔가 있다"는 이유로 상수로 인정되지 않았다. ``+``·``.concat`` 처럼 값을
    잇는 꼬리만 상수가 아니다.
    """
    tail = tail.strip()
    return tail == "" or tail.startswith((";", ")"))


def _rhs_is_constant_literal(lines: list[str], idx: int) -> bool:
    """``.innerHTML = <순수 문자열 리터럴>`` 인가 — 보간·결합이 없는 상수.

    ``el.innerHTML = ""`` · ``= '<p class="x">고정 문구</p>'`` · 다줄 템플릿 리터럴에
    ``${`` 가 하나도 없는 경우. 값의 출처가 코드 자체이므로 주입이 아니다.
    개선요청 #34 를 계기로 포털 HTML 을 실측하니 새 발견 26건 중 9건이 이 모양이었다
    (2026-08-30). ``+`` 결합·``${`` 보간·식별자는 상수가 아니다.
    """
    m = _CONST_RHS_RE.search(lines[idx])
    if m is None:
        return False
    rhs = (m.group(1) if m.group(1) is not None else m.group(2) or "").strip()
    if not rhs:
        return False
    q = rhs[0]
    if q in ("'", '"'):
        # 같은 줄에서 닫히고, 닫힌 뒤에 결합 연산자가 없어야 한다.
        end = rhs.find(q, 1)
        while end != -1 and rhs[end - 1] == "\\":
            end = rhs.find(q, end + 1)
        if end == -1:
            return False
        return _tail_is_statement_end(rhs[end + 1:])
    if q == "`":
        body = rhs[1:]
        j = idx
        while True:
            close = body.find("`")
            while close != -1 and close > 0 and body[close - 1] == "\\":
                close = body.find("`", close + 1)
            if close != -1:
                if "${" in body[:close]:
                    return False
                return _tail_is_statement_end(body[close + 1:])
            if "${" in body:
                return False
            j += 1
            if j >= len(lines) or j - idx > _TEMPLATE_MAX_LINES:
                return False            # 닫는 백틱을 못 찾음 — 보수적으로 상수 아님
            body = lines[j]
    return False


def attenuate_html_sink_findings(
    findings: list[Finding], code: str, filename: str,
) -> list[Finding]:
    """정화 정황·CSS 문맥이 있는 HTML sink 발견을 block → warn 으로 낮춘다.

    **삭제하지 않는다.** 낮춘 이유는 ``severity_adjusted`` 에 남아 보고서에 뜬다.
    """
    if not any(_SINK_RE.search(f.evidence or "") for f in findings):
        return findings

    lines = code.splitlines()
    if not lines:
        return findings
    sanitizers, helpers, local_defs = _local_sanitizing_helpers(lines)

    adjusted: list[Finding] = []
    for f in findings:
        idx = f.location.line - 1
        if (
            f.decision != Decision.block
            or f.confidence != "pattern-only"       # 정밀 엔진의 발견은 줄 휴리스틱으로 되돌리지 않는다
            or not (0 <= idx < len(lines))
            or not _SINK_RE.search(f.evidence or "")
        ):
            adjusted.append(f)
            continue

        if _rhs_is_constant_literal(lines, idx):
            # 값이 코드에 박힌 상수 — 주입할 외부 값이 없다(*관찰*). 내린다.
            continue
        evidence = _sanitize_evidence(lines, idx, sanitizers, helpers, local_defs)
        if evidence == "direct":
            # 주입 지점을 감싼 정화 호출이고, 그것이 '본문에 정화가 없는 지역
            # 함수'가 아님을 확인했다 — 여기서만 발견을 내린다. 예전 룰의
            # 삭제와 겉보기는 같지만 근거가 다르다: 그쪽은 줄에 `sanitize` 라는
            # **글자**가 있으면 지웠고(그래서 `sanitizeMaybe` 에 뚫렸다),
            # 이쪽은 그 이름이 이 파일에서 정화하지 않는 함수인지 **확인**한다.
            continue
        if evidence == "helper":
            reason, floor = _HELPER_REASON, Severity.medium
        elif _is_style_element(lines, idx):
            reason, floor = _STYLE_REASON, Severity.medium
        else:
            adjusted.append(f)          # 정황 없음 — 그대로 차단
            continue

        lowered = floor if f.severity in (Severity.critical, Severity.high) else f.severity
        adjusted.append(f.model_copy(update={
            "severity": lowered,
            "decision": Decision.warn,
            "requires_approval_to_bypass": False,
            "severity_adjusted": f"{f.severity.value} → {lowered.value} · {reason}",
        }))
    return adjusted


# ── js-taint 출처 판정에 따른 감쇄 ──────────────────────────────────────────

_TAINT_UNKNOWN_REASON = (
    "값의 출처를 추적하지 못함 — 패턴 후보(정밀 검토). 외부 입력·서버 응답이 "
    "이 값에 닿는지 확인하세요. 닿지 않으면 수용 예외로 기록하고, 닿으면 정화하세요"
)
_TAINT_SANITIZED_REASON = (
    "보간된 값이 모두 정화 호출을 거침(추론) — 정화 함수가 모든 경로에서 "
    "이스케이프하는지, 속성 문맥(따옴표 없는 attr)에 쓰이지 않는지 확인하세요"
)


def attenuate_by_taint_verdict(findings: list[Finding], verdicts: dict) -> list[Finding]:
    """js-taint 가 sink 줄의 출처를 판정한 경우, regex 차단을 그 판정에 맞춘다.

    - const     → 발견 없음(주입할 값이 없다 — html_sink_context 의 상수 판정과 같은 근거)
    - sanitized → warn · medium (추론 — 이유를 남긴다)
    - unknown   → warn · 심각도 유지 (정밀 검토 — 이 엔진이 보고도 출처를 못 찾았다)
    - tainted   → 손대지 않는다(js-taint 가 자기 발견을 냈고 dedupe 가 그것을 남긴다)

    판정이 없는 줄(엔진이 모르는 sink 모양, 엔진 실패)은 **그대로 차단**이다.
    """
    if not verdicts:
        return findings
    from .js_taint import CONST, SANITIZED, UNKNOWN
    out: list[Finding] = []
    for f in findings:
        v = verdicts.get(f.location.line)
        if (
            v is None
            or f.decision != Decision.block
            or f.engine != "regex"
            or f.rule_id not in ("KISA-JS-INPUT-04", "GOV-HTML-DOM-XSS-001")
        ):
            out.append(f)
            continue
        if v.state == CONST:
            continue
        if v.state == SANITIZED:
            lowered = Severity.medium if f.severity in (Severity.critical, Severity.high) else f.severity
            out.append(f.model_copy(update={
                "severity": lowered,
                "decision": Decision.warn,
                "requires_approval_to_bypass": False,
                "severity_adjusted": f"{f.severity.value} → {lowered.value} · {_TAINT_SANITIZED_REASON} ({v.reason})",
            }))
            continue
        if v.state == UNKNOWN:
            out.append(f.model_copy(update={
                "decision": Decision.warn,
                "requires_approval_to_bypass": False,
                "severity_adjusted": f"{f.severity.value} → {f.severity.value} (차단→검토) · {_TAINT_UNKNOWN_REASON} ({v.reason})",
            }))
            continue
        out.append(f)
    return out
