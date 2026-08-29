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
"""
from __future__ import annotations

import re

from ..schema import Decision, Finding, Severity

# 정화로 인정하는 호출. `sanitize\w*` 가 sanitizeForRender·sanitizeHtml 을 덮는다.
_SANITIZER_RE = re.compile(
    r"(?i)\b(?:DOMPurify|sanitiz\w*|escapeHtml|escapeHTML|purify|xss)\s*\(",
)

# 이 모듈이 손대는 sink. 값의 출처를 줄 하나로는 알 수 없는 것들.
_SINK_RE = re.compile(r"dangerouslySetInnerHTML|\.(?:inner|outer)HTML\s*=")

# 지역 정의 — `function foo(` · `const foo =` · `foo: (` (객체 메서드는 제외)
_DEF_RE = re.compile(
    r"^(\s*)(?:export\s+)?(?:default\s+)?(?:async\s+)?"
    r"(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=)"
)

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


def _local_sanitizing_helpers(lines: list[str]) -> tuple[set[str], set[str]]:
    """(정화하는 지역 정의, 모든 지역 정의) 이름 집합.

    '모든 지역 정의'가 왜 필요한가: sink 바로 옆에 `sanitizeMaybe(x)` 처럼
    **이름만 정화인 호출**이 있을 때, 그것이 이 파일에 정의돼 있고 본문에
    정화가 없으면 정화로 쳐 주면 안 된다. 반대로 `DOMPurify.sanitize` 나
    import 된 `sanitizeForRender` 는 본문을 볼 수 없으므로 믿는다 —
    볼 수 없는 것을 의심해 전부 차단하면 아무도 쓰지 않는다.

    이름(`sanitizeX`)이 아니라 **본문**을 본다 — 이름은 아무 뜻이 없고,
    본문에 정화가 없는 헬퍼(실측의 `getCachedArticleHtml`)를 통과시키면
    의도적으로 정화를 끈 진짜 위험이 사라진다.
    """
    defs: list[tuple[str, int, int]] = []          # (이름, 들여쓰기, 시작줄 index)
    for i, line in enumerate(lines):
        m = _DEF_RE.match(line)
        if m:
            defs.append((m.group(2) or m.group(3), len(m.group(1)), i))

    safe: set[str] = set()
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
        body = re.sub(rf"\b{re.escape(name)}\b", "", body)
        if _SANITIZER_RE.search(body):
            safe.add(name)
    return safe, {name for name, _, _ in defs}


def _is_style_element(lines: list[str], idx: int) -> bool:
    """sink 가 `<style ...>` 여는 태그 안에 있는가(여는 줄이 위에 있을 수 있다)."""
    for j in range(max(0, idx - _STYLE_LOOKBACK), idx + 1):
        if _STYLE_OPEN_RE.search(lines[j]):
            # 사이에 다른 태그가 열렸으면 style 이 아니다(보수적).
            between = "".join(lines[j:idx + 1])
            if not re.search(r"<(?!style\b)[A-Za-z]", between[between.index("<style") + 6:]):
                return True
    return False


def _sanitize_evidence(
    lines: list[str], idx: int, helpers: set[str], local_defs: set[str],
) -> str | None:
    """정화 정황의 **종류** — "direct" · "helper" · None.

    종류를 구분하는 이유: 주입 지점에 정화 호출이 그대로 있는 것은 *관찰*이고,
    헬퍼 본문을 보고 판단한 것은 *추론*이다. 확신의 정도가 다르면 등급도 달라야
    한다(실측 lexdiff: 직접 11건 · 추론 7건).
    """
    window = "\n".join(lines[idx:min(idx + _SINK_WINDOW, len(lines))])
    for call in _SANITIZER_RE.finditer(window):
        name = call.group(0).rstrip("( \t").rsplit(".", 1)[-1]
        # `이름만 정화`인 지역 함수는 인정하지 않는다. 적대적 검증에서
        # `sanitizeMaybe(h) { return h.trim() }` 가 그대로 통과했다.
        if name in local_defs and name not in helpers:
            continue
        return "direct"                 # 같은 줄 또는 바로 아래(다줄 JSX)
    m = _HTML_VALUE_RE.search(window)
    if m and m.group(1) in helpers:
        return "helper"                 # 본문에 정화가 있는 지역 헬퍼를 거친다
    # `.innerHTML = name` 형태의 변수 경유도 같은 기준으로 본다.
    m2 = re.search(r"\.(?:inner|outer)HTML\s*=\s*([A-Za-z_$][\w$]*)", lines[idx])
    return "helper" if (m2 and m2.group(1) in helpers) else None


_CONST_RHS_RE = re.compile(r"\.(?:inner|outer)HTML\s*=\s*(.*)$")
_TEMPLATE_MAX_LINES = 80      # 다줄 템플릿 리터럴을 따라갈 상한(방어적)


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
    rhs = m.group(1).strip()
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
        tail = rhs[end + 1:].strip().rstrip(";").strip()
        return tail == ""
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
                tail = body[close + 1:].strip().rstrip(";").strip()
                return tail == ""
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
    helpers, local_defs = _local_sanitizing_helpers(lines)

    adjusted: list[Finding] = []
    for f in findings:
        idx = f.location.line - 1
        if (
            f.decision != Decision.block
            or not (0 <= idx < len(lines))
            or not _SINK_RE.search(f.evidence or "")
        ):
            adjusted.append(f)
            continue

        if _rhs_is_constant_literal(lines, idx):
            # 값이 코드에 박힌 상수 — 주입할 외부 값이 없다(*관찰*). 내린다.
            continue
        evidence = _sanitize_evidence(lines, idx, helpers, local_defs)
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
