"""HTML sink 문맥 감쇄 — 정화 정황이 있으면 차단을 낮추되 **지우지 않는다**.

이 모듈의 존재 이유는 실측 한 건에 있다(2026-08-08, lexdiff)::

    // 법제처 API 법령 본문 = 신뢰 소스. sanitize 생략으로 조당 ~30ms 절감.
    const html = extractArticleText(article, false, lawTitle)
    return <div dangerouslySetInnerHTML={{ __html: html }} />

`dangerouslySetInnerHTML={{ __html: 지역헬퍼(x) }}` 7건 중 6건은 헬퍼 본문이
`sanitizeForRender(...)` 로 끝나는 정상 방어였지만, 위 1건은 개발자가 **의도적으로
정화를 껐다**. "한 홉 따라가서 함수면 통과" 로 만들었다면 이 진짜 위험이 함께
사라졌을 것이다.

그래서 이 파일의 테스트는 두 축이다:
  ① 정화 정황이 있으면 block → warn 으로 **낮아지는가** (그리고 목록에 남는가)
  ② 본문에 정화가 없는 헬퍼는 **그대로 차단인가**  ← 이쪽이 더 중요하다
"""
from __future__ import annotations

from gvskb.scanner import scan_code
from gvskb.schema import Decision, Severity

_SANITIZED_HELPER = """\
import { sanitizeForRender } from '@/lib/sanitize-html-render'

export function Detail({ detail }) {
  const processHtml = React.useCallback((html: string) => {
    const cleaned = html.replace(/<br\\s*\\/?>/gi, '<br>')
    return sanitizeForRender(cleaned)
  }, [])

  return (
    <div dangerouslySetInnerHTML={{ __html: processHtml(detail.holdings) }} />
  )
}
"""

# 실측 그대로 — 헬퍼 본문에 정화가 없다(주석으로 '생략'을 명시했다).
_UNSANITIZED_HELPER = """\
const articleHtmlCache = new Map<string, string>()

function getCachedArticleHtml(article: LawArticle, lawTitle: string): string {
  const key = `${lawTitle}|${article.jo}`
  const cached = articleHtmlCache.get(key)
  if (cached !== undefined) return cached
  // 법제처 API 법령 본문 = 신뢰 소스. sanitize 생략으로 조당 ~30ms 절감.
  const html = extractArticleText(article, false, lawTitle)
  articleHtmlCache.set(key, html)
  return html
}

const ArticleContent = React.memo(function ArticleContent({ article, lawTitle }) {
  const html = useMemo(() => getCachedArticleHtml(article, lawTitle), [article])
  return <div dangerouslySetInnerHTML={{ __html: html }} />
})
"""

_MULTILINE_SANITIZE = """\
export function View({ item }) {
  return (
    <div
      dangerouslySetInnerHTML={{
        __html: sanitizeForRender(
          (item.content || '').replace(/<br>/g, '<br />')
        ),
      }}
    />
  )
}
"""

_STYLE_ELEMENT = """\
const ChartStyle = ({ id, config }) => {
  return (
    <style
      dangerouslySetInnerHTML={{
        __html: Object.entries(THEMES).map(([theme, prefix]) => `
${prefix} [data-chart=${id}] { --color: red; }
`).join("\\n"),
      }}
    />
  )
}
"""

_RAW_INJECTION = """\
export function Raw({ post }) {
  return <div dangerouslySetInnerHTML={{ __html: post.content }} />
}
"""


def _sink_findings(code: str, filename: str = "comp.tsx"):
    return [f for f in scan_code(code, filename=filename).findings
            if f.rule_id == "KISA-JS-INPUT-04"]


# ---------------------------------------------------------------------------
# ② 먼저 — 낮추면 안 되는 것들
# ---------------------------------------------------------------------------

def test_helper_without_sanitizer_in_body_stays_blocked() -> None:
    """헬퍼 **이름**이 아니라 **본문**을 본다. 본문에 정화가 없으면 그대로 차단.
    이 테스트가 무너지면 '의도적으로 정화를 끈' 진짜 위험이 조용히 사라진다."""
    hits = _sink_findings(_UNSANITIZED_HELPER)
    assert hits, "발견 자체가 사라졌습니다"
    assert any(f.decision == Decision.block for f in hits), \
        f"차단이 풀렸습니다: {[(f.decision, f.severity_adjusted) for f in hits]}"


def test_raw_value_stays_blocked() -> None:
    hits = _sink_findings(_RAW_INJECTION)
    assert any(f.decision == Decision.block for f in hits)


# ---------------------------------------------------------------------------
# ① 낮추되 지우지 않는다
# ---------------------------------------------------------------------------

def test_fake_sanitizer_named_helper_stays_blocked() -> None:
    """이름만 정화인 지역 함수는 인정하지 않는다.
    적대적 검증(2026-08-08)에서 `sanitizeMaybe(h){return h.trim()}` 가
    **룰의 같은-줄 부정탐색**을 통과해 발견 자체가 사라졌다 — 부분문자열
    `sanitize` 로 걸렀기 때문이다. 이제 룰은 거르지 않고, 여기서 본문을 본다."""
    code = (
        "function sanitizeMaybe(h) {\n"
        "  return h.trim()\n"
        "}\n"
        "const V = () => <div dangerouslySetInnerHTML={{ __html: sanitizeMaybe(x) }} />\n"
    )
    hits = _sink_findings(code)
    assert hits, "발견이 삭제되었습니다"
    assert any(f.decision == Decision.block for f in hits), \
        [(f.decision, f.severity_adjusted) for f in hits]


def test_local_sanitizing_helper_is_attenuated_not_deleted() -> None:
    """헬퍼 1홉은 **추론**이다 — 낮추되 medium 에 세워 확인 대상으로 남긴다."""
    hits = _sink_findings(_SANITIZED_HELPER)
    assert hits, "감쇄가 아니라 삭제되었습니다 — 목록에 남아야 합니다"
    assert all(f.decision == Decision.warn for f in hits)
    assert all(f.severity == Severity.medium for f in hits), [f.severity for f in hits]
    assert all("추론" in (f.severity_adjusted or "") for f in hits), \
        [f.severity_adjusted for f in hits]


def test_direct_trusted_sanitizer_call_is_dropped() -> None:
    """주입 지점을 감싼 정화 호출은 *관찰*이고 표준 정상 패턴이라 내린다.
    실측 lexdiff 에서 이 형태만 11건이었다 — 남기면 목록을 덮어 아무도 안 읽는다.
    예전 룰의 삭제와 겉보기는 같지만, 여기서는 그 이름이 이 파일에서 정화하지
    않는 함수인지 **확인한 뒤** 내린다(위 가짜 헬퍼 테스트가 그 경계다)."""
    code = (
        "import { sanitizeForRender } from '@/lib/sanitize'\n"
        "const V = () => <div dangerouslySetInnerHTML={{ __html: sanitizeForRender(x) }} />\n"
    )
    assert not _sink_findings(code)


def test_multiline_jsx_sanitizer_is_recognised() -> None:
    """줄 단위로는 다음 줄의 정화를 못 본다 — 창(window)으로 본다.
    실측 `virtualized-full-article-view.tsx:500` 이 이 모양으로 차단됐었다."""
    assert not _sink_findings(_MULTILINE_SANITIZE)


def test_multiline_jsx_without_sanitizer_still_blocks() -> None:
    """창을 넓힌 것이 '다줄이면 봐준다'가 되면 안 된다 — 반대 방향도 고정한다."""
    code = (
        "export function View({ item }) {\n"
        "  return (\n"
        "    <div\n"
        "      dangerouslySetInnerHTML={{\n"
        "        __html: item.content,\n"
        "      }}\n"
        "    />\n"
        "  )\n"
        "}\n"
    )
    hits = _sink_findings(code)
    assert any(f.decision == Decision.block for f in hits), \
        [(f.location.line, f.decision) for f in hits]


def test_style_element_is_attenuated_with_its_own_reason() -> None:
    """<style> 에 들어가는 것은 HTML 이 아니라 CSS — 즉시 XSS 는 아니지만
    </style> 탈출이 가능하므로 '안전'이 아니라 '경고'다."""
    hits = _sink_findings(_STYLE_ELEMENT)
    assert hits
    assert all(f.decision == Decision.warn for f in hits)
    assert all("</style>" in (f.severity_adjusted or "") for f in hits), \
        [f.severity_adjusted for f in hits]


def test_attenuation_reason_is_visible_in_report() -> None:
    """낮춘 사실이 보고서에 뜨지 않으면 '조용히 봐준 것'과 구별되지 않는다."""
    from gvskb.report import render_markdown

    report = scan_code(_SANITIZED_HELPER, filename="comp.tsx")
    md = render_markdown(report)
    assert "정화 호출" in md, md[:400]


# ---------------------------------------------------------------------------
# 경계 — 감쇄가 다른 것으로 새지 않는가
# ---------------------------------------------------------------------------

def test_sanitizer_elsewhere_in_file_does_not_clear_a_raw_sink() -> None:
    """파일 어딘가에 sanitize 가 있다는 이유만으로 낮추면 안 된다 —
    정화된 값과 안 된 값이 한 파일에 같이 있는 것이 정상이다."""
    code = _SANITIZED_HELPER + "\n" + _RAW_INJECTION
    hits = _sink_findings(code)
    assert any(f.decision == Decision.block for f in hits), \
        f"파일 전역 sanitize 로 전부 낮춰졌습니다: {[f.decision for f in hits]}"
    assert any(f.decision == Decision.warn for f in hits)


def test_non_html_findings_are_untouched() -> None:
    """이 감쇄기는 HTML sink 만 손댄다 — 다른 룰의 차단을 건드리면 안 된다."""
    code = 'const API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234";\n'
    report = scan_code(code, filename="x.mjs")
    secrets = [f for f in report.findings if f.rule_id.startswith("GOV-SECRET")]
    assert secrets and all(f.severity_adjusted is None for f in secrets)
