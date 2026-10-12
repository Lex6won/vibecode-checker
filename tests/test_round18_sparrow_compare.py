"""실측 비교(2026-10-13, 우체국보험 약관검색기 · 스패로우 vs 체커)에서 찾은 빈틈 — 회귀·적대적 검증.

스패로우는 `innerHTML` 8건을 전부 '보통'으로 냈고, 체커는 5건 중 2건을 '높음'으로 올렸다.
둘 다 실제 XSS 는 없었다(모든 자리가 정화돼 있었다). 체커의 '높음' 2건은 위험이 커서가
아니라 **출처 추적이 끊긴 자리**였고, 그 사이 메인 HTML 은 로고 base64 한 줄 때문에
검사조차 되지 않았으며, 앱이 만든 데이터 535개는 "외부 라이브러리"로 적혔다.

이 파일의 테스트는 두 축이다:
  ① 정상 패턴(여러 줄 선언·map(정화)·URL 인코딩·함수 지역 변수·숫자 이름)이 **내려가는가**
  ② 같은 모양의 진짜 위험(정화 없는 요소·부분 인코딩·decode·오염된 지역 변수)이 **그대로 차단인가**
"""

from __future__ import annotations

from pathlib import Path

from gvskb.scanner import (
    BUILD_ARTIFACT_SKIP_REASON,
    GENERATED_BUNDLE_SKIP_REASON,
    VENDOR_BUNDLE_SKIP_REASON,
    scan_code,
    scan_path,
)
from gvskb.schema import Decision

_ESC = "function esc(s){ return String(s ?? '').replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c])); }\n"


def _xss(code: str, filename: str = "app.js"):
    return [f for f in scan_code(code, filename=filename).findings if f.rule_id == "KISA-JS-INPUT-04"]


def _is_review(hits) -> bool:
    return bool(hits) and hits[0].decision == Decision.warn and "정화 호출" in (hits[0].severity_adjusted or "")


def _is_blocked(hits) -> bool:
    return bool(hits) and hits[0].decision == Decision.block


# ---------------------------------------------------------------------------
# 스캐너 — 무엇을 보고 무엇을 뺐는지
# ---------------------------------------------------------------------------


def test_html_with_embedded_base64_image_is_still_scanned(tmp_path: Path) -> None:
    """실측: 로고 `data:image/png;base64,…` 27,893자 한 줄 때문에 메인 HTML 전체가 빠졌다."""
    page = (
        "<!doctype html><html><body>\n"
        '<img src="data:image/png;base64,' + "iVBORw0KGgo" * 3000 + '">\n'
        "<script>\n"
        "document.getElementById('out').innerHTML = location.hash;\n"
        "</script>\n"
        "</body></html>\n"
    )
    (tmp_path / "page.html").write_text(page, encoding="utf-8")

    report = scan_path(tmp_path)

    assert "page.html" in {f.replace("\\", "/") for f in report.scanned_files}
    assert not any(s.reason == BUILD_ARTIFACT_SKIP_REASON for s in report.skipped_files)
    assert any(f.rule_id == "KISA-JS-INPUT-04" for f in report.findings), "HTML 안의 인라인 스크립트가 검사돼야 한다"


def test_data_uri_in_js_does_not_hide_the_code(tmp_path: Path) -> None:
    code = 'const logo = "data:image/png;base64,' + "AAAA" * 1000 + '";\n' + "el.innerHTML = location.hash;\n"
    (tmp_path / "app.js").write_text(code, encoding="utf-8")

    report = scan_path(tmp_path)

    assert "app.js" in {f.replace("\\", "/") for f in report.scanned_files}
    assert any(f.rule_id == "KISA-JS-INPUT-04" and f.decision == Decision.block for f in report.findings)


def test_genuinely_minified_html_is_still_excluded(tmp_path: Path) -> None:
    """과잉 교정 방지 — base64 가 아닌 진짜 압축 HTML 은 여전히 빌드 산출물이다."""
    (tmp_path / "page.html").write_text("<div>" + "<span>x</span>" * 500 + "</div>", encoding="utf-8")
    report = scan_path(tmp_path)
    assert any(s.reason == BUILD_ARTIFACT_SKIP_REASON for s in report.skipped_files)


def test_generated_data_shards_are_not_called_vendor_bundles(tmp_path: Path) -> None:
    """실측: `data/catalog.js`·해시 이름 gzip 조각 535개가 "벤더 번들(외부 라이브러리)"로 적혔다."""
    data = tmp_path / "data" / "pages"
    data.mkdir(parents=True)
    (tmp_path / "data" / "catalog.js").write_text(
        'window.TERMS_CATALOG_V1={"records":[' + '{"code":"1000000","name":"교육보험"},' * 200 + "]}", encoding="utf-8",
    )
    (data / ("0" * 64 + ".js")).write_text(
        'window.TERMS_TEXT_SHARDS=window.TERMS_TEXT_SHARDS||{};window.TERMS_TEXT_SHARDS["' + "0" * 64 + '"]="'
        + "H4sIAAAAAAAC/" * 400 + '";', encoding="utf-8",
    )
    # 대조군: 배너에 이름·버전이 있는 미니파이드 파일은 여전히 벤더 번들이다.
    (tmp_path / "moment.js").write_text("/*! moment.js v2.29.4 */\n" + "var a=1;" * 400, encoding="utf-8")

    report = scan_path(tmp_path)

    reasons = {s.path.replace("\\", "/"): s.reason for s in report.skipped_files}
    assert reasons["data/catalog.js"] == GENERATED_BUNDLE_SKIP_REASON
    assert reasons["data/pages/" + "0" * 64 + ".js"] == GENERATED_BUNDLE_SKIP_REASON
    assert reasons["moment.js"] == VENDOR_BUNDLE_SKIP_REASON
    assert [(b["name"], b["version"]) for b in report.vendor_bundles] == [("moment", "2.29.4")]


# ---------------------------------------------------------------------------
# 오염 추적 — ① 내려가야 하는 것 / ② 그대로 차단이어야 하는 것
# ---------------------------------------------------------------------------


def test_declaration_whose_arrow_body_continues_on_next_line_is_followed() -> None:
    """실측 app.js:79 — `const validities = (…).map((item) =>` 줄바꿈 뒤 정화 템플릿."""
    code = (
        _ESC
        + "function render(record) {\n"
        + "  const rows = (record.items || []).map((item) =>\n"
        + "    `${esc(item.a)} / ${esc(item.b)}`\n"
        + "  );\n"
        + "  el.innerHTML = `<div>${rows.length ? rows.join('<br>') : '없음'}</div>`;\n"
        + "}\n"
    )
    assert _is_review(_xss(code)), [(f.decision, f.severity_adjusted) for f in _xss(code)]


def test_multiline_declaration_with_unescaped_element_stays_blocked() -> None:
    code = (
        _ESC
        + "const data = JSON.parse(raw);\n"
        + "const rows = (data.items || []).map((item) =>\n"
        + "  `<td>${item.note}</td>`\n"
        + ");\n"
        + "el.innerHTML = rows.join('');\n"
    )
    assert _is_blocked(_xss(code)), [(f.decision, f.severity_adjusted) for f in _xss(code)]


def test_map_with_sanitizer_reference_is_sanitized() -> None:
    """실측 app.js:85 — `evidence.map(escapeHtml).join("<br>")`."""
    base = _ESC + "const data = JSON.parse(raw);\nconst notes = data.notes;\n"
    assert _is_review(_xss(base + "el.innerHTML = `<p>${notes.map(esc).join('<br>')}</p>`;\n"))
    assert _is_review(_xss(base + "el.innerHTML = `<p>${notes.map((n) => esc(n)).join('<br>')}</p>`;\n"))


def test_map_without_real_sanitizer_stays_blocked() -> None:
    base = _ESC + "const data = JSON.parse(raw);\nconst notes = data.notes;\n"
    for sink in (
        "el.innerHTML = `<p>${notes.map(String).join('<br>')}</p>`;\n",          # 정화가 아닌 함수
        "el.innerHTML = `<p>${notes.map((n) => n).join('<br>')}</p>`;\n",        # 그대로 통과
        "el.innerHTML = `<p>${notes.map((n) => esc(n) + n).join('<br>')}</p>`;\n",  # 부분 정화
    ):
        hits = _xss(base + sink)
        assert _is_blocked(hits), (sink, [(f.decision, f.severity_adjusted) for f in hits])


def test_url_encoding_is_html_safe_but_decoding_is_not() -> None:
    """`encodeURIComponent` 출력에는 `< > " &` 가 없다. 반대로 `decodeURIComponent` 는 출처다."""
    src = "const q = location.search;\n"
    assert _is_review(_xss(src + 'el.innerHTML = `<a href="/s?q=${encodeURIComponent(q)}">열기</a>`;\n'))
    assert _is_blocked(_xss(src + 'el.innerHTML = `<a href="/s?q=${encodeURIComponent(q)}">${q}</a>`;\n'))
    assert _is_blocked(_xss(src + 'el.innerHTML = `<a href="/s?q=${decodeURIComponent(q)}">열기</a>`;\n'))


def test_helper_return_resolves_its_own_local_variables() -> None:
    """실측 app.js:49 pdfUrl — `const suffix = …; return `…${suffix}``. 지역 변수는 그 함수 범위에서 찾는다."""
    code = (
        _ESC
        + "function pdfUrl(record, pageNumber) {\n"
        + "  const suffix = pageNumber ? `#page=${pageNumber}` : '';\n"
        + "  return `pdf/${encodeURIComponent(record.docId)}.pdf${suffix}`;\n"
        + "}\n"
        + "function render(record, hits) {\n"
        + '  el.innerHTML = hits.map((item) => `<a href="${pdfUrl(record, item.pageNumber)}">${item.pageNumber}</a>`).join(\'\');\n'
        + "}\n"
    )
    hits = _xss(code)
    assert _is_review(hits), [(f.decision, f.severity_adjusted) for f in hits]


def test_helper_whose_local_variable_is_tainted_stays_blocked() -> None:
    code = (
        _ESC
        + "function pdfUrl(record) {\n"
        + "  const suffix = location.hash;\n"
        + "  return `pdf/${encodeURIComponent(record.docId)}.pdf${suffix}`;\n"
        + "}\n"
        + 'el.innerHTML = `<a href="${pdfUrl(rec)}">열기</a>`;\n'
    )
    hits = _xss(code)
    assert _is_blocked(hits), [(f.decision, f.severity_adjusted) for f in hits]


def test_numeric_looking_names_are_not_unknown_but_input_names_still_are() -> None:
    # 숫자만 들어간 템플릿은 HTML 이 될 수 없다 — 발견이 없거나, 있어도 출처 미상은 아니다.
    hits = _xss("el.innerHTML = `<b>${rowCount}</b> / ${item.pageNumber} / ${total_count}`;\n")
    assert not hits or (hits[0].decision == Decision.warn and "찾지 못함" not in (hits[0].severity_adjusted or ""))
    # `userNumber` 는 이름이 입력값을 뜻한다 — 숫자 이름 규칙보다 먼저 잡힌다.
    assert _is_blocked(_xss("el.innerHTML = `<b>${userNumber}</b>`;\n"))
