"""외부 연결 인벤토리 — 추출·집계·리포트 렌더 검증.

위반(Finding)이 아니라 검토용 목록이므로, 위험 건수(finding_count)에 섞이지
않고 별도 external_surface 로만 나타나는 것까지 확인한다.
"""
from __future__ import annotations

from pathlib import Path

from gvskb.report import render_html, render_markdown
from gvskb.scanner import scan_code, scan_path
from gvskb.scanners.external_surface import (
    dedupe_connections,
    extract_api_connections,
    inventory_packages,
)


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# 추출기
# ---------------------------------------------------------------------------


def test_extract_openai_sdk_call_maps_to_host_with_model() -> None:
    conns = extract_api_connections(
        'r = openai.chat.completions.create(model="gpt-4o", messages=m)', "chat.py"
    )
    assert len(conns) == 1
    c = conns[0]
    assert c.target == "api.openai.com"
    assert c.category == "ai"
    assert c.model == "gpt-4o"
    assert c.region == "국외"


def test_extract_pii_adjacent_across_multiline_call_is_warn() -> None:
    code = (
        "r = openai.chat.completions.create(model='gpt-4o',\n"
        "    messages=[{'role':'user','content': f'민원 {q} 전화 {phone}'}])\n"
    )
    conns = extract_api_connections(code, "chat.py")
    assert conns[0].pii_adjacent is True
    assert conns[0].review_level == "warn"


def test_extract_excludes_internal_hosts() -> None:
    code = "requests.post('http://10.0.0.5/api'); requests.get('http://localhost:3000/x')"
    assert extract_api_connections(code, "x.py") == []


def test_extract_sentry_dsn_host_is_clean_not_userinfo() -> None:
    # https://KEY@o4506.ingest.sentry.io/1 의 호스트는 o4506.ingest.sentry.io (KEY 아님)
    code = "Sentry.init({dsn: 'https://abc123@o4506.ingest.sentry.io/1'})"
    conns = extract_api_connections(code, "init.js")
    hosts = {c.target for c in conns}
    assert "o4506.ingest.sentry.io" in hosts
    assert "abc123" not in hosts


def test_extract_merges_same_host_in_one_file() -> None:
    code = (
        "m = genai.GenerativeModel('gemini-1.5-pro')\n"
        "out = m.generate_content(doc)\n"
    )
    conns = extract_api_connections(code, "sum.py")
    assert len(conns) == 1  # 한 파일의 같은 호스트는 1행으로 병합
    assert conns[0].model == "gemini-1.5-pro"


def test_inventory_packages_classifies_known_sdks() -> None:
    pkgs = [
        {"name": "openai", "version": "4.28.0"},
        {"name": "lodash", "version": "4.17.21"},
    ]
    conns = inventory_packages(pkgs, "package.json")
    by = {c.target: c for c in conns}
    assert by["openai"].category == "ai"
    assert by["openai"].version == "4.28.0"
    assert by["lodash"].category == "library"


def test_dedupe_sorts_warn_first() -> None:
    conns = (
        extract_api_connections("mixpanel.track('x', {})", "a.js")
        + extract_api_connections(
            "openai.chat.completions.create(messages=[{'content': '전화 010'}])", "b.py"
        )
    )
    ordered = dedupe_connections(conns)
    assert ordered[0].review_level == "warn"  # ⚠가 맨 위


# ---------------------------------------------------------------------------
# 스캐너 통합
# ---------------------------------------------------------------------------


def test_scan_code_populates_external_surface() -> None:
    report = scan_code(
        'openai.chat.completions.create(model="gpt-4o", messages=m)',
        filename="chat.py",
        language="python",
    )
    assert any(c.target == "api.openai.com" for c in report.external_surface)


def test_external_surface_not_counted_as_finding() -> None:
    # 외부 연결은 검토용 목록이지 위반이 아니다 — finding_count 에 섞이면 안 된다.
    report = scan_code(
        "mixpanel.track('view', {id: 1})", filename="track.js", language="javascript"
    )
    assert report.external_surface  # 외부 연결은 잡혔고
    assert report.summary.finding_count == 0  # 위험 건수에는 안 섞임


def test_scan_path_aggregates_api_and_packages(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", 'openai.chat.completions.create(model="gpt-4o", messages=m)\n')
    _write(tmp_path / "requirements.txt", "openai==4.28.0\nrequests>=2.0\n")
    _write(
        tmp_path / "package.json",
        '{"dependencies": {"mixpanel-browser": "^2.47.0"}}\n',
    )
    report = scan_path(tmp_path)
    targets = {c.target for c in report.external_surface}
    kinds = {c.kind for c in report.external_surface}
    assert "api.openai.com" in targets        # 코드의 API 호출
    assert "openai" in targets                # requirements.txt 패키지
    assert "mixpanel-browser" in targets      # package.json 패키지
    assert {"api", "package"} <= kinds


# ---------------------------------------------------------------------------
# 리포트 렌더
# ---------------------------------------------------------------------------


def _report_with_external():
    return scan_code(
        "openai.chat.completions.create(model='gpt-4o', messages=[{'content':'전화 010'}])",
        filename="chat.py",
        language="python",
    )


def test_render_html_has_inventory_section_and_card() -> None:
    html = render_html(_report_with_external())
    assert "외부 연결 인벤토리" in html
    assert "외부 연결 (" in html          # (A) 최상단 요약 카드
    assert "api.openai.com" in html
    # ⚠(PII) 있으면 기본 펼침(절충)
    assert 'class="sec inv" open' in html


def test_render_html_inventory_is_self_contained() -> None:
    html = render_html(_report_with_external()).lower()
    # 복사 버튼용 인라인 <script>는 외부 로딩이 아니므로 허용 — 외부 리소스를
    # '불러오는' 태그만 금지한다(망분리·이메일에서도 아무것도 로드하지 않음).
    for tag in ("<script src", "<iframe", "<link rel", "<img", "@import", "url(http"):
        assert tag not in html  # 외부 로딩 태그 없음


def test_render_markdown_has_inventory_section() -> None:
    md = render_markdown(_report_with_external())
    assert "## 외부 연결 인벤토리" in md
    assert "api.openai.com" in md
    assert "국외" in md


def test_no_inventory_section_when_no_external() -> None:
    report = scan_code("def add(a, b):\n    return a + b\n", filename="x.py", language="python")
    assert not report.external_surface
    # 섹션 마커로 확인(CSS 주석에 같은 한국어 문구가 있어 phrase 매칭은 부적절).
    assert 'class="sec inv"' not in render_html(report)
    assert "## 외부 연결 인벤토리" not in render_markdown(report)
# ---------------------------------------------------------------------------
# 운영주체·호출 지점 수 — 국외이전 검토는 "누구에게, 어느 나라로"가 특정돼야 한다
# ---------------------------------------------------------------------------


def test_api_connection_carries_operator_and_call_count() -> None:
    code = (
        'r1 = openai.chat.completions.create(model="gpt-4o", messages=m1)\n'
        "x = 1\n"
        'r2 = openai.chat.completions.create(model="gpt-4o", messages=m2)\n'
    )
    conns = extract_api_connections(code, "app.py")
    assert len(conns) == 1
    c = conns[0]
    assert c.operator == "OpenAI(미국)"
    assert c.call_count == 2          # 호출 지점 2곳
    assert c.location == "app.py:1"   # location은 첫 지점


def test_unknown_host_operator_is_none() -> None:
    conns = extract_api_connections('requests.post("https://api.unknown-vendor.io/v1/x")', "a.py")
    assert conns[0].operator is None


def test_package_operator_from_catalog() -> None:
    pkgs = inventory_packages(
        [{"name": "openai", "version": "1.2.0"}, {"name": "flask", "version": "2.0"}],
        "requirements.txt",
    )
    by_name = {c.target: c for c in pkgs}
    assert by_name["openai"].operator == "OpenAI(미국)"
    assert by_name["flask"].operator is None  # 로컬 라이브러리 — 전송 대상 없음/미상


def test_report_renders_operator_and_extra_call_sites(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", (
        'r1 = openai.chat.completions.create(model="gpt-4o", messages=m1)\n'
        'r2 = openai.chat.completions.create(model="gpt-4o", messages=m2)\n'
    ))
    report = scan_path(tmp_path)
    md = render_markdown(report)
    html = render_html(report)
    for out in (md, html):
        assert "OpenAI(미국)" in out          # 운영주체·국가
        assert "외 1곳" in out                 # 첫 지점 + 추가 호출 수
        assert "학습 이용·보존" in out          # 체크리스트 문구
