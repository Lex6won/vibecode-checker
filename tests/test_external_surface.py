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


def test_installer_download_hosts_are_classified_not_unclassified() -> None:
    """실측(응소ON): 온프레미스 설치 스크립트의 배포처가 전부 '미분류'로 남았다.

    운영 중 전송이 아니라 설치 자재 다운로드이므로 국외이전 검토 대상은 아니지만,
    폐쇄망에서는 곧 '설치 불가' 지점이라 무엇을 반입해야 하는지 드러나야 한다.
    """
    for host in ("nginx.org", "nginx.com", "nssm.cc", "slproweb.com",
                 "www.python.org", "github.com"):
        conns = extract_api_connections(f'curl https://{host}/download', "app.py")
        assert conns, f"{host} 를 잡지 못했다"
        c = conns[0]
        assert c.category == "infra", f"{host} 가 {c.category} 로 분류됐다"
        assert c.operator, f"{host} 의 운영주체가 비어 있다"


def test_doc_context_does_not_erase_known_host_warning() -> None:
    """문맥 표시가 카탈로그의 구체적 경고를 덮어쓰면 안 된다.

    실측(응소ON): 설치 가이드가 `Invoke-RestMethod https://api.ipify.org` 실행을
    안내하는데, 통짜 문구가 이를 '다운로드 주소'로 덮어써 '서버 공인 IP 노출'
    경고가 보고서에서 사라졌다 — 문서라는 이유로 위험을 지운 셈이다.
    """
    conns = extract_api_connections(
        "<code>Invoke-RestMethod https://api.ipify.org</code>",
        "deploy/서버설치가이드.html",
    )
    c = conns[0]
    assert "운영 중 전송 아님" in c.data_summary       # 문맥은 남기고
    assert "공인 IP" in c.data_summary                 # 경고는 지우지 않는다
    assert "다운로드 주소" not in c.data_summary


def test_doc_context_generic_text_only_when_host_unknown() -> None:
    """아는 게 없을 때만 통짜 문구를 쓴다(원래 노이즈 억제 의도는 유지)."""
    conns = extract_api_connections(
        "curl https://vendor-unknown-xyz.example/setup.zip", "deploy/install.bat"
    )
    assert conns[0].data_summary == "설치·안내 문서의 다운로드 주소(운영 중 전송 아님)"


def test_google_hosts_do_not_shadow_googleapis_entries() -> None:
    """부분 문자열 매칭이라 카탈로그 **순서**가 판정을 바꾼다 — 회귀 방지."""
    maps_api = extract_api_connections('requests.get("https://maps.googleapis.com/x")', "a.py")
    assert maps_api[0].data_summary.startswith("지도·좌표 요청")
    fonts = extract_api_connections('requests.get("https://fonts.googleapis.com/css")', "a.py")
    assert fonts[0].category == "cdn"
    gh_api = extract_api_connections('requests.get("https://api.github.com/repos/x")', "a.py")
    assert gh_api[0].data_summary == "저장소·릴리스 조회"


def test_google_maps_link_names_the_coordinate_risk() -> None:
    """실측(응소ON): 신고 좌표가 `maps?q={lat},{lon}` 로 외부에 실려 나갔다.

    _lookup_host 는 호스트만 보므로 용도를 단정할 수 없다 — 단정하는 대신
    확인 지점(경로)을 지목해야 검토자가 무엇을 볼지 안다.
    """
    conns = extract_api_connections(
        'link = f"https://www.google.com/maps?q={lat},{lon}"', "app.py"
    )
    c = conns[0]
    assert c.category == "platform"
    assert c.operator == "Google(미국)"
    assert "경로 확인 필요" in c.data_summary


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


# ---------------------------------------------------------------------------
# 외부 정적 리소스(CDN) — 폐쇄망(망분리) 영향 표시
# ---------------------------------------------------------------------------

_CDN_HTML = (
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=X">\n'
    '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n'
    '<script src="/static/local.js"></script>\n'
    '<a href="https://www.example.com/docs">docs</a>\n'
)


def _res(report):
    return [c for c in report.external_surface if c.kind == "resource"]


def test_cdn_script_and_link_detected_as_resource_breaks() -> None:
    r = scan_code(_CDN_HTML, filename="index.html", language="html")
    targets = {c.target for c in _res(r)}
    assert "cdn.jsdelivr.net" in targets
    assert "fonts.googleapis.com" in targets
    for c in _res(r):
        assert c.airgap_impact == "breaks"
        assert c.category == "cdn"
    jsd = next(c for c in _res(r) if c.target == "cdn.jsdelivr.net")
    assert jsd.operator == "jsDelivr(국외)"      # 카탈로그 운영주체
    assert jsd.region == "국외"


def test_anchor_href_is_not_a_resource() -> None:
    """<a href>는 이동 링크 — 리소스 로딩(화면 파손 신호)이 아니다."""
    r = scan_code(_CDN_HTML, filename="index.html", language="html")
    assert "www.example.com" not in {c.target for c in _res(r)}


def test_local_and_internal_resources_not_flagged() -> None:
    code = (
        '<script src="/static/app.js"></script>\n'
        '<script src="https://192.168.0.10/lib.js"></script>\n'
        '<link href="./style.css" rel="stylesheet">\n'
    )
    r = scan_code(code, filename="index.html", language="html")
    assert _res(r) == []


def test_css_import_and_esm_import_detected() -> None:
    css = '@import url("https://fonts.googleapis.com/css2?family=Y");\n'
    js = 'import confetti from "https://esm.sh/canvas-confetti";\n'
    assert _res(scan_code(css, filename="a.css", language="css"))
    assert _res(scan_code(js, filename="a.js", language="javascript"))


def test_resource_line_not_double_counted_as_api() -> None:
    """script src 줄의 호스트가 api로 중복 계상되면 안 된다."""
    r = scan_code(_CDN_HTML, filename="index.html", language="html")
    api_targets = {c.target for c in r.external_surface if c.kind == "api"}
    assert "cdn.jsdelivr.net" not in api_targets
    assert "fonts.googleapis.com" not in api_targets


def test_api_calls_marked_as_egress() -> None:
    code = 'requests.post("https://api.openai.com/v1/chat/completions")\n'
    r = scan_code(code, filename="app.py", language="python")
    api = [c for c in r.external_surface if c.kind == "api"]
    assert api and api[0].airgap_impact == "egress"


def test_report_renders_airgap_callout_and_resource_table() -> None:
    r = scan_code(_CDN_HTML, filename="index.html", language="html")
    md = render_markdown(r)
    html = render_html(r)
    for out in (md, html):
        assert "폐쇄망(망분리) 배포 시 확인" in out
        assert "로딩 실패" in out
        assert "SRI(integrity)" in out
        assert "외부 리소스 로딩 (CDN 등)" in out


def test_no_airgap_callout_without_external_points() -> None:
    r = scan_code("x = 1\n", filename="app.py", language="python")
    assert "폐쇄망(망분리) 배포 시 확인" not in render_markdown(r)


def test_external_connection_backcompat_without_airgap_field() -> None:
    """구버전 JSON(airgap_impact 없음)도 그대로 파싱된다."""
    from gvskb.schema import ExternalConnection
    c = ExternalConnection.model_validate(
        {"kind": "api", "target": "api.openai.com"}
    )
    assert c.airgap_impact is None
