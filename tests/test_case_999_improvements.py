"""실측 999건 사례(2026-09-16)에서 도출한 개선 — 회귀·적대적 검증.

사례의 본질은 미탐이 아니라 **구분 없는 과탐**이었다: innerHTML 873건 중 817건이
"패턴만 일치" 차단이었고, 진짜 저장형 XSS(`f.note`) 한 건이 그 안에 섞여 보이지
않았다. 동시에 유일한 서버 파일 `server.js`(1MB)가 크기 상한에 걸려 **검사조차
되지 않았는데** coverage 는 온전하다고 했다.

이 파일의 테스트는 두 축이다:
  ① 정상 패턴(상수·정화 템플릿·화면 폴백)이 차단에서 **내려가는가**
  ② 진짜 위험(외부 출처·가짜 정화·나중 오염·부분 정화)이 **그대로 차단인가** ← 더 중요
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from gvskb.gate import gate_status
from gvskb.scanner import (
    DEFAULT_MAX_FILE_BYTES,
    attenuate_upload_data_findings,
    content_tree_hash,
    path_class,
    scan_code,
    scan_path,
)
from gvskb.schema import Decision, Severity

_ESC = "function esc(s){ return String(s ?? '').replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c])); }\n"


def _xss(code: str, filename: str = "app.js"):
    return [f for f in scan_code(code, filename=filename).findings if f.rule_id == "KISA-JS-INPUT-04"]


# ---------------------------------------------------------------------------
# ② 먼저 — 내려가면 안 되는 것들 (적대적)
# ---------------------------------------------------------------------------

def test_fetch_response_into_template_is_blocked_confirmed() -> None:
    """사례의 `f.note`: 서버 응답을 정화 없이 템플릿에 넣는다. 다른 칸은 esc() 를 거쳤다."""
    code = (
        _ESC
        + "const data = await fetch('/api/files').then(r => r.json());\n"
        + "const html = data.files.map(f => `<tr><td>${esc(f.name)}</td><td>${f.note}</td></tr>`).join('');\n"
        + "tb.innerHTML = html;\n"
    )
    hits = _xss(code)
    assert hits and hits[0].decision == Decision.block
    assert hits[0].engine == "js-taint" and hits[0].confidence == "confirmed"


def test_multiline_template_with_partial_escape_is_blocked() -> None:
    """여러 줄 템플릿 — `${esc(title)}` 한 칸이 있다고 `${f.note}` 까지 내리면 안 된다.
    예전 '창(4줄) 안에 정화 호출이 있으면 direct' 규칙이 바로 여기서 뚫렸다."""
    code = (
        _ESC
        + "const FILES = JSON.parse(raw);\n"
        + "let html = '';\n"
        + "for (const f of FILES) {\n"
        + "  html += `\n"
        + "    <div class=\"f\">\n"
        + "      <b>${esc(f.name)}</b>\n"
        + "      <p>${f.note}</p>\n"
        + "    </div>`;\n"
        + "}\n"
        + "list.innerHTML = html;\n"
    )
    hits = _xss(code)
    assert hits and hits[0].decision == Decision.block, [(f.decision, f.severity_adjusted) for f in hits]


def test_sink_before_later_taint_is_not_dropped() -> None:
    """줄 순서 우회: sink 가 먼저 나오고 오염은 나중 함수에서 일어난다.
    sink 시점 상태(CONST)로 판정하면 발견이 **삭제**된다 — 파일 전체 기준으로 본다."""
    code = (
        "let html = '';\n"
        "function render(){ el.innerHTML = html; }\n"
        "async function load(){ html = await fetch('/api/x').then(r => r.json()); render(); }\n"
    )
    hits = _xss(code)
    assert hits, "발견이 사라졌습니다 — 나중 줄의 오염이 무시됐습니다"
    assert hits[0].decision == Decision.block


def test_fake_escape_with_entity_in_comment_is_not_trusted() -> None:
    """주석에 `&lt;` 를 적어 둔 가짜 정화 함수 — 본문 판정은 주석을 지우고 본다."""
    code = (
        "function esc(s){ /* replaces < with &lt; */ return s; }\n"
        "el.innerHTML = esc(req.body.comment);\n"
    )
    hits = _xss(code)
    assert hits and hits[0].decision == Decision.block, [(f.decision, f.severity_adjusted) for f in hits]


def test_fake_escape_with_entity_string_but_no_replace_is_not_trusted() -> None:
    code = (
        "function esc(s){ const marker = '&lt;'; return s + marker.length; }\n"
        "el.innerHTML = esc(location.hash);\n"
    )
    hits = _xss(code)
    assert hits and hits[0].decision == Decision.block


def test_escape_call_plus_raw_tail_is_not_sanitized() -> None:
    """`esc(a) + b` — 감싸지 않은 꼬리가 주입 지점이다."""
    code = _ESC + "el.innerHTML = esc(title) + userInput;\n"
    hits = _xss(code)
    assert hits and hits[0].decision == Decision.block


def test_plus_equals_sink_is_detected() -> None:
    """사례에서 `+=` 는 한 건도 잡히지 않았다 — 룰 패턴이 `=` 만 알았다."""
    hits = _xss("el.innerHTML += userInput;\n")
    assert hits and hits[0].decision == Decision.block


def test_comparison_is_not_a_sink() -> None:
    assert not _xss("if (el.innerHTML == '') render();\n")


def test_engine_failure_keeps_regex_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """js-taint 가 죽으면 '출처 미상 → 검토' 완화를 적용하지 않는다(fail-closed)."""
    from gvskb.scanners import js_taint

    def boom(code, project=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(js_taint, "classify_html_sinks", boom)
    r = scan_code("const html = build(x);\nel.innerHTML = html;\n", filename="app.js")
    hits = [f for f in r.findings if f.rule_id == "KISA-JS-INPUT-04"]
    assert hits and hits[0].decision == Decision.block
    assert any(e.name == "js-taint" for e in r.engines.failed)


def test_cross_file_unverified_escape_is_rejected(tmp_path: Path) -> None:
    """다른 파일에 정의된 `esc` 가 정화하지 않으면 어휘에 맞아도 인정하지 않는다."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "util.js").write_text("export function esc(s){ return s; }\n", encoding="utf-8")
    (tmp_path / "page.js").write_text(
        "import { esc } from './lib/util.js';\nel.innerHTML = esc(req.body.note);\n", encoding="utf-8"
    )
    r = scan_path(tmp_path)
    hits = [f for f in r.findings if f.rule_id == "KISA-JS-INPUT-04"]
    assert hits and hits[0].decision == Decision.block, [(f.decision, f.severity_adjusted) for f in hits]


# ---------------------------------------------------------------------------
# ① 내려가되 지우지 않는다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", [
    "if (!x) { bar.innerHTML = ''; return; }\n",
    "if (!FILES.length) { wrap.innerHTML = '<div class=\"e\">없음</div>'; return; }\n",
    "document.documentElement.innerHTML =\n  '<div>static</div>';\n",
    "el.innerHTML += '<li>고정</li>';\n",
    "list.insertAdjacentHTML('beforeend', '<hr>');\n",
])
def test_constant_assignments_are_not_findings(code: str) -> None:
    """사례의 상수 대입 211건 — 한 줄 블록(`= ''; return; }`)이 '뒤에 뭔가 있다'는 이유로 남았다."""
    assert not _xss(code), code


def test_escaped_template_is_review_not_block() -> None:
    code = (
        _ESC
        + "const html = rows.map(r => `<tr><td>${esc(r.name)}</td><td>${esc(r.note)}</td></tr>`).join('');\n"
        + "tb.innerHTML = html;\n"
    )
    hits = _xss(code)
    assert hits, "감쇄가 아니라 삭제되었습니다"
    assert hits[0].decision == Decision.warn and hits[0].severity == Severity.medium
    assert "정화 호출" in (hits[0].severity_adjusted or "")


def test_unknown_origin_is_review_with_reason() -> None:
    hits = _xss("const html = build(x);\nel.innerHTML = html;\n")
    assert hits and hits[0].decision == Decision.warn
    assert hits[0].severity == Severity.high, "심각도는 유지 — 판정만 검토로"
    assert hits[0].confidence == "pattern-only"
    assert "정밀 검토" in (hits[0].severity_adjusted or "")


def test_cross_file_verified_escape_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "util.js").write_text("export " + _ESC, encoding="utf-8")
    (tmp_path / "page.js").write_text(
        "import { esc } from './lib/util.js';\n"
        "const html = rows.map(r => `<td>${esc(r.name)}</td>`).join('');\n"
        "tb.innerHTML = html;\n",
        encoding="utf-8",
    )
    r = scan_path(tmp_path)
    hits = [f for f in r.findings if f.rule_id == "KISA-JS-INPUT-04"]
    assert hits and hits[0].decision == Decision.warn, [(f.decision, f.severity_adjusted) for f in hits]


def test_html_inline_script_multiline_template_with_escape() -> None:
    code = (
        "<html><body><script>\n" + _ESC
        + "const bd = document.getElementById('x');\n"
        + "bd.innerHTML = `\n  <div>${esc(title)}</div>\n  <div>${count.length}</div>`;\n"
        + "</script></body></html>\n"
    )
    hits = _xss(code, "page.html")
    assert hits and hits[0].decision == Decision.warn and hits[0].severity == Severity.medium


# ---------------------------------------------------------------------------
# 경로 역할 — 업로드 데이터 · 빌드 도구
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("public/uploads/cases/case_1.XML", "upload-data"),
    ("app/attachments/x.html", "upload-data"),
    ("_seed/std-ilwi/build.js", "build-tool"),
    ("scripts/migrate.js", "build-tool"),
    ("webpack.config.js", "build-tool"),
    ("public/tools/excel-light/app.js", "runtime"),   # 최상위가 아닌 tools 는 운영 코드
    ("src/media/js/app.js", "runtime"),
    ("tests/test_x.py", "test"),
    ("public/js/dashboard.js", "runtime"),
])
def test_path_class_roles(path: str, expected: str) -> None:
    assert path_class(path) == expected


def test_upload_data_attenuates_code_shape_but_keeps_pii() -> None:
    from gvskb.scanners.regex_scanner import build_finding, lookup_rule

    xss = build_finding(lookup_rule("KISA-JS-INPUT-04"), filename="public/uploads/a.html", line_no=1, evidence="x", engine="regex")
    pii = build_finding(lookup_rule("GOV-PII-RRN-001"), filename="public/uploads/a.xml", line_no=1, evidence="x", engine="regex")
    out = attenuate_upload_data_findings([xss, pii], "public/uploads/a.html")
    assert out[0].decision == Decision.warn and out[0].severity == Severity.low
    assert "업로드 데이터" in (out[0].severity_adjusted or "")
    assert out[1].decision == pii.decision and out[1].severity == pii.severity, "값 기반 발견은 그대로"


def test_summary_has_new_path_classes_and_confidence_split() -> None:
    r = scan_code("el.innerHTML = location.hash;\nconst h = build(x);\nel.innerHTML = h;\n", filename="a.js")
    s = r.summary
    assert set(s.by_path_class) >= {"runtime", "test", "sample", "upload-data", "build-tool"}
    assert s.has_block_level_findings == s.blocked is True
    assert sum(s.block_by_confidence.values()) == s.by_decision["block"]
    assert s.by_confidence["confirmed"] == 1


# ---------------------------------------------------------------------------
# 검사 범위 — 큰 실행 소스는 '판정 밖'이지 '이상 없음'이 아니다
# ---------------------------------------------------------------------------

def test_oversized_source_makes_gate_undetermined(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text("const a = 1;\n" * 20_000, encoding="utf-8")
    (tmp_path / "ok.js").write_text("const b = 2;\n", encoding="utf-8")
    r = scan_path(tmp_path, max_file_bytes=100_000)
    assert r.coverage.complete is False
    assert r.coverage.oversized_source_files == ["server.js"]
    assert r.coverage.truncated is False, "파일 수 상한과는 별개의 사실이다"
    g = gate_status(r)
    assert g["verdict"] == "undetermined"
    assert "server.js" in g["reason"] and "안전하다는 뜻이 아닙니다" in g["reason"]


def test_oversized_source_with_findings_adds_coverage_criterion(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text("const a = 1;\n" * 20_000, encoding="utf-8")
    (tmp_path / "bad.js").write_text("el.innerHTML = location.hash;\n", encoding="utf-8")
    g = gate_status(scan_path(tmp_path, max_file_bytes=100_000))
    assert g["verdict"] == "conditional"
    assert "coverage" in g["conditional_criteria"]
    assert "검사되지 않은 실행 소스" in g["reason"]


def test_oversized_data_file_does_not_break_completeness(tmp_path: Path) -> None:
    (tmp_path / "seed.json").write_text('{"a": 1}\n' * 20_000, encoding="utf-8")
    (tmp_path / "ok.js").write_text("const b = 2;\n", encoding="utf-8")
    r = scan_path(tmp_path, max_file_bytes=100_000)
    assert r.coverage.complete is True
    assert r.coverage.oversized_data_count == 1 and r.coverage.oversized_source_count == 0
    assert gate_status(r)["verdict"] == "approved"


def test_default_limit_covers_the_case_server_file() -> None:
    assert DEFAULT_MAX_FILE_BYTES >= 1_027_071


def test_oversized_banner_in_reports(tmp_path: Path) -> None:
    from gvskb.report import render_html, render_markdown

    (tmp_path / "server.js").write_text("const a = 1;\n" * 20_000, encoding="utf-8")
    r = scan_path(tmp_path, max_file_bytes=100_000)
    assert "검사되지 않았습니다" in render_markdown(r) and "server.js" in render_markdown(r)
    assert "server.js" in render_html(r)


def test_cli_repro_command_carries_max_file_bytes() -> None:
    import argparse

    from gvskb.cli import _scan_reproduce_command

    args = argparse.Namespace(path="x", profile="public-default-strict", scenario=None,
                              max_files=20_000, max_file_bytes=16_000_000)
    assert "--max-file-bytes 16000000" in _scan_reproduce_command(args)


# ---------------------------------------------------------------------------
# 소스 결속 — dirty 여도 무엇을 읽었는지 증명한다
# ---------------------------------------------------------------------------

def test_content_tree_hash_is_deterministic_and_path_normalized(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("const a = 1;\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.js").write_text("const b = 2;\n", encoding="utf-8")
    r1, r2 = scan_path(tmp_path), scan_path(tmp_path)
    snap = r1.source_snapshot
    assert snap is not None and snap.content_tree_hash and snap.file_count == 2
    assert snap.content_tree_hash == r2.source_snapshot.content_tree_hash
    assert set(snap.file_hashes) == {"a.js", "sub/b.js"}, "경로는 / 로 정규화"
    assert content_tree_hash({"sub/b.js": "x", "a.js": "y"}) == content_tree_hash({"a.js": "y", "sub/b.js": "x"})
    (tmp_path / "a.js").write_text("const a = 2;\n", encoding="utf-8")
    assert scan_path(tmp_path).source_snapshot.content_tree_hash != snap.content_tree_hash


# ---------------------------------------------------------------------------
# 작은 정확도 수정
# ---------------------------------------------------------------------------

def test_recursion_rule_ignores_member_call_delegation() -> None:
    code = "function guessFields(text) { return window.VendorContactExtract.guessFields(text); }\n"
    assert not [f for f in scan_code(code, filename="a.js").findings if f.rule_id == "KISA-JS-TIME-01"]
    tp = "function factorial(x) { return x * factorial(x - 1); }\n"
    assert [f for f in scan_code(tp, filename="a.js").findings if f.rule_id == "KISA-JS-TIME-01"]


def test_xml_namespace_urls_are_not_external_connections() -> None:
    from gvskb.scanners.external_surface import extract_api_connections

    code = (
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">\n'
        'const NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";\n'
        'const DC = "http://purl.org/dc/elements/1.1/";\n'
        'fetch("https://api.openai.com/v1/chat");\n'
    )
    hosts = {c.target for c in extract_api_connections(code, "a.js")}
    assert hosts == {"api.openai.com"}


def test_swallowed_exception_frontend_vs_backend() -> None:
    front = "<script>\ntry { PageHeader.render(); } catch (e) { console.warn(e); }\n</script>\n"
    hits = [f for f in scan_code(front, filename="page.html").findings if f.rule_id == "KISA-JS-ERR-03"]
    assert hits and hits[0].severity == Severity.low and "프런트엔드" in (hits[0].severity_adjusted or "")

    back = "const jwt = require('jsonwebtoken');\ntry { key = getKey(); } catch (e) { console.log(e); }\n"
    hits = [f for f in scan_code(back, filename="server.js").findings if f.rule_id == "KISA-JS-ERR-03"]
    assert hits and hits[0].severity == Severity.medium and not hits[0].severity_adjusted

    front_auth = "<script>\ntry { token = login(user); } catch (e) {}\n</script>\n"
    hits = [f for f in scan_code(front_auth, filename="page.html").findings if f.rule_id == "KISA-JS-ERR-03"]
    assert hits and hits[0].severity == Severity.medium, "화면 코드여도 인증 문맥이면 유지"


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - (9 if d > 4 else 0)
        total += d
    return total % 10 == 0


def _luhn_number(prefix: str = "401488881234") -> str:
    for last in range(10):
        n = prefix + "000" + str(last)
        if _luhn_ok(n):
            return f"{n[:4]}-{n[4:8]}-{n[8:12]}-{n[12:]}"
    raise AssertionError


def test_card_number_in_material_code_field_is_review() -> None:
    num = _luhn_number()
    ctx = f"<자재코드>{num}</자재코드>\n"
    hits = [f for f in scan_code(ctx, filename="a.xml").findings if f.rule_id == "GOV-PII-CARD-001"]
    assert hits and hits[0].decision == Decision.warn and hits[0].severity == Severity.medium
    pay = f"card_number = '{num}'\n"
    hits = [f for f in scan_code(pay, filename="pay.py").findings if f.rule_id == "GOV-PII-CARD-001"]
    assert hits and hits[0].decision == Decision.block, "결제 문맥은 그대로 차단"
    bare = f"x = '{num}'\n"
    hits = [f for f in scan_code(bare, filename="a.py").findings if f.rule_id == "GOV-PII-CARD-001"]
    assert hits and hits[0].decision == Decision.block, "문맥이 없으면 낮추지 않는다"


# ---------------------------------------------------------------------------
# 성능 가드 — 분류기가 이차 시간으로 터지지 않는다
# ---------------------------------------------------------------------------

def test_classifier_scales_on_sink_heavy_file() -> None:
    body = _ESC + "".join(
        f"const html{i} = rows.map(r => `<tr><td>${{esc(r.a{i})}}</td></tr>`).join('');\n"
        f"document.getElementById('t{i}').innerHTML = html{i};\n"
        for i in range(400)
    )
    t = time.perf_counter()
    r = scan_code(body, filename="big.js")
    assert time.perf_counter() - t < 8.0
    xss = [f for f in r.findings if f.rule_id == "KISA-JS-INPUT-04"]
    assert len(xss) == 400 and all(f.decision == Decision.warn for f in xss)


# ---------------------------------------------------------------------------
# 2차 적대적 검증(Codex, 2026-09-19) — 동명 정화 함수 · 변수 범위 · 이차 시간
# ---------------------------------------------------------------------------

def test_conflicting_esc_definitions_follow_the_import(tmp_path: Path) -> None:
    """safe-helper 의 정상 esc 와 unsafe-helper 의 `return s` esc 가 공존한다.
    unsafe 쪽을 import 한 페이지의 `esc(location.hash)` 는 발견 0건이었다(P0 미탐)."""
    (tmp_path / "safe-helper.js").write_text("export " + _ESC, encoding="utf-8")
    (tmp_path / "unsafe-helper.js").write_text("export function esc(s){ return s; }\n", encoding="utf-8")
    (tmp_path / "page.js").write_text(
        "import { esc } from './unsafe-helper.js';\nel.innerHTML = esc(location.hash);\n", encoding="utf-8"
    )
    (tmp_path / "ok.js").write_text(
        "import { esc } from './safe-helper.js';\nel.innerHTML = esc(location.hash);\n", encoding="utf-8"
    )
    r = scan_path(tmp_path)
    by_file = {f.location.file.replace("\\", "/"): f for f in r.findings if f.rule_id == "KISA-JS-INPUT-04"}
    assert "page.js" in by_file and by_file["page.js"].decision == Decision.block, by_file
    assert "ok.js" not in by_file, "정상 esc 를 import 한 쪽은 직접 정화 → 발견 없음"


def test_conflicting_esc_without_import_is_not_trusted(tmp_path: Path) -> None:
    """import 가 없어 연결을 모르면, 트리 안에서 뜻이 갈리는 이름은 믿지 않는다."""
    (tmp_path / "a.js").write_text(_ESC, encoding="utf-8")
    (tmp_path / "b.js").write_text("function esc(s){ return s; }\n", encoding="utf-8")
    (tmp_path / "page.js").write_text("el.innerHTML = esc(location.hash);\n", encoding="utf-8")
    hits = [f for f in scan_path(tmp_path).findings if f.rule_id == "KISA-JS-INPUT-04"]
    assert hits and hits[0].decision == Decision.block


def test_html_script_src_links_the_escape_definition(tmp_path: Path) -> None:
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "util.js").write_text(_ESC, encoding="utf-8")
    (tmp_path / "page.html").write_text(
        '<script src="/js/util.js"></script>\n<script>\nel.innerHTML = esc(location.hash);\n</script>\n',
        encoding="utf-8",
    )
    assert not [f for f in scan_path(tmp_path).findings if f.rule_id == "KISA-JS-INPUT-04"]


def test_same_variable_name_in_different_functions_does_not_cross_taint() -> None:
    """Codex 재현 1 — bad() 의 html 이 safe() 의 html 을 오염시키면 안 된다."""
    code = (
        "function bad(req) {\n  let html = req.body.note;\n}\n\n"
        "function safe() {\n  const html = '<p>safe</p>';\n  el.innerHTML = html;\n}\n"
    )
    assert not _xss(code)


def test_reassignment_order_within_one_function_is_respected() -> None:
    """Codex 재현 2 — 같은 함수 안에서 상수로 재할당하면 sink 시점 값은 상수다."""
    assert not _xss("let html = req.body.note;\nhtml = '<p>safe</p>';\nel.innerHTML = html;\n")
    hits = _xss("let html = '<p>';\nhtml = req.body.note;\nel.innerHTML = html;\n")
    assert hits and hits[0].decision == Decision.block


def test_module_variable_assigned_in_another_function_stays_tainted() -> None:
    """범위 인식이 예전 우회(다른 함수의 나중 오염)를 되살리면 안 된다."""
    code = "let html = '';\nconst load = () => { html = location.hash; };\nfunction render(){ el.innerHTML = html; }\n"
    hits = _xss(code)
    assert hits and hits[0].decision == Decision.block


def test_shadowed_local_constant_is_not_tainted_by_outer() -> None:
    code = "let html = req.body.x;\nfunction render(){ const html = '<b>ok</b>'; el.innerHTML = html; }\n"
    assert not _xss(code)


def test_mixed_sanitizer_and_plain_functions_scale_linearly() -> None:
    """정화 함수 3천 + 일반 함수 3천 = 0.27MB 가 329초 걸렸다(본문 × 알려진 이름 정규식)."""
    code = "\n".join(
        (f"function f{i}(x){{ return x.replace(/</g,'&lt;'); }}" if i % 2 else f"function g{i}(x){{ return x + {i}; }}")
        for i in range(6000)
    ) + "\nel.innerHTML = f1(a);\n"
    t = time.perf_counter()
    scan_code(code, filename="big.js")
    assert time.perf_counter() - t < 15.0


def test_upload_data_urls_are_not_external_connections(tmp_path: Path) -> None:
    (tmp_path / "public" / "uploads").mkdir(parents=True)
    (tmp_path / "public" / "uploads" / "case.xml").write_text(
        '<doc><link>https://vendor.example.com/api/v1/items</link></doc>\n', encoding="utf-8"
    )
    (tmp_path / "app.js").write_text('fetch("https://api.openai.com/v1/chat");\n', encoding="utf-8")
    hosts = {c.target for c in scan_path(tmp_path).external_surface}
    assert hosts == {"api.openai.com"}


# ---------------------------------------------------------------------------
# 3차 — 원본 소스(2026-09-19 zip)로 재검증하며 찾은 빈틈. 실제 f.note 모양 그대로.
# ---------------------------------------------------------------------------

_RT_SHAPE = (
    "const esc = s => String(s == null ? '' : s).replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;'}[c]));\n"
    "let RT_FIELDS = null;\n"
    "function _rtReadSingleRow() {\n"
    "  const gt = k => { const el = document.querySelector(`#rtBody [data-k=\"t_${k}\"]`); return el ? el.textContent.trim() : ''; };\n"
    "  return { name: '', target: gt('target'), note: gt('note') };\n"
    "}\n"
    "function rtAddField() {\n"
    "  if (!RT_FIELDS) { RT_FIELDS = [_rtReadSingleRow()]; }\n"
    "}\n"
    "function rtRenderMulti() {\n"
    "  let html = '';\n"
    "  RT_FIELDS.forEach((f, i) => {\n"
    "    html += `\n"
    "    <tr data-fi=\"${i}\">\n"
    "      <td>${esc(f.target)}</td>\n"
    "      <td>${NOTE_CELL}</td>\n"
    "    </tr>`;\n"
    "  });\n"
    "  $('rtBody').innerHTML = html;\n"
    "}\n"
)


def test_real_stored_xss_shape_is_blocked_and_fixed_shape_is_review() -> None:
    """실측 dept-consultation.html:1261 — 배열 리터럴 → 헬퍼 → 객체 리터럴 → textContent 경로."""
    vuln = _xss(_RT_SHAPE.replace("${NOTE_CELL}", "${f.note}"))
    assert vuln and vuln[0].decision == Decision.block and vuln[0].engine == "js-taint", \
        [(f.decision, f.severity_adjusted) for f in vuln]
    fixed = _xss(_RT_SHAPE.replace("${NOTE_CELL}", "${esc(f.note)}"))
    assert fixed and fixed[0].decision == Decision.warn and "정화 호출" in (fixed[0].severity_adjusted or "")


def test_callback_index_param_is_not_unknown() -> None:
    code = _ESC + "el.innerHTML = rows.map((r, i) => `<td>${i + 1}</td><td>${esc(r.n)}</td>`).join('');\n"
    hits = _xss(code)
    assert hits and hits[0].decision == Decision.warn and "정화 호출" in (hits[0].severity_adjusted or "")


def test_count_like_names_are_not_treated_as_input() -> None:
    hits = _xss("el.innerHTML = `<b>${userHiddenCnt}</b>`;\n")
    assert hits and hits[0].decision == Decision.warn, "…Cnt/…Count 는 숫자 — 이름만으로 오염이 아니다"
    hits = _xss("el.innerHTML = `<b>${userName}</b>`;\n")
    assert hits and hits[0].decision == Decision.block
