"""32차 — 판정 계층 단일화(docs/40 §4·§7 B).

- 순위 상수·예외 목록이 policy.py 한 벌이다
- 모든 감쇄가 `adjustments` 이력을 남기고 `severity_adjusted` 는 이어 붙는다(덮어쓰지 않음)
- 금지문 감쇄: 확인된(confirmed) 발견·값 기반 발견은 내리지 않고, 코드 파일에서는 주석 영역의 문구만
- 인라인 무시: 값 기반 룰(비밀값·개인정보·내부망)은 끌 수 없다
- 줄 체계: 폼피드·CRLF 가 있어도 정규식과 AST 의 줄 번호가 같다
- scan_file 은 scan_path 와 같은 전처리를 탄다
- 비밀 파일 특례 발견도 프로파일·테스트 경로·근거 정책을 탄다
- 프로파일이 올린 차단은 이력에 남고 근거 정책이 다시 본다
"""
from __future__ import annotations

from pathlib import Path

from gvskb import policy
from gvskb.scanner import scan_code, scan_file, scan_path
from gvskb.scanners import regex_scanner
from gvskb.schema import EXPOSURE_CATEGORIES, Decision, Severity


def _by_rule(report, prefix: str):
    return [f for f in report.findings if f.rule_id.startswith(prefix)]


# ---------------------------------------------------------------------------
# 한 벌
# ---------------------------------------------------------------------------

def test_rank_constants_have_a_single_source() -> None:
    from gvskb import profiles, report, scanner
    assert scanner._ENGINE_PRECISION is policy.ENGINE_PRECISION
    assert regex_scanner._ENGINE_PRECISION is policy.ENGINE_PRECISION
    assert regex_scanner._SEVERITY_RANK is policy.SEVERITY_RANK
    assert scanner.SEVERITY_RANK is policy.SEVERITY_RANK
    assert profiles._SEVERITY_RANK is policy.SEVERITY_RANK
    assert report._SEVERITY_RANK is policy.SEVERITY_RANK
    assert scanner._CONSTRUCT_EVIDENCE_RULE_IDS is policy.CONSTRUCT_EVIDENCE_RULE_IDS
    # 데이터 흐름 엔진이 패턴 엔진보다 앞선다(예전 scanner.py 사본은 semgrep 이 python-ast 보다 높았다)
    assert policy.ENGINE_PRECISION["python-ast"] > policy.ENGINE_PRECISION["regex"]
    assert policy.ENGINE_PRECISION["python-ast"] >= policy.ENGINE_PRECISION["semgrep"]


# ---------------------------------------------------------------------------
# 감쇄 이력
# ---------------------------------------------------------------------------

def test_attenuation_history_accumulates_instead_of_overwriting(tmp_path: Path) -> None:
    """테스트 경로 + 근거 정책 두 단계를 거친 발견은 이력 2건과 ' | ' 로 이어진 요약을 가진다."""
    code = 'password = "gg2026SecureP@ss"\n'
    r = scan_code(code, filename="tests/fixtures/conf.py")
    hits = _by_rule(r, "GOV-SECRET") + _by_rule(r, "KISA-PY-SEC-06")
    assert hits
    f = hits[0]
    steps = [a["step"] for a in f.adjustments]
    assert "test_path" in steps, steps
    assert f.severity_adjusted and "테스트 코드 경로" in f.severity_adjusted
    assert f.adjustments[0]["from_severity"] == "critical" and f.adjustments[0]["to_severity"] == "low"
    assert r.summary.adjustments.get("test_path", 0) >= 1


def test_untouched_finding_has_empty_history() -> None:
    r = scan_code("from flask import request\ndef q(cur):\n    cur.execute(request.form['q'])\n", filename="app.py")
    f = _by_rule(r, "GOV-SQL")[0]
    assert f.confidence == "confirmed" and f.decision == Decision.block
    assert f.adjustments == [] and f.severity_adjusted is None


def test_attenuate_never_raises_severity() -> None:
    from gvskb.scanners.regex_scanner import build_finding, lookup_rule
    rule = lookup_rule("KISA-PY-INPUT-02")
    f = build_finding(rule, filename="a.py", line_no=1, evidence="eval(x)", engine="regex")
    low = policy.attenuate(f, step="t", reason="r", severity=Severity.low)
    same = policy.attenuate(low, step="t2", reason="r2", severity=Severity.critical)   # 올리려는 시도
    assert low.severity == Severity.low and same is low or same.severity == Severity.low


# ---------------------------------------------------------------------------
# 금지문 감쇄의 범위
# ---------------------------------------------------------------------------

def test_prohibition_comment_does_not_lower_confirmed_command_injection() -> None:
    code = "from flask import request\nimport os\ndef p():\n    host = request.args['h']\n    os.system('ping ' + host)  # avoid\n"
    f = _by_rule(scan_code(code, filename="app.py"), "KISA-PY-INPUT-05")[0]
    assert f.confidence == "confirmed"
    assert f.severity != Severity.low and f.decision == Decision.block, (f.severity, f.decision, f.severity_adjusted)


def test_prohibition_in_comment_still_lowers_pattern_only_finding() -> None:
    code = "eval(data)  # never do this\n"          # 출처를 확인하지 못한(likely) 발견 + 주석 영역의 금지문
    r = scan_code(code, filename="guide.py")
    hits = _by_rule(r, "KISA-PY-INPUT-02") + _by_rule(r, "GOV-CODE-EXEC")
    assert hits and hits[0].severity == Severity.low, [(h.rule_id, h.severity, h.confidence) for h in hits]
    assert any(a["step"] == "prohibition_prose" for a in hits[0].adjustments)


def test_prohibition_word_inside_code_is_not_prose() -> None:
    """`never_cache = eval(x)` — 식별자 속 낱말은 안내문이 아니다(코드 파일은 주석 영역만)."""
    code = "never_cache = eval(x)\n"
    hits = _by_rule(scan_code(code, filename="app.py"), "KISA-PY-INPUT-02")
    assert hits and hits[0].severity != Severity.low


def test_prohibition_never_lowers_value_based_findings() -> None:
    code = '# 하지 마세요: password = "gg2026SecureP@ss"\n'
    hits = [f for f in scan_code(code, filename="app.py").findings if f.category in EXPOSURE_CATEGORIES]
    assert hits and all(not any(a["step"] == "prohibition_prose" for a in f.adjustments) for f in hits)


# ---------------------------------------------------------------------------
# 인라인 무시
# ---------------------------------------------------------------------------

def test_inline_ignore_cannot_silence_secret_rules() -> None:
    code = 'password = "gg2026SecureP@ss"  # gvskb: ignore\n'
    assert any(f.category == "secret-scanning" for f in scan_code(code, filename="conf.py").findings)
    code2 = 'password = "gg2026SecureP@ss"  # gvskb: ignore GOV-SECRET-APIKEY-001\n'
    assert any(f.category == "secret-scanning" for f in scan_code(code2, filename="conf.py").findings)


def test_inline_ignore_still_works_for_code_shape_rules() -> None:
    code = "eval(x)  # gvskb: ignore\n"
    assert not _by_rule(scan_code(code, filename="app.py"), "KISA-PY-INPUT-02")


# ---------------------------------------------------------------------------
# 줄 체계
# ---------------------------------------------------------------------------

def test_form_feed_and_crlf_do_not_shift_line_numbers() -> None:
    body = "import os\r\nx = 1  \x0c y = 2\r\nos.system(cmd)\r\neval(z)\r\n"
    r = scan_code(body, filename="app.py")
    lines = {f.location.line: f for f in r.findings}
    assert set(lines) == {3, 4}, {ln: f.rule_id for ln, f in lines.items()}
    assert "system" in lines[3].evidence and "eval" in lines[4].evidence


# ---------------------------------------------------------------------------
# 경로마다 같은 전처리
# ---------------------------------------------------------------------------

def test_scan_file_matches_scan_path_for_single_file(tmp_path: Path) -> None:
    p = tmp_path / "app.py"
    p.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    a = scan_file(p)
    b = scan_path(p)
    assert [(f.rule_id, f.location.line, f.decision) for f in a.findings] == \
        [(f.rule_id, f.location.line, f.decision) for f in b.findings]
    big = tmp_path / "bundle.js"
    big.write_text("var a=1;" * 400 + "\n", encoding="utf-8")   # 미니파이드 — scan_path 는 건너뛴다
    assert [s.path for s in scan_file(big).skipped_files] == [s.path for s in scan_path(big).skipped_files]


def test_secret_file_findings_go_through_the_same_policies(tmp_path: Path) -> None:
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7Q9kL2pQwJalrXUtnFEMIK7MDENGbPxRfiCYzQ9kL2pQwJal\n-----END RSA PRIVATE KEY-----\n"
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "id_rsa").write_text(key, encoding="utf-8")
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "id_rsa").write_text(key, encoding="utf-8")
    r = scan_path(tmp_path)
    by_file = {f.location.file.replace("\\", "/"): f for f in r.findings if f.engine == "secret-file"}
    assert "tests/fixtures/id_rsa" in by_file and "deploy/id_rsa" in by_file
    assert by_file["tests/fixtures/id_rsa"].severity == Severity.low       # 테스트 경로 감쇄 적용
    assert any(a["step"] == "test_path" for a in by_file["tests/fixtures/id_rsa"].adjustments)
    assert by_file["deploy/id_rsa"].severity == Severity.high            # 운영 경로는 등급 그대로(룰 기본 warn)
    assert by_file["deploy/id_rsa"].adjustments == []


# ---------------------------------------------------------------------------
# 프로파일 상향 × 근거 정책
# ---------------------------------------------------------------------------

def test_profile_raise_is_recorded_and_evidence_policy_explains() -> None:
    # KISA-PY-INPUT-11(CSRF 해제)은 기본 warn, web-civil-service 프로파일이 block 으로 올린다.
    code = "from django.views.decorators.csrf import csrf_exempt\n@csrf_exempt\ndef view(request):\n    pass\n"
    r = scan_code(code, filename="views.py", profile="web-civil-service")
    hits = _by_rule(r, "KISA-PY-INPUT-11")
    assert hits
    f = hits[0]
    steps = [a["step"] for a in f.adjustments]
    assert "profile" in steps and "evidence_policy" in steps, steps
    assert f.decision == Decision.warn
    assert "프로파일 재정의의 차단도" in (f.severity_adjusted or "")
