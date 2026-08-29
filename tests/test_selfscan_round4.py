"""자기검사(2026-08-29) 4차 — 구조 기반 감쇄.

- S-2 문자열 리터럴: 테스트가 `scan_code("eval(x)")` 처럼 문자열로 넣은 취약 조각
  159건이 전부 critical·block 이었다(tokenize 로 159/159 확인). 실행되는 코드가
  아니므로 낮추되 **지우지 않는다**(코드 생성기가 취약 코드를 문자열로 써내는 사례).
- S-3 룰 정의 문서: 파일명에 secret/password 가 든 룰 문서 6개가 '비밀 파일 특례'로
  스캔돼 룰의 예시 코드가 치명으로 올라왔다. 경로가 아니라 **구조 마커**로 인식한다.
- S-5 값 기반 LLM 룰의 테스트 경로 감쇄, S-6 금지문 정규식 보완.
"""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code, scan_path


def _find(code: str, filename: str = "app.py"):
    return scan_code(code, filename=filename).findings


def _one(code: str, rule: str, filename: str = "app.py"):
    fs = [f for f in _find(code, filename) if f.rule_id == rule]
    assert fs, f"{rule} 가 발화해야 한다: {code!r}"
    return fs[0]


# ── S-2: 문자열 리터럴 안의 코드 모양 ────────────────────────────────────────

@pytest.mark.parametrize("code, rule", [
    ('code = "eval(x)"', "GOV-CODE-EXEC-001"),
    ("snippet = 'os.system(cmd)'", "KISA-PY-INPUT-05"),
    ('assert "exec(payload)" in report', "KISA-PY-INPUT-02"),
    ('doc = """\nexample: subprocess.run(cmd, shell=True)\n"""', "GOV-CMD-INJECTION-001"),
])
def test_code_shape_inside_string_literal_is_attenuated_not_deleted(code, rule):
    f = _one(code, rule)
    assert f.severity.value == "low" and f.decision.value != "block"
    assert f.severity_adjusted and "문자열 리터럴" in f.severity_adjusted


@pytest.mark.parametrize("code, rule", [
    ('exec("import os; os.system(\'id\')")', "GOV-CODE-EXEC-001"),   # 바깥의 exec( 가 진짜
    ('subprocess.run("rm -rf " + path, shell=True)', "GOV-CMD-INJECTION-001"),
    ('os.system(f"del {name}")', "KISA-PY-INPUT-05"),
    ('cursor.execute("SELECT * FROM t WHERE id=%s" % request.args["id"])', "KISA-PY-INPUT-01"),
    ("cursor.execute(f\"SELECT * FROM t WHERE id={request.args['id']}\")", "GOV-SQL-INJECTION-001"),
])
def test_real_code_outside_string_stays_blocked(code, rule):
    f = _one(code, rule)
    assert f.decision.value == "block", f
    assert not (f.severity_adjusted and "문자열 리터럴" in f.severity_adjusted)


def test_string_literal_attenuation_does_not_touch_exposure_rules():
    """비밀값·개인정보는 문자열 안에 있는 것이 정상 형태다 — 낮추면 안 된다."""
    f = _one('key = "sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"', "GOV-SECRET-APIKEY-001")
    assert f.decision.value == "block"


def test_unparseable_python_is_not_attenuated():
    f = _one('def broken(:\n    code = "eval(x)"', "GOV-CODE-EXEC-001")
    assert not (f.severity_adjusted and "문자열 리터럴" in f.severity_adjusted)


# ── S-3: 룰 정의 문서 ───────────────────────────────────────────────────────

_RULE_DOC = """---
id: GOV-SECRET-DEMO-001
severity: critical
detection:
  patterns:
    - 'sk-[A-Za-z0-9_-]{20,}'
examples:
  positive:
    - 'API_KEY = "sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"'
    - 'password = "hunter2plus9"'
---
"""


def test_rule_definition_document_examples_are_attenuated(tmp_path):
    (tmp_path / "GOV-SECRET-DEMO-001.md").write_text(_RULE_DOC, encoding="utf-8")
    rep = scan_path(str(tmp_path))
    assert rep.findings, "룰 문서라도 발견을 지우지는 않는다"
    assert all(f.decision.value != "block" for f in rep.findings), [f.rule_id for f in rep.findings]
    # 비밀 자재 검사(secret-file 엔진)는 룰 문서라도 낮추지 않는다 — 예시에 진짜 키를 붙여 넣는 사고 대비.
    assert all(f.severity_adjusted and "룰 정의 문서" in f.severity_adjusted
               for f in rep.findings if f.engine != "secret-file")


def test_plain_secrets_note_is_still_blocked(tmp_path):
    """이름이 secrets.md 인 메모 파일은 룰 문서가 아니다 — 그대로 잡는다."""
    (tmp_path / "secrets.md").write_text('api_key: "sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"\n', encoding="utf-8")
    rep = scan_path(str(tmp_path))
    assert any(f.decision.value == "block" for f in rep.findings)


def test_rule_like_name_without_markers_is_still_blocked(tmp_path):
    (tmp_path / "GOV-SECRET-KEYS-001.md").write_text('OPENAI_API_KEY="sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"\n', encoding="utf-8")
    rep = scan_path(str(tmp_path))
    assert any(f.decision.value == "block" for f in rep.findings)


def test_benchmark_manifest_is_recognised(tmp_path):
    (tmp_path / "manifest.yaml").write_text(
        'cases:\n  - {id: A-01, file: app.py, line: 3, sink: "rrn = \\"900101-1234567\\"", expected_rule_ids: [GOV-PII-RRN-001]}\n',
        encoding="utf-8")
    rep = scan_path(str(tmp_path))
    assert rep.findings and all(f.decision.value != "block" for f in rep.findings)


# ── S-5: 값 기반 LLM 룰의 테스트 경로 감쇄 ───────────────────────────────────

_PII_PROMPT = 'prompt = "민원인 900101-1234567 의 체납 내역을 요약해줘"; openai.chat.completions.create(messages=[{"role":"user","content":prompt}])'


def test_pii_prompt_rule_attenuated_under_tests_dir():
    f = _one(_PII_PROMPT, "GOV-LLM-PII-PROMPT-001", "tests/test_bot.py")
    assert f.decision.value != "block" and f.severity_adjusted


def test_pii_prompt_rule_still_blocks_in_app_code():
    f = _one(_PII_PROMPT, "GOV-LLM-PII-PROMPT-001", "bot.py")
    assert f.decision.value == "block"


# ── S-6: 금지문 정규식 ───────────────────────────────────────────────────────

def test_korean_general_prohibition_form_is_recognised():
    f = _one("os.system(cmd)  # 이렇게 쓰지 마세요", "KISA-PY-INPUT-05")
    assert f.decision.value != "block" and "금지·주의" in (f.severity_adjusted or "")


@pytest.mark.parametrize("code", [
    "unsafe_eval = eval(x)",
    "never_cache = eval(x)",
    "result = deprecated_eval(y) or eval(y)",
])
def test_identifier_fragments_do_not_count_as_prohibition(code):
    f = _one(code, "GOV-CODE-EXEC-001")
    assert f.decision.value == "block", f.severity_adjusted


# ── 자기검사 재점검(2026-08-29): 주석 안의 코드 모양은 실행되지 않는다 ──
def test_code_shape_in_comment_is_attenuated_but_real_call_on_same_line_is_not():
    rep = scan_code('x = load(v)  # 예전에는 eval(v) 였음', filename="app.py")
    ex = [f for f in rep.findings if f.rule_id == "GOV-CODE-EXEC-001"]
    assert ex and ex[0].decision.value != "block" and ex[0].severity_adjusted
    rep2 = scan_code('y = eval(v)  # eval 은 위험', filename="app.py")
    ex2 = [f for f in rep2.findings if f.rule_id == "GOV-CODE-EXEC-001"]
    assert ex2 and ex2[0].decision.value == "block"
