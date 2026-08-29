"""자기검사(2026-08-29) 1차 수정의 회귀·적대 테스트.

체커가 자기 저장소를 검사해 493건이 나왔고, 그중 제품 코드 오탐의 원인 세
가지를 고쳤다. 각 항목은 **양방향**으로 고정한다 — 오탐이 사라졌는지와,
같은 모양의 진짜 취약 코드가 여전히 잡히는지.
"""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code
from gvskb.scanners.regex_scanner import redact_evidence


def _ids(code: str, filename: str, language: str | None = None) -> set[str]:
    return {f.rule_id for f in scan_code(code, filename=filename, language=language).findings}


# ── S-1: 데이터 파일 언어 스코프 ───────────────────────────────────────────

@pytest.mark.parametrize("code, filename, absent", [
    ('sink: "hashlib.md5(pw.encode())"', "manifest.yaml", "KISA-PY-SEC-04"),
    ('- "document.write(location.hash)"', "cases.yml", "KISA-JS-INPUT-04"),
    ('- "document.write(location.hash)"', "cases.yml", "GOV-HTML-DOM-XSS-001"),
    ('{"id": "llm-eval-in-evaluate-json"}', "corpus.json", "GOV-LLM-OUTPUT-HANDLING-001"),
    ('sink: "redirect(request.args[\\"next\\"])"', "manifest.yaml", "KISA-PY-INPUT-07"),
    ('sink: "pickle.loads(blob)"', "manifest.yaml", "KISA-PY-CODE-03"),
])
def test_language_scoped_rules_skip_data_files(code, filename, absent):
    """YAML/JSON 은 언어가 있어야 한다 — '미상이면 통과'가 오탐의 근원이었다."""
    assert absent not in _ids(code, filename)


@pytest.mark.parametrize("code, filename, present", [
    ('api_key: "sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"', "config.yaml", "GOV-SECRET-APIKEY-001"),
    ('DB_PASSWORD=Adm1n2026!Secure', "prod.env", "GOV-SECRET-APIKEY-001"),
    ('rrn: "900101-1234567"', "seed.json", "GOV-PII-RRN-001"),
    ('  "prepare": "node -e \\"require(\'child_process\').exec(cmd)\\""', "package.json", "KISA-JS-INPUT-05"),
    ("  run: os.system(user_input)", "workflow.yml", "GOV-CMD-INJECTION-001"),
    ("  run: eval(user_input)", "workflow.yml", "GOV-CODE-EXEC-001"),
])
def test_value_rules_and_optin_exec_rules_still_see_data_files(code, filename, present):
    """값 규칙은 어디서나, 실행 코드가 실리는 룰은 opt-in 으로 계속 본다."""
    assert present in _ids(code, filename)


def test_explicit_language_overrides_extension():
    assert "KISA-PY-SEC-04" in _ids("hashlib.md5(pw.encode())", "x.yaml", language="python")


# ── R-2: GOV-CODE-EXEC-001 수신자 배제 ──────────────────────────────────────

@pytest.mark.parametrize("code", [
    "result = session.exec(select(User)).all()",   # SQLModel — 실사용 오탐
    "engine.eval(expression)",
    "m = pattern.exec(text)",
    "cp.exec(cmd)",
    "value = ast.literal_eval(raw)",
])
def test_code_exec_ignores_method_receivers(code):
    assert "GOV-CODE-EXEC-001" not in _ids(code, "app.py")


@pytest.mark.parametrize("code", [
    "eval(user_input)",
    "exec(code)",
    "builtins.eval(s)",
    "x = eval( completion )",
    "exec (payload)",
])
def test_code_exec_still_fires_on_builtins(code):
    fs = [f for f in scan_code(code, filename="app.py").findings if f.rule_id == "GOV-CODE-EXEC-001"]
    assert fs and fs[0].decision.value == "block"


# ── R-1: 벤더 접두사 좌측 경계 ─────────────────────────────────────────────

@pytest.mark.parametrize("code, filename", [
    ('url: "https://www.nist.gov/itl/ai-risk-management-framework"', "security_sources.yaml"),
    ('name = "desk-management-tool-for-public-sector"', "app.py"),
    ('slug = "task-scheduler-with-long-name-here"', "app.py"),
    ('mask_token_1234567890abcdefXYZ = 1', "app.py"),
    ('x = "NAKIAABCDEFGHIJKLMNOPQ"', "app.py"),
    ('who = "laughp_Abcdefghijklmnopqrstuvwxyz0123456789"', "app.py"),
    ('ref = "MSG.aaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbb"', "app.py"),
])
def test_vendor_prefix_needs_left_boundary(code, filename):
    assert "GOV-SECRET-APIKEY-001" not in _ids(code, filename)


@pytest.mark.parametrize("code", [
    'headers = {"Authorization": "Bearer sk-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"}',
    'OPENAI_API_KEY="sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"',
    'OPENAI_API_KEY=sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ',
    'url = "https://api.example.com/v1?key=sk-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"',
    '{"key":"sk-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"}',
    'aws = "AKIAABCDEFGHIJKLMNOP"',
    'tok = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
    'tok = "glpat-Ab3xK9mQ2pR7sT1uV5wY8zC4"',
    'tok = "xoxb-1234567890-abcdefghij"',
    'tok = "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"',
    'tok = "SG.Ab3xK9mQ2pR7sT1uV5wY8zC4.dE6fG0hJAb3xK9mQ2pR7sT1u"',
    'client = RegistryClient(base_url, "sk_ggtrust_Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ")',
])
def test_vendor_tokens_still_detected(code):
    assert "GOV-SECRET-APIKEY-001" in _ids(code, "app.py")


# ── 마스킹 경계 ─────────────────────────────────────────────────────────────

def test_public_url_is_not_masked():
    line = 'url: "https://www.nist.gov/itl/ai-risk-management-framework"'
    assert redact_evidence(line) == line


@pytest.mark.parametrize("line", [
    'API_KEY = "sk-proj-Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ"',
    'client = RegistryClient(base_url, "sk_ggtrust_Ab3xK9mQ2pR7sT1uV5wY8zC4")',
])
def test_real_keys_still_masked(line):
    out = redact_evidence(line)
    assert out != line and "Ab3xK9mQ2pR7sT1uV5wY8zC4" not in out
