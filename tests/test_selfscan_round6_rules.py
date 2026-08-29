"""자기검사 6차 — 룰 정밀도(R-3/4/5/8/9/10/12/13). 각 항목 양방향 고정."""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code


def _ids(code: str, filename: str = "app.py") -> set[str]:
    return {f.rule_id for f in scan_code(code, filename=filename).findings}


# ── R-3 OUTPUT-HANDLING: sink 는 호출/대입 형태 ──
@pytest.mark.parametrize("code, filename", [
    ('case_id = "llm-eval-in-evaluate-json"', "corpus.py"),
    ('why = "evaluateResponseQuality 안의 eval — 오탐"', "notes.py"),
    ("if (el.innerHTML == response) { return; }", "app.ts"),
    ("response.exec_time = 3", "app.py"),
    ("llm_exec_policy = 'strict'", "app.py"),
    ("const retrieval = await getResponse()", "app.ts"),
])
def test_output_handling_ignores_prose_and_identifiers(code, filename):
    assert "GOV-LLM-OUTPUT-HANDLING-001" not in _ids(code, filename)


@pytest.mark.parametrize("code, filename", [
    ("exec(llm_response)", "app.py"),
    ("os.system(model_output.strip())", "app.py"),
    ("subprocess.run(model_output, shell=True)", "app.py"),
    ("element.innerHTML = llmResponse", "app.ts"),
    ("div.innerHTML=llmText", "app.js"),
    ("res = eval( completion )", "app.py"),
    ("executeTool(llmResponse)", "app.ts"),
    ("document.body.innerHTML = model_output", "app.js"),
])
def test_output_handling_still_fires(code, filename):
    assert "GOV-LLM-OUTPUT-HANDLING-001" in _ids(code, filename)


# ── R-4 PII-PROMPT: 값 신호 ──
@pytest.mark.parametrize("code", [
    'prompt = "민원 챗봇입니다. 무엇을 도와드릴까요?"',
    'prompt = build_prompt(rrn_masked)',
    'messages = [{"role": "system", "content": "전화 상담 시간은 9시입니다"}]',
])
def test_pii_prompt_needs_value_signal(code):
    assert "GOV-LLM-PII-PROMPT-001" not in _ids(code)


@pytest.mark.parametrize("code", [
    'prompt = f"민원인 주민번호는 {rrn} 입니다"',
    'messages = [{"role": "user", "content": f"전화 {phone}"}]',
    'prompt = "Q: " + resident_no',
    'prompt = "민원인 900101-1234567 의 체납 내역을 요약해줘"',
    'messages=[{"content": "이름 홍길동 전화 010-2345-6789"}]',
])
def test_pii_prompt_still_fires(code):
    assert "GOV-LLM-PII-PROMPT-001" in _ids(code)


# ── R-5 AGENT: 동사 경계 ──
@pytest.mark.parametrize("code", [
    "mcp.dropdown(x)", "agent.approved(x)", "agent.transferable(x)",
    "mcp.deletion_log(x)", "agent.paymentStatus()", "tools.dropzoneInit()",
])
def test_agent_rule_ignores_embedded_verbs(code):
    assert "GOV-AGENT-EXCESSIVE-AUTHORITY-001" not in _ids(code, "agent.ts")


@pytest.mark.parametrize("code", [
    "assistant.sendEmail(to)", "agent.dropTable(t)", "agent.DELETE(x)",
    "agent.delete_account(id)", "tools.deleteFile(path)", "toolRegistry.removeUser(uid)",
    "mcpClient.transfer_funds(a, b)",
])
def test_agent_rule_still_fires(code):
    assert "GOV-AGENT-EXCESSIVE-AUTHORITY-001" in _ids(code, "agent.ts")


# ── R-8 INPUT-13 ↔ INPUT-07, R-9 ERR-01 ↔ FLASK-DEBUG ──
def test_redirect_is_open_redirect_only():
    ids = _ids('return redirect(request.args["next"])')
    assert "KISA-PY-INPUT-07" in ids and "KISA-PY-INPUT-13" not in ids


@pytest.mark.parametrize("code", [
    'response["Location"] = request.args["next"]',
    "resp.set_cookie('lang', request.args['lang'])",
    'Response(body, headers={"X-Redirect": request.args["u"]})',
])
def test_header_injection_still_fires(code):
    assert "KISA-PY-INPUT-13" in _ids(code)


def test_flask_debug_reported_once():
    ids = _ids('app.run(host="0.0.0.0", debug=True)')
    assert "GOV-FLASK-DEBUG-001" in ids and "KISA-PY-ERR-01" not in ids
    assert "KISA-PY-ERR-01" in _ids("DEBUG = True")
    assert "KISA-PY-ERR-01" in _ids('return jsonify({"error": str(e)}), 500')


# ── R-10 SEC-06 픽스처 가드 ──
def test_sec06_fixture_guard_matches_sibling():
    assert "KISA-PY-SEC-06" not in _ids('password = "dummy_password_1"')
    for real in ('password = "latestbuild9x2"', 'password = "P@ssw0rd!"', '비밀번호 = "Adm1n2026"'):
        assert "KISA-PY-SEC-06" in _ids(real), real


# ── R-12 PEM: PRIVATEKEY 단독 ──
def test_pem_header_reported_by_privatekey_rule_only():
    ids = _ids('KEY = """-----BEGIN RSA PRIVATE KEY-----"""')
    assert "GOV-SECRET-PRIVATEKEY-001" in ids and "GOV-SECRET-APIKEY-001" not in ids


# ── R-13 confidence label ──
def test_confidence_label_depends_on_engine():
    from gvskb.report import _confidence_label
    assert "데이터 흐름" not in _confidence_label("confirmed", "regex")
    assert "데이터 흐름" in _confidence_label("confirmed", "python-ast")
