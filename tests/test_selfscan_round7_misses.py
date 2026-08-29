"""자기검사 7차 — 전수 분석에서 드러난 미탐 보강(S-10/11/12). 양방향 고정."""
from __future__ import annotations

import pytest

from gvskb.scanner import scan_code


def _find(code: str, rule: str, filename: str = "app.py"):
    return [f for f in scan_code(code, filename=filename).findings if f.rule_id == rule]


# ── S-10: 프롬프트 주입 미탐 ──
@pytest.mark.parametrize("code, conf", [
    # 인라인 결합, 동적 부분이 매개변수뿐 → 출처를 추적한 적 없으니 likely
    ("SYSTEM = 'you are a helpful bot'\ndef ask(user_input):\n    return client.chat.completions.create(messages=[{'role':'user','content': SYSTEM + user_input}])", "likely"),
    # 스코프 안에서 대입을 따라 조립을 확인 → SQL 룰과 같은 규약으로 confirmed
    ("def ask(user_input):\n    p = '요약: %s' % user_input\n    return client.chat.completions.create(messages=[{'content': p}])", "confirmed"),
    ("def ask(user_input):\n    p = '지시: ' + user_input\n    return chain.invoke(p)", "confirmed"),
    ("def ask(user_input):\n    p = f'{SYSTEM_PROMPT}\\n{user_input}'\n    return llm.predict(p)", "confirmed"),
])
def test_prompt_injection_new_shapes_detected(code, conf):
    fs = _find(code, "GOV-LLM-PROMPT-INJECTION-001")
    assert fs, code
    assert fs[0].confidence == conf


def test_prompt_injection_confirmed_when_assembled_in_scope():
    code = "user_input = request.args['q']\np = 'x: ' + user_input\nclient.chat.completions.create(messages=[{'content': p}])"
    fs = _find(code, "GOV-LLM-PROMPT-INJECTION-001")
    assert fs and fs[0].confidence == "confirmed"


@pytest.mark.parametrize("code", [
    "def ask(user_input):\n    return client.chat.completions.create(messages=[{'role':'user','content': user_input}])",  # 맨몸 매개변수 — 설계상 미발화
    "def run(q):\n    return db.invoke(q)",                                 # 수신자 db — LLM 아님
    "def run(q):\n    return queue.stream(q + 'x')",
    "p = 'hello'\nchain.invoke(p)",                                          # 상수
])
def test_prompt_injection_negatives_stay_quiet(code):
    assert not _find(code, "GOV-LLM-PROMPT-INJECTION-001"), code


# ── S-11: sh -c <오염값> ──
def test_sh_dash_c_with_dynamic_command_detected():
    code = 'subprocess.run(["sudo", "-u", "root", "sh", "-c", cmd])'
    assert _find(code, "KISA-PY-INPUT-05")
    assert _find('subprocess.Popen(["/bin/bash", "-c", "ls " + user_dir])', "KISA-PY-INPUT-05")


@pytest.mark.parametrize("code", [
    'subprocess.run(["sh", "-c", "echo hello"])',      # 상수 명령
    'subprocess.run(["ls", "-l", path])',               # 셸 아님
    'subprocess.run(["sh", "script.sh", arg])',         # -c 없음
    'subprocess.run(["cmd", "/c", "del", fname], check=False)',   # 명령어 상수, 동적인 건 인자 (코퍼스 음성)
])
def test_sh_dash_c_negatives(code):
    assert not _find(code, "KISA-PY-INPUT-05"), code


# ── S-12: yaml.load ──
@pytest.mark.parametrize("code", [
    "cfg = yaml.load(request.data, Loader=yaml.Loader)",
    "cfg = yaml.load(text)",
    "cfg = yaml.load(text, yaml.FullLoader)",
])
def test_unsafe_yaml_load_detected(code):
    assert _find(code, "KISA-PY-CODE-03"), code


@pytest.mark.parametrize("code", [
    "cfg = yaml.load(text, Loader=yaml.SafeLoader)",
    "cfg = yaml.load(text, yaml.CSafeLoader)",
    "cfg = yaml.safe_load(text)",
])
def test_safe_yaml_load_quiet(code):
    assert not _find(code, "KISA-PY-CODE-03"), code
