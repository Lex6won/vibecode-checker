"""증거 마스킹 — 알아보되 쓰지는 못하게.

**왜 통째로 가리지 않기로 했나.** 담당자는 유출된 키를 폐기·재발급해야 하는데,
`***REDACTED***` 만으로는 한 파일에 키가 여러 개일 때 어느 것인지 구분할 수
없다. 조치로 이어지지 않는 증거는 증거가 아니다.

**왜 원문을 싣지 않나.** 이 보고서는 `.check-reports/` 에 파일로 저장되고
결재로 올라가고 감사로그에 남는다. 원문을 쓰면 유출본이 한 벌 더 생긴다.
주민등록번호·카드번호라면 보고서 자체가 개인정보 파일이 된다.

그래서 **부분 마스킹**이다. 이 파일은 그 절충이 양쪽 모두에서 성립하는지
고정한다 — ① 식별에 쓸 만큼 남는가 ② 복원에 쓸 만큼 남지는 않는가.
"""

from __future__ import annotations

import re

import pytest

from gvskb.report import MASKING_NOTE, render_html, render_markdown
from gvskb.scanner import scan_code
from gvskb.scanners.regex_scanner import MASK_MARK, evidence_is_masked, redact_evidence

# 실제 형태를 흉내 낸 가짜 값. 벤더 접두사를 소스에 리터럴로 두면 GitHub
# push protection 이 커밋을 거부하므로 런타임에 조립한다.
_OPENAI = "sk-" + "proj-" + "Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ7kL9"
_GGTRUST = "sk_" + "ggtrust_" + "Zx9Yw8Vu7Ts6Rq5Pn4Ml3Kj2Hg1Fe0Dc"
_AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"


# ---------------------------------------------------------------------------
# ① 알아볼 수 있는가 — 조치로 이어지려면 어느 값인지 구분돼야 한다
# ---------------------------------------------------------------------------

def test_two_different_keys_stay_distinguishable() -> None:
    """통째로 가리면 이 구분이 사라진다 — 부분 마스킹의 존재 이유."""
    a = redact_evidence(f'PRIMARY = "{_OPENAI}"')
    b = redact_evidence(f'PRIMARY = "{_GGTRUST}"')
    assert a != b, "서로 다른 두 키가 보고서에서 같은 문자열이 됐다"


def test_vendor_prefix_survives() -> None:
    """`sk-proj-` 같은 접두사는 비밀이 아니라 **어느 서비스인지**를 말한다."""
    out = redact_evidence(f'OPENAI_API_KEY = "{_OPENAI}"')
    assert out.startswith('OPENAI_API_KEY = "sk-proj-'), out
    assert "OPENAI_API_KEY" in out, "어느 변수가 걸렸는지도 남아야 한다"


# ---------------------------------------------------------------------------
# ② 쓸 수는 없는가 — 여기가 무너지면 보고서가 유출 경로가 된다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    f'OPENAI_API_KEY = "{_OPENAI}"',
    f'client = RegistryClient(base, "{_GGTRUST}")',
    f"error: token {_GGTRUST} rejected by registry",
    f'AWS_ACCESS_KEY = "{_AWS_ID}"',
])
def test_secret_material_never_appears_whole(line: str) -> None:
    out = redact_evidence(line)
    for secret in (_OPENAI, _GGTRUST, _AWS_ID):
        assert secret not in out, f"원문이 그대로 남았다: {out}"


@pytest.mark.parametrize("secret", [_OPENAI, _GGTRUST, _AWS_ID])
def test_at_most_a_third_of_a_secret_is_revealed(secret: str) -> None:
    """노출 비율 상한. 여기가 느슨해지면 '부분 마스킹'이 말뿐이 된다.

    앞 ¼(최대 8자) + 뒤 ⅛(최대 4자) 규칙이므로 어떤 길이에서도 ⅜을 넘지 않는다.
    """
    out = redact_evidence(f'KEY = "{secret}"')
    masked_value = out.split('"')[1]
    # 표식을 걷어낸 나머지가 곧 노출된 부분이다.
    kept_len = len(masked_value.replace(MASK_MARK, ""))
    assert kept_len <= len(secret) * 3 // 8, f"{kept_len}/{len(secret)}자 노출: {out}"
    assert kept_len > 0, "식별할 수 없으면 부분 마스킹의 의미가 없다"


@pytest.mark.parametrize("value, why", [
    ("hunter2", "짧은 값은 비율로 따져도 남는 부분이 너무 크다"),
    ("sk-abcdefgh", "최소 길이 sk- 키"),
    ("abc123", "6자"),
])
def test_short_values_are_masked_whole(value: str, why: str) -> None:
    out = redact_evidence(f'api_key = "{value}"')
    assert value not in out, why
    assert MASK_MARK in out


# ---------------------------------------------------------------------------
# ③ 비밀번호는 예외 — 저엔트로피라 앞 몇 자가 추측을 실질적으로 돕는다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", ["password", "PASSWORD", "passwd", "pwd"])
def test_passwords_are_masked_whole(key: str) -> None:
    """API 키는 기계가 만든 고엔트로피 값이지만 비밀번호는 사람이 짓는다.

    `P@ss…` 넉 자는 추측 공간을 실제로 좁히고, 어느 비밀번호인지는 변수명이
    이미 말해 주므로 부분 노출로 얻는 것도 없다.
    """
    out = redact_evidence(f'{key} = "P@ssw0rd2026Prod!"')
    assert out == f'{key} = "{MASK_MARK}"', out
    assert "P@ss" not in out


def test_api_keys_are_not_masked_whole() -> None:
    """비밀번호 예외가 다른 비밀값까지 삼키면 ①이 무너진다."""
    for key in ("api_key", "API_KEY", "client_secret", "TOKEN"):
        out = redact_evidence(f'{key} = "Xj3k9Lm2Np5Qr8St1Uv4Wx7Yz0Ab3Cd6"')
        assert out != f'{key} = "{MASK_MARK}"', f"{key} 가 통째로 가려졌다"


# ---------------------------------------------------------------------------
# ④ 두 번 가리지 않는다 — 겹치면 남겨 둔 식별 정보가 사라진다
# ---------------------------------------------------------------------------

def test_already_masked_value_is_not_masked_again() -> None:
    """`sk-` 규칙이 가린 값을 따옴표 규칙이 다시 가리면 접두사가 사라진다.

    실제로 그랬다 — `API_KEY = "sk-proj-…"` 가 `API_KEY = "***REDACTED***"` 로
    나와 어느 서비스의 키인지 알 수 없었다.
    """
    out = redact_evidence(f'API_KEY = "{_OPENAI}"')
    assert "sk-proj-" in out, out
    assert out.count(MASK_MARK) == 1, f"두 번 가려졌다: {out}"


# ---------------------------------------------------------------------------
# ⑤ 가렸다는 사실을 말하는가 — 그리고 안 가렸을 때 말하지 않는가
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, masked", [
    (f'API_KEY = "{_OPENAI}"', True),
    ('rrn = "900101-1234567"', True),
    ('phone = "010-9876-5432"', True),
    ('password = "hunter2"', True),
    ("eval(user_input)", False),
    ("os.system(cmd)", False),
    ("", False),
])
def test_evidence_is_masked_reports_the_truth(text: str, masked: bool) -> None:
    assert evidence_is_masked(redact_evidence(text)) is masked, text


def test_report_labels_only_what_it_actually_masked() -> None:
    """늘 켜져 있는 경고는 경고가 아니다.

    예전에는 모든 증거에 '자동 마스킹됨' 딱지가 붙었다. `eval(x)` 옆의 그
    딱지를 본 담당자는 무엇이 가려졌는지 찾다가 지치고, 그러면 진짜 가려진
    자리에서도 딱지를 읽지 않는다.
    """
    report = scan_code(
        f'API_KEY = "{_OPENAI}"\neval(user_input)\n', filename="settings.py",
    )
    md = render_markdown(report)

    masked_lines = [ln for ln in md.splitlines() if "증거(민감값 일부 가림)" in ln]
    plain_lines = [ln for ln in md.splitlines()
                   if re.match(r"- \*\*증거\*\*:", ln.strip())]
    assert masked_lines, "가려진 증거에 딱지가 없다"
    assert plain_lines, "안 가린 증거에도 딱지가 붙었다"
    assert all("API_KEY" in ln for ln in masked_lines)
    assert all("eval" in ln for ln in plain_lines)


def test_masking_policy_is_explained_once_when_relevant() -> None:
    """왜 다 안 보이는지 담당자가 묻기 전에 답한다 — 단, 가린 게 있을 때만."""
    masked = render_markdown(scan_code(f'API_KEY = "{_OPENAI}"', filename="a.py"))
    assert masked.count(MASKING_NOTE) == 1

    clean = render_markdown(scan_code("eval(user_input)", filename="a.py"))
    assert MASKING_NOTE not in clean, "안 가린 보고서에 마스킹 안내를 실으면 거짓말이다"


def test_masking_note_renders_in_html_without_raw_markdown() -> None:
    """같은 문자열을 두 렌더러가 쓴다. 한쪽에 맞춘 서식은 다른 쪽에 날것으로 찍힌다."""
    html_doc = render_html(scan_code(f'API_KEY = "{_OPENAI}"', filename="a.py"))
    assert "민감값 일부 가림" in html_doc
    assert "유출본을 한 벌 더" in html_doc
    assert "**" not in MASKING_NOTE and "`" not in MASKING_NOTE


# ---------------------------------------------------------------------------
# ⑥ 국내 관행 — 주민등록번호·휴대전화는 이미 부분 마스킹이 표준이다
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expect, why", [
    ('rrn = "900101-1234567"', 'rrn = "900101-1******"', "생년월일·성별자리만"),
    ('phone = "010-9876-5432"', 'phone = "010-****-5432"', "뒷 네 자리만"),
    ('tel = "01098765432"', 'tel = "010-****-5432"', "하이픈 없는 입력도 같은 모양으로"),
])
def test_korean_pii_keeps_the_conventional_shape(raw: str, expect: str, why: str) -> None:
    """담당자가 눈에 익은 모양이어야 읽는다. 여기까지 `[마스킹]` 으로 바꾸면 낯설어진다."""
    assert redact_evidence(raw) == expect, why


def test_rrn_serial_never_leaks() -> None:
    """뒷 여섯 자리는 어떤 경우에도 남지 않는다."""
    assert "234567" not in redact_evidence('id = "900101-1234567"')
    assert "234567" not in redact_evidence("id = 9001011234567")
