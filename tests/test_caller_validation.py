"""``caller`` 클라이언트 검증 — 연동합의 §3(개인 식별자 절대 전송 금지).

**이 테스트가 지키는 것**: 호출자가 신고한 문자열이 개인을 식별하는 값이면
그것이 우리 감사 기록과 레지스트리 봉투에 그대로 남지 않는다는 것.

이 규칙을 제안한 것은 우리인데 정작 우리 쪽에 검증이 없었다. `caller` 는
레지스트리로만 나가는 값이 아니라 **우리 감사로그에도 그대로 들어간다** —
공공기관 감사 기록에 사번·PC명이 섞이면 그 기록 자체가 개인정보 파일이 된다.

두 번째로 중요한 것은 **거부한 값을 다시 흘리지 않는 것**이다. 경고 메시지에
문제의 값을 실어 보여 주면 stderr 와 CI 로그로 막으려던 것을 그대로 내보내게
된다. 검증이 유출 경로가 되면 안 된다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb.audit import (
    CALLER_INVALID,
    _reset_caller_warnings_for_tests,
    normalize_caller,
    record_package_check,
    safe_caller,
)


@pytest.fixture(autouse=True)
def _reset_warnings():
    _reset_caller_warnings_for_tests()
    yield
    _reset_caller_warnings_for_tests()


def _rows(audit_dir: Path) -> list[dict]:
    out: list[dict] = []
    for p in sorted(audit_dir.glob("audit-*.jsonl")):
        out += [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line]
    return out


# ---------------------------------------------------------------------------
# 통과해야 하는 값 — 과잉 교정 방지
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "harness:auto",
    "cli:manual",
    "registry:manual",
    "mcp:auto",
    "vibe-harness:auto",
    "ci_runner:auto",
    "cli:manual:3120000",   # 부서코드 포함(숫자)
])
def test_valid_caller_passes_through_unchanged(value: str) -> None:
    """합의가 정한 형식은 손대지 않는다.

    검증이 정상 값을 건드리기 시작하면 담당자는 caller 신고 자체를 포기하고,
    그러면 감사 기록에서 'AUTO/MANUAL 구분'이 통째로 사라진다.
    """
    assert normalize_caller(value) == (value, "")


def test_unreported_caller_is_not_a_violation() -> None:
    """미신고는 위반이 아니다 — 빈 값은 그대로 빈 값이다."""
    assert normalize_caller("") == ("", "")
    assert normalize_caller("   ") == ("", "")


# ---------------------------------------------------------------------------
# 막아야 하는 값 — 현실적인 개인 식별자
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "hong@gg.go.kr",            # 이메일
    "kim.cheolsu",              # 이름
    "20231234",                 # 사번
    "DESKTOP-A1B2C3",           # PC명
    "192.168.10.42",            # 내부 IP
    "홍길동",                    # 한글 이름
    "user:홍길동",               # 형식은 흉내 냈으나 모드 자리가 이름
    "cli:manual:hong@gg.go.kr",  # 부서코드 자리에 이메일
])
def test_personal_identifiers_never_reach_the_record(value: str) -> None:
    """개인 식별자는 기록에 남지 않는다.

    구조 검사만으로 대부분 걸린다 — 이메일에는 ``@`` 와 ``.`` 가, IP 에는 ``.``
    가, PC명·사번에는 ``:`` 가 없다. 사람 이름을 일반적으로 알아볼 수는 없지만,
    합의가 정한 ``<출처>:<모드>`` 형태를 요구하는 것만으로 실무에서 실제로
    들어오는 값들은 막힌다.
    """
    recorded, _code = normalize_caller(value)
    assert value not in recorded
    assert recorded in (CALLER_INVALID, "cli:manual")


def test_bad_department_code_drops_only_that_slot() -> None:
    """부서코드만 규칙 위반이면 그 슬롯만 버리고 앞부분은 살린다.

    값 하나가 규칙을 어겼다고 ``<출처>:<모드>`` 까지 버리면 감사 귀속이 통째로
    사라진다 — 이름을 지우자고 'AUTO/MANUAL 구분'까지 잃는 것은 과잉 교정이다.
    """
    assert normalize_caller("cli:manual:홍길동") == ("cli:manual", "dept_dropped")
    assert normalize_caller("harness:auto:seoul-dept") == ("harness:auto", "dept_dropped")


def test_malformed_value_is_marked_not_blanked() -> None:
    """형식 위반은 빈 값이 아니라 표식으로 남긴다.

    빈 값으로 지우면 '신고하지 않음'과 구분되지 않아, 규칙 위반이 있었다는
    사실 자체가 감사 기록에서 사라진다.
    """
    recorded, code = normalize_caller("20231234")
    assert recorded == CALLER_INVALID
    assert code == "malformed"
    assert recorded != ""


def test_normalize_is_idempotent() -> None:
    """검증을 두 번 거쳐도 값이 변하지 않는다.

    진입 지점(server)과 싱크(audit·봉투) 양쪽에서 호출되므로, 두 번째 호출이
    첫 결과를 다시 망가뜨리면 안 된다.
    """
    once, _ = normalize_caller("20231234")
    assert normalize_caller(once) == (once, "")


# ---------------------------------------------------------------------------
# 경고 — 유출하지 않으면서, 피로하지 않게
# ---------------------------------------------------------------------------


def test_warning_never_echoes_the_rejected_value(capsys: pytest.CaptureFixture) -> None:
    """거부한 값을 경고에 싣지 않는다 — 검증이 유출 경로가 되면 안 된다."""
    safe_caller("hong@gg.go.kr")
    err = capsys.readouterr().err
    assert err.strip(), "위반이 조용히 넘어갔다"
    assert "hong@gg.go.kr" not in err
    assert "hong" not in err


def test_same_violation_warns_once_per_process(capsys: pytest.CaptureFixture) -> None:
    """같은 위반은 한 번만 알린다(합의 §4-4 · 작업원칙 6).

    락파일 800건이면 같은 caller 로 이벤트가 수백 건 생긴다. 줄마다 경고하면
    담당자는 경고를 무시하게 되고, 그러면 그 사이의 진짜 위험도 함께 묻힌다.
    조치는 '호출자 설정 수정' 한 건이므로 알림도 한 건이다.
    """
    for _ in range(50):
        safe_caller("20231234")
    assert capsys.readouterr().err.count("[gvskb]") == 1


def test_different_violations_warn_separately(capsys: pytest.CaptureFixture) -> None:
    """조치가 다르면 알림도 다르다 — 형식 위반과 부서코드 위반은 고칠 곳이 다르다."""
    safe_caller("20231234")
    safe_caller("cli:manual:홍길동")
    assert capsys.readouterr().err.count("[gvskb]") == 2


def test_valid_caller_is_silent(capsys: pytest.CaptureFixture) -> None:
    """정상 값에는 아무 말도 하지 않는다 — 경고 피로의 반대편 실수."""
    safe_caller("harness:auto")
    assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# 실제 기록에 반영되는가 (단위 함수가 아니라 파일까지)
# ---------------------------------------------------------------------------


def test_audit_log_stores_sanitized_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """감사로그 파일에 원본 값이 남지 않는다.

    순수 함수 검증만으로는 '싱크에서 실제로 호출되는가'를 보장하지 못한다 —
    호출을 빠뜨리면 함수는 초록불인데 파일은 오염된다.
    """
    monkeypatch.setenv("GVSKB_AUDIT_DIR", str(tmp_path))
    record_package_check(
        [{"name": "requests", "version": "2.31.0", "ecosystem": "pypi",
          "verdict": "not_found", "checked": True}],
        tool="check_package", caller="hong@gg.go.kr", scope="single",
    )
    rows = _rows(tmp_path)
    assert rows, "감사 이벤트가 기록되지 않았다"
    assert all(r["caller"] == CALLER_INVALID for r in rows)
    raw = "".join(p.read_text(encoding="utf-8") for p in tmp_path.glob("audit-*.jsonl"))
    assert "hong@gg.go.kr" not in raw


def test_registry_envelope_stores_sanitized_caller() -> None:
    """레지스트리 봉투에도 원본 값이 실리지 않는다(합의 §5-B)."""
    from gvskb.tools.registry_client import _envelope

    env = _envelope(
        {"name": "requests", "version": "2.31.0", "ecosystem": "pypi", "verdict": "not_found"},
        caller="DESKTOP-A1B2C3", source_scope="lockfile", now_iso="2026-08-02T00:00:00Z",
    )
    assert env["caller"] == CALLER_INVALID
    assert "DESKTOP-A1B2C3" not in json.dumps(env, ensure_ascii=False)
