"""보고서를 **어디에 모을지 사용자가 정한다** — 그리고 어디 갔는지 알 수 있어야 한다.

실사용 지적(2026-08-09):

> *"점검 파일을 다운 받는 위치에 저장하는거지? 근데 찾기가 너무 어려워.
> 별도로 폴더를 지정하게 해주면 좋겠어."*

기능이 **있기는 했다** — `GVSKB_REPORT_DIR` 환경변수. 그런데 Windows 에서
환경변수를 설정하려면 시스템 속성 창을 열어야 한다. 공무원이 쓸 수 있는
방법이 아니었으니 **사실상 없는 기능**이었다.

함께 드러난 것: 공용 폴더로 모으면 파일명이 `2026-08-09_1745_보안점검` 뿐이라
**어느 사업 보고서인지 알 수 없다.** 여러 부서가 한 폴더를 쓰는 순간 못 찾는다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gvskb import report_store as rs


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """사용자의 진짜 설정을 건드리지 않는다."""
    monkeypatch.setenv("GVSKB_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.delenv(rs.REPORT_DIR_ENV, raising=False)
    yield


# ---------------------------------------------------------------------------
# ① 기본값은 그대로 — 지정하지 않은 사람의 동작을 바꾸지 않는다
# ---------------------------------------------------------------------------

def test_default_stays_next_to_the_project(tmp_path: Path) -> None:
    proj = tmp_path / "사업A"
    proj.mkdir()
    path = rs.resolve_report_path(proj)
    assert path.parent == proj / rs.REPORT_DIR_NAME
    assert path.name.endswith("_보안점검")
    assert "사업A" not in path.name, "프로젝트 옆에서는 폴더가 이미 맥락이다"


def test_default_reason_is_explained() -> None:
    configured, reason = rs.configured_report_dir()
    assert configured is None
    assert rs.REPORT_DIR_NAME in reason, "왜 여기 저장되는지 말할 수 있어야 한다"


# ---------------------------------------------------------------------------
# ② 설정 파일로 지정할 수 있다 — 환경변수 없이
# ---------------------------------------------------------------------------

def test_config_file_redirects_reports(tmp_path: Path) -> None:
    shared = tmp_path / "보안점검모음"
    rs.write_config({rs.CONFIG_KEY_REPORT_DIR: str(shared)})

    configured, reason = rs.configured_report_dir()
    assert configured == shared
    assert "설정 파일" in reason

    path = rs.resolve_report_path(tmp_path / "사업A")
    assert path.parent == shared


def test_shared_folder_puts_the_project_name_in_the_filename(tmp_path: Path) -> None:
    """날짜만으로는 어느 사업 보고서인지 알 수 없다 — 한 폴더에 쌓이면 곧바로 막힌다."""
    rs.write_config({rs.CONFIG_KEY_REPORT_DIR: str(tmp_path / "모음")})
    a = rs.resolve_report_path(tmp_path / "민원챗봇").name
    b = rs.resolve_report_path(tmp_path / "예산시스템").name
    assert "민원챗봇" in a and "예산시스템" in b
    assert a != b, "같은 분에 두 사업을 검사하면 파일이 서로 덮어쓴다"


def test_broken_config_does_not_break_scanning(tmp_path: Path) -> None:
    """설정이 깨졌다고 검사가 멈추면 안 된다 — 저장 위치는 판정과 무관하다."""
    cfg = rs.config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("{ 이건 JSON 이 아니다", encoding="utf-8")
    assert rs.read_config() == {}
    assert rs.configured_report_dir()[0] is None


# ---------------------------------------------------------------------------
# ③ 우선순위 — 급한 것이 이긴다
# ---------------------------------------------------------------------------

def test_env_wins_over_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rs.write_config({rs.CONFIG_KEY_REPORT_DIR: str(tmp_path / "설정")})
    monkeypatch.setenv(rs.REPORT_DIR_ENV, str(tmp_path / "환경변수"))
    configured, reason = rs.configured_report_dir()
    assert configured == tmp_path / "환경변수"
    assert rs.REPORT_DIR_ENV in reason


def test_explicit_output_wins_over_everything(tmp_path: Path) -> None:
    rs.write_config({rs.CONFIG_KEY_REPORT_DIR: str(tmp_path / "설정")})
    chosen = tmp_path / "직접" / "이름"
    assert rs.resolve_report_path(tmp_path / "사업A", explicit=str(chosen)) == chosen


# ---------------------------------------------------------------------------
# ④ CLI — 지정하고, 확인하고, 되돌린다
# ---------------------------------------------------------------------------

def _run_config(**kw) -> int:
    import argparse

    from gvskb.cli import _cmd_config

    base = {"report_dir": None, "clear_report_dir": False}
    base.update(kw)
    return _cmd_config(argparse.Namespace(**base))


def test_cli_sets_and_clears(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    shared = tmp_path / "보안점검"
    assert _run_config(report_dir=str(shared)) == 0
    out = capsys.readouterr().out
    assert str(shared.resolve()) in out, "지정한 뒤 **실제 경로**를 보여줘야 한다"
    assert shared.is_dir(), "폴더를 미리 만들어 둬야 나중에 실패하지 않는다"
    assert rs.configured_report_dir()[0] == shared.resolve()

    assert _run_config(clear_report_dir=True) == 0
    assert rs.configured_report_dir()[0] is None
    assert rs.REPORT_DIR_NAME in capsys.readouterr().out, "되돌린 뒤에도 어디 저장되는지 말한다"


def test_cli_always_reports_where_it_will_save(capsys: pytest.CaptureFixture[str]) -> None:
    """아무것도 바꾸지 않아도 위치를 말한다 — 그게 이 명령의 존재 이유다."""
    assert _run_config() == 0
    out = capsys.readouterr().out
    assert "보고서 저장 위치" in out
    assert "근거" in out and "설정" in out


def test_cli_stores_an_absolute_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """상대경로로 저장하면 실행 위치에 따라 딴 데 생긴다."""
    monkeypatch.chdir(tmp_path)
    _run_config(report_dir="점검결과")
    saved = json.loads(rs.config_path().read_text(encoding="utf-8"))
    assert Path(saved[rs.CONFIG_KEY_REPORT_DIR]).is_absolute()


def test_scan_report_dir_flag_is_one_off(tmp_path: Path) -> None:
    """`--report-dir` 은 이번 한 번만 — 설정을 바꾸지 않는다."""
    from gvskb.cli import build_parser

    once = tmp_path / "임시"
    args = build_parser().parse_args(["scan", str(tmp_path), "--report-dir", str(once)])
    assert args.report_dir == str(once)
    assert rs.read_config() == {}, "일회성 지정이 설정을 건드리면 안 된다"


def test_one_off_folder_also_gets_the_project_name(tmp_path: Path) -> None:
    """설정이 없어도 공용 폴더로 보내면 이름이 붙어야 한다."""
    name = rs.default_report_basename(tmp_path / "민원챗봇", shared=True)
    assert "민원챗봇" in name
    assert "민원챗봇" not in rs.default_report_basename(tmp_path / "민원챗봇", shared=False)


# ---------------------------------------------------------------------------
# ⑤ doctor 도 말한다 — 검사하기 **전에** 물어볼 수 있어야 한다
# ---------------------------------------------------------------------------

def test_doctor_shows_where_reports_go(tmp_path: Path) -> None:
    from gvskb import diagnostics

    rs.write_config({rs.CONFIG_KEY_REPORT_DIR: str(tmp_path / "모음")})
    checks = diagnostics.check_report_dir()
    names = {c["name"] for c in checks}
    assert "보고서 저장 위치" in names and "설정 파일" in names
    assert any(str(tmp_path / "모음") in str(c.get("value")) for c in checks)


def test_doctor_actually_registers_the_check(tmp_path: Path) -> None:
    """함수를 직접 부르는 것만으로는 **등록됐는지** 알 수 없다.

    변이 검사에서 `run_diagnostics()` 의 목록에서 빼도 테스트가 통과했다 —
    함수는 살아 있는데 아무도 부르지 않는 상태를 못 잡고 있었다.
    """
    from gvskb import diagnostics

    rs.write_config({rs.CONFIG_KEY_REPORT_DIR: str(tmp_path / "모음")})
    report = diagnostics.run_diagnostics(network=False)
    names = {c["name"] for c in report["checks"]}
    assert "보고서 저장 위치" in names, "doctor 가 저장 위치를 말하지 않는다"
