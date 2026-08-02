"""재현 명령의 정직성 — 보고서가 주장하는 것이 실제로 성립하는가.

보고서는 재현 명령 위에 **"같은 결과를 다시 만들거나 다른 환경에서 검증하려면"**
이라고 적는다. 재현을 명시적으로 주장하는 문장이다.

그런데 `--include-installed`(전이 의존성 포함)와 `--env`(쿨다운 기준 3·7·14일)가
명령에서 빠져 있었고, 둘 다 **발견이 줄어드는 방향**으로 결과를 바꾼다. 결재
문서를 검증하러 재실행한 사람이 더 깨끗한 결과를 받고 "해소됐다"고 읽게 된다 —
도구가 스스로 만들어 내는 조용한 초록불이다.

등급은 명령과 별개로 **본문에도** 적는다. 명령줄을 읽지 않는 결재자도 어느
기준으로 나온 판정인지 알 수 있어야 한다.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from gvskb.cli import _scan_reproduce_command


def _args(**kw) -> argparse.Namespace:
    base = {
        "path": "./proj", "profile": "public-default-strict", "scenario": None,
        "max_files": 500, "check_deps": False, "include_installed": False,
        "env": None, "fail_on": "warn", "registry_bundle": None,
    }
    base.update(kw)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# 판정을 바꾸는 옵션은 빠지면 안 된다
# ---------------------------------------------------------------------------


def test_include_installed_is_carried() -> None:
    """빠지면 전이 의존성이 재검사에서 통째로 사라진다."""
    cmd = _scan_reproduce_command(_args(check_deps=True, include_installed=True))
    assert "--include-installed" in cmd


def test_env_grade_is_carried() -> None:
    """빠지면 쿨다운 기준이 기본값으로 내려가 `cooldown_hold` 가 통과로 바뀐다."""
    cmd = _scan_reproduce_command(_args(check_deps=True, env="E2"))
    assert "--env E2" in cmd


def test_full_invocation_round_trips() -> None:
    """실제로 쓰는 조합이 그대로 복원되는가."""
    cmd = _scan_reproduce_command(_args(check_deps=True, include_installed=True, env="E2"))
    assert cmd == "gvskb scan ./proj --check-deps --include-installed --env E2"


def test_common_case_stays_short() -> None:
    """기본값만 쓴 실행은 짧게 — 안 읽히는 명령은 없는 것과 같다(과잉 교정 방지)."""
    assert _scan_reproduce_command(_args()) == "gvskb scan ./proj"


def test_options_that_do_not_change_verdicts_are_omitted() -> None:
    """종료 코드·부산물만 바꾸는 것은 넣지 않는다 — 재현되는 판정은 같다."""
    cmd = _scan_reproduce_command(_args(
        check_deps=True, fail_on="block", registry_bundle="bundle.json",
    ))
    assert "--fail-on" not in cmd
    assert "--registry-bundle" not in cmd


# ---------------------------------------------------------------------------
# 등급은 본문에도 보여야 한다
# ---------------------------------------------------------------------------


def _scan_with_deps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, env: str | None):
    from gvskb import cli

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    src = tmp_path / "proj"
    src.mkdir()
    (src / "app.py").write_text('print("ok")\n', encoding="utf-8")
    (src / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    out = tmp_path / "r.md"
    argv = ["scan", str(src), "--check-deps", "-o", str(out)]
    if env:
        argv += ["--env", env]
    cli.main(argv)
    return out.read_text(encoding="utf-8"), (tmp_path / "r.html").read_text(encoding="utf-8")


def test_report_states_the_env_grade_that_produced_the_verdicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """어느 기준으로 나온 판정인지 보고서에 적힌다 — 없으면 검증할 수 없다."""
    md, html = _scan_with_deps(tmp_path, monkeypatch, env="E2")
    for doc in (md, html):
        assert "실행환경 등급" in doc
        assert "E2" in doc
        assert "14일" in doc          # 쿨다운 기준일까지 — 등급 문자만으로는 의미가 없다


def test_unspecified_env_still_reports_the_applied_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """'지정하지 않음'과 '적용되지 않음'은 다르다 — 안 줘도 기준일은 적용됐다."""
    md, _html = _scan_with_deps(tmp_path, monkeypatch, env=None)
    assert "실행환경 등급" in md
    assert "E1" in md and "7일" in md
    assert "미지정이라 기본값 적용" in md


def test_no_env_line_without_dependency_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """의존성 검사를 안 했으면 등급은 판정에 관여하지 않는다 — 적지 않는다.

    관여하지 않은 값을 적으면 읽는 사람이 근거로 오해한다.
    """
    from gvskb import cli

    src = tmp_path / "proj"
    src.mkdir()
    (src / "app.py").write_text('print("ok")\n', encoding="utf-8")
    out = tmp_path / "r.md"
    cli.main(["scan", str(src), "-o", str(out)])
    assert "실행환경 등급" not in out.read_text(encoding="utf-8")
