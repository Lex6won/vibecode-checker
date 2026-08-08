"""프로세스 신선도 진단 — "디스크가 최신인가"가 아니라 "메모리가 최신인가".

실측 사고(2026-08-08): 룰 3종의 과탐을 고쳐 머지까지 끝냈는데 MCP 서버는 계속
옛 룰로 판정했다. 그런데 ``server_status`` 는 ``commit_id`` 를 호출 시점의
``.git/HEAD`` 에서 읽어 **최신 커밋**을 답했고, ``total_rules`` 도 인텔 캐시로
늘어나 최신처럼 보였다. 사용자가 판별용 코드를 직접 짜서야 낡음을 알았다.

여기 테스트는 두 방향을 모두 고정한다:

- **잡아야 하는 것** — 커밋 이동, 룰·코드 내용 변경(크기가 같아도)
- **잡으면 안 되는 것** — mtime 만 흔들린 경우, 커밋을 알 수 없는 설치본

거짓 '낡음'은 재시작 한 번이면 끝나지만 거짓 '최신'은 틀린 판정을 믿게 만든다.
그렇다고 거짓 '낡음'을 방치하면 경고가 배경 소음이 되어 아무도 안 본다.
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from gvskb import diagnostics

REPO_ROOT = Path(__file__).resolve().parent.parent


def _probe(commit: str | None, code: str, rules: str) -> dict:
    """지문 비교에 필요한 최소 형태의 probe."""
    return {
        "commit_id": commit,
        "code": {"files": 1, "bytes": 1, "digest": code},
        "rules": {"files": 1, "bytes": 1, "digest": rules},
        "rules_dir": "/x",
    }


# --------------------------------------------------------------------------
# 지문 — 무엇을 잡고 무엇을 흘려보내는가
# --------------------------------------------------------------------------

def test_fingerprint_detects_content_change(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text("hello", encoding="utf-8")
    before = diagnostics._tree_fingerprint(tmp_path)
    (tmp_path / "a.md").write_text("world", encoding="utf-8")
    assert diagnostics._tree_fingerprint(tmp_path) != before


def test_fingerprint_detects_edit_to_a_file_that_is_not_the_newest(tmp_path: Path) -> None:
    """수정된 파일이 트리에서 **가장 최신이 아닐 때**의 같은 크기 치환.

    처음 구현은 (파일 수, 총 바이트, 최신 mtime) 만 봤고, 실측에서 바로 이
    조건 때문에 **탐지에 실패했다**: 룰 하나를 고쳐도 그 파일이 트리 최신이
    아니면 ``max`` 가 그대로였고 크기·개수도 그대로였다. 지문이 안 변한 채
    '최신'이라 답하는, 고치려던 것과 똑같은 결함이다.

    파일이 하나뿐인 tmp 디렉터리로 시험하면 수정한 파일이 곧 최신이 되어
    stat 기반 지문도 통과해 버린다 — 그래서 더 최신인 이웃 파일을 함께 둔다.
    """
    import os

    target = tmp_path / "rule.md"
    newest = tmp_path / "zz_newest.md"
    target.write_text("severity: high", encoding="utf-8")
    newest.write_text("이 파일이 트리에서 가장 최신", encoding="utf-8")

    newest_mtime = newest.stat().st_mtime_ns
    old_mtime = newest_mtime - 10**10  # target 을 확실히 과거로 못박는다
    os.utime(target, ns=(old_mtime, old_mtime))
    before = diagnostics._tree_fingerprint(tmp_path)

    target.write_text("severity: hig1", encoding="utf-8")  # 길이 동일
    os.utime(target, ns=(old_mtime, old_mtime))  # mtime 도 그대로 — stat 은 못 본다

    after = diagnostics._tree_fingerprint(tmp_path)
    assert after["files"] == before["files"]
    assert after["bytes"] == before["bytes"]
    assert newest.stat().st_mtime_ns == newest_mtime, "트리 최신 mtime 이 안 바뀌어야 유효한 시험"
    assert after["digest"] != before["digest"]


def test_fingerprint_ignores_mtime_only_change(tmp_path: Path) -> None:
    """내용이 같은데 mtime 만 바뀐 경우는 낡음이 아니다.

    OneDrive 동기화, 같은 내용의 git checkout, 파일 복사 — 전부 여기 해당한다.
    mtime 기반 지문이었다면 이런 저장소에서 매번 거짓 '낡음'이 떴을 것이다.
    """
    target = tmp_path / "a.md"
    target.write_text("same", encoding="utf-8")
    before = diagnostics._tree_fingerprint(tmp_path)
    st = target.stat()
    import os

    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    assert diagnostics._tree_fingerprint(tmp_path) == before


def test_fingerprint_detects_added_and_removed_files(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text("x", encoding="utf-8")
    before = diagnostics._tree_fingerprint(tmp_path)
    (tmp_path / "b.md").write_text("y", encoding="utf-8")
    with_added = diagnostics._tree_fingerprint(tmp_path)
    assert with_added != before
    (tmp_path / "b.md").unlink()
    assert diagnostics._tree_fingerprint(tmp_path) == before


def test_fingerprint_detects_rename_with_identical_content(tmp_path: Path) -> None:
    """이름만 바뀌어도 룰 ID·경로 기반 동작이 달라질 수 있다 — 경로도 지문에 넣는다."""
    src = tmp_path / "a.md"
    src.write_text("same bytes", encoding="utf-8")
    before = diagnostics._tree_fingerprint(tmp_path)
    src.rename(tmp_path / "b.md")
    after = diagnostics._tree_fingerprint(tmp_path)
    assert after["bytes"] == before["bytes"]
    assert after["digest"] != before["digest"]


def test_fingerprint_ignores_unrelated_extensions(tmp_path: Path) -> None:
    """판정을 바꾸지 않는 파일(.log, .html 리포트 등)로 경고가 뜨면 안 된다."""
    (tmp_path / "a.md").write_text("x", encoding="utf-8")
    before = diagnostics._tree_fingerprint(tmp_path)
    (tmp_path / "report.html").write_text("<p>결과</p>", encoding="utf-8")
    (tmp_path / "run.log").write_text("noise", encoding="utf-8")
    assert diagnostics._tree_fingerprint(tmp_path) == before


# --------------------------------------------------------------------------
# 판정 — 잡아야 하는 것
# --------------------------------------------------------------------------

def test_freshness_flags_commit_move(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", _probe("a" * 40, "c", "r"))
    monkeypatch.setattr(diagnostics, "_freshness_probe", lambda: _probe("b" * 40, "c", "r"))
    fresh = diagnostics.runtime_freshness()
    assert fresh["process_stale"] is True
    assert fresh["loaded_commit_id"] == "a" * 40
    assert fresh["disk_commit_id"] == "b" * 40
    assert "재시작" in fresh["remedy"]


@pytest.mark.parametrize(("changed", "label"), [("code", "소스 코드"), ("rules", "룰 파일")])
def test_freshness_flags_tree_change(
    monkeypatch: pytest.MonkeyPatch, changed: str, label: str
) -> None:
    """커밋이 그대로여도(= 커밋 안 한 작업 트리 수정) 잡아야 한다."""
    loaded = _probe("a" * 40, "c", "r")
    now = _probe("a" * 40, "c2" if changed == "code" else "c", "r2" if changed == "rules" else "r")
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", loaded)
    monkeypatch.setattr(diagnostics, "_freshness_probe", lambda: now)
    fresh = diagnostics.runtime_freshness()
    assert fresh["process_stale"] is True
    assert any(label in r for r in fresh["reasons"])


def test_freshness_names_a_changed_rules_dir_instead_of_blaming_edits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``GVSKB_RULES_DIR`` 을 바꾼 경우 이유를 정확히 말해야 한다.

    지문만 비교하면 "룰 파일이 수정되었습니다" 가 나오는데, 사용자는 있지도
    않은 파일 수정을 찾아 헤맨다. 낡았다는 판정 자체는 옳다 — 프로세스는
    여전히 이전 경로의 룰을 쓰고 있기 때문이다.
    """
    loaded = _probe("a" * 40, "c", "r")
    now = _probe("a" * 40, "c", "다른내용")
    now["rules_dir"] = "/other"
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", loaded)
    monkeypatch.setattr(diagnostics, "_freshness_probe", lambda: now)
    fresh = diagnostics.runtime_freshness()
    assert fresh["process_stale"] is True
    assert any("룰 디렉터리" in r and "/other" in r for r in fresh["reasons"])
    assert not any("룰 파일이 프로세스 시작 이후 수정" in r for r in fresh["reasons"])


def test_stale_verdict_always_carries_a_remedy(monkeypatch: pytest.MonkeyPatch) -> None:
    """'낡았다'고만 하고 무엇을 하라는 말이 없으면 사용자는 재설치를 반복한다."""
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", _probe("a" * 40, "c", "r"))
    monkeypatch.setattr(diagnostics, "_freshness_probe", lambda: _probe("b" * 40, "c", "r"))
    fresh = diagnostics.runtime_freshness()
    diagnostics._mark_stale(fresh, "추가 근거")
    assert fresh["remedy"]
    assert "재설치가 아니라 재시작" in fresh["remedy"]

    quiet = {"process_stale": False, "reasons": [], "remedy": ""}
    diagnostics._mark_stale(quiet, "뒤늦게 발견한 근거")
    assert quiet["process_stale"] is True
    assert quiet["remedy"], "나중에 붙는 근거에도 조치 방법이 따라와야 한다"


# --------------------------------------------------------------------------
# 판정 — 잡으면 안 되는 것(오경보 금지)
# --------------------------------------------------------------------------

def test_freshness_quiet_when_nothing_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    same = _probe("a" * 40, "c", "r")
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", same)
    monkeypatch.setattr(diagnostics, "_freshness_probe", lambda: dict(same))
    fresh = diagnostics.runtime_freshness()
    assert fresh["process_stale"] is False
    assert fresh["reasons"] == []
    assert fresh["remedy"] == ""


@pytest.mark.parametrize("missing_side", ["loaded", "disk"])
def test_freshness_does_not_guess_when_commit_unknown(
    monkeypatch: pytest.MonkeyPatch, missing_side: str
) -> None:
    """.git 이 없는 배포본(pip 로 받은 사본, 망분리 반입본)에서 오경보 금지.

    한쪽 커밋을 모르면 비교가 성립하지 않는다. 모른다는 이유로 낡았다고 하면
    정상 설치에서 매번 경고가 떠 경고 자체가 무시된다.
    """
    loaded = _probe(None if missing_side == "loaded" else "a" * 40, "c", "r")
    now = _probe(None if missing_side == "disk" else "a" * 40, "c", "r")
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", loaded)
    monkeypatch.setattr(diagnostics, "_freshness_probe", lambda: now)
    assert diagnostics.runtime_freshness()["process_stale"] is False


def test_freshness_does_not_guess_when_probe_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """지문 수집이 실패한(None) 쪽은 비교하지 않는다 — 권한·경합 환경 대비."""
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", _probe("a" * 40, "c", "r"))
    monkeypatch.setattr(
        diagnostics,
        "_freshness_probe",
        lambda: {"commit_id": "a" * 40, "code": None, "rules": None},
    )
    assert diagnostics.runtime_freshness()["process_stale"] is False


def test_this_process_is_fresh() -> None:
    """방금 뜬 프로세스는 정의상 최신이다 — 여기서 stale 이면 지문이 불안정한 것."""
    assert diagnostics.runtime_freshness()["process_stale"] is False


# --------------------------------------------------------------------------
# 노출 — 사용자가 찾아 헤매지 않아도 보이는가
# --------------------------------------------------------------------------

def test_install_identity_reports_loaded_commit_not_disk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``commit_id`` 는 **메모리에 올라간** 커밋이어야 한다.

    호출 시점의 ``.git/HEAD`` 를 그대로 답하면, 머지가 끝난 뒤에도 옛 코드로
    돌고 있는 프로세스가 스스로를 '최신'이라 보고한다 — 실제로 그랬다.
    """
    monkeypatch.setattr(diagnostics, "_direct_url_metadata", lambda: {})
    monkeypatch.setattr(diagnostics, "_git_head_commit", lambda _p: ("d" * 40, "main"))
    monkeypatch.setattr(diagnostics, "_LOADED_PROBE", _probe("1" * 40, "c", "r"))
    identity = diagnostics.install_identity()
    assert identity["commit_id"] == "1" * 40
    assert identity["disk_commit_id"] == "d" * 40


def test_server_status_exposes_freshness_and_rule_source() -> None:
    status = diagnostics.runtime_status_for_mcp()
    fresh = status["runtime_freshness"]
    assert {"process_stale", "reasons", "loaded_commit_id", "disk_commit_id", "remedy"} <= set(fresh)
    # 룰 개수의 출처를 밝힌다 — 디스크를 다시 읽은 수를 최신으로 오해하면 안 된다.
    assert "메모리" in status["rule_count_source"] or "디스크" in status["rule_count_source"]


def test_doctor_includes_runtime_freshness_check() -> None:
    report = diagnostics.run_diagnostics(network=False)
    names = {c["name"] for c in report["checks"]}
    assert "Runtime freshness" in names


# --------------------------------------------------------------------------
# 번들 MCP 설정 — 클론한 사람이 실제로 띄울 수 있는가
# --------------------------------------------------------------------------

def test_bundled_mcp_config_uses_installed_console_script() -> None:
    """`.mcp.json` 의 command 는 pip 이 만들어 주는 진입점이어야 한다.

    bare ``python`` 은 Windows 에서 Microsoft Store 스텁으로 잡히는 일이 잦고,
    그때 서버는 오류도 없이 그냥 뜨지 않는다. 게다가 이 설정에는 ``PYTHONPATH``
    가 없어, 스텁이 아니더라도 소스 체크아웃을 못 찾는다.
    """
    entry = json.loads((REPO_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    server = entry["mcpServers"]["vibecode-checker"]
    scripts = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["scripts"]
    assert server["command"] in scripts, (
        f"{server['command']} 는 pyproject 의 [project.scripts] 에 없습니다 — "
        "설치본과 함께 만들어지지 않는 명령을 번들 설정에 넣으면 안 됩니다."
    )
    assert server["command"] == "gvskb-server"


def test_readme_mcp_snippets_do_not_regress_to_bare_python() -> None:
    """README 의 MCP 스니펫이 세 군데 있어, 한 곳만 고치면 나머지가 되살아난다."""
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert '"command": "python"' not in text
    assert text.count('"command": "gvskb-server"') >= 3
