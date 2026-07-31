"""중앙(기관) 예외 오버레이 — GVSKB_EXCEPTIONS_DIR 병합 테스트.

레지스트리·보안실이 확정한 예외 판정을 내부 배포 지점에서 내려받아 쓰는
'다운로드 준비' 메커니즘이다. 규율은 프로젝트 로컬 예외와 동일하다:
사유·승인자·만료 중 하나라도 없으면 무효.
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from gvskb.schema import CodeLocation, Decision, Finding, Severity
from gvskb.suppressions import apply_suppressions, load_central_exceptions, load_exceptions


def _finding(rule_id: str = "GOV-TEST-001", file: str = "app.py", line: int = 10) -> Finding:
    return Finding(
        id="f1", rule_id=rule_id, title="t", plain_title="t",
        severity=Severity.high, decision=Decision.block, category="test",
        location=CodeLocation(file=file, line=line),
        why_it_matters="테스트",
    )


def _future() -> str:
    return (date.today() + timedelta(days=30)).isoformat()


def _write_central(d: Path, name: str, entries: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(f"exceptions:\n{entries}", encoding="utf-8")


def test_central_dir_unset_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GVSKB_EXCEPTIONS_DIR", raising=False)
    assert load_central_exceptions() == []


def test_central_exceptions_are_merged_and_applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    central = tmp_path / "central"
    _write_central(
        central, "registry-approved.yaml",
        f"  - rule_id: GOV-TEST-001\n"
        f"    file: app.py\n"
        f"    line: 10\n"
        f"    reason: 레지스트리 확정 — 내부망 전용이라 위험 수용\n"
        f"    approved_by: 정보보안실\n"
        f"    expires: {_future()}\n",
    )
    monkeypatch.setenv("GVSKB_EXCEPTIONS_DIR", str(central))

    project_root = tmp_path / "proj"
    project_root.mkdir()
    exceptions = load_exceptions(project_root)      # 로컬 파일 없음 — 중앙만
    assert len(exceptions) == 1
    assert exceptions[0]["_origin"] == "central:registry-approved.yaml"

    f = _finding()
    result = apply_suppressions([f], exceptions)
    assert result.applied == 1
    assert f.suppressed is True
    assert "출처: central:registry-approved.yaml" in (f.suppress_reason or "")


def test_local_and_central_merge_local_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    central = tmp_path / "central"
    _write_central(
        central, "org.yaml",
        f"  - rule_id: GOV-TEST-002\n    file: b.py\n    reason: r\n"
        f"    approved_by: 보안실\n    expires: {_future()}\n",
    )
    monkeypatch.setenv("GVSKB_EXCEPTIONS_DIR", str(central))

    project_root = tmp_path / "proj"
    project_root.mkdir()
    (project_root / ".gvskb-exceptions.yaml").write_text(
        f"exceptions:\n"
        f"  - rule_id: GOV-TEST-001\n    file: a.py\n    reason: 로컬 사유\n"
        f"    approved_by: 담당자\n    expires: {_future()}\n",
        encoding="utf-8",
    )
    merged = load_exceptions(project_root)
    assert [e["_origin"] for e in merged] == ["project", "central:org.yaml"]  # 로컬 우선


def test_central_invalid_entries_still_invalid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """중앙 배포본이라도 승인자·만료 없는 예외는 무효 — 집행 규율 동일."""
    central = tmp_path / "central"
    _write_central(
        central, "sloppy.yaml",
        "  - rule_id: GOV-TEST-001\n    file: app.py\n    reason: 사유만 있음\n",
    )
    monkeypatch.setenv("GVSKB_EXCEPTIONS_DIR", str(central))
    f = _finding()
    result = apply_suppressions([f], load_central_exceptions())
    assert result.applied == 0
    assert f.suppressed is False
    assert result.invalid                            # 무효 사유가 기록된다


def test_central_missing_dir_warns_but_continues(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GVSKB_EXCEPTIONS_DIR", str(tmp_path / "no-such-dir"))
    assert load_central_exceptions() == []


def test_central_multiple_files_sorted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    central = tmp_path / "central"
    for name, rid in (("b-second.yaml", "R2"), ("a-first.yaml", "R1")):
        _write_central(
            central, name,
            f"  - rule_id: {rid}\n    file: x.py\n    reason: r\n"
            f"    approved_by: o\n    expires: {_future()}\n",
        )
    monkeypatch.setenv("GVSKB_EXCEPTIONS_DIR", str(central))
    origins = [e["_origin"] for e in load_central_exceptions()]
    assert origins == ["central:a-first.yaml", "central:b-second.yaml"]  # 이름순 결정성
