"""JSON 계약 필드 — 소비자(포털·하네스)가 문장 대신 값을 읽게 하는 장치.

배경: 이 결과를 읽는 자동화가 **없는 필드를 읽고 조용히 틀린 값을 쓰는** 사고가
두 번 반복됐다.

    2026-08-30  포털이 없는 `dependency_audit.summary.finding_count` 를 읽어
                취약 패키지 7종을 "0건"으로 표시
    2026-09-12  포털이 없는 `report.decision` 을 읽고 `summary.blocked`(소스 전용
                옛 필드)로 폴백해 **배포 판정이 양방향으로 뒤집힘**

원인은 같다 — 계약이 값이 아니라 **한국어 문장**과 암묵적 관행으로 묶여 있었다.
아래 테스트는 그 값들이 실제로 존재하고, 뜻대로 채워지는지를 못 박는다.
"""
from __future__ import annotations

import subprocess

import pytest

from gvskb.scanner import engine_status, scan_code, scan_path, source_snapshot_for
from gvskb.schema import SCAN_REPORT_SCHEMA_VERSION
from gvskb.vcps import cooldown_days_for, env_grade_supported, normalize_env_grade


# ---------------------------------------------------------------------------
# 계약 버전
# ---------------------------------------------------------------------------

def test_scan_report_carries_schema_version() -> None:
    report = scan_code("x = 1\n", filename="a.py")
    assert report.schema_version == SCAN_REPORT_SCHEMA_VERSION
    assert report.model_dump(mode="json")["schema_version"] == SCAN_REPORT_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# 검사 범위 — 문장이 아니라 값으로
# ---------------------------------------------------------------------------

def test_coverage_reports_truncation_as_a_value(tmp_path) -> None:
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")

    report = scan_path(str(tmp_path), max_files=2)

    assert report.coverage.truncated is True
    assert report.coverage.over_limit_count == 3
    assert report.coverage.max_files == 2
    assert report.coverage.scanned_count == 2
    # 사람용 문장도 그대로 남는다 — 둘 다 있어야 한다.
    assert any("max_files=" in (s.reason or "") for s in report.skipped_files)


def test_coverage_is_false_when_everything_was_scanned(tmp_path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    report = scan_path(str(tmp_path), max_files=100)
    assert report.coverage.truncated is False
    assert report.coverage.over_limit_count == 0


# ---------------------------------------------------------------------------
# 엔진 상태 — "안 돌았음"과 "돌았는데 깨끗함"을 구분한다
# ---------------------------------------------------------------------------

def test_engines_are_recorded_on_every_report() -> None:
    report = scan_code("x = 1\n", filename="a.py")
    names = set(report.engines.used) | {e.name for e in report.engines.unavailable}
    # 항상 도는 엔진은 사용 목록에 있어야 한다.
    assert "regex" in report.engines.used
    assert {"regex", "python-ast", "js-taint", "semgrep"} <= names


def test_unavailable_engine_carries_a_reason() -> None:
    status = engine_status()
    for item in status.unavailable:
        assert item.reason, f"{item.name}: 사유 없이 '미수행'만 적으면 무엇을 잃었는지 알 수 없다"


def test_engine_failure_is_recorded_not_swallowed() -> None:
    """엔진이 죽어도 검사는 계속되지만, 죽었다는 사실은 남아야 한다."""
    status = engine_status({"semgrep": "RuntimeError: boom"})
    failed = {item.name: item.reason for item in status.failed}
    assert failed.get("semgrep") == "RuntimeError: boom"
    assert "semgrep" not in status.used


# ---------------------------------------------------------------------------
# 소스 신원 — 무엇을 검사했는가
# ---------------------------------------------------------------------------

def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def test_source_snapshot_is_none_outside_a_git_repo(tmp_path) -> None:
    """모르는 것을 지어내지 않는다."""
    assert source_snapshot_for(tmp_path) is None


@pytest.mark.skipif(not _git_available(), reason="git 이 없는 환경")
def test_source_snapshot_records_commit_and_dirty_state(tmp_path) -> None:
    def run(*args: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *args], capture_output=True, check=True)

    run("init")
    run("config", "user.email", "test@example.com")
    run("config", "user.name", "test")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")
    run("add", ".")
    run("commit", "-m", "init")

    snapshot = source_snapshot_for(tmp_path)
    assert snapshot is not None
    assert len(snapshot.commit or "") == 40
    assert snapshot.dirty is False
    # 락파일 지문이 있어야 패키지 판정도 재현할 수 있다.
    assert "requirements.txt" in snapshot.lockfiles

    (tmp_path / "a.py").write_text("x = 2\n", encoding="utf-8")
    assert source_snapshot_for(tmp_path).dirty is True, (
        "커밋되지 않은 변경이 있으면 커밋 해시만으로 재현되지 않는다 — 숨기면 안 된다"
    )


# ---------------------------------------------------------------------------
# 실행환경 등급 — 조용한 폴백 금지
# ---------------------------------------------------------------------------

def test_env_grade_normalizes_case() -> None:
    assert normalize_env_grade(" e2 ") == "E2"
    assert cooldown_days_for("e2")[1] == "E2", "표기 차이로 판정 기준이 달라지면 안 된다"


def test_unsupported_env_grade_is_reported_not_silently_replaced() -> None:
    # E3(대민·개인정보)는 체커가 의도적으로 지원하지 않는 등급이다.
    assert env_grade_supported("E3") is False
    assert env_grade_supported("E9") is False
    # 적용값은 기본 등급이지만, 그 사실이 호출자에게 전달되어야 한다.
    assert cooldown_days_for("E3")[1] == "E1"


def test_supported_grades_stay_supported() -> None:
    for grade in ("E0", "E1", "E2"):
        assert env_grade_supported(grade) is True
    assert env_grade_supported(None) is True, "미지정은 기본 등급 사용 — 지원 대상이다"


def test_audit_manifest_refuses_unsupported_grade_without_checking() -> None:
    """E3 는 낮은 등급으로 바꿔 계산하지 않고 **검사 자체를 하지 않는다**.

    기본 등급으로 계산한 뒤 "검토 필요"만 붙이면, 그 수치가 이 업무의 기준인 것
    처럼 읽힌다. 답하지 않는 것이 정직하다.
    """
    import asyncio

    from gvskb.tools.check_package import audit_manifest

    result = asyncio.run(audit_manifest("flask==2.0.0\n", ecosystem="pypi", env_grade="E3"))

    assert result["verdict"] == "unsupported_env_grade"
    assert result["requires_review"] is True
    assert result["env_grade"] is None, "적용된 등급이 없어야 한다 — 검사하지 않았으므로"
    assert result["requested_env_grade"] == "E3"
    assert result["checks"] == [], "패키지를 하나도 검사하지 않아야 한다"
    assert result["checked_count"] == 0


def test_check_package_refuses_unsupported_grade_without_network() -> None:
    """단일 패키지 경로도 같다 — 네트워크를 쓰지 않고 즉시 끝난다."""
    import asyncio

    from gvskb.tools.check_package import check_package_impl

    result = asyncio.run(check_package_impl("flask", ecosystem="pypi", env_grade="E3"))

    assert result["verdict"] == "unsupported_env_grade"
    assert result["checked"] is False
    assert result["requires_review"] is True


def test_supported_grade_still_runs_the_audit(monkeypatch) -> None:
    """좁히다가 정상 경로를 막으면 안 된다(반대 방향 회귀).

    오프라인 모드로 고정한다 — 네트워크 의존 테스트는 CI 에서 흔들린다.
    """
    import asyncio

    monkeypatch.setenv("GVSKB_MODE", "offline")
    from gvskb.tools.check_package import audit_manifest

    result = asyncio.run(audit_manifest("flask==2.0.0\n", ecosystem="pypi", env_grade="E2"))
    assert result["verdict"] != "unsupported_env_grade"
    assert result["env_grade"] == "E2", "적용된 등급이 결과에 남아야 한다"
    assert result["parsed_count"] == 1, "정상 등급에서는 패키지를 실제로 파싱해야 한다"


# ---------------------------------------------------------------------------
# 인라인 무시 집계 — 면제가 보고서에 드러나야 한다
# ---------------------------------------------------------------------------

def test_inline_ignore_count_reaches_suppression_summary(tmp_path) -> None:
    (tmp_path / "a.py").write_text(
        "eval(user_input)  # gvskb: ignore\n"
        "x = 1\n",
        encoding="utf-8",
    )
    report = scan_path(str(tmp_path))
    assert report.suppression_summary is not None, (
        "승인자·사유 없이 검사를 끈 줄이 있으면 요약에 드러나야 한다"
    )
    assert report.suppression_summary["inline_ignored"] == 1


def test_no_suppression_summary_when_nothing_was_suppressed(tmp_path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    report = scan_path(str(tmp_path))
    assert report.suppression_summary is None
