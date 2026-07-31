"""GitHub Actions 워크플로 정합성 — 실측 장애 기반 회귀 방지.

실측 장애(2026-07-25 ~ 07-30, 6일 연속):
``gh workflow run`` 호출에 ``actions: write`` 권한이 없어 HTTP 403 으로 실패했고,
그 결과 KEV 룰 PR 이 **24일간 병합되지 못한 채** 방치됐다. 권한 선언은 코드
리뷰에서 놓치기 쉬우므로 테스트로 고정한다.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOW_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"


def _load(name: str) -> dict:
    path = WORKFLOW_DIR / name
    if not path.is_file():
        pytest.skip(f"{name} not present")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _all_run_scripts(workflow: dict) -> str:
    out = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            if isinstance(step.get("run"), str):
                out.append(step["run"])
    return "\n".join(out)


def test_workflows_are_valid_yaml() -> None:
    for path in WORKFLOW_DIR.glob("*.yml"):
        yaml.safe_load(path.read_text(encoding="utf-8"))


def test_workflow_dispatch_requires_actions_write() -> None:
    """``gh workflow run`` 을 쓰는 워크플로는 actions: write 를 선언해야 한다.

    없으면 HTTP 403 으로 조용히 실패한다(실측: 6일 연속 실패 + 룰 PR 24일 정체).
    """
    for path in WORKFLOW_DIR.glob("*.yml"):
        wf = yaml.safe_load(path.read_text(encoding="utf-8"))
        scripts = _all_run_scripts(wf)
        if "gh workflow run" not in scripts:
            continue
        perms = wf.get("permissions") or {}
        assert perms.get("actions") == "write", (
            f"{path.name} 이 `gh workflow run` 을 쓰는데 permissions.actions: write 가 없다 "
            "— HTTP 403 으로 실패한다"
        )


def test_intel_workflow_declares_required_permissions() -> None:
    wf = _load("update-intel.yml")
    perms = wf.get("permissions") or {}
    # PR 생성·번들 릴리스·체크 dispatch 에 각각 필요하다.
    assert perms.get("contents") == "write"
    assert perms.get("pull-requests") == "write"
    assert perms.get("actions") == "write"


def test_intel_workflow_fails_when_bundle_not_published() -> None:
    """사용자가 매일 받는 것은 번들이다 — 배포 실패는 반드시 빨간불이어야 한다.

    이전 구조는 수집 스텝이 continue-on-error 인데 최종 검증이 없어 **수집이
    실패해도 잡이 초록불**로 끝났다(보안 도구에서 가장 위험한 침묵).
    """
    wf = _load("update-intel.yml")
    steps = wf["jobs"]["refresh"]["steps"]
    gate = [s for s in steps if s.get("if") == "always()" and "run" in s]
    assert gate, "always() 로 도는 상태 게이트 스텝이 없다"
    script = gate[-1]["run"]
    assert "exit 1" in script, "실패 조건에서 종료 코드를 내지 않는다"
    assert "BUNDLE" in script and "REFRESH" in script, "수집·배포 결과를 판정하지 않는다"


def test_rule_pr_failure_does_not_fail_the_job() -> None:
    """룰 카드 병합 실패가 번들 배포 성공까지 빨간불로 덮으면 안 된다(경고 피로)."""
    wf = _load("update-intel.yml")
    steps = wf["jobs"]["refresh"]["steps"]
    automerge = [s for s in steps if s.get("id") == "automerge"]
    assert automerge, "auto-merge 스텝에 id 가 없어 결과를 판정할 수 없다"
    assert automerge[0].get("continue-on-error") is True


def test_test_workflow_has_packaging_job() -> None:
    """구버전 사본이 현재 코드를 가리는 사고를 CI 가 잡아야 한다."""
    wf = _load("test.yml")
    assert "packaging" in (wf.get("jobs") or {}), "패키징 스모크 잡이 없다"
    scripts = _all_run_scripts(wf)
    assert "install_problem" in scripts, "설치 정합성 검사를 호출하지 않는다"
