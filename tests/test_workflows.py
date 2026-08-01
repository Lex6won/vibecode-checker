"""GitHub Actions 워크플로 정합성 — 실측 장애 기반 회귀 방지.

실측 장애 1 (2026-07-25 ~ 07-30, 6일 연속):
``gh workflow run`` 호출에 ``actions: write`` 권한이 없어 HTTP 403 으로 실패했다.

실측 장애 2 (2026-07-07 ~ 07-31, PR #4 가 24일간 정체):
장애 1 을 고쳐 dispatch 가 성공한 뒤에도 PR 은 계속 BLOCKED 이었다. **그
``gh workflow run`` 우회책 자체가 원인**이었다 — GITHUB_TOKEN 이 만든 PR 은
pull_request 런이 ``action_required``(승인 대기)에서 멈춰 head 커밋의
statusCheckRollup 이 null 이 되고, 룰셋은 필수 체크가 "보고되지 않았다"고
판단한다. 이름·SHA·앱ID 가 일치하는 성공 체크를 dispatch 로 따로 붙여도
그 게이트는 통과하지 못한다. 해법은 PR 을 PAT 로 만드는 것이다.

두 장애 모두 코드 리뷰에서 놓치기 쉬운 선언(권한·토큰)이 원인이므로 테스트로
고정한다.
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


def _steps(workflow: dict, job: str = "refresh") -> list[dict]:
    return workflow["jobs"][job]["steps"]


def test_intel_workflow_declares_required_permissions() -> None:
    wf = _load("update-intel.yml")
    perms = wf.get("permissions") or {}
    # 룰 카드 커밋(contents)·PR 생성과 자동 병합(pull-requests)에 필요하다.
    assert perms.get("contents") == "write"
    assert perms.get("pull-requests") == "write"
    # actions: write 는 `gh workflow run` 우회책 때문에 받았던 권한이다.
    # 그 우회책이 제거됐으므로 권한도 반납한다(최소 권한). 다시 필요해졌다면
    # 그건 우회책이 되살아났다는 뜻이니 여기서 멈추고 다시 판단해야 한다.
    if "gh workflow run" not in _all_run_scripts(wf):
        assert "actions" not in perms, (
            "`gh workflow run` 을 쓰지 않는데 actions: write 를 들고 있다 — 불필요한 권한"
        )


def test_intel_pr_is_not_created_with_github_token() -> None:
    """PR 은 PAT 로 만들어야 한다 — GITHUB_TOKEN 으로 만들면 영구히 병합되지 않는다.

    실측(PR #4, 24일 정체): GITHUB_TOKEN 이 만든 PR 의 pull_request 런은 전부
    ``action_required`` 에서 멈춰 필수 체크가 "보고되지 않음"으로 남는다.
    """
    wf = _load("update-intel.yml")
    cpr = [s for s in _steps(wf) if "create-pull-request" in str(s.get("uses", ""))]
    assert cpr, "PR 생성 스텝을 찾지 못했다"
    token = str((cpr[0].get("with") or {}).get("token", ""))
    assert "secrets.GITHUB_TOKEN" not in token, (
        "PR 을 GITHUB_TOKEN 으로 만들면 필수 체크가 승인 대기에 걸려 영구 BLOCKED 된다"
    )
    assert "secrets." in token, "PR 생성 토큰이 시크릿으로 지정돼 있지 않다"

    # 자동 병합도 같은 토큰으로 걸어야 한다 — GITHUB_TOKEN 으로 병합하면
    # main 으로의 push 가 재귀 방지에 걸려 main HEAD 에 CI 가 붙지 않는다.
    automerge = [s for s in _steps(wf) if s.get("id") == "automerge"]
    assert automerge, "auto-merge 스텝이 없다"
    gh_token = str((automerge[0].get("env") or {}).get("GH_TOKEN", ""))
    assert "secrets.GITHUB_TOKEN" not in gh_token, (
        "GITHUB_TOKEN 으로 병합하면 main HEAD 에 CI 가 붙지 않는다"
    )


def test_intel_workflow_does_not_fake_required_checks() -> None:
    """dispatch 로 필수 체크를 대신 채우려 하면 안 된다 — 게이트를 통과하지 못한다."""
    wf = _load("update-intel.yml")
    scripts = _all_run_scripts(wf)
    assert "gh workflow run test.yml" not in scripts, (
        "workflow_dispatch 로 만든 체크런은 이름·SHA 가 같아도 PR 필수 체크를 "
        "충족시키지 못한다(PR #4 가 24일 정체한 원인)"
    )


def test_missing_pr_token_is_reported_not_silent() -> None:
    """토큰이 없어 PR 을 못 만든 상황이 '새 KEV 가 없었다'와 구분돼야 한다.

    구분되지 않으면 조용한 초록불이 된다 — 토큰 만료 시에도 같은 일이 벌어진다.
    """
    wf = _load("update-intel.yml")
    gate = [s for s in _steps(wf) if s.get("if") == "always()" and "run" in s]
    assert gate, "always() 로 도는 상태 게이트 스텝이 없다"
    script = gate[-1]["run"]
    assert "PR_TOKEN_STATE" in script, "PR 토큰 상태를 상태 게이트가 판정하지 않는다"
    assert "::warning::" in script, "토큰 이상이 로그에 흔적을 남기지 않는다"


def test_pr_token_is_checked_on_every_run_not_only_when_rules_change() -> None:
    """토큰 점검이 '새 룰이 있을 때'에만 돌면 만료를 늦게 발견한다.

    실측(2026-07-31 스케줄 실행): 새 KEV 가 없어 detect 가 changed=false 를 내자
    토큰 관련 단계가 전부 skipped 됐다. 이 구조면 토큰이 만료돼도 다음에 새 KEV 가
    나오는 날까지 아무도 모르고, 그날 처음 실패한다. PAT 는 만료가 있으므로
    언젠가 반드시 오는 상황이다.
    """
    wf = _load("update-intel.yml")
    step = [s for s in _steps(wf) if s.get("id") == "prtoken"]
    assert step, "prtoken 스텝이 없다"
    cond = str(step[0].get("if", ""))
    assert "changed" not in cond, (
        "토큰 점검이 detect.changed 에 묶여 있다 — 새 룰이 없는 날엔 만료를 발견하지 못한다"
    )
    # 존재 여부만 보면 만료된 토큰이 'available' 로 통과한다. 실제 조회까지 해야 한다.
    assert "gh api" in step[0].get("run", ""), "토큰 유효성(만료·권한)을 실제로 확인하지 않는다"


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


def test_lint_rule_set_is_pinned() -> None:
    """린터 규칙 집합을 명시해야 한다 — 기본값은 버전마다 바뀐다.

    실측: ruff 0.16 이 기본 규칙을 확대해 **코드 변경 없이** CI 가 139건 실패했다
    (로컬 0.15 는 통과 → CI 만 깨지는 상태). 규칙은 의도적으로 선택해야 한다.
    """
    import tomllib

    pyproject = WORKFLOW_DIR.parent.parent / "pyproject.toml"
    cfg = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    select = ((cfg.get("tool") or {}).get("ruff") or {}).get("lint", {}).get("select")
    assert select, "pyproject 에 [tool.ruff.lint] select 가 없다 — 기본값 변경에 취약하다"


def test_dev_tools_have_upper_bounds() -> None:
    """린터·테스트 러너는 상한을 둔다(기본 동작 변경이 CI 를 깨뜨린 실측 사례)."""
    import tomllib

    pyproject = WORKFLOW_DIR.parent.parent / "pyproject.toml"
    cfg = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    dev = (cfg["project"].get("optional-dependencies") or {}).get("dev", [])
    for spec in dev:
        assert "<" in spec, f"{spec} 에 상한이 없다 — 상위 버전 변경에 무방비다"


def test_test_workflow_has_packaging_job() -> None:
    """구버전 사본이 현재 코드를 가리는 사고를 CI 가 잡아야 한다."""
    wf = _load("test.yml")
    assert "packaging" in (wf.get("jobs") or {}), "패키징 스모크 잡이 없다"
    scripts = _all_run_scripts(wf)
    assert "install_problem" in scripts, "설치 정합성 검사를 호출하지 않는다"
