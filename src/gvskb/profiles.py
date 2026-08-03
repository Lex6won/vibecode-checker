"""정책 프로파일 — 같은 finding도 업무 시나리오에 따라 decision이 달라진다.

공무원 입장에서 "민원 챗봇 코드"와 "내부 통계 DB 조회 코드"는 위협 모델이
다릅니다. 같은 SQL injection이라도 후자에선 절대 block이지만 전자에선 LLM
경로 차단이 우선입니다. 이 모듈은 그 차이를 정책 YAML로 표현합니다.
"""
from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .schema import Decision, Finding, Severity

# 기본 프로파일 — 정책이 비어 있어도 정상 동작.
DEFAULT_PROFILE_ID = "public-default-strict"

_SEVERITY_RANK = {Severity.low: 0, Severity.medium: 1, Severity.high: 2, Severity.critical: 3}


class ProfileSpec(BaseModel):
    """A scenario-bound policy profile."""

    profile_id: str
    name: str = ""
    description: str = ""
    applies_to: list[str] = Field(default_factory=list)
    data_policy: dict = Field(default_factory=dict)
    network_policy: dict = Field(default_factory=dict)
    package_policy: dict = Field(default_factory=dict)
    agent_policy: dict = Field(default_factory=dict)
    logging_policy: dict = Field(default_factory=dict)
    decision_overrides: dict[str, str] = Field(
        default_factory=dict,
        description="rule_id → 'block' | 'warn' | 'allow' override",
    )
    category_overrides: dict[str, str] = Field(
        default_factory=dict,
        description="category → 'block' | 'warn' | 'allow' override",
    )
    severity_min: str | None = Field(
        default=None,
        description="Drop findings below this severity ('low' | 'medium' | 'high' | 'critical')",
    )
    exceptions: dict = Field(default_factory=dict)
    resolved: bool = Field(
        default=True,
        description=(
            "정책 파일을 실제로 찾아 읽었는가. False 면 요청한 프로파일이 없어 "
            "아무 정책도 적용되지 않은 상태다 — 호출자는 이를 '적용됨'으로 "
            "기록해서는 안 된다."
        ),
    )


def _resolve_policies_dir() -> Path:
    """env override → repo checkout → packaged data (same precedence as rules)."""
    override = os.environ.get("GVSKB_POLICIES_DIR")
    if override:
        return Path(override)
    pkg_root = Path(__file__).resolve().parent
    project_root = pkg_root.parent.parent
    repo_policies = project_root / "policies"
    if repo_policies.exists():
        return repo_policies
    return Path(str(resources.files("gvskb").joinpath("policies")))


def load_profile(profile_id: str) -> ProfileSpec:
    """Load a profile by id. Falls back to an empty spec for unknown ids.

    ``resolved=False`` 로 **찾지 못했음을 값에 실어** 돌려준다. 예전에는 빈 스펙과
    정상 스펙이 구분되지 않아, 호출자가 요청한 이름을 그대로 리포트에 적었다 —
    실측(하네스 연동, 2026-08-03): `profile="dev-quick"` 이 정책 파일을 못 찾아
    아무 필터도 적용되지 않았는데 **보고서에는 `dev-quick` 으로 판정했다고 적혔다.**
    판정 근거를 틀리게 말하는 것이라 조용한 초록불과 같은 계열의 결함이다.
    """
    pid = profile_id or DEFAULT_PROFILE_ID
    p = _resolve_policies_dir() / f"{pid.replace('_', '-')}.yaml"
    if not p.exists():
        # Try snake_case form as a fallback (file naming variance)
        p = _resolve_policies_dir() / f"{pid.replace('-', '_')}.yaml"
    if not p.exists():
        return ProfileSpec(profile_id=pid, name=f"unknown profile: {pid}", resolved=False)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    spec = ProfileSpec.model_validate(data)
    spec.resolved = True
    return spec


def list_profiles() -> list[str]:
    """Return profile_id list available in the resolved policies dir."""
    pdir = _resolve_policies_dir()
    if not pdir.exists():
        return []
    return sorted(p.stem.replace("_", "-") for p in pdir.glob("*.yaml"))


def apply_profile(findings: list[Finding], profile: ProfileSpec) -> list[Finding]:
    """Apply decision/category overrides and severity_min filter.

    Returns a new list; original findings are not mutated.
    """
    out: list[Finding] = []
    min_rank = _SEVERITY_RANK.get(Severity(profile.severity_min)) if profile.severity_min else -1

    for f in findings:
        if min_rank is not None and min_rank >= 0:
            if _SEVERITY_RANK[f.severity] < min_rank:
                continue

        new_decision = f.decision
        if f.rule_id in profile.decision_overrides:
            new_decision = Decision(profile.decision_overrides[f.rule_id])
        elif f.category in profile.category_overrides:
            new_decision = Decision(profile.category_overrides[f.category])

        if new_decision is f.decision:
            out.append(f)
        else:
            out.append(f.model_copy(update={
                "decision": new_decision,
                "requires_approval_to_bypass": new_decision == Decision.block,
            }))
    return out
