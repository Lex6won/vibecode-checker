"""게이트 판정 — "이 결과는 막아야 하는가"를 **한 곳에서만** 계산한다.

## 왜 필요한가 (실측 결함)

`ScanSummary.blocked` 은 **소스 발견만** 보고 정해진다. 의존성 감사는 스캔이
끝난 뒤에 `report.dependency_audit` 로 붙기 때문이다. 그래서 이런 일이 있었다:

    의존성 CRITICAL 취약 패키지 있음
      · 보고서 본문   → "배포 불가 — 차단 기준에 걸린 패키지가 있습니다"
      · summary.blocked → False
      · MCP render_report 의 `blocked` → False
      · CLI `--fail-on block` 종료코드 → 0 (통과)

**같은 문서가 사람에게는 막으라고 하고 기계에게는 통과라고 답했다.** 라운드 9의
*"게이트가 없는 필드를 읽음"* 과 같은 유형이 우리 쪽에 있었던 것이다.

## 왜 둘을 나누는가

라운드 13에서 위치를 다시 정했다.

> **소스는 보조, 의존성은 게이트.**

의존성 판정은 *"이 버전에 이 CVE 가 있다"* 는 **사실 조회**라 오탐이 구조적으로
거의 없다. 소스 룰은 추론이라 맥락을 모르면 틀린다. 상용툴이 PR 을 막는 것도
대부분 SCA 이지 SAST 가 아니다.

그런데 우리는 둘을 `blocked` 하나로 묶어 놨었다. 소스 오탐 하나 때문에 팀이
게이트를 통째로 꺼 버리면, **오탐이 없는 의존성 차단까지 함께 꺼진다.** 그래서
신호를 나눠 두 가지를 가능하게 한다:

- 기관은 `--fail-on dependency` 로 **의존성만** 막고 소스는 참고로 둘 수 있다.
- 연동 하네스는 `blocked_source` / `blocked_dependency` 를 따로 읽어
  자기 정책을 세울 수 있다.

`blocked` 는 둘의 합집합으로 남긴다 — 기존 소비자가 조용히 느슨해지면 안 된다.
"""
from __future__ import annotations

from .schema import Decision, ScanReport


def gate_status(report: ScanReport) -> dict:
    """이 결과의 게이트 판정 — 소스·의존성을 나눠서, 합집합과 함께.

    반환::

        {
          "blocked": bool,              # 둘 중 하나라도 막으면 True (기존 계약)
          "blocked_source": bool,       # 소스 룰이 막는가
          "blocked_dependency": bool,   # 의존성 감사가 막는가
          "source_block_count": int,
          "dependency_vulnerable": int,
          "dependency_unchecked": int,  # 판정 불가 — '안전'이 아니다
          "reason": str,                # 사람이 읽는 한 줄
        }
    """
    from .report import _dep_risk       # 순환 import 회피 — 표시 계층의 집계를 재사용

    block_count = sum(
        1 for f in report.findings
        if f.decision == Decision.block and not f.suppressed
    )
    blocked_source = bool(block_count) or bool(report.summary.blocked)
    vuln, unchecked, _not_found, blocked_dependency = _dep_risk(report)

    return {
        "blocked": blocked_source or blocked_dependency,
        "blocked_source": blocked_source,
        "blocked_dependency": blocked_dependency,
        "source_block_count": block_count,
        "dependency_vulnerable": vuln,
        "dependency_unchecked": unchecked,
        "reason": _reason(blocked_source, blocked_dependency, block_count, vuln, unchecked),
    }


def _reason(
    src: bool, dep: bool, block_count: int, vuln: int, unchecked: int,
) -> str:
    if src and dep:
        return (
            f"소스 차단 {block_count}건과 차단 기준에 걸린 패키지가 함께 있습니다. "
            "**둘 다** 해소해야 합니다 — 소스만 고치면 배포 차단이 풀리지 않습니다."
        )
    if dep:
        return (
            f"소스 차단은 없고 **패키지**가 막습니다(취약 {vuln}종). "
            "안전한 버전으로 올린 뒤 다시 검사하세요."
        )
    if src:
        base = f"**소스** 차단 {block_count}건입니다."
        if unchecked:
            base += (
                f" 더불어 패키지 {unchecked}종은 **판정 불가**입니다 — "
                "'안전'이라는 뜻이 아닙니다."
            )
        return base
    if unchecked:
        return (
            f"차단 없음. 다만 패키지 {unchecked}종이 **판정 불가**입니다 — "
            "'안전'이라는 뜻이 아니므로 온라인 환경에서 다시 검사하세요."
        )
    return "차단 없음."


#: `--fail-on` 이 받는 값과 그 뜻. CLI 도움말·MCP 문서가 같은 표를 쓴다.
FAIL_ON_CHOICES: dict[str, str] = {
    "never": "언제나 0 — 검사만 하고 파이프라인은 막지 않습니다",
    "warn": "발견이 하나라도 있으면 실패 (기본)",
    "block": "차단(block) 판정일 때만 실패 — 소스·의존성 둘 다 본다",
    "dependency": (
        "**의존성 차단만** 실패 — 소스 발견은 보고만 합니다. "
        "'소스는 보조, 의존성은 게이트' 를 그대로 옮긴 설정입니다"
    ),
}


def should_fail(report: ScanReport, fail_on: str) -> bool:
    """`--fail-on` 정책에 따라 이 결과가 파이프라인을 막아야 하는가."""
    if fail_on == "never":
        return False
    status = gate_status(report)
    if fail_on == "dependency":
        return status["blocked_dependency"]
    if status["blocked"]:
        return True
    return fail_on == "warn" and report.summary.finding_count > 0
