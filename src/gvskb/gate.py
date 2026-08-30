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

## 판정은 세 단계다 (2026-08-09 개정)

예전 기준은 **취약점 하나라도 CVSS HIGH 면 차단**이었다. 실측 4개 저장소가
전부 차단됐고, 차단 근거는 **100% `high` 등급 하나**였다 — 악성 0건, KEV 0건,
CRITICAL 0건. 가장 강한 신호 셋은 한 번도 발동한 적이 없는데 가장 흔한 신호와
결과가 같았다.

    차단이 예외가 아니라 기본값이 되면, 그것은 더 이상 신호가 아니다.

게다가 `noti.kpetro` 의 `xlsx 0.18.5` 는 **수정본이 없다.** 담당자가 게이트를
만족시킬 방법이 없었다. 만족시킬 수 없는 게이트는 우회되거나 꺼진다.

그래서 셋으로 나눈다.

===========  =========================================================
판정          조건
===========  =========================================================
**차단**      악성 패키지 · 기관 레지스트리 거부 · 레지스트리에 없는 이름
              (슬롭스쿼팅 의심) · **CISA KEV 등재**(실제로 악용 중) ·
              **CVSS CRITICAL**
**조건부**    그 밖의 모든 발견 — CVSS HIGH 이하 · 쿨다운 · 판정 불가 ·
              **소스 발견 전부**(block 등급 포함)
**승인**      조치할 것이 없음
===========  =========================================================

## 왜 소스는 차단하지 않는가

라운드 13에서 위치를 정했다: **소스는 보조, 의존성은 게이트.** 의존성 판정은
*"이 버전에 이 CVE 가 있다"* 는 **사실 조회**라 오탐이 구조적으로 거의 없고,
소스 룰은 추론이라 맥락을 모르면 틀린다.

그런데 의존성 차단을 좁히면서 소스를 그대로 두면 **원칙이 뒤집힌다** — 오탐이
적은 쪽은 거의 안 막고 틀릴 수 있는 쪽이 막게 된다. 그래서 소스 발견은 전부
조건부로 둔다.

**대신 비밀값·개인정보 노출은 결론 박스에서 따로 세어 앞으로 끌어낸다.**
조건부라고 해서 조용히 넘어가면 안 되는 것이 있다 — 노출된 키는 코드에서
지우는 것만으로 끝나지 않고 **반드시 재발급**해야 한다.

## 필드 계약

`blocked` 의 뜻이 **좁아졌다.** 이 값만 읽어 온 소비자(연동 하네스·레지스트리)는
예전에 막던 것을 이제 통과시킨다. 조용히 느슨해지지 않도록 두 가지를 둔다.

- `verdict` — ``blocked`` | ``conditional`` | ``approved`` | ``undetermined``.
  새 소비자는 이쪽을 읽는다.
- `requires_action` — 차단이든 조건부든 **사람이 할 일이 남았는가**.
  예전 `blocked` 의 "뭔가 조치가 필요하다"는 뜻을 그대로 옮겨 담는다.

CLI 기본값 ``--fail-on warn`` 은 그대로라 CI 는 여전히 발견이 있으면 실패한다.
느슨해지는 것은 ``--fail-on block`` 을 명시한 경우뿐이다.
"""
from __future__ import annotations

from .schema import Decision, ScanReport

#: 배포를 **막는** 사유. 이 다섯만 차단이다.
BLOCK_CRITERIA: dict[str, str] = {
    "malicious": "악성 패키지",
    "registry_rejected": "기관 레지스트리 거부",
    "not_found": "레지스트리에 없는 이름(가짜 이름 의심)",
    "kev": "CISA KEV 등재 — 실제로 악용되고 있음",
    "critical": "CVSS CRITICAL 취약점",
}

#: 사람이 확인해야 하지만 배포를 막지는 않는 사유.
CONDITIONAL_CRITERIA: dict[str, str] = {
    "vulnerable": "CVSS HIGH 이하 취약점",
    "cooldown": "발행 직후 버전 — 아직 신뢰할 수 없음",
    "unchecked": "판정 불가 — '안전'이라는 뜻이 아님",
    "suspicious_name": "인기 패키지와 이름이 거의 같음(타이포스쿼팅 의심)",
    "version_not_found": "요청한 버전이 저장소에 없음(오타·자리차지 패키지 의심)",
    "source": "소스 코드 발견",
}


def _severities(check: dict) -> set[str]:
    """이 패키지에 붙은 취약점 등급 전부.

    ``advisories[].severity`` 와 ``max_cve`` 를 **둘 다** 본다. 실측 데이터에서는
    두 값이 일치했지만, advisory 목록이 비거나 잘린 경로에서 ``max_cve`` 에만
    등급이 남을 수 있다. 차단 판정을 한쪽 필드에만 걸면 그 경로에서 CRITICAL 이
    조용히 통과한다 — 게이트에서 가장 비싼 실패다.
    """
    out = {
        str(a.get("severity") or "").upper()
        for a in (check.get("advisories") or [])
        if isinstance(a, dict)
    }
    top = str(check.get("max_cve") or "").upper()
    if top:
        out.add(top)
    return out


def _dependency_block_reasons(report: ScanReport) -> list[dict]:
    """차단 사유를 **패키지 단위로, 근거와 함께** 모은다.

    이유를 함께 담는 것이 핵심이다. 예전 결론 박스는 *"차단 기준에 걸린 패키지가
    있습니다"* 라고만 적어, 읽는 사람이 **어떤 기준인지 알 수 없었다.**
    """
    from .report import _dep_audits, _dep_merged_components

    audits = _dep_audits(report)
    if not audits:
        return []

    reasons: list[dict] = []
    for comp in _dep_merged_components(audits):
        check = comp.get("check") or {}
        hits: list[str] = []
        if check.get("is_malicious_package"):
            hits.append("malicious")
        if check.get("verdict") == "registry_rejected":
            hits.append("registry_rejected")
        if check.get("verdict") == "not_found":
            hits.append("not_found")
        if check.get("in_kev"):
            hits.append("kev")
        if "CRITICAL" in _severities(check):
            hits.append("critical")
        if not hits:
            continue
        reasons.append({
            "package": check.get("name"),
            "version": check.get("version"),
            "criteria": hits,
            "labels": [BLOCK_CRITERIA[h] for h in hits],
            "recommended_version": check.get("recommended_version"),
        })
    return reasons


def _has_dep_verdict(report: ScanReport, verdict: str) -> bool:
    """의존성 컴포넌트 중 해당 판정이 하나라도 있는가."""
    from .report import _dep_audits, _dep_merged_components

    audits = _dep_audits(report)
    if not audits:
        return False
    return any(
        (comp.get("check") or {}).get("verdict") == verdict
        for comp in _dep_merged_components(audits)
    )


def _has_cooldown_hold(report: ScanReport) -> bool:
    """발행 직후 버전 보류가 있는가.

    `CONDITIONAL_CRITERIA` 에 이름만 올려 두고 아무도 계산하지 않으면 **죽은
    기준**이 된다 — 이 프로젝트가 죽은 검증기로 한 번 겪은 일이다.
    """
    from .report import _dep_audits, _dep_merged_components

    audits = _dep_audits(report)
    if not audits:
        return False
    return any(
        (comp.get("check") or {}).get("verdict") == "cooldown_hold"
        for comp in _dep_merged_components(audits)
    )


def _exposure_counts(report: ScanReport) -> dict:
    """조건부라도 **조용히 넘어가면 안 되는 것**을 따로 센다.

    노출된 키는 코드에서 지우는 것만으로 끝나지 않는다 — Git 이력에 남으므로
    **반드시 재발급**해야 한다. 개인정보는 제거와 유출 신고가 따른다.
    조치의 종류가 다르므로 두 값을 나눠 센다.
    """
    secret = pii = secret_att = pii_att = 0
    for f in report.findings:
        if f.suppressed:
            continue
        # 도구가 스스로 낮춘 것(테스트 경로·안내문·문자열·룰 문서)은 "재발급하라"고
        # 말할 근거가 약하다 — "비밀값 129건 재발급" 중 98건이 그랬다(실측 2026-08-29).
        # 총량은 그대로 두고 살아 있는 것과 낮춘 것을 갈라 센다.
        attenuated = bool(f.severity_adjusted)
        if f.category == "secret-scanning":
            secret += 1
            secret_att += attenuated
        elif f.category == "privacy-public-sector":
            pii += 1
            pii_att += attenuated
    return {
        "secret": secret, "pii": pii,
        "secret_live": secret - secret_att, "secret_attenuated": secret_att,
        "pii_live": pii - pii_att, "pii_attenuated": pii_att,
    }


def attach_gate(report: ScanReport) -> ScanReport:
    """저장·반환 직전에 게이트 판정을 보고서 안에 새긴다.

    의존성 감사는 스캔이 끝난 뒤 붙으므로 **가장 마지막**에 불러야 한다. JSON 을
    읽는 쪽이 ``summary.blocked``(소스 기준)가 아니라 이 값을 보게 하기 위한 것.
    """
    report.gate = gate_status(report)
    return report


def gate_status(report: ScanReport) -> dict:
    """이 결과의 게이트 판정 — 차단 / 조건부 승인 / 승인.

    반환::

        {
          "verdict": "blocked" | "conditional" | "approved" | "undetermined",
          "blocked": bool,                 # verdict == "blocked"
          "conditional": bool,             # verdict == "conditional"
          "requires_action": bool,         # 차단이든 조건부든 할 일이 남았는가
          "block_reasons": [ {package, version, criteria, labels, ...} ],
          "conditional_criteria": [str],   # 왜 조건부인가
          "exposure": {"secret": int, "pii": int},
          "blocked_source": bool,          # 소스에 block 등급 발견이 있는가(사실)
          "blocked_dependency": bool,      # 의존성이 차단 기준에 걸렸는가
          "source_block_count": int,
          "dependency_vulnerable": int,
          "dependency_unchecked": int,
          "reason": str,                   # 사람이 읽는 한 줄
        }
    """
    from .report import _dep_risk       # 순환 import 회피 — 표시 계층의 집계를 재사용

    block_count = sum(
        1 for f in report.findings
        if f.decision == Decision.block and not f.suppressed
    )
    has_source_block = bool(block_count) or bool(report.summary.blocked)
    vuln, unchecked, not_found, _audit_flag = _dep_risk(report)

    block_reasons = _dependency_block_reasons(report)
    blocked = bool(block_reasons)

    conditional_criteria: list[str] = []
    if vuln:
        conditional_criteria.append("vulnerable")
    if _has_cooldown_hold(report):
        conditional_criteria.append("cooldown")
    if unchecked:
        conditional_criteria.append("unchecked")
    if _has_dep_verdict(report, "suspicious_name"):
        conditional_criteria.append("suspicious_name")
    if _has_dep_verdict(report, "version_not_found"):
        conditional_criteria.append("version_not_found")
    if report.summary.finding_count:
        conditional_criteria.append("source")

    exposure = _exposure_counts(report)
    # 소스를 한 건도 보지 못했으면 '안전'이 아니라 '판정 불가'다.
    undetermined = (
        not blocked
        and not report.scanned_files
        and report.summary.finding_count == 0
        and not vuln
        and not unchecked
    )

    if blocked:
        verdict = "blocked"
    elif undetermined:
        verdict = "undetermined"
    elif conditional_criteria:
        verdict = "conditional"
    else:
        verdict = "approved"

    return {
        "verdict": verdict,
        "blocked": verdict == "blocked",
        "conditional": verdict == "conditional",
        "requires_action": verdict in ("blocked", "conditional"),
        "block_reasons": block_reasons,
        "conditional_criteria": conditional_criteria,
        "exposure": exposure,
        # 아래 둘은 **사실 보고**다. `blocked_source` 는 더 이상 배포를 막지
        # 않지만(소스는 보조), 자기 정책으로 막고 싶은 소비자를 위해 남긴다.
        "blocked_source": has_source_block,
        "blocked_dependency": blocked,
        "source_block_count": block_count,
        "dependency_vulnerable": vuln,
        "dependency_unchecked": unchecked,
        "dependency_not_found": not_found,
        "reason": _reason(verdict, block_reasons, conditional_criteria, exposure,
                          block_count, vuln, unchecked),
    }


def _reason(
    verdict: str,
    block_reasons: list[dict],
    conditional: list[str],
    exposure: dict,
    block_count: int,
    vuln: int,
    unchecked: int,
) -> str:
    if verdict == "undetermined":
        return "판정 불가 — 검사된 파일이 0개입니다. 경로·확장자를 확인하세요."
    if verdict == "blocked":
        names = ", ".join(
            f"{r['package']} {r['version'] or ''}".strip() for r in block_reasons[:3])
        labels = sorted({lab for r in block_reasons for lab in r["labels"]})
        more = f" 외 {len(block_reasons) - 3}종" if len(block_reasons) > 3 else ""
        head = (
            f"배포 불가 — {' · '.join(labels)}에 해당하는 패키지가 있습니다"
            f"({names}{more}). 사유 기록으로 넘길 수 없는 등급입니다."
        )
        if block_count:
            head += (
                f" **소스만 고치면 차단이 풀리지 않습니다** — 소스 {block_count}건과 "
                "패키지를 함께 해소하세요."
            )
        if unchecked:
            head += (
                f" 더불어 패키지 {unchecked}종은 **판정 불가**입니다 — "
                "'안전'이라는 뜻이 아닙니다."
            )
        return head
    if verdict == "approved":
        return "조치할 항목이 없습니다."

    parts: list[str] = []
    if vuln:
        parts.append(f"취약 패키지 {vuln}종")
    if unchecked:
        parts.append(f"판정 불가 {unchecked}종")
    if block_count:
        parts.append(f"소스 높은 위험 {block_count}건")
    body = " · ".join(parts) or "확인할 항목"
    tail = ""
    if unchecked:
        # 판정 불가를 세기만 하고 뜻을 안 적으면, 담당자는 '차단 없음'만 읽고
        # 넘어간다. **확인하지 못한 것은 안전한 것이 아니다.**
        tail += " 판정 불가는 **'안전'이라는 뜻이 아닙니다** — 온라인 환경에서 다시 검사하세요."
    s_live, s_att = exposure.get("secret_live", exposure["secret"]), exposure.get("secret_attenuated", 0)
    p_live, p_att = exposure.get("pii_live", exposure["pii"]), exposure.get("pii_attenuated", 0)
    if s_live:
        tail = (
            f" **비밀값 노출 {s_live}건이 포함돼 있습니다 — "
            "코드에서 지우는 것만으로는 끝나지 않습니다. 해당 값을 반드시 "
            "재발급(폐기)하세요.**"
            + (f" (테스트·문서로 추정돼 낮춘 {s_att}건은 별도 — 진짜 값이 아닌지 확인하세요.)" if s_att else "")
        )
    elif p_live:
        tail = (
            f" **개인정보 {p_live}건이 포함돼 있습니다 — 제거 후 "
            "유출 여부를 기관 지침에 따라 확인하세요.**"
            + (f" (테스트·문서로 추정돼 낮춘 {p_att}건은 별도.)" if p_att else "")
        )
    elif s_att or p_att:
        tail = (
            f" 비밀값·개인정보 모양 {s_att + p_att}건이 있으나 테스트·문서로 추정돼 낮췄습니다 — "
            "진짜 값이 섞여 있지 않은지만 확인하세요."
        )
    return (
        f"차단 사유는 없습니다. 확인이 필요한 항목이 있습니다({body}). "
        f"해소하거나, 해소하지 않는 사유를 남긴 뒤 배포하세요.{tail}"
    )


#: `--fail-on` 이 받는 값과 그 뜻. CLI 도움말·MCP 문서가 같은 표를 쓴다.
FAIL_ON_CHOICES: dict[str, str] = {
    "never": "언제나 0 — 검사만 하고 파이프라인은 막지 않습니다",
    "warn": "발견이 하나라도 있으면 실패 (기본) — 조건부 승인도 여기서 걸립니다",
    "block": (
        "**차단**일 때만 실패 — 악성 · 기관 거부 · 미존재 · CISA KEV · "
        "CVSS CRITICAL. 조건부 승인은 통과합니다"
    ),
    "dependency": (
        "의존성 차단만 실패 — 지금은 `block` 과 같습니다(소스는 차단하지 않음). "
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
