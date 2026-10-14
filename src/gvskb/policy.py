"""판정 계층의 **단일 원천** (32차, 2026-10-15).

감쇄 10종·근거 정책·프로파일·중복 제거가 저마다 예외 목록과 순위 상수를 들고 있었다
(전면 점검 docs/40 §4-1: `_ENGINE_PRECISION` 2벌(semgrep 순서 반대)·`SEVERITY_RANK` 3벌·
값 기반 목록이 감쇄마다 다름). 같은 목록을 여러 곳에 적으면 언젠가 어긋난다 — 여기 한 곳에
두고 전부 여기서 가져간다.

- 순위 상수: ``SEVERITY_RANK``·``DECISION_RANK``·``ENGINE_PRECISION``·``CONFIDENCE_RANK``
- 예외 목록: ``is_value_based``(값 자체가 위험 — 비밀값·개인정보·내부망), ``CONSTRUCT_EVIDENCE_RULE_IDS``
  (구문 자체가 약점 — 근거 정책의 예외)
- 감쇄 기록: ``attenuate``/``record_adjustment`` — 모든 감쇄는 이 함수를 거쳐 ``Finding.adjustments``
  에 **이력**으로 쌓인다(예전엔 ``severity_adjusted`` 문자열을 덮어써 몇 단계를 거쳤는지 알 수 없었다).
- 줄 체계: ``split_lines``/``normalize_newlines`` — 정규식은 ``str.splitlines()``(폼피드·U+2028 도 줄),
  AST 는 ``\\n`` 만 세어 같은 발견이 다른 줄로 2건이 됐다(§4-4). 전부 ``\\n`` 으로 센다.
"""
from __future__ import annotations

from .schema import EXPOSURE_CATEGORIES, VALUE_BASED_RULE_IDS, Decision, Finding, Severity

# ── 순위 상수 (한 벌) ──────────────────────────────────────────────────────────
SEVERITY_RANK: dict[Severity, int] = {
    Severity.low: 0, Severity.medium: 1, Severity.high: 2, Severity.critical: 3,
}
DECISION_RANK: dict[Decision, int] = {Decision.block: 2, Decision.warn: 1, Decision.allow: 0}
#: 엔진의 근거 강도 — 데이터 흐름을 본 발견이 패턴만 본 발견보다 앞선다. 중복 제거(같은 룰·줄)와
#: 그룹 병합이 같은 순위를 쓴다. semgrep 은 Windows 에서 꺼져 있지만 켜지면 js-taint 와 같은 급.
ENGINE_PRECISION: dict[str, int] = {
    "python-ast": 3, "js-taint": 2, "semgrep": 2, "secret-file": 1, "regex": 1,
}
CONFIDENCE_RANK: dict[str, int] = {"confirmed": 3, "likely": 2, "pattern-only": 1}

# ── 예외 목록 (한 벌) ──────────────────────────────────────────────────────────
#: 구문 자체가 약점인 룰 — 값이 어디서 왔는지와 무관하게 그 코드 모양이 곧 위험이다(인증서 검증
#: 해제, eval/exec, 디버그 모드, XXE, 자동 이스케이프 해제, 한 줄에 출처와 sink 가 함께 있는 DOM XSS,
#: 개인정보 값이 프롬프트에 박힘). 근거 정책은 이 룰의 차단을 '유력/패턴'이라고 내리지 않는다.
CONSTRUCT_EVIDENCE_RULE_IDS: frozenset[str] = frozenset({
    "GOV-FLASK-DEBUG-001", "KISA-PY-ENCAP-02",
    "KISA-PY-SEC-11", "KISA-JS-SEC-11",
    "KISA-PY-INPUT-02", "KISA-JS-INPUT-02", "KISA-JS-API-02", "GOV-CODE-EXEC-001",
    "KISA-PY-INPUT-04", "KISA-PY-INPUT-08", "KISA-JS-INPUT-08",
    "GOV-INTERNAL-NET-001", "GOV-HTML-DOM-XSS-001",
    "GOV-LLM-PII-PROMPT-001",
})


def is_value_based(finding: Finding) -> bool:
    """값 자체가 위험인 발견(비밀값·개인정보·내부망) — 경로·문맥 감쇄의 대상이 아니다.

    실측(2026-08): 같은 집합이 세 곳에 따로 적혀 있었고 하나에 `public-sector-internal` 이 빠져
    테스트 픽스처의 사설 IP 48건이 차단으로 올라왔다. 카테고리와 룰 ID 둘 다 본다.
    """
    return (
        finding.category in EXPOSURE_CATEGORIES
        or finding.rule_id in VALUE_BASED_RULE_IDS
        or finding.engine == "secret-file"          # 비밀 파일 특례 — 값(키 자재) 그 자체다
    )


def is_value_based_rule(rule_id: str, category: str | None) -> bool:
    return (category in EXPOSURE_CATEGORIES) or (rule_id in VALUE_BASED_RULE_IDS)


def is_construct_evidence(finding: Finding) -> bool:
    return finding.rule_id in CONSTRUCT_EVIDENCE_RULE_IDS


# ── 감쇄 기록 ──────────────────────────────────────────────────────────────────

def record_adjustment(
    finding: Finding, *, step: str, reason: str,
    severity: Severity | None = None, decision: Decision | None = None,
) -> Finding:
    """판정을 바꾸고 그 사실을 ``adjustments`` 이력과 ``severity_adjusted`` 요약에 남긴다.

    ``severity_adjusted`` 는 기존 소비자(보고서·게이트·포털)를 위해 유지하되 **덮어쓰지 않고 이어
    붙인다**(`" | "`). 사람이 읽는 형식은 그대로: ``high → low · 사유`` / ``high → high (차단→검토) · 사유``.
    """
    new_sev = severity if severity is not None else finding.severity
    new_dec = decision if decision is not None else finding.decision
    arrow = f"{finding.severity.value} → {new_sev.value}"
    if new_sev == finding.severity and finding.decision == Decision.block and new_dec == Decision.warn:
        arrow += " (차단→검토)"
    elif new_sev == finding.severity and finding.decision != Decision.block and new_dec == Decision.block:
        arrow += " (검토→차단)"
    note = f"{arrow} · {reason}"
    entry = {
        "step": step,
        "from_severity": finding.severity.value, "to_severity": new_sev.value,
        "from_decision": finding.decision.value, "to_decision": new_dec.value,
        "reason": reason,
    }
    prior = finding.severity_adjusted
    return finding.model_copy(update={
        "severity": new_sev,
        "decision": new_dec,
        "requires_approval_to_bypass": new_dec == Decision.block and finding.requires_approval_to_bypass
        if new_dec == finding.decision else new_dec == Decision.block,
        "severity_adjusted": f"{prior} | {note}" if prior else note,
        "adjustments": [*finding.adjustments, entry],
    })


def attenuate(
    finding: Finding, *, step: str, reason: str,
    severity: Severity | None = None, decision: Decision | None = None,
) -> Finding:
    """**낮추기만** 하는 감쇄 — 등급은 올리지 않고, 결정은 지정이 없으면 차단→검토."""
    new_sev = finding.severity
    if severity is not None and SEVERITY_RANK[severity] < SEVERITY_RANK[finding.severity]:
        new_sev = severity
    if decision is None:
        new_dec = Decision.warn if finding.decision == Decision.block else finding.decision
    else:
        new_dec = decision if DECISION_RANK[decision] <= DECISION_RANK[finding.decision] else finding.decision
    if new_sev == finding.severity and new_dec == finding.decision:
        return finding          # 바꿀 것이 없으면 이력도 남기지 않는다
    return record_adjustment(finding, step=step, reason=reason, severity=new_sev, decision=new_dec)


def adjustment_counts(findings) -> dict[str, int]:
    """단계별 감쇄 건수 — 보고서·포털이 "도구가 스스로 낮춘 것"을 집계로 보이게 한다."""
    out: dict[str, int] = {}
    for f in findings:
        for a in getattr(f, "adjustments", None) or []:
            out[a["step"]] = out.get(a["step"], 0) + 1
    return out


# ── 줄 체계 (한 벌) ──────────────────────────────────────────────────────────────

def normalize_newlines(code: str) -> str:
    """CRLF·CR → LF. 검사 입력은 한 번만 정규화하고 모든 엔진이 같은 본문을 본다."""
    if "\r" not in code:
        return code
    return code.replace("\r\n", "\n").replace("\r", "\n")


def split_lines(code: str) -> list[str]:
    """``\\n`` 으로만 줄을 나눈다 — ``str.splitlines()`` 는 폼피드(``\\x0c``)·``\\x1c``·U+2028 도
    줄로 세어 AST(``\\n`` 만)와 줄 번호가 어긋났다. 끝의 빈 조각은 뺀다."""
    lines = normalize_newlines(code).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines
