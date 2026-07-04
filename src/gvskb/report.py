"""사람이 읽는 한국어 리포트 생성.

공무원이 검사 결과를 그대로 공문 '붙임'(보안팀 제출·보고)으로 사용할 수 있도록
Markdown 한 장 분량의 결론·요약·증거·수정 가이드·재현 절차·면책을 묶어서 출력합니다.
결재(서명)는 상위 공문이 담당하므로 리포트에는 결재 요소를 넣지 않습니다.

핵심 시나리오는 "MCP로 코딩 → 완성 소스 재검증 → 리포트"이므로, 리포트는
*수정 후 다시 검증하는 방법*까지 명시합니다.
"""
from __future__ import annotations

import html
from collections import Counter, defaultdict
from datetime import datetime

from .schema import Decision, Finding, ScanReport, Severity

_SEVERITY_RANK = {Severity.critical: 3, Severity.high: 2, Severity.medium: 1, Severity.low: 0}
_SEVERITY_EMOJI = {
    Severity.critical: "[CRITICAL]",
    Severity.high: "[HIGH]",
    Severity.medium: "[MEDIUM]",
    Severity.low: "[LOW]",
}
_SEVERITY_LABEL_KO = {
    Severity.critical: "치명",
    Severity.high: "높음",
    Severity.medium: "보통",
    Severity.low: "낮음",
}

# Map a reference fragment to a human-readable guideline group. Order matters —
# the first matching prefix wins so more specific labels (e.g. "KISA Python")
# are checked before broader ones (e.g. "KISA").
_GUIDELINE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("KISA Python", "KISA Python 시큐어코딩"),
    ("KISA JS", "KISA JavaScript 시큐어코딩"),
    ("KISA",      "KISA"),
    ("MOIS",      "행정안전부 SW 개발보안"),
    ("국정원",     "국정원 AI 보안 가이드"),
    ("OWASP LLM", "OWASP LLM Top 10"),
    ("OWASP Agentic", "OWASP Agentic Top 10"),
    ("OWASP",     "OWASP"),
    ("NIST",      "NIST"),
    ("CISA",      "CISA"),
    ("CWE",       "CWE 분류"),
    ("CVE",       "CVE"),
    ("개인정보",   "개인정보보호위원회"),
)


def _classify_reference(ref: str) -> str | None:
    for needle, label in _GUIDELINE_PATTERNS:
        if needle in ref:
            return label
    return None


def _guideline_distribution(findings: list[Finding]) -> Counter[str]:
    """Count findings per guideline group based on their references.

    A finding can cite multiple guidelines (e.g. KISA + CWE + OWASP). We count
    each *distinct* guideline once per finding to avoid double-weighting.
    """
    counts: Counter[str] = Counter()
    for f in findings:
        seen: set[str] = set()
        for ref in (f.references or []):
            label = _classify_reference(ref)
            if label and label not in seen:
                counts[label] += 1
                seen.add(label)
    return counts


# ---------------------------------------------------------------------------
# 집계 헬퍼 — Markdown/HTML 두 렌더러가 같은 요약 데이터를 공유한다.
# (가) 1페이지 요약, (나) 파일별 세부, (다) 수정 프롬프트가 모두 이걸 쓴다.
# ---------------------------------------------------------------------------

_LINE_LIST_LIMIT = 8


def _by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    d: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        d[f.location.file].append(f)
    return d


def _ordered_files(by_file: dict[str, list[Finding]]) -> list[str]:
    """위험이 많고 심각한 파일이 위로 오도록 정렬."""
    return sorted(
        by_file.keys(),
        key=lambda fn: (
            -max(_SEVERITY_RANK[f.severity] for f in by_file[fn]),
            -len(by_file[fn]),
            fn,
        ),
    )


def _file_max_severity(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), key=lambda s: _SEVERITY_RANK[s])


def _rule_groups(findings: list[Finding]) -> list[dict]:
    """rule_id 단위로 묶어 '무슨 문제 몇 건'을 만든다(위험 유형 Top용).

    같은 룰의 설명을 한 번만 보여주고 위치는 목록으로 합치기 위한 기반.
    심각도 높은 순 → 건수 많은 순으로 정렬.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.rule_id].append(f)
    rows: list[dict] = []
    for rid, fs in groups.items():
        sev = _file_max_severity(fs)
        rows.append({
            "rule_id": rid,
            "title": fs[0].plain_title,
            "severity": sev,
            "decision": fs[0].decision,
            "count": len(fs),
            "files": len({f.location.file for f in fs}),
            "sample": fs[0],
            "findings": fs,
        })
    rows.sort(key=lambda r: (-_SEVERITY_RANK[r["severity"]], -r["count"], r["rule_id"]))
    return rows


def _top_actions(findings: list[Finding], n: int = 5) -> list[dict]:
    """가장 먼저 손볼 위험 유형 Top N — 차단 우선, 그다음 심각도·빈도."""
    def key(r: dict) -> tuple:
        block = 0 if r["decision"] == Decision.block else 1
        return (block, -_SEVERITY_RANK[r["severity"]], -r["count"], r["rule_id"])

    return sorted(_rule_groups(findings), key=key)[:n]


def _line_list(findings: list[Finding], limit: int = _LINE_LIST_LIMIT) -> str:
    """같은 룰의 발견 위치를 'line a, b, c 외 N건' 으로 합친다."""
    lines = sorted({f.location.line for f in findings})
    shown = ", ".join(str(n) for n in lines[:limit])
    if len(lines) > limit:
        shown += f" 외 {len(lines) - limit}건"
    return shown


def _locations_by_file(findings: list[Finding], limit_lines: int = _LINE_LIST_LIMIT) -> str:
    """수정 프롬프트용: 'app.py(line 2, 5); other.js(line 9)' 형태."""
    byf: dict[str, list[int]] = defaultdict(list)
    for f in findings:
        byf[f.location.file].append(f.location.line)
    parts: list[str] = []
    for fn in _ordered_files_by_name(byf):
        lines = sorted(set(byf[fn]))
        ls = ", ".join(str(n) for n in lines[:limit_lines])
        if len(lines) > limit_lines:
            ls += f" 외 {len(lines) - limit_lines}건"
        parts.append(f"{fn.replace(chr(92), '/')}(line {ls})")
    return "; ".join(parts)


def _ordered_files_by_name(byf: dict[str, list[int]]) -> list[str]:
    return sorted(byf.keys(), key=lambda fn: (-len(byf[fn]), fn))


def _build_artifact_skips(report: ScanReport) -> list:
    """빌드 산출물(압축/번들·빌드출력 디렉터리)로 제외된 항목."""
    return [s for s in report.skipped_files if "빌드 산출물" in (s.reason or "")]


# 초보자용 "다음 할 일" 행동 안내. 보안을 몰라도 결과를 받은 직후 바로 따라할
# 수 있도록, 자기가 쓰던 AI 코딩 도구에 그대로 말하는 흐름(고치기→확인→재검사)을
# 제시한다. 결과를 받고 "그래서 뭘 하지?" 에서 막히지 않게 하는 것이 목적.
_SAY_FIX = "방금 보안검사에서 나온 위험들을 안전하게 고쳐줘"
_SAY_RESCAN = "다시 검사해줘"

_ACTION_STEPS: tuple[tuple[str, str, str], ...] = (
    (
        "고치기",
        "지금 코딩하던 AI 도구(커서·클로드 코드 등)에 그대로 말하세요",
        _SAY_FIX,
    ),
    (
        "확인하기",
        "AI가 바꾼 내용을 살펴보고 적용하세요. 업무 로직이 바뀌면 담당자와 상의하세요.",
        "",
    ),
    (
        "다시 검사",
        "고친 뒤 한 번 더 검사해 0건이 되는지 확인하세요. 도구에 이렇게 말하면 됩니다",
        _SAY_RESCAN,
    ),
)

_ACTION_LEAD_BLOCK = "🚫 지금 이대로 올리거나 배포하면 안 됩니다. 아래 3단계로 고친 뒤 다시 검사하세요."
_ACTION_LEAD_WARN = "⚠️ 운영에 반영하기 전에 고치는 것을 권합니다. 아래 3단계를 따르세요."
_ACTION_CAVEAT = (
    "코드만으론 안 끝나는 것 — API 키·비밀번호가 노출됐다면 코드에서 지우는 것만으론 "
    "부족합니다. 그 값은 반드시 새로 발급(폐기)하고, 유출이 의심되면 보안담당자에게 알리세요."
)


def _action_lead(report: ScanReport) -> str:
    block_count = report.summary.by_decision.get(Decision.block.value, 0)
    if report.summary.blocked or block_count:
        return _ACTION_LEAD_BLOCK
    return _ACTION_LEAD_WARN


# ---------------------------------------------------------------------------
# 외부 연결 인벤토리 — 위험(findings)과 분리된 "검토용 목록". 사용 금지가 아니라
# 어디로 데이터가 나가는지 보안팀이 보게 한다. PII 인접·국외는 우선 검토 신호.
# ---------------------------------------------------------------------------

_CATEGORY_LABEL_KO = {
    "ai": "외부 AI",
    "analytics": "분석",
    "error": "에러추적",
    "payment": "결제",
    "messaging": "메시지",
    "library": "라이브러리",
    "other": "기타",
}


def _external_stats(report: ScanReport) -> tuple[int, int, int, int]:
    """(외부 API 수, 플러그인 수, 국외 전송 수, ⚠검토 필요 수)."""
    api = [c for c in report.external_surface if c.kind == "api"]
    pkg = [c for c in report.external_surface if c.kind == "package"]
    gukoe = sum(1 for c in report.external_surface if c.region == "국외")
    warn = sum(1 for c in report.external_surface if c.review_level == "warn")
    return len(api), len(pkg), gukoe, warn


def _cat_ko(cat: str) -> str:
    return _CATEGORY_LABEL_KO.get(cat, cat)


def _verdict_line(report: ScanReport) -> str:
    """One sentence an executive can read without scrolling."""
    summary = report.summary
    if summary.finding_count == 0:
        # 검사 대상 파일이 0개면 "위험 없음"이 아니라 "검사 안 됨" — 저장된
        # 리포트만 보고 안전하다고 오해하지 않도록 결론에서 분명히 구분한다.
        if not report.scanned_files:
            return (
                "⚠ 검사된 파일 없음 — 스캔 대상 파일이 0개입니다. 경로·지원 확장자·"
                "제외 설정을 확인하세요. 이 결과를 '안전'으로 해석하지 마세요."
            )
        return "위험 없음 — 본 검사에서 발견된 위반 사항이 없습니다."
    block_count = summary.by_decision.get(Decision.block.value, 0)
    warn_count = summary.by_decision.get(Decision.warn.value, 0)
    top_sev = summary.highest_severity
    sev_ko = _SEVERITY_LABEL_KO[top_sev] if top_sev else "보통"
    if summary.blocked or block_count:
        return (
            f"차단 권고 — {sev_ko} 등급 포함 총 {summary.finding_count}건 발견, "
            f"이 중 차단(block) {block_count}건. 커밋·배포 전 수정 또는 보안담당자 승인 필요."
        )
    return (
        f"수정 권고 — {sev_ko} 등급 포함 총 {summary.finding_count}건 발견, "
        f"경고(warn) {warn_count}건. 운영 반영 전 우선 검토하세요."
    )


# ---------------------------------------------------------------------------
# 보안팀 제출용 강화 — 검토 범위·한계 고지 / 배포 판정 / 개인정보 요약 /
# 실행 모드 배너 / 같은 줄 다중 지적. MD·HTML 렌더러가 공유한다.
# ---------------------------------------------------------------------------

# 한계 고지 — 비전문가가 "발견 0건 = 안전"으로 오해하지 않도록 문서 상단부에
# 항상 고지한다(발견 유무와 무관). HTML은 핵심 문장만 굵게 강조하기 위해 분리.
_LIMIT_HEAD = "본 도구는 정적 분석 기반의 1차 보안 린터입니다."
_LIMIT_ZERO = "발견 0건이 '안전'을 보장하지 않습니다."
_LIMIT_BODY = (
    "여러 줄에 걸쳐 조립되는 일부 SQL/명령 삽입, 설계·인가·업무로직상 취약점, "
    "실행 중에만 드러나는 취약점은 놓칠 수 있습니다. 의존성(패키지) 취약점은 "
    "scan_dependencies(또는 gvskb check-package)로 별도 점검하세요."
)
_LIMIT_TAIL = "본 결과는 보안담당자의 공식 보안성 검토를 대체하지 않습니다."


def _ext_distribution(scanned_files: list[str]) -> Counter[str]:
    """검사한 파일의 확장자 분포 — 검토 범위(어떤 언어/파일을 봤는지) 표기용."""
    c: Counter[str] = Counter()
    for fp in scanned_files:
        name = fp.replace("\\", "/").rsplit("/", 1)[-1]
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else "(확장자 없음)"
        c[ext] += 1
    return c


def _short_reason(reason: str) -> str:
    """생략 사유를 집계용 짧은 라벨로 축약(긴 안내문은 앞부분만)."""
    r = (reason or "기타").split("—")[0].strip()
    return r if len(r) <= 30 else r[:29] + "…"


def _unique_location_count(findings: list[Finding]) -> int:
    """같은 (파일, 줄)을 1곳으로 세는 고유 위치 수 — 이중 계상 오해 방지."""
    return len({(f.location.file, f.location.line) for f in findings})


def _multi_rule_lines(findings: list[Finding]) -> list[dict]:
    """한 줄에 여러 룰이 함께 걸린 위치 목록(표시 계층 전용 — core dedupe와 무관)."""
    by_loc: dict[tuple[str, int], list[Finding]] = defaultdict(list)
    for f in findings:
        by_loc[(f.location.file, f.location.line)].append(f)
    rows: list[dict] = []
    for (fn, line), fs in sorted(by_loc.items()):
        rules = sorted({f.rule_id for f in fs})
        if len(rules) >= 2:
            rows.append({"file": fn, "line": line, "rules": rules})
    return rows


# 개인정보·비밀값·LLM 프롬프트 관련 발견 분류 — 공공기관에서 가장 먼저 확인해야
# 하는 유형이라 별도 요약으로 상단 부각한다.
_PRIVACY_CATEGORY_KEYS = ("privacy-public-sector", "secret-scanning", "llm")
_PRIVACY_RULE_KEYS = ("PII", "SECRET", "LLM")


def _is_privacy_related(f: Finding) -> bool:
    cat = (f.category or "").lower()
    if any(k in cat for k in _PRIVACY_CATEGORY_KEYS):
        return True
    rid = (f.rule_id or "").upper()
    return any(k in rid for k in _PRIVACY_RULE_KEYS)


def _privacy_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if _is_privacy_related(f)]


def _deploy_verdict(report: ScanReport) -> tuple[str, str]:
    """운영서버 배포 판정 한 줄 + 표시 색 — 보안팀이 승인 근거로 쓰는 결론.

    항상 '잔여 위험' 개념을 함께 언급해 도구 미탐지 영역이 남아 있음을 알린다.
    """
    s = report.summary
    block_n = s.by_decision.get(Decision.block.value, 0)
    warn_n = s.by_decision.get(Decision.warn.value, 0)
    if s.finding_count == 0 and not report.scanned_files:
        return (
            "판정 불가 — 검사된 파일이 0개라 배포 가부를 판단할 수 없습니다. "
            "경로·확장자를 확인해 다시 검사하세요.",
            "#607d8b",
        )
    if s.blocked or block_n:
        return (
            f"🚫 배포 불가 — 차단(block) {block_n}건을 해소하거나 보안담당자 승인이 "
            "필요합니다. 미해소 항목은 잔여 위험으로 남습니다.",
            "#c0392b",
        )
    if s.finding_count:
        return (
            f"⚠ 조건부 — 경고 {warn_n}건을 검토한 후 배포하세요. 수정하지 않기로 한 "
            "항목은 잔여 위험으로 기록·관리해야 합니다.",
            "#e67e22",
        )
    return (
        "✅ 심각 위험 미발견 — 단, 아래 '검토 범위 및 한계' 고지를 참조하세요. "
        "본 도구가 탐지하지 못하는 영역은 잔여 위험으로 남습니다.",
        "#2e7d32",
    )


def _scan_mode_note(report: ScanReport) -> str | None:
    """실행 모드·인텔 기준일 배너 — scan_mode가 없으면 아무것도 표시하지 않음."""
    mode = report.scan_mode
    if not mode:
        return None
    fresh = report.intel_freshness or {}
    dates = " · ".join(f"{k} {v}" for k, v in fresh.items())
    if mode == "offline":
        note = "🔌 오프라인(망분리) 검사 — 의존성·인텔 정보는 로컬 캐시 기준입니다"
        if dates:
            note += f" (기준일 {dates})"
        note += (
            ". 기준일 이후 공개된 취약점은 반영되지 않았을 수 있으므로 "
            "미갱신 항목을 '안전'으로 간주하지 마세요."
        )
        return note
    note = "🌐 온라인 검사 — 실시간 의존성·인텔 정보를 사용할 수 있는 모드에서 검사했습니다"
    if dates:
        note += f" (기준일 {dates})"
    return note + "."


# ---------------------------------------------------------------------------
# 보안 분야 분류기 — 보안담당자가 "어느 보안 분야가 문제인지" 한눈에 보도록
# rule_id / category 를 9개 분야로 매핑한다. 위에서부터 첫 매칭 우선(first
# match wins)이므로 더 구체적인 분야(개인정보·비밀값)가 먼저 걸린다.
# ---------------------------------------------------------------------------

_DOMAIN_PRIVACY = (1, "🆔 개인정보 노출")
_DOMAIN_SECRET = (2, "🔑 비밀값·인증정보 노출")
_DOMAIN_INJECTION = (3, "💉 주입·원격 코드 실행")
_DOMAIN_WEB = (4, "🌐 웹 취약점")
_DOMAIN_CRYPTO = (5, "🔐 암호화·통신 보안")
_DOMAIN_MISCONFIG = (6, "⚙️ 보안 설정 오류")
_DOMAIN_AI = (7, "🤖 AI·자동화 위험")
_DOMAIN_QUALITY = (8, "🧩 코드 안정성·오류처리")
_DOMAIN_OTHER = (9, "🔎 그 외 보안 점검")


def _security_domain(f: Finding) -> tuple[int, str]:
    """발견 1건 → (정렬순서, "이모지 분야명"). 위에서부터 첫 매칭 우선."""
    cat = (f.category or "").lower()
    rid = (f.rule_id or "").upper()
    if cat in ("privacy-public-sector", "public-sector-internal") or "PII" in rid:
        return _DOMAIN_PRIVACY
    if cat == "secret-scanning" or "SECRET" in rid or "SEC-06" in rid or "SEC-13" in rid:
        return _DOMAIN_SECRET
    if any(k in rid for k in (
            "SQL", "CMD", "INPUT-01", "INPUT-02", "INPUT-05", "CODE-03", "CODE-05")):
        return _DOMAIN_INJECTION
    if cat == "xss" or any(k in rid for k in (
            "XSS", "HTML", "INPUT-04", "INPUT-03", "INPUT-07",
            "INPUT-11", "INPUT-12", "INPUT-13")):
        return _DOMAIN_WEB
    if any(k in rid for k in (
            "SEC-04", "SEC-05", "SEC-07", "SEC-10", "SEC-11", "SEC-14", "SEC-15",
            "TLS", "CERT", "CRYPTO")):
        return _DOMAIN_CRYPTO
    if cat == "misconfig" or any(k in rid for k in (
            "FLASK", "DEBUG", "SEC-03", "SEC-12", "ENCAP-02")):
        return _DOMAIN_MISCONFIG
    if cat in ("llm-appsec", "agent-safety") or "LLM" in rid or "AGENT" in rid:
        return _DOMAIN_AI
    if any(k in rid for k in ("CODE", "ERR", "TIME", "ENCAP")):
        return _DOMAIN_QUALITY
    return _DOMAIN_OTHER


def _group_by_domain(findings: list[Finding]) -> list[dict]:
    """분야별로 findings 를 모아 정렬순서대로 반환. 빈 분야는 생략."""
    buckets: dict[tuple[int, str], list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[_security_domain(f)].append(f)
    out: list[dict] = []
    for (order, label), fs in sorted(buckets.items()):
        out.append({
            "order": order,
            "label": label,
            "findings": fs,
            "count": len(fs),
            "files": len({f.location.file for f in fs}),
            "max_severity": _file_max_severity(fs),
        })
    return out


def _domain_has_blocker(findings: list[Finding]) -> bool:
    """치명(critical) 또는 차단(block)이 포함된 분야인지 — 기본 펼침 판단용."""
    return any(
        f.decision == Decision.block or f.severity == Severity.critical
        for f in findings
    )


def _hero_line(report: ScanReport) -> tuple[str, str]:
    """판정 히어로 배너 — 비전문가가 첫 문장만 읽어도 되는 쉬운 결론. (문장, 색)."""
    s = report.summary
    if s.finding_count == 0 and not report.scanned_files:
        return (
            "⚠ 검사된 파일이 없습니다 — 경로·확장자를 확인해 다시 검사하세요. "
            "이 결과를 '안전'으로 해석하면 안 됩니다.",
            "#607d8b",
        )
    block_n = s.by_decision.get(Decision.block.value, 0)
    if s.blocked or block_n:
        danger = sum(
            1 for f in report.findings
            if f.decision == Decision.block or f.severity == Severity.critical
        ) or block_n
        return (
            f"🚫 지금 이대로 배포하면 안 됩니다 — 치명·차단 위험 {danger}건. "
            "아래를 고치고 다시 검사하세요.",
            "#c0392b",
        )
    if s.finding_count:
        return (
            f"⚠️ 배포 전에 고칠 것이 있습니다 — 주의 필요 {s.finding_count}건. "
            "아래 순서대로 고친 뒤 다시 검사하세요.",
            "#e67e22",
        )
    return (
        "✅ 심각한 위험은 발견되지 않았습니다 — 단, 아래 '검토 범위 및 한계'를 꼭 확인하세요.",
        "#2e7d32",
    )


# 배포 승인/미승인 — 두괄식 결과 박스(초록=승인 · 빨강=미승인 · 주황=보류).
_VERDICT_TONE = {
    "ok": ("배포 승인 가능", "✅"),
    "block": ("배포 미승인 — 차단", "🚫"),
    "warn": ("배포 보류 — 확인 필요", "⚠"),
    "none": ("판정 불가", "❔"),
}


def _deploy_status(report: ScanReport) -> str:
    """배포 판정 tone: 'ok'(초록) | 'block'(빨강) | 'warn'(주황) | 'none'(회색)."""
    s = report.summary
    if s.finding_count == 0 and not report.scanned_files:
        return "none"
    if s.finding_count == 0:
        return "ok"
    if s.blocked or s.by_decision.get(Decision.block.value, 0):
        return "block"
    return "warn"


def _verdict_box_md(report: ScanReport) -> list[str]:
    """결론 = 승인/미승인 박스(Markdown). 색은 HTML에서만 — MD는 이모지·문구로."""
    tone = _deploy_status(report)
    label, emoji = _VERDICT_TONE[tone]
    deploy_text, _ = _deploy_verdict(report)
    return [f"> ### {emoji} {label}", ">", f"> **배포 판정** · {deploy_text}", ""]


def _verdict_box_html(report: ScanReport) -> str:
    """결론 = 승인(초록)/미승인(빨강) 박스(HTML). 두괄식으로 가장 크게."""
    tone = _deploy_status(report)
    label, emoji = _VERDICT_TONE[tone]
    deploy_text, _ = _deploy_verdict(report)
    return (
        f'<div class="verdict v-{tone}">'
        f'<div class="vstatus">{emoji} {_esc(label)}</div>'
        f'<div class="vdetail">배포 판정 · {_esc(deploy_text)}</div>'
        "</div>"
    )


def _meta_rows(report: ScanReport, ts: str) -> list[tuple[str, str]]:
    rows = [("대상", report.target), ("검사일시", ts), ("프로파일", report.profile)]
    if report.scenario:
        rows.append(("시나리오", report.scenario))
    if report.language:
        rows.append(("언어 힌트", report.language))
    return rows


def _meta_table_md(report: ScanReport, ts: str) -> list[str]:
    """문서 헤더 — 대상·검사일시·프로파일을 키-값 표로(긴 경로도 깔끔하게)."""
    out = ["| 항목 | 값 |", "|---|---|"]
    for k, v in _meta_rows(report, ts):
        val = f"`{v}`" if k in ("대상",) else v
        out.append(f"| {k} | {val} |")
    out.append("")
    return out


def _meta_table_html(report: ScanReport, ts: str) -> str:
    cells = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in _meta_rows(report, ts)
    )
    return f'<table class="metatbl">{cells}</table>'


def _pii_callout_md(pii: list[Finding]) -> list[str]:
    """개인정보·비밀값 주의 콜아웃(Markdown) — '비밀값' 분야 바로 아래에 붙는다."""
    pii_files = len({f.location.file for f in pii})
    return [
        f"> 🔑 **개인정보·비밀값 주의** — 관련 발견 **{len(pii)}건** · 파일 {pii_files}개. "
        "노출된 비밀값(키·비밀번호)은 코드에서 지우는 것만으로 부족하며 반드시 "
        "**재발급(폐기)** 해야 합니다. 개인정보 유출 정황이 있으면 기관 "
        "개인정보보호 담당자에게 지체 없이 알리세요.",
        "",
    ]


def _pii_callout_html(pii: list[Finding]) -> str:
    """개인정보·비밀값 주의 콜아웃(HTML) — '비밀값' 분야 바로 아래에 붙는다."""
    pii_files = len({f.location.file for f in pii})
    return (
        f'<div class="piibox"><div class="ph">🔑 개인정보·비밀값 주의 — '
        f"{len(pii)}건 · 파일 {pii_files}개</div>"
        '<div class="kv" style="font-size:13px">노출된 비밀값(키·비밀번호)은 코드 삭제만으로 '
        "부족합니다 — <b>반드시 재발급(폐기)</b>하고, 개인정보 유출 정황은 기관 "
        "개인정보보호 담당자에게 지체 없이 알리세요.</div></div>"
    )


def render_markdown(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
    reproduce_command: str | None = None,
) -> str:
    """Render a ScanReport as a self-contained Korean Markdown document.

    Args:
        report: the scan report to render.
        generated_at: timestamp shown in the header (defaults to now).
        reproduce_command: optional exact CLI command that produced this report.
            When omitted, a sensible default referencing the target is emitted.

    이 문서는 공문의 '붙임'으로 제출되는 것을 전제로 한다 — 결재(서명)는
    상위 공문이 담당하므로 리포트 자체에는 결재 요소를 넣지 않는다.

    The output is designed to be readable on its own — anyone can paste it into
    a Word document or print it without needing to query the MCP further.
    """
    ts = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    lines: list[str] = []

    # 승인된 예외(suppressed)는 본문 통계·상세에서 분리해 전용 섹션에만 표시.
    # (summary는 스캐너가 이미 비억제 기준으로 계산했다)
    suppressed = [f for f in report.findings if f.suppressed]
    if suppressed:
        report = report.model_copy(
            update={"findings": [f for f in report.findings if not f.suppressed]}
        )

    lines.append("# 코드 보안 검사 결과")
    lines.append("")

    # =====================================================================
    # Layer 1 — 공무원용 (접기 없음, 두괄식): 판정 히어로 → 핵심 숫자 →
    # 다음 3단계 → 가장 먼저 할 일 Top3 → 정직성 배너(모드·예외·의존성·
    # 빌드제외·한계 고지). 어려운 상세는 전부 Layer 2(보안팀)로 내린다.
    # =====================================================================

    # --- ① 문서 헤더(대상·일시·프로파일 표) → 결론(승인/미승인 박스) --------
    lines.extend(_meta_table_md(report, ts))
    lines.append("## 결론")
    lines.append("")
    lines.extend(_verdict_box_md(report))

    # --- ② 핵심 숫자 --------------------------------------------------------
    lines.append("## 요약")
    lines.append("")
    summary = report.summary
    build_skips = _build_artifact_skips(report)
    non_build_skips = [s for s in report.skipped_files if "빌드 산출물" not in (s.reason or "")]
    lines.append(f"- 검사한 파일 수: **{len(report.scanned_files)}건**")
    # 발견 건수와 고유 위치를 함께 표기 — 같은 줄에 여러 룰이 걸리면 건수가
    # 위치 수보다 커지므로, 이중 계상으로 오해하지 않도록 두 수치를 같이 쓴다.
    uniq_locs = _unique_location_count(report.findings)
    lines.append(f"- 발견된 위험: **{summary.finding_count}건** · 고유 위치 **{uniq_locs}곳**")
    lines.append(f"- 차단(block): **{summary.by_decision.get(Decision.block.value, 0)}건**")
    if summary.highest_severity:
        lines.append(
            f"- 최고 심각도: **{_SEVERITY_LABEL_KO[summary.highest_severity]} "
            f"({summary.highest_severity.value})**"
        )
    else:
        lines.append("- 최고 심각도: **—**")
    if non_build_skips:
        lines.append(f"- 생략된 파일 수: {len(non_build_skips)}건 (이유: 크기·바이너리·인코딩 등)")
    if build_skips:
        lines.append(f"- 빌드 산출물 제외: {len(build_skips)}건 (압축/번들·빌드 출력 — 원본 아님)")
    lines.append("")

    if any(summary.by_severity.values()):
        lines.append("| 심각도 | 건수 |")
        lines.append("|---|---|")
        for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low):
            count = summary.by_severity.get(sev.value, 0)
            if count:
                lines.append(f"| {_SEVERITY_LABEL_KO[sev]} ({sev.value}) | {count} |")
        lines.append("")

    if summary.finding_count == 0:
        lines.append("> 발견된 위험이 없습니다. 그러나 본 도구는 보조 가드레일이며, ")
        lines.append("> 공식 보안성 검토를 대체하지 않습니다.")
        lines.append("")

    # --- ③ 조치 가이드 (초보자용 행동 안내) — 발견이 있을 때만 -------------
    if report.findings:
        lines.append("## 🛠 조치 가이드 — 3단계만 따라 하세요")
        lines.append("")
        lines.append(f"**{_action_lead(report)}**")
        lines.append("")
        for i, (title, desc, say) in enumerate(_ACTION_STEPS, 1):
            line = f"{i}. **{title}** — {desc}"
            if say:
                line += f"  → `{say}`"
            lines.append(line)
            if title == "고치기":
                lines.append("   (또는 아래 '수정 프롬프트' 칸을 복사해 붙여넣으세요)")
        lines.append("")
        lines.append(f"> ⚠ **{_ACTION_CAVEAT}**")
        lines.append("")

    # --- ④ 가장 먼저 할 일 (Top 3) — 쉬운 말 체크리스트 --------------------
    if report.findings:
        lines.append("## 가장 먼저 할 일 (Top 3)")
        lines.append("")
        for g in _top_actions(report.findings, 3):
            dec_ko = _DECISION_LABEL_KO.get(g["decision"], g["decision"].value)
            lines.append(
                f"- [ ] **{g['title']}** — {_SEVERITY_LABEL_KO[g['severity']]}·{dec_ko} · "
                f"{g['count']}건 · 파일 {g['files']}개 (`{g['rule_id']}`)"
            )
        lines.append("")
        lines.append(
            "> 각 항목의 정확한 위치·수정 방법은 아래 '상세 검토 결과'의 "
            "분야별 카드에 있습니다."
        )
        lines.append("")

    # --- ⑤ 정직성 배너 — 실행 모드·승인 예외·의존성·빌드 제외·한계 고지 ----
    # 실행 모드·인텔 기준일 — 값이 주입된 경우에만 표시.
    mode_note = _scan_mode_note(report)
    if mode_note:
        lines.append(f"> {mode_note}")
        lines.append("")

    # 승인된 예외 요약 — 게이트 판정 이해에 필수라 결론 근처에 표기.
    lines.extend(_suppression_banner_md(report, suppressed))

    # 의존성 매니페스트는 코드 스캔이 아니라 SCA로 검사해야 한다 — 코드 스캔
    # 결과만 보고 "의존성도 안전"으로 오해하지 않도록 상단부에 강조한다.
    # 감사 결과(dependency_audit)가 병합돼 있으면 그 요약으로 대체한다.
    dep_audits = _dep_audits(report)
    manifest_skips = [
        s for s in report.skipped_files if "의존성 매니페스트" in (s.reason or "")
    ]
    if dep_audits:
        lines.append(f"> {_dep_banner_text(dep_audits)}")
        lines.append("")
    elif manifest_skips:
        names = ", ".join(s.path.replace("\\", "/").rsplit("/", 1)[-1] for s in manifest_skips)
        lines.append(
            f"> ⚠️ **의존성 검사 별도 필요** — {names} 은(는) 코드 스캔 대상이 아닙니다. "
            f"취약·악성 패키지는 `gvskb check-package` 또는 MCP `scan_dependencies`로 따로 검사하세요."
        )
        lines.append("")

    if build_skips:
        lines.append(
            f"> 🧹 **빌드 산출물 {len(build_skips)}건 제외** — 압축·번들·캐시 파일은 원본 "
            "소스가 아니라 검사 대상에서 자동 제외했습니다(오탐 방지)."
        )
        lines.append("")

    # --- ⑥ 검토 범위 및 한계 + 면책 — 조치 안내 뒤, 상세 검토 앞(신뢰성 고지) -
    lines.append("## 검토 범위 및 한계")
    lines.append("")
    ext_dist = _ext_distribution(report.scanned_files)
    ext_str = " · ".join(f"{ext} {n}건" for ext, n in ext_dist.most_common()) or "—"
    lines.append(
        f"- **검토 범위**: 파일 {len(report.scanned_files)}건 ({ext_str}) — "
        "정적(소스코드) 검사이며 코드를 실행하지 않습니다"
    )
    if report.skipped_files:
        reason_counts = Counter(_short_reason(s.reason) for s in report.skipped_files)
        rs = " · ".join(f"{r} {n}건" for r, n in reason_counts.most_common())
        lines.append(f"- **검사 제외**: {len(report.skipped_files)}건 — {rs} (아래 목록 참조)")
    lines.append("")
    lines.append(
        f"> ⚠ **한계 고지** — {_LIMIT_HEAD} **{_LIMIT_ZERO}** {_LIMIT_BODY} **{_LIMIT_TAIL}**"
    )
    lines.append("")
    lines.append(f"> {report.disclaimer.replace(chr(10), ' ')}")
    lines.append("")

    # =====================================================================
    # Layer 2 — 보안담당자용 상세 검토: 분야 개요 → 분야별 상세(비밀값 분야
    # 직후 개인정보 콜아웃) → 외부 연결 → 의존성 → 승인 예외 → 수정 프롬프트 → 부록.
    # =====================================================================
    lines.append("## 상세 검토 결과")
    lines.append("")

    domains = _group_by_domain(report.findings)

    # --- ⑥ 보안 분야 개요 — 어느 보안 분야가 문제인지 한눈에 ----------------
    lines.append("### 보안 분야 개요")
    lines.append("")
    if domains:
        lines.append("| 분야 | 최고 심각도 | 건수 | 파일 |")
        lines.append("|---|---|---|---|")
        for d in domains:
            lines.append(
                f"| {d['label']} | {_SEVERITY_LABEL_KO[d['max_severity']]} | "
                f"{d['count']} | {d['files']} |"
            )
        lines.append("")

        # 같은 (파일, 줄)에 여러 룰이 걸린 위치 — 표시 계층에서 묶어 보여
        # "건수가 부풀려졌다"는 오해를 막는다(core dedupe와는 무관).
        multi = _multi_rule_lines(report.findings)
        if multi:
            lines.append(
                f"> ℹ️ **같은 줄 다중 지적** — 발견 {summary.finding_count}건 중 고유 위치는 "
                f"{uniq_locs}곳입니다. 아래 위치는 한 줄에 여러 기준(룰)이 함께 걸린 곳으로, "
                "한 곳을 고치면 관련 룰이 함께 해소됩니다."
            )
            lines.append("")
            for m in multi[:12]:
                rules = ", ".join(f"`{r}`" for r in m["rules"])
                lines.append(
                    f"- `{m['file'].replace(chr(92), '/')}:{m['line']}` — "
                    f"관련 룰 {len(m['rules'])}개: {rules}"
                )
            if len(multi) > 12:
                lines.append(f"- … 외 {len(multi) - 12}곳")
            lines.append("")
    else:
        lines.append("> 발견된 위험이 없어 분야별 상세가 없습니다.")
        lines.append("")

    # --- ⑦ 분야별 상세 — 분야마다 룰 그룹 카드(위치·왜 위험·대응·근거).
    #     개인정보·비밀값 콜아웃은 '비밀값·인증정보 노출' 분야(없으면 개인정보
    #     분야) 바로 아래에 붙여 최민감 항목을 그 자리에서 강조한다. -----------
    pii = _privacy_findings(report.findings)
    pii_anchor = max((d["order"] for d in domains if d["order"] <= 2), default=None)
    for d in domains:
        lines.append(
            f"### {d['label']} — {_SEVERITY_LABEL_KO[d['max_severity']]} · "
            f"{d['count']}건 · 파일 {d['files']}개"
        )
        lines.append("")
        for g in _rule_groups(d["findings"]):
            lines.extend(_render_finding_group_md(g))
            lines.append("")
        if pii and d["order"] == pii_anchor:
            lines.extend(_pii_callout_md(pii))
    if pii and pii_anchor is None:  # PII가 다른 분야로만 분류된 드문 경우
        lines.extend(_pii_callout_md(pii))

    # --- ⑨ 외부 연결 인벤토리 (위험과 분리, 발견 0이어도 표시) --------------
    if report.external_surface:
        lines.extend(_render_external_surface_md(report))

    # --- ⑩ 의존성(패키지) 취약점 검사 — 병합된 경우에만 표시 ----------------
    lines.extend(_render_dependency_audit_md(report))

    # --- ⑪ 승인된 예외 내역 — 있을 때만 -------------------------------------
    lines.extend(_render_suppressions_md(suppressed))

    # --- ⑫ 수정 프롬프트 (복사용) --------------------------------------------
    if report.findings:
        lines.append("## 수정 프롬프트 (복사해서 AI에게 전달)")
        lines.append("")
        lines.append(
            f"💬 **가장 쉬운 방법** — 쓰던 AI 도구에 `{_SAY_FIX}` 라고 말하면 끝입니다. "
            "아래 블록은 유형별로 따로 복사해 쓰고 싶을 때 사용하세요."
        )
        lines.append("")
        for g in _rule_groups(report.findings):
            lines.append("```text")
            lines.append(_fix_prompt_text(g))
            lines.append("```")
            lines.append("")

    # --- ⑬ 부록 — 가이드라인 분포·생략 파일·재현 절차·재검증 ----------------
    lines.append("## 부록")
    lines.append("")
    if report.findings:
        dist = _guideline_distribution(report.findings)
        if dist:
            lines.append("### 가이드라인별 분포")
            lines.append("")
            lines.append("> 한 발견 사항이 여러 가이드라인을 인용한 경우 각 그룹에서 1회씩 집계합니다.")
            lines.append("")
            lines.append("| 가이드라인 | 인용 건수 |")
            lines.append("|---|---|")
            for label, count in dist.most_common():
                lines.append(f"| {label} | {count} |")
            lines.append("")

    if non_build_skips:
        lines.append("### 생략된 파일")
        lines.append("")
        for sf in non_build_skips[:30]:
            lines.append(f"- `{sf.path}` — {sf.reason}")
        if len(non_build_skips) > 30:
            lines.append(f"- … 외 {len(non_build_skips) - 30}건")
        lines.append("")
    if build_skips:
        lines.append("### 빌드 산출물 제외")
        lines.append("")
        lines.append(
            "> 압축/번들·빌드 출력 디렉터리는 원본 소스가 아니므로 검사하지 않습니다 (오탐 방지)."
        )
        for sf in build_skips[:15]:
            lines.append(f"- `{sf.path.replace(chr(92), '/')}`")
        if len(build_skips) > 15:
            lines.append(f"- … 외 {len(build_skips) - 15}건")
        lines.append("")

    lines.append("### 재현 절차")
    lines.append("")
    repro = reproduce_command or f"gvskb scan {report.target} --profile {report.profile}"
    lines.append("같은 결과를 다시 만들거나 다른 환경에서 검증하려면 다음과 같이 실행합니다.")
    lines.append("")
    lines.append("```bash")
    lines.append(repro)
    lines.append("```")
    lines.append("")
    lines.append(f"- 프로파일: `{report.profile}`")
    if report.scenario:
        lines.append(f"- 시나리오: `{report.scenario}`")
    if report.language:
        lines.append(f"- 언어 힌트: `{report.language}`")
    lines.append("- 룰셋은 `gvskb rules` 또는 `gvskb doctor` 로 현재 로드된 목록·버전을 확인할 수 있습니다.")
    lines.append("")

    lines.append("### 수정 후 다시 검증")
    lines.append("")
    lines.append("발견 사항을 수정한 뒤에는 같은 검사를 한 번 더 돌려 회귀를 막으세요.")
    lines.append("")
    lines.append("- **CLI**: 위의 재현 명령(`gvskb scan ...`)을 다시 실행합니다.")
    lines.append(
        "- **MCP (IDE)**: 수정한 코드 블록을 `scan_code` 도구에 다시 넘기거나, 파일 단위라면 "
        "`scan_path` 를 호출합니다."
    )
    lines.append(
        "- **수정 시 LLM 안내**: 처리 순서(차단 → 치명·높음 → 자동수정 → 나머지)를 "
        "그대로 LLM 프롬프트의 지시문으로 사용하면 우선순위가 어긋나지 않습니다."
    )
    lines.append("")

    # (면책은 상단 '검토 범위 및 한계' 아래로 이동했다 — 여기서는 반복하지 않는다)
    lines.append("---")
    lines.append("")
    lines.append("*생성: vibecode-checker · 공공 바이브코딩 보안 가드레일*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML 리포트 — MD와 동일한 ScanReport 데이터에서 직접 렌더링하는 "카드 강조형".
# 자체 포함 단일 파일(외부 CDN·폰트·외부 스크립트 없음 — 아무 리소스도 로드하지
# 않는다)이라 망분리·이메일·인쇄(→PDF)에 그대로 쓸 수 있다. 복사 버튼용 인라인
# 스크립트만 있으며 미지원 환경에선 텍스트가 그대로 보인다. 동적 텍스트는 전부
# html.escape 로 이스케이프한다.
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    Severity.critical: "#c0392b",
    Severity.high: "#e67e22",
    Severity.medium: "#c9a227",
    Severity.low: "#7f8c8d",
}
_DECISION_COLOR = {
    Decision.block: "#c0392b",
    Decision.warn: "#e67e22",
    Decision.allow: "#2e7d32",
}
_DECISION_LABEL_KO = {
    Decision.block: "차단",
    Decision.warn: "경고",
    Decision.allow: "허용",
}

_HTML_CSS = """
*{box-sizing:border-box}
body{margin:0;background:#eceff1;color:#1f2937;
  font-family:"Malgun Gothic","맑은 고딕","Apple SD Gothic Neo","Noto Sans KR",
  "Segoe UI",sans-serif;line-height:1.6;font-size:15px}
.page{max-width:820px;margin:24px auto;background:#fff;padding:40px 44px;
  box-shadow:0 1px 6px rgba(0,0,0,.12);border-radius:8px}
h1{font-size:24px;margin:0 0 4px;letter-spacing:-.3px}
h2{font-size:17px;margin:30px 0 12px;padding-bottom:6px;border-bottom:2px solid #e5e7eb}
h3{font-size:15px;margin:22px 0 8px;color:#111827}
.sub{color:#6b7280;font-size:13px;margin-bottom:18px}
.hero{padding:20px 24px;border-radius:10px;color:#fff;margin:10px 0 12px;
  page-break-inside:avoid}
.hero .heromain{font-weight:800;font-size:20px;line-height:1.45}
.hero .herosub{font-size:13px;font-weight:600;opacity:.93;margin-top:8px}
.meta{font-size:14px;color:#374151;margin:0 0 8px}
.meta b{color:#111827}
.depwarn{background:#fff8e1;border:1px solid #f0d27a;border-radius:6px;
  padding:10px 14px;font-size:13.5px;color:#7a5b00;margin:10px 0}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 4px}
.chip{padding:5px 12px;border-radius:999px;font-size:13px;font-weight:600;color:#fff}
.kv{font-size:14px;margin:2px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0}
th,td{border:1px solid #e5e7eb;padding:6px 10px;text-align:left}
th{background:#f3f4f6}
ol.steps{margin:6px 0 0;padding-left:22px}
ol.steps li{margin:3px 0}
.card{border:1px solid #e5e7eb;border-left:6px solid #999;border-radius:8px;
  padding:14px 16px;margin:12px 0;background:#fff;page-break-inside:avoid}
.card .badge{display:inline-block;color:#fff;font-weight:700;font-size:12px;
  padding:2px 9px;border-radius:5px;margin-right:8px;vertical-align:middle}
.card .ftitle{font-weight:700;font-size:15px;vertical-align:middle}
.card .loc{color:#6b7280;font-size:13px;margin-left:6px}
.row{margin:7px 0;font-size:14px}
.row .lab{display:inline-block;min-width:104px;color:#6b7280;font-weight:600;vertical-align:top}
.row .val{display:inline-block;max-width:600px}
.tag{display:inline-block;font-size:12px;padding:1px 7px;border-radius:4px;
  background:#eef2ff;color:#3730a3;margin-right:6px}
pre{background:#0f172a;color:#e2e8f0;border-radius:6px;padding:11px 13px;
  font-size:12.5px;overflow:auto;font-family:"D2Coding","Consolas",
  "Courier New",monospace;white-space:pre-wrap;word-break:break-all;margin:6px 0}
code.ev{background:#f1f5f9;border-radius:4px;padding:1px 6px;font-size:12.5px;
  font-family:"Consolas","Courier New",monospace;word-break:break-all}
.disc{background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;
  padding:12px 16px;font-size:13.5px;color:#475569;margin:8px 0}
.foot{text-align:center;color:#9ca3af;font-size:12px;margin-top:28px}
.buildnote{background:#f1f5f9;border:1px dashed #cbd5e1;border-radius:6px;
  padding:8px 13px;font-size:12.5px;color:#64748b;margin:8px 0}
.actionbox{border:2px solid #2563eb;border-radius:10px;padding:14px 18px;
  margin:12px 0 16px;background:#eff6ff}
.actionbox .ah{font-weight:800;font-size:15px;color:#1e3a8a;margin-bottom:8px}
.actionbox .lead{font-size:14px;color:#1e293b;margin-bottom:10px;font-weight:600}
.actionbox ol{margin:0;padding-left:0;list-style:none;counter-reset:step}
.actionbox li{position:relative;padding:6px 0 6px 34px;font-size:14px;
  border-top:1px solid #dbeafe}
.actionbox li:first-child{border-top:none}
.actionbox li::before{counter-increment:step;content:counter(step);
  position:absolute;left:0;top:6px;width:23px;height:23px;border-radius:50%;
  background:#2563eb;color:#fff;font-weight:800;font-size:12.5px;
  text-align:center;line-height:23px}
.actionbox .say{display:inline-block;background:#1e293b;color:#e2e8f0;
  border-radius:5px;padding:2px 9px;font-size:13px;margin:3px 0;
  font-family:"D2Coding","Consolas",monospace}
.actionbox .caveat{margin-top:10px;background:#fff7ed;border:1px solid #fed7aa;
  border-radius:6px;padding:9px 12px;font-size:12.8px;color:#9a3412}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:6px 0 4px}
.stat{flex:1 1 120px;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px;
  background:#fafafa;min-width:120px}
.stat .num{font-size:24px;font-weight:800;line-height:1.1}
.stat .lab{font-size:12.5px;color:#6b7280;margin-top:3px}
.typetbl td.sev,.typetbl td.cnt{text-align:center;white-space:nowrap}
.sevdot{display:inline-block;color:#fff;font-weight:700;font-size:11.5px;
  padding:1px 8px;border-radius:5px}
a.jump{color:#1d4ed8;text-decoration:none;font-weight:600}
a.jump:hover{text-decoration:underline}
ul.todo{list-style:none;margin:6px 0;padding:0}
ul.todo li{border:1px solid #e5e7eb;border-radius:7px;padding:9px 12px;margin:7px 0;
  background:#fff;font-size:14px}
ul.todo .box{font-weight:800;color:#9ca3af;margin-right:8px}
ul.todo .meta2{color:#6b7280;font-size:12.5px;margin-left:6px}
.fixprompt{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:13px 15px;
  margin:10px 0;font-size:12.5px;font-family:"D2Coding","Consolas","Courier New",monospace;
  white-space:pre-wrap;word-break:break-all}
/* 접기형 일반 섹션(분야별 상세·수정 프롬프트·외부 연결·부록 등) */
details.sec{border:1px solid #e5e7eb;border-radius:8px;margin:14px 0;background:#fff;overflow:hidden}
details.sec>summary{cursor:pointer;list-style:none;padding:13px 16px;font-weight:800;font-size:16px;background:#f3f4f6}
details.sec>summary::-webkit-details-marker{display:none}
details.sec>summary::before{content:"▶  ";color:#9ca3af;font-size:12px}
details.sec[open]>summary::before{content:"▼  "}
details.sec>summary:hover{background:#eceef1}
details.sec .secbody{padding:4px 16px 14px}
/* 외부 연결 인벤토리 */
.invnote{background:#eff6ff;border:1px solid #93c5fd;border-radius:8px;padding:11px 15px;
  font-size:13px;color:#1e3a8a;margin:8px 0}
.invnote .hl{color:#9a3412;font-weight:700}
.subh{font-weight:800;font-size:14px;margin:14px 0 6px;color:#111827}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#fff}
.pill.ai{background:#7c3aed}.pill.analytics{background:#0891b2}.pill.error{background:#475569}
.pill.payment{background:#b45309}.pill.messaging{background:#0d9488}
.pill.library{background:#9ca3af}.pill.other{background:#6b7280}
tr.w td{background:#fff7ed}
.go{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;font-weight:700}
.go.out{background:#fee2e2;color:#b91c1c}.go.in{background:#dcfce7;color:#166534}.go.q{background:#eef2f7;color:#64748b}
.rev{display:inline-block;padding:1px 8px;border-radius:5px;font-size:11px;font-weight:700}
.rev.warn{background:#fde2c8;color:#9a3412}.rev.info{background:#eef2f7;color:#64748b}
.invcheck{background:#f8fafc;border-left:4px solid #2563eb;padding:9px 13px;font-size:12.5px;color:#334155;margin:12px 0 4px}
.oper{font-size:11px;color:#6b7280;white-space:nowrap}
/* 배포 판정·실행 모드·검토 범위·개인정보 요약 (보안팀 제출용) */
.deploy{border:2px solid #9ca3af;border-radius:8px;padding:12px 16px;font-weight:700;
  font-size:14.5px;margin:0 0 12px;background:#fff;page-break-inside:avoid}
.scanmode{background:#f0f9ff;border:1px solid #7dd3fc;border-radius:6px;
  padding:9px 13px;font-size:13px;color:#075985;margin:8px 0}
.scopebox{background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;
  padding:12px 16px;font-size:13.5px;color:#78350f;margin:8px 0;page-break-inside:avoid}
.piibox{border:2px solid #be185d;background:#fdf2f8;border-radius:10px;
  padding:12px 16px;margin:14px 0;page-break-inside:avoid}
.piibox .ph{font-weight:800;color:#9d174d;font-size:15px;margin-bottom:6px}
.dupnote{background:#f8fafc;border:1px dashed #94a3b8;border-radius:6px;
  padding:9px 13px;font-size:12.8px;color:#475569;margin:8px 0}
/* 문서 헤더 표(대상·검사일시·프로파일) */
.metatbl{border-collapse:collapse;margin:6px 0 14px;font-size:13px;width:100%}
.metatbl th{text-align:left;background:#f3f4f6;color:#374151;padding:6px 10px;
  white-space:nowrap;width:96px;border:1px solid #e5e7eb;font-weight:700}
.metatbl td{padding:6px 10px;color:#111827;border:1px solid #e5e7eb;word-break:break-all}
/* 결론 = 승인(초록)/미승인(빨강) 박스 — 두괄식 결과 */
.verdict{border:3px solid;border-radius:12px;padding:16px 20px;margin:6px 0 16px;page-break-inside:avoid}
.verdict .vstatus{font-size:22px;font-weight:800;margin-bottom:6px}
.verdict .vdetail{font-size:14px;line-height:1.55}
.v-ok{background:#ecfdf5;border-color:#16a34a;color:#065f46}
.v-block{background:#fef2f2;border-color:#dc2626;color:#991b1b}
.v-warn{background:#fffbeb;border-color:#d97706;color:#92400e}
.v-none{background:#f3f4f6;border-color:#6b7280;color:#374151}
/* 면책 박스(요약부로 이동) — 이미지의 어두운 테두리 박스 */
.discbox{border:2px solid #111827;border-radius:8px;background:#fff;
  padding:12px 16px;font-size:12.8px;color:#374151;margin:10px 0 14px;page-break-inside:avoid}
/* 수정 프롬프트 — '가장 쉬운 방법' 강조 + 복사 버튼 */
.easyfix{border:2px solid #2563eb;background:#eff6ff;border-radius:10px;
  padding:12px 16px;margin:4px 0 12px;page-break-inside:avoid}
.easyfix .eh{font-weight:800;color:#1e3a8a;font-size:15px;margin-bottom:4px}
.easyfix .ed{font-size:12.8px;color:#334155;margin-bottom:8px}
.easyrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.saycode{flex:1;min-width:200px;background:#fff;border:1px solid #bfdbfe;border-radius:6px;
  padding:8px 10px;font-size:13px;color:#111827}
.fixwrap{position:relative;margin:8px 0}
.copybtn{cursor:pointer;border:1px solid #2563eb;background:#2563eb;color:#fff;
  border-radius:6px;padding:5px 12px;font-size:12.5px;font-weight:700;white-space:nowrap}
.copybtn:hover{background:#1d4ed8}
.copybtn.ok{background:#16a34a;border-color:#16a34a}
.fixwrap .copybtn{position:absolute;top:8px;right:8px}
.fixwrap .fixprompt{padding-right:70px}
@media print{
  body{background:#fff}
  .page{box-shadow:none;margin:0;max-width:none;border-radius:0;padding:0 6mm}
  .card{break-inside:avoid}
  details.sec{break-inside:auto}
  details.sec>summary::before{content:""}
  details.sec>.secbody{display:block !important}
  /* 최신 Chromium/Edge는 닫힌 <details> 내용을 ::details-content 로 클리핑해
     인쇄에서 상세가 통째로 빠진다 — 인쇄 시 강제로 펼친다(위 display 규칙 유지). */
  details::details-content{content-visibility:visible !important;display:block !important;height:auto !important}
  pre,.fixprompt{white-space:pre-wrap}
}
""".strip()


# 복사 버튼용 인라인 스크립트 — 외부 리소스를 전혀 로딩하지 않는다(자체완결 유지).
# navigator.clipboard 우선, 미지원(file:// 등)이면 execCommand 폴백, 둘 다 안 되면
# 프롬프트 텍스트가 그대로 보이므로 사용자가 직접 선택·복사할 수 있다(우아한 저하).
_COPY_SCRIPT = """
<script>
(function () {
  function fallback(t) {
    try {
      var ta = document.createElement('textarea');
      ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.focus(); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta);
      return Promise.resolve();
    } catch (e) { return Promise.reject(e); }
  }
  function copyText(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(t).catch(function () { return fallback(t); });
    }
    return fallback(t);
  }
  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('.copybtn') : null;
    if (!b) return;
    var t = b.getAttribute('data-copy') || '';
    copyText(t).then(function () {
      var o = b.textContent; b.textContent = '✓ 복사됨'; b.classList.add('ok');
      setTimeout(function () { b.textContent = o; b.classList.remove('ok'); }, 1500);
    }).catch(function () { b.textContent = '직접 선택해 복사하세요'; });
  });
})();
</script>
""".strip()


def _esc(text: str) -> str:
    return html.escape(str(text), quote=True)


def _verdict_css_color(report: ScanReport) -> str:
    summary = report.summary
    if summary.finding_count == 0:
        return "#607d8b" if not report.scanned_files else "#2e7d32"
    block_count = summary.by_decision.get(Decision.block.value, 0)
    if summary.blocked or block_count:
        return "#c0392b"
    return "#e67e22"


def render_html(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
    reproduce_command: str | None = None,
) -> str:
    """Render a ScanReport as a self-contained Korean HTML document (card style).

    Same content as :func:`render_markdown` — both render from the one
    ``ScanReport`` so the two outputs never diverge. The HTML embeds all CSS
    inline (no external CDN/font/script — loads nothing), so it opens in air-gapped environments,
    attaches to email, and prints to PDF as a 붙임 document. 결재(서명)는
    상위 공문이 담당하므로 리포트 자체에는 결재 요소를 넣지 않는다.
    """
    ts = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    # 승인된 예외(suppressed)는 본문 통계·상세에서 분리해 전용 섹션에만 표시.
    suppressed = [f for f in report.findings if f.suppressed]
    if suppressed:
        report = report.model_copy(
            update={"findings": [f for f in report.findings if not f.suppressed]}
        )
    summary = report.summary
    p: list[str] = []
    p.append("<!DOCTYPE html>")
    p.append('<html lang="ko"><head><meta charset="utf-8">')
    p.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    p.append("<title>코드 보안 검사 결과</title>")
    p.append(f"<style>{_HTML_CSS}</style></head><body>")
    p.append('<div class="page">')

    p.append("<h1>🛡️ 코드 보안 검사 결과</h1>")
    p.append('<div class="sub">vibecode-checker · 공공 바이브 코딩 보안 가드레일</div>')

    # === Layer 1 — 공무원용: 문서 헤더 표 → 결론(승인/미승인 박스) ==========
    #   순서: 헤더표 → 결론 박스 → 한눈에 보기 → 조치 가이드 → Top 3 →
    #   정직성 배너 → 검토 범위·한계+면책. 상세는 Layer 2로. ================
    p.append(_meta_table_html(report, ts))
    p.append(_verdict_box_html(report))

    build_skips = _build_artifact_skips(report)

    # --- 한눈에 보기 (핵심 숫자) ---
    p.append("<h2>한눈에 보기</h2>")
    top_sev = summary.highest_severity
    block_n = summary.by_decision.get(Decision.block.value, 0)
    sev_label = (
        f"{_SEVERITY_LABEL_KO[top_sev]}" if top_sev else "—"
    )
    sev_col = _SEVERITY_COLOR[top_sev] if top_sev else "#9ca3af"
    p.append('<div class="stats">')
    p.append(
        f'<div class="stat"><div class="num">{len(report.scanned_files)}</div>'
        '<div class="lab">검사한 파일</div></div>'
    )
    uniq_locs = _unique_location_count(report.findings)
    find_lab = "발견된 위험" + (f" · 고유 위치 {uniq_locs}곳" if report.findings else "")
    p.append(
        f'<div class="stat"><div class="num">{summary.finding_count}</div>'
        f'<div class="lab">{find_lab}</div></div>'
    )
    p.append(
        f'<div class="stat"><div class="num" style="color:'
        f'{"#c0392b" if block_n else "#1f2937"}">{block_n}</div>'
        '<div class="lab">차단(block)</div></div>'
    )
    p.append(
        f'<div class="stat"><div class="num" style="color:{sev_col}">{sev_label}</div>'
        '<div class="lab">최고 심각도</div></div>'
    )
    if report.external_surface:  # (A) 외부 연결 현황을 최상단 요약에 노출
        n_api, n_pkg, gukoe, ext_warn = _external_stats(report)
        sub = f"국외 {gukoe}" + (f"·⚠{ext_warn}" if ext_warn else "")
        p.append(
            f'<div class="stat"><div class="num" style="color:'
            f'{"#c0392b" if ext_warn else "#1f2937"}">{n_api + n_pkg}</div>'
            f'<div class="lab">외부 연결 ({sub})</div></div>'
        )
    p.append("</div>")

    chips = []
    for sev in (Severity.critical, Severity.high, Severity.medium, Severity.low):
        c = summary.by_severity.get(sev.value, 0)
        if c:
            chips.append(
                f'<span class="chip" style="background:{_SEVERITY_COLOR[sev]}">'
                f"{_SEVERITY_LABEL_KO[sev]} {c}</span>"
            )
    if chips:
        p.append(f'<div class="chips">{"".join(chips)}</div>')

    if summary.finding_count == 0:
        p.append(
            '<div class="disc">발견된 위험이 없습니다. 다만 본 도구는 보조 가드레일이며 '
            "공식 보안성 검토를 대체하지 않습니다.</div>"
        )

    # --- 조치 가이드 (초보자용 행동 안내) — 발견이 있을 때만 ---------------
    if report.findings:
        p.append('<div class="actionbox">')
        p.append('<div class="ah">🛠 조치 가이드 — 3단계만 따라 하세요</div>')
        p.append(f'<div class="lead">{_esc(_action_lead(report))}</div>')
        p.append("<ol>")
        for title, desc, say in _ACTION_STEPS:
            li = f"<b>{_esc(title)}</b> · {_esc(desc)}"
            if say:
                li += f'<br><span class="say">▶ {_esc(say)}</span>'
            if title == "고치기":
                li += '<br><span style="font-size:12.5px;color:#475569">' \
                      "(또는 아래 '수정 프롬프트' 칸의 복사 버튼을 쓰세요)</span>"
            p.append(f"<li>{li}</li>")
        p.append("</ol>")
        p.append(f'<div class="caveat">⚠ <b>{_esc(_ACTION_CAVEAT)}</b></div>')
        p.append("</div>")

    # --- 가장 먼저 할 일 (Top 3) — 공무원이 뭘 먼저 고칠지 ------------------
    if report.findings:
        p.append("<h2>가장 먼저 할 일 (Top 3)</h2>")
        p.append('<ul class="todo">')
        for g in _top_actions(report.findings, 3):
            dec_ko = _DECISION_LABEL_KO.get(g["decision"], g["decision"].value)
            p.append(
                f'<li><span class="box">☐</span>'
                f'<span class="sevdot" style="background:{_SEVERITY_COLOR[g["severity"]]}">'
                f'{_SEVERITY_LABEL_KO[g["severity"]]}</span> '
                f"<b>{_esc(g['title'])}</b>"
                f'<span class="meta2">{dec_ko} · {g["count"]}건 · 파일 {g["files"]}개 · '
                f'{_esc(g["rule_id"])}</span></li>'
            )
        p.append("</ul>")
        p.append(
            '<div class="kv" style="font-size:12.5px;color:#64748b">각 항목의 정확한 위치·수정 '
            "방법은 아래 '상세 검토 결과'의 분야별 카드에 있습니다.</div>"
        )

    # --- 정직성 배너 — 실행 모드·승인 예외·의존성·빌드 제외 -----------------
    mode_note = _scan_mode_note(report)
    if mode_note:
        p.append(f'<div class="scanmode">{_esc(mode_note)}</div>')
    for line in _suppression_banner_md(report, suppressed):
        text = line.lstrip("> ").strip()
        if text:
            p.append(f'<div class="scanmode">{_esc(text).replace("**", "")}</div>')
    dep_audits = _dep_audits(report)
    manifest_skips = [s for s in report.skipped_files if "의존성 매니페스트" in (s.reason or "")]
    if dep_audits:
        banner = _esc(_dep_banner_text(dep_audits)).replace("**", "")
        p.append(f'<div class="depwarn">{banner}</div>')
    elif manifest_skips:
        names = ", ".join(s.path.replace("\\", "/").rsplit("/", 1)[-1] for s in manifest_skips)
        p.append(
            '<div class="depwarn">⚠️ <b>의존성 검사 별도 필요</b> — '
            f"{_esc(names)} 은(는) 코드 스캔 대상이 아닙니다. 취약·악성 패키지는 "
            '<code class="ev">gvskb check-package</code> 또는 MCP '
            '<code class="ev">scan_dependencies</code>로 따로 검사하세요.</div>'
        )
    if build_skips:
        p.append(
            f'<div class="buildnote">🧹 빌드 산출물 {len(build_skips)}건 제외 — '
            "압축·번들·캐시 파일은 원본 소스가 아니라 검사 대상에서 자동 제외했습니다 "
            "(오탐 방지).</div>"
        )

    # --- 검토 범위 및 한계 + 면책 — 조치 안내 뒤, 상세 검토 앞(신뢰성 고지) --
    p.append("<h2>검토 범위 및 한계</h2>")
    ext_dist = _ext_distribution(report.scanned_files)
    ext_str = " · ".join(f"{_esc(ext)} {n}건" for ext, n in ext_dist.most_common()) or "—"
    p.append(
        f'<div class="kv"><b>검토 범위</b> — 파일 {len(report.scanned_files)}건 ({ext_str}) · '
        "정적(소스코드) 검사이며 코드를 실행하지 않습니다</div>"
    )
    if report.skipped_files:
        reason_counts = Counter(_short_reason(s.reason) for s in report.skipped_files)
        rs = " · ".join(f"{_esc(r)} {n}건" for r, n in reason_counts.most_common())
        p.append(
            f'<div class="kv"><b>검사 제외</b> — {len(report.skipped_files)}건 ({rs}) · '
            "아래 '생략된 파일' 목록 참조</div>"
        )
    p.append(
        f'<div class="scopebox">⚠ <b>한계 고지</b> — {_esc(_LIMIT_HEAD)} '
        f"<b>{_esc(_LIMIT_ZERO)}</b> {_esc(_LIMIT_BODY)} <b>{_esc(_LIMIT_TAIL)}</b></div>"
    )
    p.append(f'<div class="discbox">{_esc(report.disclaimer.replace(chr(10), " "))}</div>')

    # =====================================================================
    # Layer 2 — 보안담당자용 상세 검토: 분야 개요 → 분야별 상세(기본 닫힘,
    # 비밀값 분야 직후 개인정보 콜아웃) → 외부 연결 → 의존성 → 승인 예외 →
    # 수정 프롬프트 → 부록
    # =====================================================================
    p.append("<h2>상세 검토 결과</h2>")
    p.append(
        '<div class="kv">각 <b>보안 분야</b>를 클릭해 펼치면 위치·취약점 설명·대응방안·근거를 '
        "확인할 수 있습니다. (인쇄 시에는 모두 펼쳐집니다.)</div>"
    )

    domains = _group_by_domain(report.findings)

    # --- 보안 분야 개요 — 어느 분야가 문제인지 한눈에 -----------------------
    p.append('<div class="subh">보안 분야 개요</div>')
    if domains:
        p.append("<table><tr><th>분야</th><th>최고 심각도</th><th>건수</th><th>파일</th></tr>")
        for d in domains:
            p.append(
                f"<tr><td>{_esc(d['label'])}</td>"
                f'<td class="sev"><span class="sevdot" style="background:'
                f'{_SEVERITY_COLOR[d["max_severity"]]}">{_SEVERITY_LABEL_KO[d["max_severity"]]}</span></td>'
                f'<td class="cnt">{d["count"]}</td><td class="cnt">{d["files"]}</td></tr>'
            )
        p.append("</table>")

        # 같은 (파일, 줄)에 여러 룰이 걸린 위치 — 건수 부풀림 오해 방지.
        multi = _multi_rule_lines(report.findings)
        if multi:
            items = " · ".join(
                f"<b>{_esc(m['file'].replace(chr(92), '/'))}:{m['line']}</b>"
                f" — 관련 룰 {len(m['rules'])}개 ({_esc(', '.join(m['rules']))})"
                for m in multi[:12]
            )
            if len(multi) > 12:
                items += f" · 외 {len(multi) - 12}곳"
            p.append(
                f'<div class="dupnote">ℹ️ <b>같은 줄 다중 지적</b> — 발견 '
                f"{summary.finding_count}건 중 고유 위치는 {uniq_locs}곳입니다. "
                f"한 줄에 여러 기준(룰)이 함께 걸린 위치: {items}. "
                "한 곳을 고치면 관련 룰이 함께 해소됩니다.</div>"
            )
    else:
        p.append('<div class="disc">발견된 위험이 없어 분야별 상세가 없습니다.</div>')

    # --- 분야별 상세 — 분야마다 <details>(치명·차단 분야는 기본 펼침).
    #     개인정보·비밀값 콜아웃은 '비밀값' 분야(없으면 개인정보) 바로 아래. -----
    pii = _privacy_findings(report.findings)
    pii_anchor = max((d["order"] for d in domains if d["order"] <= 2), default=None)
    for d in domains:
        # 기본은 닫힘(사용자 요청) — 클릭해 펼친다. 인쇄 시에는 print CSS 로 모두 펼쳐짐.
        p.append(
            '<details class="sec"><summary>'
            f'<span class="sevdot" style="background:{_SEVERITY_COLOR[d["max_severity"]]}">'
            f'{_SEVERITY_LABEL_KO[d["max_severity"]]}</span> '
            f'{_esc(d["label"])} — {d["count"]}건 · 파일 {d["files"]}개</summary>'
            '<div class="secbody">'
        )
        for g in _rule_groups(d["findings"]):
            p.extend(_render_rule_group_html(g))
        p.append("</div></details>")
        if pii and d["order"] == pii_anchor:
            p.append(_pii_callout_html(pii))
    if pii and pii_anchor is None:
        p.append(_pii_callout_html(pii))

    # === 승인된 예외 내역 — 있을 때만 =====================================
    p.extend(_render_suppressions_html(suppressed))

    # === 의존성(패키지) 취약점 검사 — 병합된 경우에만 표시 ================
    p.extend(_render_dependency_audit_html(report))

    # === 외부 연결 인벤토리 (위험과 분리, 발견 0이어도 표시) ==============
    if report.external_surface:
        p.extend(_render_external_surface_html(report))

    # === 수정 프롬프트 (복사용) — 기본 접기. 각 블록에 복사 버튼(인라인 JS) ===
    if report.findings:
        p.append(
            '<details class="sec"><summary>🛠 수정 프롬프트 (복사해서 AI에게 전달)'
            '</summary><div class="secbody">'
        )
        # ① 가장 쉬운 방법 — 강조 박스 + 한 줄 프롬프트 복사 버튼
        p.append(
            '<div class="easyfix"><div class="eh">💬 가장 쉬운 방법</div>'
            '<div class="ed">쓰던 AI 도구(커서·클로드 코드 등)에 아래 문장을 그대로 '
            "붙여넣으면 끝입니다. 아래 유형별 블록은 필요할 때 따로 복사하세요.</div>"
            f'<div class="easyrow"><code class="saycode">{_esc(_SAY_FIX)}</code>'
            f'<button type="button" class="copybtn" data-copy="{_esc(_SAY_FIX)}">📋 복사</button>'
            "</div></div>"
        )
        # ② 유형별 수정 프롬프트 — 각 블록마다 복사 버튼
        for g in _rule_groups(report.findings):
            text = _fix_prompt_text(g)
            p.append(
                '<div class="fixwrap">'
                f'<button type="button" class="copybtn" data-copy="{_esc(text)}">📋 복사</button>'
                f'<div class="fixprompt">{_esc(text)}</div></div>'
            )
        p.append("</div></details>")

    # === 부록 (기술 정보) — 기본 접기 ====================================
    non_build_skips = [s for s in report.skipped_files if "빌드 산출물" not in (s.reason or "")]
    repro = reproduce_command or f"gvskb scan {report.target} --profile {report.profile}"
    p.append('<details class="sec"><summary>📎 부록 (가이드라인 분포·생략 파일·재현·재검증)'
             '</summary><div class="secbody">')
    dist = _guideline_distribution(report.findings) if report.findings else None
    if dist:
        p.append('<div class="subh">가이드라인별 분포</div>')
        p.append("<table><tr><th>가이드라인</th><th>인용 건수</th></tr>")
        for label, count in dist.most_common():
            p.append(f"<tr><td>{_esc(label)}</td><td>{count}</td></tr>")
        p.append("</table>")
    if non_build_skips:
        p.append('<div class="subh">생략된 파일</div><table><tr><th>경로</th><th>이유</th></tr>')
        for sf in non_build_skips[:30]:
            p.append(f"<tr><td>{_esc(sf.path)}</td><td>{_esc(sf.reason)}</td></tr>")
        p.append("</table>")
        if len(non_build_skips) > 30:
            p.append(f'<div class="kv">… 외 {len(non_build_skips) - 30}건</div>')
    if build_skips:
        sample = ", ".join(_esc(s.path) for s in build_skips[:6])
        more = f" 외 {len(build_skips) - 6}건" if len(build_skips) > 6 else ""
        p.append(
            f'<div class="buildnote">빌드 산출물 제외 {len(build_skips)}건: {sample}{more} '
            "— 압축/번들·빌드 출력 디렉터리는 원본 소스가 아니므로 검사하지 않습니다.</div>"
        )
    p.append('<div class="subh">재현 절차</div>')
    p.append('<div class="kv">같은 결과를 다시 만들거나 다른 환경에서 검증하려면 다음을 실행합니다.</div>')
    p.append(f"<pre>{_esc(repro)}</pre>")
    p.append('<div class="subh">수정 후 다시 검증</div>')
    p.append('<ol class="steps">')
    p.append('<li><b>CLI</b>: 위 재현 명령(<code class="ev">gvskb scan ...</code>)을 다시 실행</li>')
    p.append(
        '<li><b>MCP(IDE)</b>: 수정한 코드를 <code class="ev">scan_code</code>에 다시 넘기거나 '
        '파일은 <code class="ev">scan_path</code> 호출</li>'
    )
    p.append("<li><b>LLM 안내</b>: 위 권장 처리 순서(차단→치명·높음→자동수정→나머지)를 그대로 지시문으로 사용</li>")
    p.append("</ol>")
    p.append("</div></details>")

    # (면책은 상단 '검토 범위 및 한계' 아래로 이동했다 — 여기서는 반복하지 않는다)
    p.append('<div class="foot">생성: vibecode-checker · 공공 바이브 코딩 보안 가드레일</div>')
    p.append("</div>")  # .page
    # 복사 버튼용 인라인 스크립트(외부 리소스 로딩 없음 — 자체완결 유지).
    # 클립보드 미지원 환경에서도 프롬프트 텍스트는 그대로 보인다(우아한 저하).
    p.append(_COPY_SCRIPT)
    p.append("</body></html>")
    return "\n".join(p)


def _fix_prompt_text(group: dict) -> str:
    """복사용 수정 프롬프트 한 블록(룰 그룹 기준). AI 도구에 그대로 붙여넣는다."""
    f: Finding = group["sample"]
    sev = _SEVERITY_LABEL_KO[group["severity"]]
    dec = _DECISION_LABEL_KO.get(group["decision"], group["decision"].value)
    locs = _locations_by_file(group["findings"])
    out = [
        f"[{sev}/{dec}] {f.plain_title} ({group['rule_id']}) — {group['count']}건",
        f"위치: {locs}",
    ]
    if f.why_it_matters:
        out.append(f"왜 위험: {f.why_it_matters.strip()}")
    if f.safe_fix:
        out.append(f"안전한 수정 방향: {f.safe_fix.strip()}")
    out.append("지시: 위 위치의 코드를 안전한 패턴으로 수정하고, 수정 후 다시 검사해 주세요.")
    return "\n".join(out)


def _render_external_surface_html(report: ScanReport) -> list[str]:
    """외부 연결 인벤토리 섹션(HTML) — 접기형. ⚠가 있으면 기본 펼침(절충)."""
    api = [c for c in report.external_surface if c.kind == "api"]
    pkg = [c for c in report.external_surface if c.kind == "package"]
    n_api, n_pkg, gukoe, warn = _external_stats(report)
    head_extra = ""
    if gukoe or warn:
        bits = []
        if gukoe:
            bits.append(f"국외 {gukoe}")
        if warn:
            bits.append(f"⚠개인정보 {warn}")
        head_extra = f' · <span style="color:#c0392b">{" · ".join(bits)}</span>'
    out: list[str] = [
        f'<details class="sec inv"{" open" if warn else ""}>'
        f"<summary>🌐 외부 연결 인벤토리 — API {n_api} · 플러그인 {n_pkg}{head_extra}</summary>"
        '<div class="secbody">',
        '<div class="invnote">⚠ <b>사용 금지가 아닙니다.</b> 외부로 데이터를 보낼 수 있는 지점 '
        '목록입니다. <span class="hl">⚠ 개인정보 인접</span>·<span class="hl">국외 전송</span>을 '
        "먼저 확인하세요.</div>",
    ]
    if api:
        out.append('<div class="subh">① 외부 API 호출 (검토 필요 먼저)</div>')
        out.append(
            "<table><tr><th>대상(호스트)</th><th>종류</th><th>모델</th><th>위치</th>"
            "<th>이용 정보(요약)</th><th>국외이전(운영주체)</th><th>검토</th></tr>"
        )
        for c in api:
            cls = ' class="w"' if c.review_level == "warn" else ""
            region = c.region or "확인"
            rcls = "out" if c.region == "국외" else ("in" if c.region == "국내" else "q")
            rev = (
                '<span class="rev warn">검토 필요</span>'
                if c.review_level == "warn"
                else '<span class="rev info">참고</span>'
            )
            # 호출 지점 수 — 첫 위치 + "외 N곳"으로 검토 규모를 보여준다.
            loc = c.location if c.call_count <= 1 else f"{c.location} 외 {c.call_count - 1}곳"
            # 운영주체·국가 — 국외이전 검토는 "누구에게, 어느 나라로"가 특정돼야 한다.
            oper = c.operator or "미상 — 직접 확인"
            out.append(
                f"<tr{cls}><td>{_esc(c.target)}</td>"
                f'<td><span class="pill {_esc(c.category)}">{_esc(_cat_ko(c.category))}</span></td>'
                f"<td>{_esc(c.model or '—')}</td><td>{_esc(loc)}</td>"
                f"<td>{_esc(c.data_summary)}</td>"
                f'<td><span class="go {rcls}">{_esc(region)}</span>'
                f'<br><span class="oper">{_esc(oper)}</span></td><td>{rev}</td></tr>'
            )
        out.append("</table>")
    if pkg:
        out.append('<div class="subh">② 설치된 외부 플러그인 · 라이브러리</div>')
        out.append(
            "<table><tr><th>플러그인/라이브러리</th><th>버전</th><th>종류</th>"
            "<th>전송 대상(운영주체)</th><th>이용 정보(요약)</th></tr>"
        )
        for c in pkg:
            out.append(
                f"<tr><td>{_esc(c.target)}</td><td>{_esc(c.version or '—')}</td>"
                f'<td><span class="pill {_esc(c.category)}">{_esc(_cat_ko(c.category))}</span></td>'
                f"<td>{_esc(c.operator or '—')}</td>"
                f"<td>{_esc(c.data_summary)}</td></tr>"
            )
        out.append("</table>")
    out.append(
        '<div class="invcheck"><b>검토 체크리스트</b> — ⚠ 지점마다: ① 무슨 데이터? '
        "② 개인정보 포함? ③ 국외이전 동의·망분리·기관 AI정책 부합? "
        "④ AI API 입력 데이터의 <b>학습 이용·보존 여부</b>는 서비스 약관과 기관 계약"
        "(옵트아웃 설정)으로 확인</div>"
    )
    out.append(
        '<div class="disc">※ <b>최소 목록</b>입니다 — 변수로 조립된 호스트는 누락될 수 있습니다. '
        "'이용 정보·국외'는 검토를 돕는 신호이며 실제 전송 페이로드를 확정하지 않습니다.</div>"
    )
    out.append("</div></details>")
    return out


def _render_rule_group_html(group: dict) -> list[str]:
    """파일 안에서 같은 룰을 한 카드로 묶어 렌더(설명 1번 + 위치목록 + 외 N건)."""
    f: Finding = group["sample"]
    findings: list[Finding] = group["findings"]
    sev_color = _SEVERITY_COLOR[group["severity"]]
    dec_color = _DECISION_COLOR.get(group["decision"], "#555")
    out: list[str] = [f'<div class="card" style="border-left-color:{sev_color}">']
    out.append(
        f'<div><span class="badge" style="background:{sev_color}">'
        f"{_SEVERITY_LABEL_KO[group['severity']]}</span>"
        f'<span class="badge" style="background:{dec_color}">'
        f"{_DECISION_LABEL_KO.get(group['decision'], group['decision'].value)}</span>"
        f'<span class="ftitle">{_esc(f.plain_title)}</span>'
        f'<span class="loc">{group["count"]}건 · line {_esc(_line_list(findings))}</span></div>'
    )
    out.append(
        f'<div class="row"><span class="tag">{_esc(f.rule_id)}</span>'
        f'<span class="tag">{_esc(f.category)}</span></div>'
    )
    if f.evidence:
        out.append(
            f'<div class="row"><span class="lab">증거(마스킹됨)</span>'
            f'<span class="val"><code class="ev">{_esc(_oneline(f.evidence))}</code></span></div>'
        )
    if f.why_it_matters:
        out.append(
            f'<div class="row"><span class="lab">왜 위험한가</span>'
            f'<span class="val">{_esc(f.why_it_matters.strip())}</span></div>'
        )
    if f.public_sector_impact:
        out.append(
            f'<div class="row"><span class="lab">공공 업무 영향</span>'
            f'<span class="val">{_esc(", ".join(f.public_sector_impact))}</span></div>'
        )
    if f.safe_fix:
        out.append('<div class="row"><span class="lab">안전한 수정 방향</span></div>')
        out.append(f"<pre>{_esc(f.safe_fix.strip())}</pre>")
    flags = []
    if f.can_auto_fix:
        flags.append("자동 수정 가능 (diff 미리보기 후 적용)")
    if f.requires_approval_to_bypass:
        flags.append("우회 시 보안담당자 승인 + 감사 로그 필요")
    if flags:
        out.append(
            f'<div class="row"><span class="lab">처리</span>'
            f'<span class="val">{_esc(" · ".join(flags))}</span></div>'
        )
    if f.references:
        out.append(
            f'<div class="row"><span class="lab">출처</span>'
            f'<span class="val">{_esc(", ".join(f.references[:5]))}</span></div>'
        )
    out.append("</div>")
    return out


# ---------------------------------------------------------------------------
# 승인된 예외(.gvskb-exceptions.yaml) — 발견을 숨기지 않고 게이트만 통과.
# 보안팀은 "무엇이 왜 면제됐고 언제 만료되나"를 항상 볼 수 있어야 한다.
# ---------------------------------------------------------------------------


def _suppression_banner_md(report: ScanReport, suppressed: list[Finding]) -> list[str]:
    out: list[str] = []
    ss = report.suppression_summary or {}
    if suppressed:
        out.append(
            f"> ℹ️ **승인된 예외 {len(suppressed)}건 적용** — 요약 건수·배포 판정에서 "
            "제외됐습니다. 아래 '승인된 예외 내역'에서 사유·승인자·만료일을 확인하세요."
        )
        out.append("")
    for e in ss.get("expired", []) or []:
        out.append(
            f"> ⚠️ **만료된 예외** — `{e.get('rule_id', '?')}` ({e.get('file', '?')}) 의 예외가 "
            f"{e.get('expires', '?')} 에 만료돼 **다시 차단 대상**입니다. 재승인하거나 수정하세요."
        )
        out.append("")
    return out


def _render_suppressions_md(suppressed: list[Finding]) -> list[str]:
    if not suppressed:
        return []
    out: list[str] = ["## 승인된 예외 내역 (게이트 통과, 기록 유지)", ""]
    out.append("| 룰 | 위치 | 심각도 | 사유(승인·만료 포함) |")
    out.append("|---|---|---|---|")
    for f in suppressed:
        reason = (f.suppress_reason or "").replace("|", "\\|")  # MD 표 파이프 이스케이프
        out.append(
            f"| `{f.rule_id}` | `{f.location.file}:{f.location.line}` | "
            f"{_SEVERITY_LABEL_KO[f.severity]} | {reason} |"
        )
    out.append("")
    out.append("> 예외는 위험이 사라졌다는 뜻이 아닙니다 — 만료일이 지나면 자동으로 다시 차단됩니다.")
    out.append("")
    return out


def _render_suppressions_html(suppressed: list[Finding]) -> list[str]:
    if not suppressed:
        return []
    out: list[str] = [
        '<details class="sec" open><summary>승인된 예외 내역 — '
        f"{len(suppressed)}건 (게이트 통과, 기록 유지)</summary>",
        '<div class="secbody">',
        "<table><tr><th>룰</th><th>위치</th><th>심각도</th><th>사유(승인·만료 포함)</th></tr>",
    ]
    for f in suppressed:
        out.append(
            f"<tr><td>{_esc(f.rule_id)}</td>"
            f"<td>{_esc(f.location.file)}:{f.location.line}</td>"
            f"<td>{_esc(_SEVERITY_LABEL_KO[f.severity])}</td>"
            f"<td>{_esc(f.suppress_reason or '')}</td></tr>"
        )
    out.append("</table>")
    out.append('<div class="disc">예외는 위험이 사라졌다는 뜻이 아닙니다 — '
               "만료일이 지나면 자동으로 다시 차단됩니다.</div>")
    out.append("</div></details>")
    return out


# ---------------------------------------------------------------------------
# 의존성(패키지) 취약점 감사 — scan_dependencies/audit_manifest 결과를 사람용
# 리포트에 병합한다. 보안팀이 "코드 + 패키지" 위험을 한 문서에서 보게 하고,
# 판정 불가(unchecked/unparsed)를 '안전'으로 오해하지 않도록 명시한다.
# ---------------------------------------------------------------------------


def _dep_audits(report: ScanReport) -> list[dict]:
    """dependency_audit 필드 → audit dict 목록. 단일 dict / {'audits':[...]} 모두 수용."""
    da = report.dependency_audit
    if not da or not isinstance(da, dict):
        return []
    if isinstance(da.get("audits"), list):
        return [a for a in da["audits"] if isinstance(a, dict)]
    return [da]


def _dep_stats(audits: list[dict]) -> tuple[int, int, int, bool]:
    """(검사됨, 판정불가, 취약·악성 패키지 수, 차단 여부) 합계."""
    checked = sum(int(a.get("checked_count") or 0) for a in audits)
    unchecked = sum(int(a.get("unchecked_count") or 0) for a in audits)
    unchecked += sum(1 for a in audits if a.get("verdict") == "unparsed")  # 파싱 실패도 판정불가
    vuln = 0
    for a in audits:
        for c in a.get("checks") or []:
            if c.get("is_malicious_package") or c.get("vulnerability_count"):
                vuln += 1
    blocked = any(a.get("blocked") for a in audits)
    return checked, unchecked, vuln, blocked


def _dep_banner_text(audits: list[dict]) -> str:
    checked, unchecked, vuln, blocked = _dep_stats(audits)
    if blocked:
        return (f"🚫 **의존성 검사 포함** — 악성·고위험 패키지 발견(취약·악성 {vuln}건). "
                "아래 '의존성(패키지) 취약점 검사' 섹션을 확인하세요.")
    if vuln:
        return (f"⚠️ **의존성 검사 포함** — 알려진 취약점 있는 패키지 {vuln}건. "
                "아래 '의존성(패키지) 취약점 검사' 섹션을 확인하세요.")
    if unchecked:
        return (f"⚠️ **의존성 일부 판정 불가** — {unchecked}건은 검사되지 못했습니다"
                "(캐시 없는 오프라인·API 실패·파싱 불가). **판정 불가는 '안전'이 아닙니다.**")
    return f"✅ **의존성 검사 포함** — 패키지 {checked}건, 알려진 취약점 없음(검사 시점 기준)."


def _pkg_verdict_label(check: dict) -> str:
    if check.get("is_malicious_package"):
        return "🚫 악성 의심"
    n = check.get("vulnerability_count") or 0
    if n:
        return f"⚠ 취약점 {n}건"
    if check.get("checked"):
        return "이상 없음(검사 시점)"
    return "판정 불가"


def _pkg_note(check: dict) -> str:
    bits: list[str] = []
    heur = check.get("heuristics") or {}
    if heur.get("typosquat_warning"):
        bits.append("타이포스쿼팅 의심")
    if check.get("kev_signals"):
        bits.append("CISA KEV 신호")
    if not check.get("checked") and check.get("note"):
        bits.append("검사 불가 사유 있음")
    return " · ".join(bits)


def _render_dependency_audit_md(report: ScanReport) -> list[str]:
    audits = _dep_audits(report)
    if not audits:
        return []
    checked, unchecked, vuln, blocked = _dep_stats(audits)
    out: list[str] = ["## 📦 의존성(패키지) 취약점 검사", ""]
    out.append(f"> 검사 {checked}건 · 판정 불가 {unchecked}건 · 취약·악성 {vuln}건"
               + (" · **차단 권고**" if blocked else ""))
    out.append("")
    for a in audits:
        title = a.get("manifest") or a.get("ecosystem", "manifest")
        out.append(f"### `{title}` ({a.get('ecosystem', '?')}) — 판정: {a.get('verdict', '?')}")
        out.append("")
        if a.get("verdict") == "unparsed":
            out.append(f"> ⚠ {a.get('note', '파싱하지 못했습니다.')} **파싱 0건은 '안전'이 아닙니다.**")
            out.append("")
            continue
        out.append("| 패키지 | 버전 | 판정 | 비고 |")
        out.append("|---|---|---|---|")
        for c in a.get("checks") or []:
            out.append(
                f"| `{c.get('name', '?')}` | {c.get('version') or '—'} | "
                f"{_pkg_verdict_label(c)} | {_pkg_note(c)} |"
            )
        out.append("")
    if unchecked:
        out.append("> ⚠ **판정 불가는 '안전'이 아닙니다** — 온라인 환경 또는 최신 인텔 캐시"
                   "(`gvskb update-intel`)로 다시 검사하세요.")
        out.append("")
    return out


def _render_dependency_audit_html(report: ScanReport) -> list[str]:
    audits = _dep_audits(report)
    if not audits:
        return []
    checked, unchecked, vuln, blocked = _dep_stats(audits)
    keep_open = blocked or vuln > 0 or unchecked > 0
    out: list[str] = [
        f'<details class="sec"{" open" if keep_open else ""}>'
        f"<summary>📦 의존성(패키지) 취약점 검사 — 검사 {checked} · 판정불가 {unchecked} · 취약·악성 {vuln}</summary>"
        '<div class="secbody">',
    ]
    for a in audits:
        title = a.get("manifest") or a.get("ecosystem", "manifest")
        out.append(f'<div class="subh">{_esc(str(title))} ({_esc(str(a.get("ecosystem", "?")))}) '
                   f"— 판정: {_esc(str(a.get('verdict', '?')))}</div>")
        if a.get("verdict") == "unparsed":
            out.append(f'<div class="depwarn">⚠ {_esc(str(a.get("note", "파싱하지 못했습니다.")))} '
                       "<b>파싱 0건은 '안전'이 아닙니다.</b></div>")
            continue
        out.append("<table><tr><th>패키지</th><th>버전</th><th>판정</th><th>비고</th></tr>")
        for c in a.get("checks") or []:
            bad = c.get("is_malicious_package") or c.get("vulnerability_count")
            cls = ' class="w"' if bad else ""
            out.append(
                f"<tr{cls}><td>{_esc(str(c.get('name', '?')))}</td>"
                f"<td>{_esc(str(c.get('version') or '—'))}</td>"
                f"<td>{_esc(_pkg_verdict_label(c))}</td><td>{_esc(_pkg_note(c))}</td></tr>"
            )
        out.append("</table>")
    if unchecked:
        out.append('<div class="depwarn">⚠ <b>판정 불가는 \'안전\'이 아닙니다</b> — 온라인 환경 '
                   '또는 최신 인텔 캐시(<code class="ev">gvskb update-intel</code>)로 다시 검사하세요.</div>')
    out.append("</div></details>")
    return out


def _render_external_surface_md(report: ScanReport) -> list[str]:
    """외부 연결 인벤토리 섹션(Markdown). MD는 접기가 없으므로 표로 펼쳐 출력."""
    api = [c for c in report.external_surface if c.kind == "api"]
    pkg = [c for c in report.external_surface if c.kind == "package"]
    n_api, n_pkg, gukoe, warn = _external_stats(report)
    out: list[str] = ["## 🌐 외부 연결 인벤토리 (보안팀 검토용)", ""]
    out.append(
        f"> ⚠ **사용 금지가 아닙니다.** 외부로 데이터를 보낼 수 있는 지점 목록입니다 "
        f"(API {n_api} · 플러그인 {n_pkg} · 국외 {gukoe} · ⚠개인정보 {warn}). "
        "⚠ 개인정보 인접·국외 전송을 먼저 확인하세요."
    )
    out.append("")
    if api:
        out.append("### ① 외부 API 호출 (검토 필요 먼저)")
        out.append("")
        out.append("| 대상(호스트) | 종류 | 모델 | 위치 | 이용 정보 | 국외이전(운영주체) | 검토 |")
        out.append("|---|---|---|---|---|---|---|")
        for c in api:
            mark = "⚠ 검토" if c.review_level == "warn" else "참고"
            loc = c.location if c.call_count <= 1 else f"{c.location} 외 {c.call_count - 1}곳"
            oper = f"{c.region or '확인'} — {c.operator}" if c.operator else f"{c.region or '확인'} — 미상(직접 확인)"
            out.append(
                f"| `{c.target}` | {_cat_ko(c.category)} | {c.model or '—'} | "
                f"`{loc}` | {c.data_summary} | {oper} | {mark} |"
            )
        out.append("")
    if pkg:
        out.append("### ② 설치된 외부 플러그인 · 라이브러리")
        out.append("")
        out.append("| 플러그인/라이브러리 | 버전 | 종류 | 전송 대상(운영주체) | 이용 정보 |")
        out.append("|---|---|---|---|---|")
        for c in pkg:
            out.append(
                f"| `{c.target}` | {c.version or '—'} | {_cat_ko(c.category)} | "
                f"{c.operator or '—'} | {c.data_summary} |"
            )
        out.append("")
    out.append(
        "> **검토 체크리스트** — ⚠ 지점마다: ① 무슨 데이터? ② 개인정보 포함? "
        "③ 국외이전 동의·망분리·기관 AI정책 부합? "
        "④ AI API 입력 데이터의 **학습 이용·보존 여부**는 서비스 약관·기관 계약(옵트아웃 설정)으로 확인"
    )
    out.append(
        "> ※ 최소 목록 — 변수로 조립된 호스트는 누락될 수 있고, '이용 정보·국외'는 "
        "검토 신호이며 페이로드 확정이 아닙니다."
    )
    out.append("")
    return out


def _render_finding_group_md(group: dict) -> list[str]:
    """파일 안에서 같은 룰을 한 항목으로 묶어 출력(설명 1번 + 위치목록 + 외 N건)."""
    f: Finding = group["sample"]
    findings: list[Finding] = group["findings"]
    tag = _SEVERITY_EMOJI[group["severity"]]
    out: list[str] = []
    out.append(
        f"#### {tag} {_SEVERITY_LABEL_KO[group['severity']]} · {group['decision'].value} — "
        f"{f.plain_title} ({group['count']}건)"
    )
    out.append("")
    out.append(f"- **위치**: line {_line_list(findings)}")
    out.append(f"- **룰**: `{f.rule_id}`")
    out.append(f"- **카테고리**: {f.category}")
    if f.evidence:
        out.append(f"- **증거(자동 마스킹됨)**: `{_oneline(f.evidence)}`")
    if f.why_it_matters:
        out.append(f"- **왜 위험한가**: {f.why_it_matters.strip()}")
    if f.public_sector_impact:
        out.append(f"- **공공 업무 영향**: {', '.join(f.public_sector_impact)}")
    if f.safe_fix:
        out.append("- **안전한 수정 방향**:")
        out.append("")
        out.append("  ```")
        for ln in f.safe_fix.strip().splitlines():
            out.append(f"  {ln}")
        out.append("  ```")
    if f.can_auto_fix:
        out.append("- **자동 수정 가능**: 예 (diff 미리보기 후 적용)")
    if f.requires_approval_to_bypass:
        out.append("- **우회 시 승인 필요**: 보안담당자 승인 + 감사 로그 기록")
    if f.references:
        refs = ", ".join(f.references[:5])
        out.append(f"- **출처**: {refs}")
    return out


def _oneline(text: str, limit: int = 160) -> str:
    s = " ".join(text.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# SARIF 2.1.0 — CI·보안도구 연동용 표준 출력 (GitHub code scanning 업로드 가능)
# ---------------------------------------------------------------------------

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _sarif_level(f: Finding) -> str:
    """SARIF level 매핑 — 차단(block)과 치명·높음은 error로."""
    if f.decision == Decision.block:
        return "error"
    if f.severity in (Severity.critical, Severity.high):
        return "error"
    if f.severity == Severity.medium:
        return "warning"
    return "note"


def render_sarif(report: ScanReport) -> dict:
    """ScanReport → SARIF 2.1.0 dict.

    CI 파이프라인(GitHub code scanning `upload-sarif`)이나 기관 보안도구가
    표준 형식으로 결과를 수집할 수 있게 한다. 사람용 md/html과 동일한
    ScanReport 하나에서 렌더되므로 내용이 갈라지지 않는다.
    """
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    results: list[dict] = []
    for f in report.findings:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id,
                "name": f.title or f.rule_id,
                "shortDescription": {"text": f.plain_title or f.title or f.rule_id},
                "fullDescription": {"text": (f.why_it_matters or "")[:1000]},
                "helpUri": "https://github.com/Lex6won/vibecode-checker",
                "defaultConfiguration": {"level": _sarif_level(f)},
                "properties": {
                    "severity": f.severity.value,
                    "decision": f.decision.value,
                    "category": f.category,
                    "references": f.references[:5],
                },
            })
        message = f.plain_title or f.title
        if f.safe_fix:
            message += f" — 수정 방향: {f.safe_fix.strip().splitlines()[0][:200]}"
        entry = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _sarif_level(f),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.file.replace("\\", "/")},
                    "region": {"startLine": max(1, f.location.line)},
                },
            }],
            "partialFingerprints": {"gvskbFindingId": f.id},
        }
        if f.suppressed:
            # SARIF 표준 억제 표기 — 도구들이 자동으로 '해결됨 아님, 면제됨'으로 처리
            entry["suppressions"] = [{
                "kind": "external",
                "justification": (f.suppress_reason or "")[:500],
            }]
        results.append(entry)
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vibecode-checker",
                "informationUri": "https://github.com/Lex6won/vibecode-checker",
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "target": report.target,
                "profile": report.profile,
                "scan_mode": report.scan_mode or "online",
                "scanned_files": len(report.scanned_files),
                "disclaimer": report.disclaimer,
            },
        }],
    }
