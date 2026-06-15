"""사람이 읽는 한국어 리포트 생성.

공무원이 검사 결과를 그대로 상위 결재·보고용으로 사용할 수 있도록
Markdown 한 장 분량의 결론·요약·증거·수정 가이드·재현 절차·면책을 묶어서 출력합니다.

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

    The output is designed to be readable on its own — anyone can paste it into
    a Word document or print it without needing to query the MCP further.
    """
    ts = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
    lines: list[str] = []

    lines.append("# 코드 보안 검사 결과")
    lines.append("")

    # --- 결론 (한 줄) -----------------------------------------------------
    lines.append("## 결론")
    lines.append("")
    lines.append(f"> {_verdict_line(report)}")
    lines.append("")

    # 의존성 매니페스트는 코드 스캔이 아니라 SCA로 검사해야 한다 — 코드 스캔
    # 결과만 보고 "의존성도 안전"으로 오해하지 않도록 결론 바로 아래에 강조한다.
    manifest_skips = [
        s for s in report.skipped_files if "의존성 매니페스트" in (s.reason or "")
    ]
    if manifest_skips:
        names = ", ".join(s.path.replace("\\", "/").rsplit("/", 1)[-1] for s in manifest_skips)
        lines.append(
            f"> ⚠️ **의존성 검사 별도 필요** — {names} 은(는) 코드 스캔 대상이 아닙니다. "
            f"취약·악성 패키지는 `gvskb check-package` 또는 MCP `scan_dependencies`로 따로 검사하세요."
        )
        lines.append("")

    build_skips = _build_artifact_skips(report)
    if build_skips:
        lines.append(
            f"> 🧹 **빌드 산출물 {len(build_skips)}건 제외** — 압축·번들·캐시 파일은 원본 "
            "소스가 아니라 검사 대상에서 자동 제외했습니다(오탐 방지)."
        )
        lines.append("")

    lines.append(f"- **대상**: `{report.target}`")
    lines.append(f"- **검사일시**: {ts}")
    lines.append(f"- **프로파일**: {report.profile}")
    if report.scenario:
        lines.append(f"- **시나리오**: {report.scenario}")
    if report.language:
        lines.append(f"- **언어 힌트**: {report.language}")
    lines.append("")

    # --- 요약 -------------------------------------------------------------
    lines.append("## 요약")
    lines.append("")
    summary = report.summary
    non_build_skips = [s for s in report.skipped_files if "빌드 산출물" not in (s.reason or "")]
    lines.append(f"- 검사한 파일 수: **{len(report.scanned_files)}건**")
    lines.append(f"- 발견된 위험: **{summary.finding_count}건**")
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

    by_file = _by_file(report.findings)
    ordered_files = _ordered_files(by_file)

    # --- 1페이지 요약: 위험 유형 + 파일별 요약 + 가장 먼저 할 일 -----------
    if report.findings:
        groups = _rule_groups(report.findings)
        lines.append("## 위험 유형 (무슨 문제가 몇 건)")
        lines.append("")
        lines.append("| 위험 유형 | 룰 | 심각도 | 건수 | 파일 |")
        lines.append("|---|---|---|---|---|")
        for g in groups:
            lines.append(
                f"| {g['title']} | `{g['rule_id']}` | "
                f"{_SEVERITY_LABEL_KO[g['severity']]} | {g['count']} | {g['files']} |"
            )
        lines.append("")

        lines.append("## 파일별 위험 요약")
        lines.append("")
        lines.append("| 파일 | 최고 심각도 | 건수 |")
        lines.append("|---|---|---|")
        for fn in ordered_files:
            ffs = by_file[fn]
            msev = _file_max_severity(ffs)
            lines.append(
                f"| `{fn.replace(chr(92), '/')}` | {_SEVERITY_LABEL_KO[msev]} | {len(ffs)} |"
            )
        lines.append("")

        lines.append("## 가장 먼저 할 일 (Top 5)")
        lines.append("")
        for g in _top_actions(report.findings, 5):
            dec_ko = _DECISION_LABEL_KO.get(g["decision"], g["decision"].value)
            lines.append(
                f"- [ ] **{g['title']}** — {_SEVERITY_LABEL_KO[g['severity']]}·{dec_ko} · "
                f"{g['count']}건 · 파일 {g['files']}개 (`{g['rule_id']}`)"
            )
        lines.append("")

    # --- 가이드라인별 분포 (출처 집계) -------------------------------------
    if report.findings:
        dist = _guideline_distribution(report.findings)
        if dist:
            lines.append("## 가이드라인별 분포")
            lines.append("")
            lines.append("> 한 발견 사항이 여러 가이드라인을 인용한 경우 각 그룹에서 1회씩 집계합니다.")
            lines.append("")
            lines.append("| 가이드라인 | 인용 건수 |")
            lines.append("|---|---|")
            for label, count in dist.most_common():
                lines.append(f"| {label} | {count} |")
            lines.append("")

    # --- 처리 순서 + 파일별 발견(룰 중복제거) ----------------------------
    if summary.finding_count == 0:
        lines.append("> 발견된 위험이 없습니다. 그러나 본 도구는 보조 가드레일이며, ")
        lines.append("> 공식 보안성 검토를 대체하지 않습니다.")
        lines.append("")
    else:
        lines.append("## 권장 처리 순서")
        lines.append("")
        lines.append("1. **차단(block)** 항목 — 커밋·배포 전에 반드시 수정 또는 보안담당자 승인 필요")
        lines.append("2. **경고(warn) + 치명/높음** — 운영 반영 전 우선 수정")
        lines.append("3. **자동 수정 가능** 항목 — diff 미리보기 후 적용")
        lines.append("4. **나머지 warn** — 차주 정비 일정에 반영")
        lines.append("")

        lines.append("## 파일별 발견 사항")
        lines.append("")
        for fname in ordered_files:
            ffs = by_file[fname]
            lines.append(f"### `{fname.replace(chr(92), '/')}` — {len(ffs)}건")
            lines.append("")
            for g in _rule_groups(ffs):
                lines.extend(_render_finding_group_md(g))
                lines.append("")

        # --- 수정 프롬프트 (복사용) -------------------------------------
        lines.append("## 수정 프롬프트 (복사해서 AI에게 전달)")
        lines.append("")
        lines.append("위험 유형별로 아래 블록을 복사해 AI 코딩 도구에 붙여넣으면 우선순위대로 수정할 수 있습니다.")
        lines.append("")
        for g in _rule_groups(report.findings):
            lines.append("```text")
            lines.append(_fix_prompt_text(g))
            lines.append("```")
            lines.append("")

    if non_build_skips:
        lines.append("## 생략된 파일")
        lines.append("")
        for sf in non_build_skips[:30]:
            lines.append(f"- `{sf.path}` — {sf.reason}")
        if len(non_build_skips) > 30:
            lines.append(f"- … 외 {len(non_build_skips) - 30}건")
        lines.append("")
    if build_skips:
        lines.append("## 빌드 산출물 제외")
        lines.append("")
        lines.append(
            "> 압축/번들·빌드 출력 디렉터리는 원본 소스가 아니므로 검사하지 않습니다 (오탐 방지)."
        )
        for sf in build_skips[:15]:
            lines.append(f"- `{sf.path.replace(chr(92), '/')}`")
        if len(build_skips) > 15:
            lines.append(f"- … 외 {len(build_skips) - 15}건")
        lines.append("")

    # --- 재현 절차 -------------------------------------------------------
    lines.append("## 재현 절차")
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

    # --- 수정 후 다시 검증 ----------------------------------------------
    lines.append("## 수정 후 다시 검증")
    lines.append("")
    lines.append("발견 사항을 수정한 뒤에는 같은 검사를 한 번 더 돌려 회귀를 막으세요.")
    lines.append("")
    lines.append("- **CLI**: 위의 재현 명령(`gvskb scan ...`)을 다시 실행합니다.")
    lines.append(
        "- **MCP (IDE)**: 수정한 코드 블록을 `scan_code` 도구에 다시 넘기거나, 파일 단위라면 "
        "`scan_path` 를 호출합니다."
    )
    lines.append(
        "- **수정 시 LLM 안내**: 위 권장 처리 순서(차단 → 치명·높음 → 자동수정 → 나머지) 를 "
        "그대로 LLM 프롬프트의 지시문으로 사용하면 우선순위가 어긋나지 않습니다."
    )
    lines.append("")

    # --- 면책 ------------------------------------------------------------
    lines.append("## 면책")
    lines.append("")
    lines.append("> " + report.disclaimer.replace("\n", " "))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*생성: vibecode-checker · 공공 바이브코딩 보안 가드레일*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML 리포트 — MD와 동일한 ScanReport 데이터에서 직접 렌더링하는 "카드 강조형".
# 자체 포함 단일 파일(외부 CDN·폰트·JS 없음)이라 망분리·이메일·인쇄(→PDF)에
# 그대로 쓸 수 있다. 동적 텍스트는 전부 html.escape 로 이스케이프한다.
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
.sub{color:#6b7280;font-size:13px;margin-bottom:18px}
.banner{padding:16px 20px;border-radius:8px;font-weight:700;font-size:16px;
  color:#fff;margin:8px 0 16px}
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
.filehdr{font-size:15px;font-weight:700;margin:22px 0 10px;color:#111827}
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
details.file{border:1px solid #e5e7eb;border-radius:8px;margin:10px 0;background:#fff;
  page-break-inside:avoid;overflow:hidden}
details.file>summary{cursor:pointer;list-style:none;padding:12px 16px;font-weight:700;
  font-size:14.5px;background:#f8fafc;display:flex;align-items:center;gap:8px}
details.file>summary::-webkit-details-marker{display:none}
details.file>summary::before{content:"▶";font-size:11px;color:#9ca3af;transition:none}
details.file[open]>summary::before{content:"▼"}
details.file>summary:hover{background:#f1f5f9}
details.file .body{padding:6px 16px 14px}
.fixprompt{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:13px 15px;
  margin:10px 0;font-size:12.5px;font-family:"D2Coding","Consolas","Courier New",monospace;
  white-space:pre-wrap;word-break:break-all}
.fixhdr{font-weight:700;font-size:14px;margin:14px 0 4px;color:#111827}
@media print{
  body{background:#fff}
  .page{box-shadow:none;margin:0;max-width:none;border-radius:0;padding:0 6mm}
  .card{break-inside:avoid}
  details.file{break-inside:avoid}
  details.file>summary::before{content:""}
  details.file>.body{display:block !important}
  pre,.fixprompt{white-space:pre-wrap}
}
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
    inline (no external CDN/font/JS), so it opens in air-gapped environments,
    attaches to email, and prints to PDF for an approval record.
    """
    ts = (generated_at or datetime.now()).strftime("%Y-%m-%d %H:%M")
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

    p.append(
        f'<div class="banner" style="background:{_verdict_css_color(report)}">'
        f"{_esc(_verdict_line(report))}</div>"
    )

    manifest_skips = [s for s in report.skipped_files if "의존성 매니페스트" in (s.reason or "")]
    if manifest_skips:
        names = ", ".join(s.path.replace("\\", "/").rsplit("/", 1)[-1] for s in manifest_skips)
        p.append(
            '<div class="depwarn">⚠️ <b>의존성 검사 별도 필요</b> — '
            f"{_esc(names)} 은(는) 코드 스캔 대상이 아닙니다. 취약·악성 패키지는 "
            '<code class="ev">gvskb check-package</code> 또는 MCP '
            '<code class="ev">scan_dependencies</code>로 따로 검사하세요.</div>'
        )

    build_skips = _build_artifact_skips(report)
    if build_skips:
        p.append(
            f'<div class="buildnote">🧹 빌드 산출물 {len(build_skips)}건 제외 — '
            "압축·번들·캐시 파일은 원본 소스가 아니라 검사 대상에서 자동 제외했습니다 "
            "(오탐 방지).</div>"
        )

    p.append(f'<div class="meta"><b>대상</b> · {_esc(report.target)}</div>')
    p.append(
        f'<div class="meta"><b>검사일시</b> · {ts} &nbsp;·&nbsp; '
        f'<b>프로파일</b> · {_esc(report.profile)}</div>'
    )
    if report.scenario or report.language:
        extra = []
        if report.scenario:
            extra.append(f"시나리오 {_esc(report.scenario)}")
        if report.language:
            extra.append(f"언어 힌트 {_esc(report.language)}")
        p.append(f'<div class="meta">{" · ".join(extra)}</div>')

    # === 1페이지 요약 (안 접힘) — 결론·핵심숫자·위험유형·파일요약·할일 ============
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
    p.append(
        f'<div class="stat"><div class="num">{summary.finding_count}</div>'
        '<div class="lab">발견된 위험</div></div>'
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

    by_file = _by_file(report.findings)
    ordered_files = _ordered_files(by_file)
    anchor_of = {fn: f"file-{i}" for i, fn in enumerate(ordered_files)}

    if report.findings:
        # --- 위험 유형 (많은 순) ----------------------------------------
        groups = _rule_groups(report.findings)
        p.append("<h2>위험 유형 (무슨 문제가 몇 건)</h2>")
        p.append('<table class="typetbl"><tr><th>위험 유형</th><th>심각도</th>'
                 "<th>건수</th><th>파일</th></tr>")
        for g in groups:
            p.append(
                f"<tr><td>{_esc(g['title'])}<br>"
                f'<span class="tag">{_esc(g["rule_id"])}</span></td>'
                f'<td class="sev"><span class="sevdot" style="background:'
                f'{_SEVERITY_COLOR[g["severity"]]}">{_SEVERITY_LABEL_KO[g["severity"]]}</span></td>'
                f'<td class="cnt">{g["count"]}</td><td class="cnt">{g["files"]}</td></tr>'
            )
        p.append("</table>")

        # --- 파일별 위험 요약 (상세로 점프) -----------------------------
        p.append("<h2>파일별 위험 요약</h2>")
        p.append("<table><tr><th>파일</th><th>최고 심각도</th><th>건수</th><th>바로가기</th></tr>")
        for fn in ordered_files:
            ffs = by_file[fn]
            msev = _file_max_severity(ffs)
            p.append(
                f"<tr><td>{_esc(fn.replace(chr(92), '/'))}</td>"
                f'<td class="sev"><span class="sevdot" style="background:'
                f'{_SEVERITY_COLOR[msev]}">{_SEVERITY_LABEL_KO[msev]}</span></td>'
                f'<td class="cnt">{len(ffs)}</td>'
                f'<td><a class="jump" href="#{anchor_of[fn]}">상세 ↓</a></td></tr>'
            )
        p.append("</table>")

        # --- 가장 먼저 할 일 Top5 --------------------------------------
        p.append("<h2>가장 먼저 할 일 (Top 5)</h2>")
        p.append('<ul class="todo">')
        for g in _top_actions(report.findings, 5):
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

        # === 파일별 상세 (접기) =========================================
        p.append("<h2>파일별 상세 (펼쳐 보기)</h2>")
        for fn in ordered_files:
            ffs = by_file[fn]
            msev = _file_max_severity(ffs)
            file_groups = _rule_groups(ffs)
            p.append(
                f'<details class="file" id="{anchor_of[fn]}"><summary>'
                f'<span class="sevdot" style="background:{_SEVERITY_COLOR[msev]}">'
                f'{_SEVERITY_LABEL_KO[msev]}</span> '
                f"📄 {_esc(fn.replace(chr(92), '/'))} — {len(ffs)}건</summary>"
                '<div class="body">'
            )
            for g in file_groups:
                p.extend(_render_rule_group_html(g))
            p.append("</div></details>")

        # === 수정 프롬프트 (복사용) =====================================
        p.append("<h2>수정 프롬프트 (복사해서 AI에게 전달)</h2>")
        p.append(
            '<div class="kv">위험 유형별로 아래 블록을 복사해 AI 코딩 도구에 그대로 '
            "붙여넣으면 우선순위대로 수정할 수 있습니다.</div>"
        )
        for g in _rule_groups(report.findings):
            p.append(f'<div class="fixprompt">{_esc(_fix_prompt_text(g))}</div>')

        # --- 우선순위 체크리스트(파일 기준) ----------------------------
        p.append('<div class="fixhdr">우선순위 체크리스트 (파일 기준)</div>')
        p.append('<ul class="todo">')
        for fn in ordered_files:
            ffs = by_file[fn]
            msev = _file_max_severity(ffs)
            p.append(
                f'<li><span class="box">☐</span>'
                f'<span class="sevdot" style="background:{_SEVERITY_COLOR[msev]}">'
                f'{_SEVERITY_LABEL_KO[msev]}</span> '
                f"<b>{_esc(fn.replace(chr(92), '/'))}</b>"
                f'<span class="meta2">{len(ffs)}건 — '
                f'<a class="jump" href="#{anchor_of[fn]}">상세 ↓</a></span></li>'
            )
        p.append("</ul>")

    # === 부록 ===========================================================
    if report.findings:
        dist = _guideline_distribution(report.findings)
        if dist:
            p.append("<h2>가이드라인별 분포</h2>")
            p.append("<table><tr><th>가이드라인</th><th>인용 건수</th></tr>")
            for label, count in dist.most_common():
                p.append(f"<tr><td>{_esc(label)}</td><td>{count}</td></tr>")
            p.append("</table>")

    non_build_skips = [s for s in report.skipped_files if "빌드 산출물" not in (s.reason or "")]
    if non_build_skips:
        p.append("<h2>생략된 파일</h2><table><tr><th>경로</th><th>이유</th></tr>")
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

    repro = reproduce_command or f"gvskb scan {report.target} --profile {report.profile}"
    p.append("<h2>재현 절차</h2>")
    p.append('<div class="kv">같은 결과를 다시 만들거나 다른 환경에서 검증하려면 다음을 실행합니다.</div>')
    p.append(f"<pre>{_esc(repro)}</pre>")

    p.append("<h2>수정 후 다시 검증</h2>")
    p.append('<ol class="steps">')
    p.append('<li><b>CLI</b>: 위 재현 명령(<code class="ev">gvskb scan ...</code>)을 다시 실행</li>')
    p.append(
        '<li><b>MCP(IDE)</b>: 수정한 코드를 <code class="ev">scan_code</code>에 다시 넘기거나 '
        '파일은 <code class="ev">scan_path</code> 호출</li>'
    )
    p.append("<li><b>LLM 안내</b>: 위 권장 처리 순서(차단→치명·높음→자동수정→나머지)를 그대로 지시문으로 사용</li>")
    p.append("</ol>")

    p.append("<h2>면책</h2>")
    p.append(f'<div class="disc">{_esc(report.disclaimer.replace(chr(10), " "))}</div>')

    p.append('<div class="foot">생성: vibecode-checker · 공공 바이브 코딩 보안 가드레일</div>')
    p.append("</div></body></html>")
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
