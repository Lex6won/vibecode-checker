"""gvskb 독립 벤치마크 드라이버.

eval_corpus/manifest.yaml 의 ground truth 라벨에 대해 gvskb scanner 의
탐지율(recall)·오탐율(FP)·경계 갭을 측정한다. gvskb evaluate 는 룰 내장
예제(자기참조)만 보므로, 외부 코퍼스 채점은 이 드라이버가 담당한다.

실행:
    GVSKB_MODE=offline PYTHONPATH=src python scripts/run_benchmark.py

산출물(eval_corpus/results/): benchmark_results.json / benchmark_results.md
패키지 코드는 수정하지 않으며 scan_path 를 in-process 로 호출한다.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "eval_corpus"
PROJECTS = CORPUS / "projects"
RESULTS = CORPUS / "results"
LINE_TOL = 2

sys.path.insert(0, str(REPO / "src"))
from gvskb.scanner import scan_path  # noqa: E402


def norm(p: str) -> str:
    return p.replace("\\", "/").lstrip("./")


def rel_to_projects(file_field: str) -> str:
    """scan_path 의 location.file 를 manifest 기준 상대경로(projects/ 제외)로 정규화."""
    s = norm(file_field)
    # scan_path 는 projects 디렉터리 기준 상대경로를 주거나 corpus 기준일 수 있음 → 끝부분 매칭
    for prefix in ("eval_corpus/projects/", "projects/"):
        if s.startswith(prefix):
            return s[len(prefix):]
    return s


def load_manifest() -> dict:
    return yaml.safe_load((CORPUS / "manifest.yaml").read_text(encoding="utf-8"))


def self_validate(cases: list[dict]) -> list[str]:
    """manifest 의 sink 문자열이 실제 파일·라인에 존재하는지 자가 검증."""
    problems = []
    for c in cases:
        fp = PROJECTS / c["file"]
        if not fp.exists():
            problems.append(f"{c['id']}: 파일 없음 {c['file']}")
            continue
        lines = fp.read_text(encoding="utf-8").splitlines()
        ln = c["line"]
        if not (1 <= ln <= len(lines)):
            problems.append(f"{c['id']}: 라인 범위 밖 {ln}")
            continue
        window = "\n".join(lines[max(0, ln - 1 - LINE_TOL): ln + LINE_TOL])
        sink = c.get("sink", "")
        if sink and sink not in window:
            problems.append(f"{c['id']}: sink 미발견 '{sink}' @ {c['file']}:{ln}")
    return problems


def run_scan(profile: str | None = None) -> list[dict]:
    report = scan_path(PROJECTS, profile=profile) if profile else scan_path(PROJECTS)
    out = []
    for f in report.findings:
        out.append(
            {
                "file": rel_to_projects(f.location.file),
                "line": f.location.line,
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "category": f.category,
                "engine": f.engine,
            }
        )
    return out


def match(case: dict, findings: list[dict], tol: int = LINE_TOL) -> dict | None:
    for fnd in findings:
        if fnd["file"] != norm(case["file"]):
            continue
        if abs(fnd["line"] - case["line"]) > tol:
            continue
        ids = case.get("expected_rule_ids") or []
        if ids:
            if fnd["rule_id"] in ids:
                return fnd
        else:
            # rule id 예측 불가 → 같은 파일·라인의 어떤 발견이든 탐지로 인정
            return fnd
    return None


def lang_of(file: str) -> str:
    ext = Path(file).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".html": "html",
        ".java": "java",
    }.get(ext, ext or "?")


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()
    cases = manifest["cases"]
    nc_files = {norm(f) for f in manifest.get("negative_control_files", [])}

    problems = self_validate(cases)
    if problems:
        print("[manifest 자가검증 실패]")
        for p in problems:
            print("  -", p)
        return 2
    print(f"[manifest 자가검증 OK] {len(cases)} 케이스")

    findings = run_scan()
    # 하네스가 실제로 부르는 프로파일(dev-quick, severity_min=high)로도 돌린다 —
    # 기본 프로파일 recall 1.0 을 보고하면서 medium 룰(ERR-03·MIXED-CONTENT 등)이
    # 조용히 빠지는 사실을 벤치마크가 숨기고 있었다(실측 2026-08-29).
    findings_quick = run_scan("dev-quick")

    vuln_cases = [c for c in cases if c["kind"] == "vulnerability"]
    hard_cases = [c for c in cases if c["kind"] == "hard_variant"]
    # `known_gap` — 외부 지침이 요구하나 **현재 탐지하지 못한다고 확인된** 항목.
    # recall 에 넣지 않는다(못 잡는 것이 사실이므로 탐지율을 왜곡한다).
    # 대신 따로 세고, **탐지되기 시작하면 알린다** — ground truth 를 갱신해야 한다는 신호다.
    gap_cases = [c for c in cases if c["kind"] == "known_gap"]

    known_kinds = {"vulnerability", "hard_variant", "known_gap"}
    unknown = [c for c in cases if c["kind"] not in known_kinds]
    if unknown:
        # 조용히 버리지 않는다 — 모르는 kind 는 집계에서 빠지므로 반드시 드러낸다.
        print(f"[경고] 알 수 없는 kind {len(unknown)}건이 집계에서 빠집니다: "
              f"{sorted({c['kind'] for c in unknown})}")

    # 1) 취약점 탐지율
    per_cat = defaultdict(lambda: [0, 0])   # category -> [detected, total]
    per_lang = defaultdict(lambda: [0, 0])
    per_proj = defaultdict(lambda: [0, 0])
    vuln_rows = []
    for c in vuln_cases:
        m = match(c, findings)
        detected = m is not None
        cat = c["category"]
        lang = lang_of(c["file"])
        proj = c["file"].split("/")[0]
        for bucket, key in ((per_cat, cat), (per_lang, lang), (per_proj, proj)):
            bucket[key][1] += 1
            if detected:
                bucket[key][0] += 1
        vuln_rows.append(
            {"id": c["id"], "file": c["file"], "line": c["line"], "category": cat,
             "detected": detected, "matched_rule": m["rule_id"] if m else None}
        )
    vuln_detected = sum(r["detected"] for r in vuln_rows)

    # 2) 경계 프로브
    hard_rows = []
    for c in hard_cases:
        m = match(c, findings, tol=1)  # 인접 시드 교차오염 방지
        hard_rows.append(
            {"id": c["id"], "file": c["file"], "line": c["line"], "category": c["category"],
             "detected": m is not None, "matched_rule": m["rule_id"] if m else None}
        )
    hard_detected = sum(r["detected"] for r in hard_rows)

    # 2-b) 알려진 공백 — 못 잡는 것이 사실. 잡히기 시작하면 그것이 뉴스다.
    gap_rows = []
    for c in gap_cases:
        m = match(c, findings)
        gap_rows.append(
            {"id": c["id"], "file": c["file"], "line": c["line"], "category": c["category"],
             "guide_item": c.get("guide_item", ""),
             "detected": m is not None, "matched_rule": m["rule_id"] if m else None}
        )
    gap_now_detected = sum(r["detected"] for r in gap_rows)

    # 3) 음성 대조군 FP
    fp_rows = [f for f in findings if f["file"] in nc_files]

    # 4) 라벨 외 추가 발견(취약 파일에서 시드와 매칭 안 된 발견)
    labeled = {(norm(c["file"]), c["line"]) for c in cases}
    vuln_files = {norm(c["file"]) for c in vuln_cases}
    extras = []
    for f in findings:
        if f["file"] in nc_files or f["file"] not in vuln_files:
            continue
        near = any(f["file"] == cf and abs(f["line"] - cl) <= LINE_TOL for cf, cl in labeled)
        if not near:
            extras.append(f)

    quick_lost = [c["id"] for c in vuln_cases if match(c, findings) and not match(c, findings_quick)]
    quick_detected = sum(1 for c in vuln_cases if match(c, findings_quick))
    results = {
        "summary": {
            "vuln_total": len(vuln_cases),
            "vuln_detected": vuln_detected,
            "vuln_recall": round(vuln_detected / len(vuln_cases), 3),
            "vuln_recall_dev_quick": round(quick_detected / len(vuln_cases), 3),
            "dev_quick_lost_cases": quick_lost,
            "hard_total": len(hard_cases),
            "hard_detected": hard_detected,
            "known_gap_total": len(gap_cases),
            "known_gap_now_detected": gap_now_detected,
            "fp_findings": len(fp_rows),
            "negative_control_files": len(nc_files),
            "unexpected_extras": len(extras),
            "total_findings": len(findings),
        },
        "per_category": {k: {"detected": v[0], "total": v[1]} for k, v in sorted(per_cat.items())},
        "per_language": {k: {"detected": v[0], "total": v[1]} for k, v in sorted(per_lang.items())},
        "per_project": {k: {"detected": v[0], "total": v[1]} for k, v in sorted(per_proj.items())},
        "vuln_rows": vuln_rows,
        "hard_rows": hard_rows,
        "gap_rows": gap_rows,
        "fp_rows": fp_rows,
        "extras": extras,
    }
    (RESULTS / "benchmark_results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # ---- Markdown ----
    s = results["summary"]
    md = []
    md.append("# gvskb 독립 벤치마크 결과\n")
    md.append(f"- dev-quick 프로파일 탐지율: **{s['vuln_recall_dev_quick']}** "
              f"(기본 프로파일 대비 빠지는 케이스: {', '.join(s['dev_quick_lost_cases']) or '없음'} — "
              "severity_min=high 가 medium 룰을 버리는 효과)\n")
    md.append(f"- 시드 취약점 탐지율(recall): **{s['vuln_detected']}/{s['vuln_total']} "
              f"= {s['vuln_recall']*100:.1f}%**")
    md.append(f"- 경계 프로브 탐지: {s['hard_detected']}/{s['hard_total']} (미탐이 정상 — 한계 측정)")
    md.append(f"- 음성 대조군 오탐(FP): **{s['fp_findings']}건** "
              f"(대조군 {s['negative_control_files']}개 파일)")
    md.append(f"- 라벨 외 추가 발견: {s['unexpected_extras']}건 / 전체 발견 {s['total_findings']}건")
    md.append(f"- **알려진 공백(known_gap)**: {s['known_gap_total']}건 — 현재 탐지 "
              f"{s['known_gap_now_detected']}건 "
              "(외부 지침이 요구하나 못 잡는다고 **확인된** 항목. recall 에 포함하지 않는다)\n")

    def tbl(title, d):
        md.append(f"## {title}\n")
        md.append("| 구분 | 탐지/전체 | 비율 |")
        md.append("|---|---:|---:|")
        for k, v in d.items():
            pct = v["detected"] / v["total"] * 100 if v["total"] else 0
            md.append(f"| {k} | {v['detected']}/{v['total']} | {pct:.0f}% |")
        md.append("")

    tbl("카테고리별 탐지율", results["per_category"])
    tbl("언어별 탐지율", results["per_language"])
    tbl("프로젝트별 탐지율", results["per_project"])

    md.append("## 미탐된 시드 취약점\n")
    md.append("| ID | 위치 | 카테고리 |")
    md.append("|---|---|---|")
    for r in vuln_rows:
        if not r["detected"]:
            md.append(f"| {r['id']} | {r['file']}:{r['line']} | {r['category']} |")
    md.append("")

    md.append("## 알려진 공백 — 외부 지침 요구 대비 미탐\n")
    md.append("> 못 잡는 것이 **확인된 사실**이라 탐지율에 넣지 않는다. "
              "`탐지됨` 으로 바뀌면 ground truth 를 갱신해야 한다는 신호다.\n")
    md.append("| ID | 지침 항목 | 위치 | 현재 |")
    md.append("|---|---|---|---|")
    for r in gap_rows:
        md.append(f"| {r['id']} | {r['guide_item'] or r['category']} | {r['file']}:{r['line']} | "
                  f"{'**탐지됨 — 갱신 필요**' if r['detected'] else '미탐'} |")
    md.append("")

    md.append("## 음성 대조군 오탐(FP) 상세\n")
    md.append("| 파일 | 라인 | 룰 | 카테고리 |")
    md.append("|---|---:|---|---|")
    for f in fp_rows:
        md.append(f"| {f['file']} | {f['line']} | {f['rule_id']} | {f['category']} |")
    md.append("")

    md.append("## 경계 프로브 결과\n")
    md.append("| ID | 위치 | 탐지 | 룰 |")
    md.append("|---|---|---|---|")
    for r in hard_rows:
        md.append(f"| {r['id']} | {r['file']}:{r['line']} | {'탐지' if r['detected'] else '미탐'} | "
                  f"{r['matched_rule'] or '-'} |")
    md.append("")

    (RESULTS / "benchmark_results.md").write_text("\n".join(md), encoding="utf-8")

    print(f"[완료] recall={s['vuln_recall']*100:.1f}%  FP={s['fp_findings']}  "
          f"hard_detected={s['hard_detected']}/{s['hard_total']}  "
          f"known_gap={s['known_gap_now_detected']}/{s['known_gap_total']}")
    if gap_now_detected:
        print(f"  ※ 알려진 공백 {gap_now_detected}건이 이제 탐지됩니다 — manifest 를 갱신하세요.")
    print(f"  → {RESULTS / 'benchmark_results.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
