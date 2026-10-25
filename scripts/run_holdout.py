"""41차 홀드아웃 말뭉치 드라이버 — 2026 공급망·에이전트 사고 구조 재현에 대한 탐지율·오탐.

기존 `run_benchmark.py`(42 케이스 · 소스 취약점)와 **별도 표**다. 설정 파일 수집기는 루트 기준으로
동작하므로 하위 폴더마다 `scan_path` 를 따로 부른다.

실행:
    GVSKB_MODE=offline PYTHONPATH=src python scripts/run_holdout.py        # 미탐·오탐 있으면 종료 1

산출물(eval_corpus/results/): holdout_results.json / holdout_results.md
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "eval_corpus" / "projects" / "j_agentic_2026"
RESULTS = REPO / "eval_corpus" / "results"
_RANK = {"pattern-only": 0, "likely": 1, "confirmed": 2}

sys.path.insert(0, str(REPO / "src"))
from gvskb.scanner import scan_path  # noqa: E402


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def _scan_root(root: Path) -> list[dict]:
    r = scan_path(root)
    return [{"file": _norm(f.location.file), "rule": f.rule_id, "confidence": f.confidence,
             "decision": f.decision.value} for f in r.findings]


def main() -> int:
    os.environ.setdefault("GVSKB_TODAY", "2026-10-25")   # 런타임 EOL 판정 기준일 고정(재현성)
    manifest = yaml.safe_load((CORPUS / "manifest.yaml").read_text(encoding="utf-8"))
    cases = manifest["cases"]
    neg_roots = manifest["negative_roots"]
    prefixes = tuple(manifest["negative_rule_prefixes"])

    by_root: dict[str, list[dict]] = {}
    for root in sorted({c["root"] for c in cases} | set(neg_roots)):
        d = CORPUS / root
        if not d.is_dir():
            print(f"[manifest 오류] 루트 없음: {root}")
            return 2
        by_root[root] = _scan_root(d)

    rows = []
    for c in cases:
        hits = [f for f in by_root[c["root"]] if f["file"] == _norm(c["file"]) and f["rule"] == c["rule"]]
        best = max((_RANK[h["confidence"]] for h in hits), default=-1)
        ok = best >= _RANK[c.get("min_confidence", "pattern-only")]
        rows.append({**c, "detected": ok, "confidence": next((k for k, v in _RANK.items() if v == best), None)})
    detected = sum(r["detected"] for r in rows)

    fps = [{"root": root, **f} for root in neg_roots for f in by_root[root] if f["rule"].startswith(prefixes)]

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = {"cases": rows, "recall": f"{detected}/{len(rows)}", "false_positives": fps}
    (RESULTS / "holdout_results.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    md = ["# 홀드아웃 말뭉치(j_agentic_2026) 결과", "",
          f"- 탐지: **{detected}/{len(rows)}** (min_confidence 이상)", f"- 음성 대조군 오탐: **{len(fps)}**", "",
          "| id | root | file | rule | 기대 확신도 | 관측 | 탐지 |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['id']} | {r['root']} | {r['file']} | {r['rule']} | {r.get('min_confidence', '-')} | "
                  f"{r['confidence'] or '-'} | {'O' if r['detected'] else '**X**'} |")
    if fps:
        md += ["", "## 오탐", ""] + [f"- {f['root']}/{f['file']} {f['rule']} ({f['confidence']})" for f in fps]
    (RESULTS / "holdout_results.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"[holdout] 탐지 {detected}/{len(rows)} · 오탐 {len(fps)}")
    for r in rows:
        if not r["detected"]:
            print(f"  미탐 {r['id']} {r['root']}/{r['file']} {r['rule']} (관측 {r['confidence']})")
    for f in fps:
        print(f"  오탐 {f['root']}/{f['file']} {f['rule']} ({f['confidence']})")
    return 0 if detected == len(rows) and not fps else 1


if __name__ == "__main__":
    sys.exit(main())
