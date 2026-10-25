"""홀드아웃 말뭉치 드라이버(41차 j_agentic_2026 · 46차 k_ts_2026) — 탐지율·오탐을 숫자로.

기존 `run_benchmark.py`(42 케이스 · 소스 취약점)와 **별도 표**다. 설정 파일 수집기는 루트 기준으로
동작하므로 하위 폴더마다 `scan_path` 를 따로 부른다.

실행:
    GVSKB_MODE=offline PYTHONPATH=src python scripts/run_holdout.py                      # j_agentic_2026
    GVSKB_MODE=offline PYTHONPATH=src python scripts/run_holdout.py --corpus k_ts_2026   # TS 말뭉치
미탐·오탐이 있으면 종료 1. `requires_engine` 케이스는 그 엔진이 없으면 '엔진 없음'으로 따로 세고 미탐으로 치지 않는다.
`kind: known_gap` 케이스는 못 잡는 것이 정상이며, 잡히면 알린다(정답표 갱신 신호).

산출물(eval_corpus/results/): <corpus>_results.json / <corpus>_results.md
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
RESULTS = REPO / "eval_corpus" / "results"
_RANK = {"pattern-only": 0, "likely": 1, "confirmed": 2}
_LINE_TOL = 2

sys.path.insert(0, str(REPO / "src"))
from gvskb.scanner import engine_status, scan_path  # noqa: E402


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def _scan_root(root: Path) -> list[dict]:
    r = scan_path(root)
    return [{"file": _norm(f.location.file), "line": f.location.line, "rule": f.rule_id,
             "confidence": f.confidence, "decision": f.decision.value} for f in r.findings]


def run(corpus_name: str) -> dict:
    os.environ.setdefault("GVSKB_TODAY", "2026-10-25")   # 런타임 EOL 판정 기준일 고정(재현성)
    corpus = REPO / "eval_corpus" / "projects" / corpus_name
    manifest = yaml.safe_load((corpus / "manifest.yaml").read_text(encoding="utf-8"))
    cases = manifest["cases"]
    neg_roots = manifest.get("negative_roots", [])
    prefixes = tuple(manifest.get("negative_rule_prefixes", []))
    engines = set(engine_status().used)

    by_root: dict[str, list[dict]] = {}
    for root in sorted({c["root"] for c in cases} | set(neg_roots)):
        d = corpus / root
        if not d.is_dir():
            raise SystemExit(f"[manifest 오류] 루트 없음: {corpus_name}/{root}")
        by_root[root] = _scan_root(d)

    rows = []
    for c in cases:
        hits = [f for f in by_root[c["root"]] if f["file"] == _norm(c["file"]) and f["rule"] == c["rule"]
                and ("line" not in c or abs(f["line"] - int(c["line"])) <= _LINE_TOL)]
        best = max((_RANK[h["confidence"]] for h in hits), default=-1)
        detected = best >= _RANK[c.get("min_confidence", "pattern-only")]
        engine = c.get("requires_engine")
        if c.get("kind") == "known_gap":
            status = "news" if detected else "gap"
        elif engine and engine not in engines:
            status = "no-engine"
        else:
            status = "ok" if detected else "miss"
        rows.append({**c, "detected": detected, "observed": next((k for k, v in _RANK.items() if v == best), None), "status": status})

    fps = [{"root": root, **f} for root in neg_roots for f in by_root[root] if f["rule"].startswith(prefixes)]
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("ok", "miss", "no-engine", "gap", "news")}
    scored = counts["ok"] + counts["miss"]
    return {"corpus": corpus_name, "engines": sorted(engines), "cases": rows, "false_positives": fps, "counts": counts,
            "recall": f"{counts['ok']}/{scored}"}


def write(out: dict) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    name = out["corpus"]
    (RESULTS / f"{name}_results.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    c = out["counts"]
    md = [f"# 말뭉치 {name} 결과", "",
          f"- 탐지: **{out['recall']}** (채점 대상 = 엔진 조건 충족 케이스, min_confidence 이상)",
          f"- 엔진 없음(채점 제외): {c['no-engine']} · 알려진 공백: {c['gap']}" + (f" · **공백이 잡힘: {c['news']} — 정답표 갱신 필요**" if c["news"] else ""),
          f"- 음성 대조군 오탐: **{len(out['false_positives'])}**", f"- 가동 엔진: {', '.join(out['engines'])}", "",
          "| id | root | file:line | rule | 기대 | 관측 | 상태 |", "|---|---|---|---|---|---|---|"]
    label = {"ok": "O", "miss": "**X**", "no-engine": "엔진 없음", "gap": "공백", "news": "**잡힘(갱신)**"}
    for r in out["cases"]:
        md.append(f"| {r['id']} | {r['root']} | {r['file']}:{r.get('line', '-')} | {r['rule']} | {r.get('min_confidence', '-')} | "
                  f"{r['observed'] or '-'} | {label[r['status']]} |")
    if out["false_positives"]:
        md += ["", "## 오탐", ""] + [f"- {f['root']}/{f['file']}:{f['line']} {f['rule']} ({f['confidence']})" for f in out["false_positives"]]
    p = RESULTS / f"{name}_results.md"
    p.write_text("\n".join(md) + "\n", encoding="utf-8")
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default="j_agentic_2026")
    args = ap.parse_args(argv)
    out = run(args.corpus)
    write(out)
    c = out["counts"]
    print(f"[{args.corpus}] 탐지 {out['recall']} · 엔진 없음 {c['no-engine']} · 공백 {c['gap']} · 잡힌 공백 {c['news']} · 오탐 {len(out['false_positives'])}")
    for r in out["cases"]:
        if r["status"] in ("miss", "news"):
            print(f"  {r['status']} {r['id']} {r['root']}/{r['file']} {r['rule']} (관측 {r['observed']})")
    for f in out["false_positives"]:
        print(f"  오탐 {f['root']}/{f['file']}:{f['line']} {f['rule']} ({f['confidence']})")
    return 0 if c["miss"] == 0 and c["news"] == 0 and not out["false_positives"] else 1


if __name__ == "__main__":
    sys.exit(main())
