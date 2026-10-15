"""실측 트리 정밀도 게이트 — "고쳤더니 다른 데가 깨졌다"를 기계가 잡는다 (3층-최소, 2026-10-14).

기관 제출 소스는 공개 저장소에 넣지 않는다. 그래서 이 스크립트는 **이 PC 의 실측 트리**와 그 발견에
사람이 붙인 라벨(저장소 밖 JSON)을 읽어, 릴리스 전후 스냅샷을 비교하고 라벨과 어긋나면 실패한다.

    # 1) 스냅샷 (소스 룰만, 의존성 검사 없음)
    python scripts/precision_gate.py snapshot --out before.json "C:/…/STARS" "C:/…/safe_check"
    # 2) 수정 뒤 다시 스냅샷하고 비교 + 라벨 대조
    python scripts/precision_gate.py compare before.json after.json --labels "C:/…/labels.json"

라벨 파일 형식(목록):
    {"tree": "STARS(손창미)_점검_20261013", "file": "stars_db.py", "line": 242,
     "rule": "GOV-SQL-INJECTION-001", "verdict": "fp", "note": "바인딩만 쓰는 SQL"}
  verdict: tp = 반드시 발견돼야 한다(사라지면 미탐 후퇴) · fp = 발견되면 안 된다(오탐 재발)
           · fp-block = 발견은 남아도 되나 차단(block)이면 안 된다(정화·숫자 값 등)
  tree 는 스냅샷 루트 경로의 마지막 폴더 이름이다.

종료 코드: 0 = 위반 없음 · 1 = 라벨 위반 · 2 = 사용법 오류.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROW_KEYS = ("file", "line", "rule", "decision", "severity", "confidence")


def _tree_name(root: str) -> str:
    return Path(root).name


def take_snapshot(roots: list[str]) -> dict:
    """루트마다 scan_path 를 돌려 발견 행·제외 목록·소요 시간을 모은다."""
    from gvskb import __version__
    from gvskb.scanner import scan_path

    out: dict = {"engine_version": __version__, "trees": {}}
    for root in roots:
        t0 = time.perf_counter()
        report = scan_path(root)
        rows = sorted(
            (
                {
                    "file": str(f.location.file).replace("\\", "/"),
                    "line": f.location.line or 0,
                    "rule": f.rule_id,
                    "decision": f.decision.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                }
                for f in report.findings
            ),
            key=lambda r: (r["file"], r["line"], r["rule"]),
        )
        out["trees"][_tree_name(root)] = {
            "root": root,
            "rows": rows,
            "skipped": sorted(({"path": s.path, "reason": s.reason} for s in report.skipped_files),
                              key=lambda x: x["path"]),
            "seconds": round(time.perf_counter() - t0, 2),
            "scanned": len(report.scanned_files),
        }
    return out


def _key(row: dict) -> tuple:
    return (row["file"], row["line"], row["rule"])


def diff_snapshots(before: dict, after: dict) -> dict:
    """트리별 {added, removed, changed, seconds_before, seconds_after}."""
    out: dict = {}
    for tree in sorted(set(before.get("trees", {})) | set(after.get("trees", {}))):
        a = before.get("trees", {}).get(tree, {})
        b = after.get("trees", {}).get(tree, {})
        ra = {_key(r): r for r in a.get("rows", [])}
        rb = {_key(r): r for r in b.get("rows", [])}
        added = [rb[k] for k in sorted(rb.keys() - ra.keys())]
        removed = [ra[k] for k in sorted(ra.keys() - rb.keys())]
        changed = [
            {"before": ra[k], "after": rb[k]}
            for k in sorted(ra.keys() & rb.keys())
            if (ra[k]["decision"], ra[k]["confidence"]) != (rb[k]["decision"], rb[k]["confidence"])
        ]
        out[tree] = {
            "added": added, "removed": removed, "changed": changed,
            "seconds_before": a.get("seconds"), "seconds_after": b.get("seconds"),
            "count_before": len(ra), "count_after": len(rb),
        }
    return out


def evaluate_labels(snapshot: dict, labels: list[dict]) -> list[dict]:
    """라벨과 스냅샷을 대조해 위반 목록을 돌려준다(비어 있으면 통과)."""
    violations: list[dict] = []
    for lab in labels:
        tree = snapshot.get("trees", {}).get(lab["tree"])
        if tree is None:
            continue    # 이 PC 에 없는 트리는 판정하지 않는다(라벨이 틀린 것이 아니다)
        hit = next((r for r in tree["rows"]
                    if r["file"] == lab["file"].replace("\\", "/") and r["line"] == lab["line"]
                    and r["rule"] == lab["rule"]), None)
        verdict = lab["verdict"]
        if verdict == "tp" and hit is None:
            violations.append({**lab, "problem": "미탐 후퇴 — 참 양성으로 라벨된 발견이 사라짐"})
        elif verdict == "fp" and hit is not None:
            violations.append({**lab, "problem": f"오탐 재발 — {hit['decision']}/{hit['confidence']} 로 다시 보고됨"})
        elif verdict == "fp-block" and hit is not None and hit["decision"] == "block":
            violations.append({**lab, "problem": "차단 재발 — 정화·안전 값인데 다시 차단됨"})
        elif verdict == "tp-block" and (hit is None or hit["decision"] != "block"):
            violations.append({**lab, "problem": "차단 후퇴 — 차단이어야 할 발견이 사라지거나 경고로 내려감"})
    return violations


def precision_by_rule(snapshot: dict, labels: list[dict]) -> dict[str, dict]:
    """룰별 (라벨된 발견 중) 정밀도 — tp / (tp + 보고된 fp)."""
    out: dict[str, dict] = {}
    for lab in labels:
        tree = snapshot.get("trees", {}).get(lab["tree"])
        if tree is None:
            continue
        present = any(r["file"] == lab["file"].replace("\\", "/") and r["line"] == lab["line"]
                      and r["rule"] == lab["rule"] for r in tree["rows"])
        slot = out.setdefault(lab["rule"], {"tp": 0, "fp_reported": 0, "fp_suppressed": 0, "fn": 0})
        if lab["verdict"] in ("tp", "tp-block"):
            slot["tp" if present else "fn"] += 1
        elif lab["verdict"] in ("fp", "fp-block"):
            slot["fp_reported" if present else "fp_suppressed"] += 1
    for slot in out.values():
        denom = slot["tp"] + slot["fp_reported"]
        slot["precision"] = round(slot["tp"] / denom, 3) if denom else None
        denom_r = slot["tp"] + slot["fn"]
        slot["recall"] = round(slot["tp"] / denom_r, 3) if denom_r else None
    return out


_LANG_EXT = {
    ".py": "python",
    ".js": "js-ts", ".jsx": "js-ts", ".mjs": "js-ts", ".cjs": "js-ts",
    ".ts": "js-ts", ".tsx": "js-ts", ".mts": "js-ts", ".cts": "js-ts",
}


def _language_of(file: str) -> str:
    """라벨의 파일 경로 → 언어 묶음(python / js-ts / other). 검토서 T1: 언어별로 따로 낸다."""
    return _LANG_EXT.get(Path(file).suffix.lower(), "other")


def precision_by_language(snapshot: dict, labels: list[dict]) -> dict[str, dict]:
    """언어 묶음별 tp/fp/fn 과 정밀도·재현율 — Python 과 JS/TS 의 성적을 한 숫자로 섞지 않는다."""
    out: dict[str, dict] = {}
    for lab in labels:
        tree = snapshot.get("trees", {}).get(lab["tree"])
        if tree is None:
            continue
        present = any(r["file"] == lab["file"].replace("\\", "/") and r["line"] == lab["line"]
                      and r["rule"] == lab["rule"] for r in tree["rows"])
        slot = out.setdefault(_language_of(lab["file"]),
                              {"labels": 0, "tp": 0, "fp_reported": 0, "fp_suppressed": 0, "fn": 0})
        slot["labels"] += 1
        if lab["verdict"] in ("tp", "tp-block"):
            slot["tp" if present else "fn"] += 1
        elif lab["verdict"] in ("fp", "fp-block"):
            slot["fp_reported" if present else "fp_suppressed"] += 1
    for slot in out.values():
        denom = slot["tp"] + slot["fp_reported"]
        slot["precision"] = round(slot["tp"] / denom, 3) if denom else None
        denom_r = slot["tp"] + slot["fn"]
        slot["recall"] = round(slot["tp"] / denom_r, 3) if denom_r else None
    return out


def _print_diff(diff: dict) -> None:
    for tree, d in diff.items():
        flag = "SAME" if not (d["added"] or d["removed"] or d["changed"]) else "DIFF"
        print(f"{flag}  {d['count_before']}→{d['count_after']}  "
              f"{d['seconds_before']}s→{d['seconds_after']}s  {tree}")
        for r in d["removed"]:
            print(f"   - {r['file']}:{r['line']} {r['rule']} {r['decision']}/{r['confidence']}")
        for r in d["added"]:
            print(f"   + {r['file']}:{r['line']} {r['rule']} {r['decision']}/{r['confidence']}")
        for c in d["changed"]:
            b, a = c["before"], c["after"]
            print(f"   ~ {a['file']}:{a['line']} {a['rule']} {b['decision']}/{b['confidence']} → {a['decision']}/{a['confidence']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("snapshot", help="실측 트리들을 검사해 스냅샷 JSON 으로")
    s1.add_argument("--out", required=True)
    s1.add_argument("roots", nargs="+")
    s2 = sub.add_parser("compare", help="두 스냅샷 비교 + 라벨 대조")
    s2.add_argument("before")
    s2.add_argument("after")
    s2.add_argument("--labels", help="라벨 JSON(저장소 밖)")
    s2.add_argument("--json", action="store_true")
    s3 = sub.add_parser("check", help="스냅샷 하나를 라벨과 대조")
    s3.add_argument("snapshot")
    s3.add_argument("--labels", required=True)
    s3.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "snapshot":
        snap = take_snapshot(args.roots)
        Path(args.out).write_text(json.dumps(snap, ensure_ascii=False, indent=1), encoding="utf-8")
        for tree, t in snap["trees"].items():
            print(f"{t['seconds']:7.2f}s  findings={len(t['rows']):4d}  scanned={t['scanned']:4d}  {tree}")
        return 0

    labels: list[dict] = []
    if getattr(args, "labels", None):
        labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    if args.cmd == "compare":
        before = json.loads(Path(args.before).read_text(encoding="utf-8"))
        after = json.loads(Path(args.after).read_text(encoding="utf-8"))
        diff = diff_snapshots(before, after)
        if args.json:
            print(json.dumps({"diff": diff, "violations": evaluate_labels(after, labels) if labels else [],
                              "precision": precision_by_rule(after, labels) if labels else {},
                              "by_language": precision_by_language(after, labels) if labels else {}},
                             ensure_ascii=False, indent=1))
        else:
            _print_diff(diff)
        target = after
    else:
        target = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        if args.json:
            print(json.dumps({"violations": evaluate_labels(target, labels),
                              "precision": precision_by_rule(target, labels),
                              "by_language": precision_by_language(target, labels)}, ensure_ascii=False, indent=1))

    if not labels:
        return 0
    violations = evaluate_labels(target, labels)
    if not args.json:
        for rule, p in sorted(precision_by_rule(target, labels).items()):
            print(f"  {rule:32s} tp={p['tp']} fp_reported={p['fp_reported']} fp_suppressed={p['fp_suppressed']} "
                  f"fn={p['fn']} precision={p['precision']} recall={p['recall']}")
        for lang, p in sorted(precision_by_language(target, labels).items()):
            print(f"  [{lang}] labels={p['labels']} tp={p['tp']} fp_reported={p['fp_reported']} "
                  f"fp_suppressed={p['fp_suppressed']} fn={p['fn']} precision={p['precision']} recall={p['recall']}")
        for v in violations:
            print(f"VIOLATION  {v['tree']}/{v['file']}:{v['line']} {v['rule']} [{v['verdict']}] — {v['problem']}")
        print(f"라벨 {len(labels)}건 대조 — 위반 {len(violations)}건")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    raise SystemExit(main())
