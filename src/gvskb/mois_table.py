"""행정안전부 SW 개발보안 49개 항목 결과표(43차 · C-19).

공공기관 점검 결재는 "항목별로 무엇이 나왔나"를 묻는다. 이 모듈은 보고서의 발견을 `rules/mois-49/` 의 항목에
항목↔룰 매핑으로 묶어 센다. 매핑 근거 세 가지(합집합):
1. 탐지 룰의 `related_baseline` 이 MOIS 항목을 가리킴
2. MOIS 항목 룰의 `related_baseline` 이 탐지 룰을 가리킴
3. CWE 가 겹침(`cwe` frontmatter)

정직성 원칙: 항목에 **자동 탐지 룰이 하나도 없으면** "발견 없음"이 아니라 "자동 탐지 없음 — 사람 점검"으로 적는다.
발견이 없는 항목도 "해당 발견 없음(안전 아님)"으로 적는다 — 설계·인가·업무 로직은 정적 분석 범위 밖이다.
49개 항목에 들어가지 않는 발견(공급망·개발환경·AI·플랫폼)은 별도 표로 센다(docs/42 §7).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from functools import lru_cache

from .schema import Decision, ScanReport, Status

MOIS_PREFIX = "MOIS-49-"
_SECTION_ORDER = ("INPUT", "SEC", "TIME", "ERR", "CODE", "ENCAP", "API", "SW")
_SECTION_KO = {"INPUT": "입력데이터 검증 및 표현", "SEC": "보안기능", "TIME": "시간 및 상태", "ERR": "에러처리",
               "CODE": "코드오류", "ENCAP": "캡슐화", "API": "API 오용", "SW": "추가(외부 입력 검증)"}
_OUTSIDE_KO = {
    "agent-supply-chain": "에이전트·개발환경 공급망", "supply-chain": "CI·패키지 공급망", "platform-security": "플랫폼(Electron·확장·MCP)",
    "hidden-code": "숨은 문자", "llm-appsec": "LLM 애플리케이션", "agent-safety": "에이전트 안전", "access-control": "접근 통제",
}


def _sort_key(item_id: str) -> tuple[int, int]:
    tail = item_id[len(MOIS_PREFIX):]
    sec, _, num = tail.rpartition("-")
    try:
        n = int(num)
    except ValueError:
        n = 99
    return (_SECTION_ORDER.index(sec) if sec in _SECTION_ORDER else 99, n)


@lru_cache(maxsize=1)
def _catalog() -> tuple[list, dict[str, set[str]], dict]:
    """(MOIS 항목 룰 목록, 항목→탐지 룰 id, 탐지 룰 id→Rule)."""
    from .loader import load_all_rules
    from .scanners.regex_scanner import RULES, _resolve_rules_dir

    rules = load_all_rules(_resolve_rules_dir())
    runtime_ids = {r["rule_id"] for r in RULES}
    items = sorted((r for r in rules if r.id.startswith(MOIS_PREFIX)), key=lambda r: _sort_key(r.id))
    detection = {r.id: r for r in rules
                 if not r.id.startswith(MOIS_PREFIX) and r.status != Status.deprecated and r.id in runtime_ids}
    mapping: dict[str, set[str]] = defaultdict(set)
    item_ids = {it.id for it in items}
    cwe_index: dict[str, set[str]] = defaultdict(set)
    for it in items:
        for c in it.cwe:
            cwe_index[c].add(it.id)
        for b in it.related_baseline:
            if b in detection:
                mapping[it.id].add(b)
    for rid, r in detection.items():
        for b in r.related_baseline:
            if b in item_ids:
                mapping[b].add(rid)
        for c in r.cwe:
            for it_id in cwe_index.get(c, ()):
                mapping[it_id].add(rid)
    return items, dict(mapping), detection


def rule_to_items() -> dict[str, list[str]]:
    """탐지 룰 id → 매핑된 MOIS 항목 id 목록."""
    _, mapping, _ = _catalog()
    out: dict[str, set[str]] = defaultdict(set)
    for item_id, rids in mapping.items():
        for rid in rids:
            out[rid].add(item_id)
    return {k: sorted(v, key=_sort_key) for k, v in out.items()}


def mois_result_table(report: ScanReport) -> dict:
    """``{"items": [...], "outside": [...], "unmapped_rules": [...]}`` — 억제된 발견은 세지 않는다."""
    items, mapping, _detection = _catalog()
    r2i = rule_to_items()
    active = [f for f in report.findings if not f.suppressed]
    per_item: dict[str, list] = defaultdict(list)
    outside: list = []
    for f in active:
        targets = r2i.get(f.rule_id) or ([f.rule_id] if f.rule_id.startswith(MOIS_PREFIX) else [])
        if not targets:
            outside.append(f)
            continue
        for t in targets:
            per_item[t].append(f)

    rows: list[dict] = []
    for it in items:
        fs = per_item.get(it.id, [])
        rules = sorted(mapping.get(it.id, set()))
        block = sum(1 for f in fs if f.decision == Decision.block)
        if fs:
            status = "발견"
        elif rules:
            status = "해당 발견 없음(안전 아님)"
        else:
            status = "자동 탐지 없음 — 사람 점검"
        sec = it.id[len(MOIS_PREFIX):].rpartition("-")[0]
        rows.append({
            "id": it.id, "section": _SECTION_KO.get(sec, sec), "title": it.title_ko, "cwe": list(it.cwe),
            "rules": rules, "findings": len(fs), "block": block, "warn": len(fs) - block,
            "files": len({f.location.file for f in fs}), "status": status,
        })

    by_cat: dict[str, dict] = {}
    for f in outside:
        cat = f.category or "uncategorized"
        slot = by_cat.setdefault(cat, {"category": cat, "label": _OUTSIDE_KO.get(cat, cat), "findings": 0, "block": 0,
                                       "rules": Counter()})
        slot["findings"] += 1
        slot["block"] += int(f.decision == Decision.block)
        slot["rules"][f.rule_id] += 1
    outside_rows = [{**v, "rules": sorted(v["rules"])} for v in sorted(by_cat.values(), key=lambda v: -v["findings"])]
    return {"items": rows, "outside": outside_rows,
            "summary": {"items": len(rows), "with_findings": sum(1 for r in rows if r["findings"]),
                        "no_detection": sum(1 for r in rows if r["status"].startswith("자동 탐지 없음")),
                        "outside_findings": len(outside)}}
