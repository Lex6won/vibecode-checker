"""SBOM(CycloneDX JSON) → 사람이 읽는 HTML 보고서(설계 A3, 결정 D4).

보안담당자는 HTML 로 보고, JSON 은 표준 원본으로 함께 둔다. 이 모듈은 **원본에 있는 값만** 옮긴다 —
없는 값은 「원본 미기재」로 적고, 새로 조회·판정·보강하지 않는다. 미기재 하위 관계를 '의존성 없음'으로 쓰지 않는다.

한 파일로 열린다(외부 스크립트·스타일·글꼴·네트워크 0). 스크립트는 점진적 향상이라, 포털처럼 스크립트를
막는 환경에서도 패키지 목록·의존관계·취약점·원본 범위가 차례로 모두 보인다.
(발표 자료용 생성기 `outputs/build_sbom_html.py` 를 체커로 옮긴 것 — 표 구성·문구는 그것을 따른다.)
"""
from __future__ import annotations

import collections
import hashlib
import html
import json
import re
from typing import Any
from urllib.parse import quote

from .sbom_html_assets import SBOM_REPORT_CSS, SBOM_REPORT_JS

MISSING = "원본 미기재"
_RANK = {"critical": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2, "info": 1, "informational": 1, "none": 0, "unknown": -1}
_SEVERITY_KO = {"critical": "치명", "high": "높음", "medium": "보통", "moderate": "보통", "low": "낮음", "info": "정보",
                "informational": "정보", "none": "없음", "unknown": "미기재"}
_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "Cargo", "nuget": "NuGet",
              "gem": "RubyGems", "composer": "Composer"}
_AREA_KO = {"frontend": "프런트엔드", "backend": "백엔드", "runtime": "실행환경", "unknown": "미기재"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _props(item: dict) -> dict[str, str]:
    return {p.get("name", ""): p.get("value", "") for p in item.get("properties") or [] if isinstance(p, dict)}


def _prop(props: dict, *keys: str) -> str | None:
    return next((props[k] for k in keys if props.get(k) not in (None, "")), None)


def _truth(value: Any) -> bool:
    return str(value).lower() == "true"


def _safe_url(value: Any) -> str:
    return value if isinstance(value, str) and re.match(r"^https?://", value, re.I) else ""


def _links(values: list[tuple[str, str]]) -> str:
    out = [f'<a href="{_h(url)}" target="_blank" rel="noopener noreferrer">{_h(label)}</a>' for url, label in values if _safe_url(url)]
    return "<br>".join(out) or f'<span class="missing">{MISSING}</span>'


def _organization(value: Any) -> str | None:
    if isinstance(value, dict):
        return value.get("name") or value.get("url")
    return value if isinstance(value, str) else None


def _severity(vuln: dict) -> str:
    ratings = vuln.get("ratings") or []
    return max((str(r.get("severity", "unknown")).lower() for r in ratings), key=lambda s: _RANK.get(s, -1), default="unknown")


def _severity_badge(sev: str) -> str:
    return f'<span class="badge sev-{_h(sev)}">{_h(_SEVERITY_KO.get(sev, sev))}</span>'


def _ecosystem(purl: str) -> str:
    match = re.match(r"^pkg:([a-z0-9.+-]+)/", purl or "", re.I)
    return _ECOSYSTEM.get(match.group(1).lower(), match.group(1)) if match else "미기재"


def render_sbom_html(doc: dict, *, source_name: str, source_sha256: str) -> str:
    """CycloneDX 문서(dict) → 한 파일 HTML 문자열. ``source_name`` 은 같은 폴더의 원본 JSON 파일 이름."""
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("CycloneDX JSON 이 필요합니다")
    metadata = doc.get("metadata") or {}
    meta_props = _props(metadata)
    root_component = metadata.get("component") or {}
    root_ref = root_component.get("bom-ref")
    root_name = root_component.get("name") or "대상 프로그램 미기재"
    components = [c for c in doc.get("components") or [] if isinstance(c, dict)]
    by_ref = {c.get("bom-ref"): c for c in components if c.get("bom-ref")}
    vulnerabilities = [v for v in doc.get("vulnerabilities") or [] if isinstance(v, dict)]

    vulns_by_ref: dict[str, list[dict]] = collections.defaultdict(list)
    for vuln in vulnerabilities:
        for affect in vuln.get("affects") or []:
            if affect.get("ref"):
                vulns_by_ref[affect["ref"]].append(vuln)

    graph: dict[str, list[str]] = {}
    parents: dict[str, list[str]] = collections.defaultdict(list)
    edges: list[tuple[str, str]] = []
    seen_edges: set[tuple[str, str]] = set()
    for dep in doc.get("dependencies") or []:
        graph.setdefault(dep.get("ref"), [])
        for child in dep.get("dependsOn") or []:
            pair = (dep.get("ref"), child)
            if pair in seen_edges:
                continue
            seen_edges.add(pair)
            edges.append(pair)
            graph[dep.get("ref")].append(child)
            parents[child].append(dep.get("ref"))
    depth = {root_ref: 0} if root_ref else {}
    queue = collections.deque(depth)
    while queue:
        node = queue.popleft()
        for child in graph.get(node, []):
            if child not in depth:
                depth[child] = depth[node] + 1
                queue.append(child)

    def label(ref: str | None) -> str:
        if ref == root_ref:
            return root_name
        c = by_ref.get(ref)
        return f'{c.get("name", "미기재")} {c.get("version", "버전 미기재")}' if c else str(ref or "참조 미기재")

    rows: list[dict] = []
    for i, c in enumerate(components):
        ref = c.get("bom-ref") or f"component:{i}"
        props = _props(c)
        purl = c.get("purl") or ""
        licenses = []
        for lic in c.get("licenses") or []:
            if lic.get("expression"):
                licenses.append(lic["expression"])
            elif isinstance(lic.get("license"), dict):
                licenses.append(lic["license"].get("id") or lic["license"].get("name") or "")
        declared = _prop(props, "gvskb:dependency_kind")
        kind = "direct" if root_ref in parents.get(ref, []) else "indirect" if (depth.get(ref) or 0) > 1 else "unknown"
        found = vulns_by_ref.get(ref, [])
        sev = max((_severity(v) for v in found), key=lambda s: _RANK.get(s, -1), default="unknown")
        raw_verdict = _prop(props, "gvskb:verdict")
        checked = _prop(props, "gvskb:checked")
        review = _truth(_prop(props, "gvskb:requires_review"))
        malicious = raw_verdict == "malicious" or _truth(_prop(props, "gvskb:is_malicious_package"))
        possible = _prop(props, "gvskb:malicious_possible")
        status = ("malicious" if malicious else "vulnerable" if found
                  else "review" if review or possible or not _truth(checked) else "no-recorded-vulnerability")
        origin_refs = [(r.get("url"), r.get("type", "출처")) for r in c.get("externalReferences") or []
                       if r.get("type") in ("distribution", "vcs", "website", "source-distribution", "documentation")]
        origin = _prop(props, "gvskb:source_registry", "gvskb:registry_url")
        if origin:
            origin_refs.insert(0, (origin, "배포 출처"))
        area = _prop(props, "gvskb:area", "gvskb:component_area")
        rows.append({
            "index": i + 1, "ref": ref, "name": c.get("name") or MISSING, "version": c.get("version") or MISSING,
            "ecosystem": _ecosystem(purl), "type": c.get("type") or MISSING,
            "area": _AREA_KO.get(area, area) or MISSING,
            "kind": kind, "kind_text": {"direct": "직접", "indirect": "간접", "unknown": "관계 미확인"}[kind],
            "declared_kind": {"direct": "직접", "indirect": "간접", "unknown": "미확인"}.get(declared, declared),
            "parent_refs": parents.get(ref, []),
            "parents": " / ".join(label(x) for x in parents.get(ref, [])) or MISSING,
            "licenses": " / ".join(x for x in licenses if x) or MISSING,
            "supplier": _organization(c.get("supplier")) or MISSING,
            "origin_refs": origin_refs, "hashes": c.get("hashes") or [], "purl": purl or MISSING,
            "status": status,
            "status_text": ("악성 패키지" if malicious else "취약점 기록 있음" if found else "악성 권고 — 확인 필요" if possible
                            else "검토 필요" if status == "review" else "확인된 취약점 기록 없음"),
            "vulnerability_count": len(found), "severity": sev, "severity_rank": _RANK.get(sev, -1),
            "recommended": _prop(props, "gvskb:recommended_version") or MISSING,
            "raw_verdict": raw_verdict or MISSING, "checked": _truth(checked), "review": review,
            "vuln_ids": [v.get("id", "미기재") for v in found],
            "vuln_search": " ".join(f'{v.get("id", "")} {v.get("description", "")} '
                                    + " ".join(_CVE_RE.findall(json.dumps(v.get("advisories") or []))) for v in found),
        })
    by_row = {r["ref"]: r for r in rows}
    direct = sum(r["kind"] == "direct" for r in rows)
    indirect = sum(r["kind"] == "indirect" for r in rows)
    affected = sum(bool(r["vulnerability_count"]) for r in rows)
    known_refs = set(by_ref) | ({root_ref} if root_ref else set())
    dangling = [(a, b) for a, b in edges if a not in known_refs or b not in known_refs]
    duplicate_refs = len([c for c in components if c.get("bom-ref")]) - len(by_ref)

    def attrs(r: dict, extra: str = "", *, with_parents: bool = True) -> str:
        # 관계 표는 행마다 상위 목록을 또 실으면 공통 의존 패키지에서 크기가 제곱으로 는다(n=5000 에 361MB, 실측).
        keys = ("name", "version", "ecosystem", "area", "kind_text", *(("parents",) if with_parents else ()), "licenses",
                "supplier", "purl", "status_text", "recommended", "raw_verdict", "vuln_search")
        search = " ".join(str(r.get(k, "")) for k in keys)
        return (f'data-search="{_h((search + " " + extra).lower())}" data-ecosystem="{_h(r["ecosystem"])}" data-status="{_h(r["status"])}" '
                f'data-kind="{_h(r["kind"])}" data-name="{_h(str(r["name"]).lower())}" data-count="{r["vulnerability_count"]}" '
                f'data-severity="{r["severity_rank"]}"')

    package_rows = []
    for r in rows:
        hashes = "<br>".join(_h(h.get("alg", "해시")) + ": " + _h(h.get("content", "")) for h in r["hashes"]) \
            or '<span class="missing">구성요소 해시 미기재</span>'
        status = f'<span class="badge state-{r["status"]}">{_h(r["status_text"])}</span>'
        risk = (f'<b>{r["vulnerability_count"]}건</b> ' + _severity_badge(r["severity"])) if r["vulnerability_count"] \
            else "<small>취약점 미기록 ≠ 안전 보증</small>"
        package_rows.append(
            f'<tr {attrs(r)}><td class="row-no">{r["index"]}</td><td><button class="package-button" data-component="{_h(r["ref"])}">'
            f'{_h(r["name"])}</button><strong class="version">{_h(r["version"])}</strong><small>{_h(r["type"])}</small></td>'
            f'<td>{_h(r["ecosystem"])}<small>구성영역: {_h(r["area"])}</small></td>'
            f'<td><span class="badge kind">{_h(r["kind_text"])}</span><small>{_h(r["parents"])}</small></td>'
            f'<td>{_h(r["licenses"])}</td><td><span>{_h(r["supplier"])}</span><small>{_links(r["origin_refs"])}</small></td>'
            f'<td>{status}<div class="risk-line">{risk}</div><small>원본 결과: {_h(r["raw_verdict"])}</small></td>'
            f'<td>{_h(r["recommended"])}</td><td class="identity"><code>{_h(r["purl"])}</code><details><summary>무결성·식별 상세</summary>'
            f'<small>bom-ref: {_h(r["ref"])}</small><small>{hashes}</small></details></td></tr>')

    dependency_rows = []
    for a, b in edges:
        r = by_row.get(b, {"name": label(b), "ecosystem": "미기재", "status": "review", "kind": "unknown",
                           "vulnerability_count": 0, "severity_rank": -1})
        dependency_rows.append(
            f'<tr {attrs(r, label(a) + " " + label(b), with_parents=False)}><td>{_h(label(a))}</td><td><button class="package-button" data-component="{_h(b)}">'
            f'{_h(label(b))}</button></td><td>{"프로그램의 직접 사용" if a == root_ref else "원본에 기재된 패키지 의존"}</td>'
            f'<td>{"참조 확인" if a in known_refs and b in known_refs else "참조 미확인"}</td></tr>')

    vuln_rows = []
    for vuln in vulnerabilities:
        sev = _severity(vuln)
        refs = [a.get("ref") for a in vuln.get("affects") or []]
        names = " / ".join(label(ref) for ref in refs)
        base = by_row.get(refs[0] if refs else None, {"name": names, "ecosystem": "미기재", "status": "vulnerable", "kind": "unknown",
                                                         "vulnerability_count": 1, "severity_rank": _RANK.get(sev, -1)})
        r = {**base, "severity_rank": _RANK.get(sev, -1), "vuln_search": ""}
        source = vuln.get("source") or {}
        url = _safe_url(source.get("url"))
        identifier = vuln.get("id", MISSING)
        cves = sorted(set(_CVE_RE.findall(json.dumps(vuln.get("advisories") or []))))
        vid = f'<a href="{_h(url)}" target="_blank" rel="noopener noreferrer">{_h(identifier)}</a>' if url else _h(identifier)
        score = " / ".join(str(x["score"]) for x in vuln.get("ratings") or [] if x.get("score") is not None) or "점수 미기재"
        vuln_rows.append(
            f'<tr {attrs(r, identifier + " " + " ".join(cves) + " " + str(vuln.get("description", "")))}><td>{vid}<small>{_h(" / ".join(cves))}</small></td>'
            f'<td>{_h(names)}</td><td>{_severity_badge(sev)}<small>{_h(score)}</small></td><td>{_h(vuln.get("description", MISSING))}</td>'
            f'<td>{_h(vuln.get("recommendation", MISSING))}</td><td>{_h(source.get("name", MISSING))}</td></tr>')

    height = max(470, len(rows) * 67 + 35)
    root_y = height / 2
    svg = [f'<svg viewBox="0 0 650 {height}" role="img" aria-label="원본에 기록된 프로젝트와 직접 의존 패키지 관계"><defs>'
           '<marker id="dep-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto">'
           '<path d="M0 0 10 5 0 10Z" fill="#839eaf"/></marker></defs>']
    for i, r in enumerate(rows):
        y = 30 + i * 67
        if root_ref in r["parent_refs"]:
            svg.append(f'<path class="edge" d="M220 {root_y} C300 {root_y},260 {y + 23},330 {y + 23}"/>')
        color = "#b64838" if r["vulnerability_count"] else "#866018"
        svg.append(f'<g class="dependency-node" data-component="{_h(r["ref"])}" tabindex="0" role="button" aria-label="{_h(r["name"])} 상세">'
                   f'<rect x="335" y="{y}" width="295" height="48" rx="9" fill="#fff" stroke="{color}"/>'
                   f'<circle cx="350" cy="{y + 24}" r="4" fill="{color}"/><text x="364" y="{y + 20}">{_h(r["name"])}</text>'
                   f'<text class="graph-small" x="364" y="{y + 38}">{_h(r["version"])} · {_h(r["kind_text"])} · 취약점 {r["vulnerability_count"]}건</text></g>')
    svg.append(f'<rect class="root-node" x="15" y="{root_y - 47}" width="205" height="94" rx="13"/>'
               f'<text class="root-caption" x="118" y="{root_y - 12}">대상 프로그램</text>'
               f'<text class="root-label" x="118" y="{root_y + 17}">{_h(root_name)}</text></svg>')

    tools = metadata.get("tools")
    tool_list = tools.get("components", []) if isinstance(tools, dict) else tools if isinstance(tools, list) else []
    metadata_rows = [
        ("대상 프로그램", root_name), ("대상 버전", root_component.get("version") or MISSING),
        ("형식", f'{doc.get("bomFormat")} {doc.get("specVersion")}'), ("문서 식별자", doc.get("serialNumber") or MISSING),
        ("생성 시각 (원본)", metadata.get("timestamp") or MISSING),
        ("생성 도구", " / ".join(f'{t.get("name", "")} {t.get("version", "")}'.strip() for t in tool_list if isinstance(t, dict)) or MISSING),
        ("룰셋 버전", meta_props.get("gvskb:ruleset_version") or MISSING), ("룰셋 지문", meta_props.get("gvskb:ruleset_digest") or MISSING),
        ("원본 파일 SHA-256", source_sha256), ("관계 해석 근거", meta_props.get("gvskb:dependency_graph_basis") or MISSING),
    ]
    missing_fields = [
        ("버전", sum(r["version"] == MISSING for r in rows)), ("구성영역", sum(r["area"] == MISSING for r in rows)),
        ("라이선스", sum(r["licenses"] == MISSING for r in rows)), ("공급자", sum(r["supplier"] == MISSING for r in rows)),
        ("배포 출처", sum(not r["origin_refs"] for r in rows)), ("구성요소 해시", sum(not r["hashes"] for r in rows)),
    ]
    beyond_root = any(a != root_ref for a, _ in edges)
    scope = ("의존관계는 원본 dependencies 에 기록된 항목만 표시합니다. 미기재 하위 관계를 의존성 없음으로 판단하지 않습니다."
             if beyond_root else
             "원본에는 프로젝트의 직접 관계만 기재되어 있습니다. 간접 의존관계는 미기재입니다. 락파일·실제 설치 구성 기반 SBOM이 있어야 범위를 더 확인할 수 있습니다.")
    ecosystems = sorted({r["ecosystem"] for r in rows})
    eco_counts = " · ".join(f'{e} {sum(r["ecosystem"] == e for r in rows)}' for e in ecosystems) or "구성요소 없음"
    payload = {"components": rows, "metadata": metadata_rows, "root_ref": root_ref, "root_name": root_name,
               "dependencies": [{"parent": a, "child": b} for a, b in edges], "original": source_name, "source_sha256": source_sha256}
    data_json = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")

    def th(text: str, key: str | None = None, numeric: bool = False) -> str:
        if key:
            return f'<th><button data-sort="{_h(key)}" data-numeric="{str(numeric).lower()}">{_h(text)} ↕</button></th>'
        return f"<th>{_h(text)}</th>"

    nojs = '<p class="nojs-note">이 화면에서는 탭·검색이 꺼져 있어 모든 표를 차례로 보여 줍니다. 파일을 내려받아 열면 탭·검색·정렬·상세 보기가 켜집니다.</p>'
    return f'''<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SBOM 구성요소·의존관계 보고서 | {_h(root_name)}</title><style>{SBOM_REPORT_CSS}</style></head><body>
<header class="topbar"><div><span class="eyebrow">SBOM REVIEW</span><h1>패키지와 의존관계,<br>한눈에 확인합니다.</h1><p>{_h(root_name)} · CycloneDX {_h(doc.get("specVersion"))} · 원본 데이터 기반 보기</p></div><div class="top-actions"><button id="print-report">인쇄 / PDF</button><button id="csv-export">패키지 CSV ↓</button><a href="{_h(quote(source_name))}" download>SBOM JSON ↓</a></div></header>
<main><div class="sample-note"><b>SBOM 열람용</b> 체커가 만든 SBOM 원본(JSON)을 사람이 읽기 쉽게 옮겼습니다. 값과 권고 버전은 원본 생성 시점의 정보이며, 이 화면에서 새로 조회·판정하지 않습니다.</div>
{nojs}
<div class="stats"><article><span>구성요소</span><b>{len(rows)}<small>개</small></b><p>{_h(eco_counts)}</p></article><article><span>취약점 기록</span><b>{len(vulnerabilities)}<small>건</small></b><p>영향 구성요소 {affected}개 · 원본 레코드 기준</p></article><article><span>기록된 의존관계</span><b>{len(edges)}<small>건</small></b><p>직접 {direct}개 · 간접 {indirect}개 기재</p></article><article><span>추가 확인</span><b>{sum(r["review"] or not r["checked"] for r in rows)}<small>개</small></b><p>원본의 검토 필요·미검사 표시 기준</p></article></div>
<div class="scope-note"><b>관계 범위</b><span>{_h(scope)}</span></div>
<nav class="tabs" role="tablist" aria-label="SBOM 보기"><button role="tab" id="tab-packages" aria-controls="pane-packages" data-tab="packages" aria-selected="true">패키지 목록 <span>{len(rows)}</span></button><button role="tab" id="tab-dependencies" aria-controls="pane-dependencies" data-tab="dependencies" aria-selected="false">의존관계 <span>{len(edges)}</span></button><button role="tab" id="tab-vulnerabilities" aria-controls="pane-vulnerabilities" data-tab="vulnerabilities" aria-selected="false">취약점 <span>{len(vulnerabilities)}</span></button><button role="tab" id="tab-provenance" aria-controls="pane-provenance" data-tab="provenance" aria-selected="false">원본·확인 범위</button></nav>
<div class="filters" id="filters"><label class="search">검색<input id="search" type="search" placeholder="패키지명 · 버전 · 취약점 ID · 설명" autocomplete="off"></label><label>생태계<select id="ecosystem"><option value="">전체</option>{"".join(f"<option>{_h(e)}</option>" for e in ecosystems)}</select></label><label>보안정보<select id="risk"><option value="">전체</option><option value="malicious">악성 패키지</option><option value="vulnerable">취약점 기록 있음</option><option value="review">검토 필요</option><option value="no-recorded-vulnerability">취약점 미기록</option></select></label><button id="reset-filters">초기화</button><span id="visible-count" aria-live="polite"></span></div>
<section id="pane-packages" class="pane" role="tabpanel" aria-labelledby="tab-packages"><div class="section-intro"><h2>패키지 목록</h2><p>원본에 없는 정보는 미기재로 표시합니다.</p></div><div class="table-wrap"><table id="package-table"><caption>SBOM 구성요소 상세 목록</caption><thead><tr>{th("No.")}{th("패키지 · 버전", "name")}{th("생태계 · 구성영역")}{th("의존분류 · 상위")}{th("라이선스")}{th("공급자 · 출처")}{th("보안정보", "count", True)}{th("원본 권고 버전")}{th("식별 · 무결성")}</tr></thead><tbody>{"".join(package_rows)}</tbody></table></div><p class="table-foot">직접·간접 분류는 프로그램 루트에서의 기록된 관계를 기준으로 합니다. 생태계는 PURL로 구분하며 구성영역·배포 출처를 생태계로 추정하지 않습니다.</p><p id="empty-packages" class="empty" hidden>검색 조건에 맞는 패키지가 없습니다.</p></section>
<section id="pane-dependencies" class="pane" role="tabpanel" aria-labelledby="tab-dependencies"><div class="section-intro"><h2>구성요소 의존관계</h2><p>원본에 기록된 연결만 그렸습니다. 패키지의 하위 관계가 미기재된 경우, 하위 의존성이 없다는 뜻은 아닙니다.</p></div><div class="dependency-layout"><div class="graph-panel"><h3>프로그램 → 직접 의존 패키지</h3>{"".join(svg)}<p class="graph-caption">선은 원본에 기록된 관계</p></div><div class="relation-panel"><h3>의존관계 표</h3><div class="table-wrap"><table id="dependency-table"><caption>상위·하위 패키지 관계</caption><thead><tr>{th("상위 구성요소")}{th("하위 구성요소", "name")}{th("관계 설명")}{th("참조 상태")}</tr></thead><tbody>{"".join(dependency_rows)}</tbody></table></div><p class="table-foot">원본의 관계 데이터에 대한 참조 확인입니다. 코드 실행·설치·실제 동작 검증을 뜻하지 않습니다.</p></div></div><p id="empty-dependencies" class="empty" hidden>검색 조건에 맞는 관계가 없습니다.</p></section>
<section id="pane-vulnerabilities" class="pane" role="tabpanel" aria-labelledby="tab-vulnerabilities"><div class="section-intro"><h2>패키지 취약점 기록</h2><p>동일 CVE의 별도 자문 기록이 있을 수 있습니다. 건수는 원본 레코드 수이며 중복된 피해·사건 수를 뜻하지 않습니다.</p></div><div class="table-wrap"><table id="vulnerability-table"><caption>취약점 ID·영향 구성요소·심각도·권고</caption><thead><tr>{th("취약점 ID / CVE")}{th("영향 구성요소", "name")}{th("최고 심각도", "severity", True)}{th("원본 설명")}{th("원본 권고")}{th("근거 정보원")}</tr></thead><tbody>{"".join(vuln_rows)}</tbody></table></div><p id="empty-vulnerabilities" class="empty" {"" if not vuln_rows else "hidden"}>{"원본에 취약점 기록이 없습니다(취약점 미기록 ≠ 안전 보증)." if not vuln_rows else "검색 조건에 맞는 취약점이 없습니다."}</p></section>
<section id="pane-provenance" class="pane" role="tabpanel" aria-labelledby="tab-provenance"><div class="section-intro"><h2>원본과 확인 범위</h2><p>변환 과정에서 자료를 보강하거나 보안 적합 여부를 새로 판정하지 않았습니다.</p></div><div class="provenance-grid"><div><h3>식별·생성 근거</h3><table class="metadata-table"><tbody>{"".join(f"<tr><th>{_h(k)}</th><td>{_h(v)}</td></tr>" for k, v in metadata_rows)}</tbody></table></div><div><h3>원본 필드 기재 상태</h3><table class="metadata-table"><thead><tr><th>필드</th><th>미기재 구성요소</th></tr></thead><tbody>{"".join(f"<tr><td>{_h(k)}</td><td>{n} / {len(rows)}</td></tr>" for k, n in missing_fields)}</tbody></table><h3 class="subheading">이번 변환에서 확인한 것</h3><ul><li>JSON 읽기와 CycloneDX 형식 표기</li><li>구성요소 참조 중복: {duplicate_refs}건</li><li>기록된 관계의 미식별 참조: {len(dangling)}건</li><li>직접·간접 분류와 취약점의 대상 연결</li></ul><p class="scope-detail">CycloneDX 전체 스키마 적합성, 라이선스 정책 적합성, 배포 출처·해시 진위, 실제 설치 구성은 이 변환에서 검증하지 않았습니다.</p></div></div></section>
<footer>원본: {_h(source_name)} · 구성요소 해시와 원본 JSON 파일 해시는 별개입니다.<br>이 보고서는 SBOM 열람용이며 기관의 사용 승인·보안성검토 결과를 발급하지 않습니다.</footer></main>
<dialog id="component-dialog"><div class="dialog-head"><div><small>COMPONENT DETAIL</small><h2 id="component-title"></h2></div><button id="close-component" aria-label="구성요소 상세 닫기">닫기 ×</button></div><div id="component-content"></div></dialog>
<script id="sbom-data" type="application/json">{data_json}</script><script>{SBOM_REPORT_JS}</script></body></html>'''


def render_sbom_html_file(sbom_path, output_path=None) -> str:
    """파일 → 파일. 반환값은 출력 경로. 출력 이름 기본값은 ``<stem>.sbom.html``(``.sbom.cdx.json`` 을 바꾼다)."""
    from pathlib import Path

    source = Path(sbom_path)
    raw = source.read_bytes()
    doc = json.loads(raw.decode("utf-8-sig"))
    if output_path is None:
        name = source.name
        stem = name[: -len(".sbom.cdx.json")] if name.endswith(".sbom.cdx.json") else source.stem
        output_path = source.with_name(f"{stem}.sbom.html")
    out = Path(output_path)
    if out.resolve() == source.resolve():
        raise ValueError("출력 경로가 원본 SBOM 과 같습니다 — 원본을 덮어쓸 수 없습니다.")
    try:
        rendered = render_sbom_html(doc, source_name=source.name, source_sha256=hashlib.sha256(raw).hexdigest())
    except (AttributeError, KeyError, TypeError) as exc:
        raise ValueError(f"CycloneDX 구조가 예상과 다릅니다: {exc}") from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    return str(out)
