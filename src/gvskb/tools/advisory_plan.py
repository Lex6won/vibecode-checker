"""취약점 권고의 우선순위와 올릴 버전 계획 (K3, 2026-11-21).

무엇이 문제였나: 한 패키지에 권고가 수십~백여 건 나오는데 전부 같은 무게였고(mlflow 127건), 권고 중 하나라도 수정판을
모르면 권고 버전이 통째로 비었다(langflow·gradio·mlflow·litellm). 막기만 하고 무엇부터, 어디까지 올리면 되는지를 주지 못했다.

여기서는 판정을 바꾸지 않는다. 같은 권고를 **정렬**하고, 확정할 수 있는 만큼의 **올릴 버전**을 덧붙인다.
- 우선순위: 실제 악용(KEV) → 로그인 없이 원격에서 닿는 높음·치명(CVSS 벡터 AV:N · PR:N) → 높음·치명 → 그 밖.
- 올릴 버전: 수정판을 아는 권고들을 모두 넘는 버전과, 그 버전으로 해소되는 건수·수정판을 모르는 건수.
  '올리면 다 해결된다'는 말은 수정판을 전부 알 때만 한다(기존 recommended_version 의 뜻은 그대로다).
"""
from __future__ import annotations

from collections.abc import Callable

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3}
PRIORITY_ORDER = ("kev", "remote-unauth", "high", "other")


def cvss_remote_unauthenticated(vector: str | None) -> bool | None:
    """CVSS 벡터가 '네트워크에서, 권한 없이'인가. 벡터가 없거나 읽지 못하면 None(모름)."""
    if not vector or not str(vector).upper().startswith("CVSS:"):
        return None
    parts = dict(p.split(":", 1) for p in str(vector).upper().split("/")[1:] if ":" in p)
    if "AV" not in parts or "PR" not in parts:
        return None
    return parts["AV"] == "N" and parts["PR"] == "N"


def prioritize(rows: list[dict], kev_cves: set[str] | None = None) -> list[dict]:
    """권고 행에 in_kev · remote_unauthenticated · priority 를 붙이고 급한 순서로 정렬한 새 목록."""
    kev = {c.upper() for c in (kev_cves or set())}
    out: list[dict] = []
    for index, row in enumerate(rows):
        ids = {str(row.get("id") or "").upper(), *(str(a).upper() for a in row.get("aliases") or [])}
        in_kev = bool(ids & kev)
        remote = cvss_remote_unauthenticated(row.get("cvss_vector"))
        sev = _SEV_RANK.get(str(row.get("severity") or "").upper(), 4)
        if in_kev:
            priority = "kev"
        elif remote and sev <= 1:
            priority = "remote-unauth"
        elif sev <= 1:
            priority = "high"
        else:
            priority = "other"
        out.append(({**row, "in_kev": in_kev, "remote_unauthenticated": remote, "priority": priority},
                    (PRIORITY_ORDER.index(priority), sev, index)))
    return [row for row, _ in sorted(out, key=lambda pair: pair[1])]


def summarize(rows: list[dict]) -> dict:
    """정렬된 권고의 요약 — 보고서 머리와 하네스 영수증이 쓴다."""
    return {
        "total": len(rows),
        "kev": sum(1 for r in rows if r.get("priority") == "kev"),
        "remote_unauthenticated": sum(1 for r in rows if r.get("remote_unauthenticated") is True),
        "critical_high": sum(1 for r in rows if _SEV_RANK.get(str(r.get("severity") or "").upper(), 4) <= 1),
    }


def _issue_groups(rows: list[dict]) -> list[list[dict]]:
    """같은 취약점을 가리키는 권고(GHSA·PYSEC·CVE 별칭이 겹치는 것)를 한 묶음으로. 순서는 처음 나온 순서."""
    parent = list(range(len(rows)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[str, int] = {}
    for index, row in enumerate(rows):
        for key in {str(row.get("id") or "").upper(), *(str(a).upper() for a in row.get("aliases") or [])} - {""}:
            if key in seen:
                parent[find(index)] = find(seen[key])
            else:
                seen[key] = index
    groups: dict[int, list[dict]] = {}
    for index, row in enumerate(rows):
        groups.setdefault(find(index), []).append(row)
    return list(groups.values())


def upgrade_plan(
    rows: list[dict], current: str | None,
    target_of: Callable[[dict, str | None], str | None], highest: Callable[[list[str]], str | None],
) -> dict | None:
    """올릴 버전 계획. 권고가 없으면 None.

    같은 취약점의 권고는 한 건으로 센다(``issues``) — 한쪽 이름(PYSEC)에 수정판이 없어도 다른 이름(GHSA)에 있으면 아는 것이다.
    ``version`` 은 수정판을 아는 취약점을 모두 넘는 버전(하나도 모르면 None), ``resolves`` 는 그 버전으로 해소되는 건수,
    ``unfixed`` 는 수정판 정보가 없는 건수다. ``complete`` 가 참일 때만 '올리면 전부 해소'다.
    """
    if not rows:
        return None
    targets: list[str] = []
    unfixed: list[str] = []
    urgent_unfixed: list[str] = []
    groups = _issue_groups(rows)
    for group in groups:
        found = [t for t in (target_of(row, current) for row in group) if t is not None]
        if found:
            targets.append(highest(found) or found[0])
        else:
            first = str(group[0].get("id") or "")
            unfixed.append(first)
            if any(row.get("priority") in ("kev", "remote-unauth") for row in group):
                urgent_unfixed.append(first)
    version = highest(targets) if targets else None
    return {
        "version": version,
        "issues": len(groups),
        "resolves": len(targets),
        "unfixed": len(unfixed),
        "unfixed_ids": unfixed[:10],
        "urgent_unfixed_ids": urgent_unfixed[:10],
        "complete": not unfixed and version is not None,
    }
