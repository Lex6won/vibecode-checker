"""벤더링된 프런트엔드 라이브러리(``*.min.js``) 식별 — 컴포넌트 취약점 검사용.

**왜 필요한가.** 이전에는 파일명에 ``.min.`` 이 들어가면 '빌드 산출물'로 보고 조용히
제외했다. 그런데 ``static/`` 에 직접 떨궈진 ``*.min.js`` 는 빌드 출력이 아니라
**벤더링된 서드파티 라이브러리**다. 매니페스트(``package.json``)도 ``node_modules``
도 없는 프로젝트에서는 SCA 발견 경로가 하나도 걸리지 않아 *아무도 그 파일을 보지
않는* 상태가 된다.

실측(공공 Flask 프로젝트, 2026-08-03): ``static/xlsx.full.min.js`` 는 SheetJS ``xlsx 0.18.5`` 로,
CVE-2023-30533(Prototype Pollution, HIGH)·CVE-2024-22363(ReDoS, HIGH)에 해당한다.
게다가 템플릿이 사용자가 고른 엑셀을 ``XLSX.read()`` 로 파싱하므로 advisory 가 명시한
취약 경로에 **실제로 도달한다**. 오탐을 피하려던 규칙이 진짜 취약 컴포넌트를 가린 것이라
설계 결함이다.

**설계 원칙.** 추측해서 단정하지 않는다. 버전을 확신할 수 없으면 ``version=None`` 으로
두고 호출측이 '판정 불가'로 남기게 한다 — 조용히 빼는 것보다 낫고, 틀린 버전으로
취약점을 단정하는 것보다도 낫다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# 파일명에서 떼어낼 배포 형태 꼬리표. ``xlsx.full.min.js`` → ``xlsx``
_DIST_TOKENS = (
    "min", "full", "slim", "bundle", "umd", "esm", "cjs", "iife",
    "prod", "production", "dev", "development", "common", "core", "all",
)

# 파일명에 버전이 박힌 형태: jquery-3.6.0.min.js · vue@2.6.14.js
_FILENAME_VER_RE = re.compile(
    # 프리릴리스는 '-' 로만 붙는다. '.' 까지 허용하면 jquery-3.6.0.min.js 의
    # `.min` 까지 버전으로 먹는다(실측).
    r"^(?P<name>[A-Za-z][\w.\-]*?)[-@_]v?(?P<ver>\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)"
    r"(?P<rest>(?:\.(?:" + "|".join(_DIST_TOKENS) + r"))*)\.js$",
    re.IGNORECASE,
)

# 선두 배너 주석: /*! jQuery v3.6.0 | (c) ... */  ·  /*! xlsx.js (C) SheetJS */
_BANNER_VER_RE = re.compile(r"v(?:ersion)?[\s:]*(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)", re.IGNORECASE)

# 라이브러리 자기 버전 대입: e.version="0.18.5"
_VER_ASSIGN_RE = re.compile(r"\.version\s*=\s*[\"'](\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)[\"']")

# 이름 토큰이 대입 앞쪽 이 범위 안에 있으면 "그 라이브러리 자신의 버전"으로 본다.
# xlsx.full.min.js 실측: `var XLSX={};function make_xlsx_lib(e){e.version="0.18.5"`
# 반면 번들된 하위 라이브러리(SSF 1.2.0 · CFB 1.2.1)는 `var Ye=function(){var e={};
# e.version="1.2.0"` 처럼 이름 토큰이 없다 — 이 차이로 갈린다.
_NAME_CONTEXT_WINDOW = 200

_BANNER_SCAN_BYTES = 500


@dataclass(frozen=True)
class VendorBundle:
    """식별 결과. ``version`` 이 None 이면 '이름은 알지만 버전 미상'이다."""

    path: str
    name: str
    version: str | None
    evidence: str          # 어디서 알아냈는지 — 사람이 검증할 수 있게 남긴다
    ecosystem: str = "npm"
    name_candidates: tuple[str, ...] = ()   # 레지스트리로 검증할 이름 후보(우선순위 순)

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "version": self.version,
            "evidence": self.evidence,
            "ecosystem": self.ecosystem,
            "name_candidates": list(self.name_candidates or (self.name,)),
        }


def _strip_dist_tokens(stem: str) -> str:
    """``xlsx.full.min`` → ``xlsx``. 배포 형태 꼬리표만 떼고 이름은 보존한다."""
    parts = stem.split(".")
    while len(parts) > 1 and parts[-1].lower() in _DIST_TOKENS:
        parts.pop()
    return ".".join(parts)


def component_name_from_filename(filename: str) -> str:
    """파일명에서 컴포넌트 이름을 추정한다(확장자·배포꼬리표·버전 제거)."""
    base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    m = _FILENAME_VER_RE.match(base)
    if m:
        return _strip_dist_tokens(m.group("name")).strip("-_.")
    stem = base[:-3] if base.lower().endswith(".js") else base
    return _strip_dist_tokens(stem).strip("-_.")


def _version_from_filename(filename: str) -> str | None:
    base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    m = _FILENAME_VER_RE.match(base)
    if not m:
        return None
    # 점을 쓰는 프리릴리스(`-beta.1`)는 뒤따르는 `.min` 까지 함께 먹으므로 다시 뗀다.
    return _strip_dist_tokens(m.group("ver"))


def _version_from_banner(text: str, name: str) -> str | None:
    """선두 배너 주석에서 버전을 읽는다 — 이름이 함께 있을 때만 신뢰한다."""
    head = text[:_BANNER_SCAN_BYTES]
    if not head.lstrip().startswith("/*"):
        return None
    end = head.find("*/")
    banner = head[: end if end != -1 else len(head)]
    if name.lower() not in banner.lower():
        return None
    m = _BANNER_VER_RE.search(banner)
    return m.group(1) if m else None


def _version_from_self_assignment(text: str, name: str) -> str | None:
    """``x.version="..."`` 중 **이름 토큰이 인접한** 것만 자기 버전으로 채택한다.

    후보가 여러 개면 단정하지 않고 None 을 돌려준다(추측 금지).
    """
    token = re.sub(r"[^a-z0-9]", "", name.lower())
    if not token:
        return None
    hits: set[str] = set()
    for m in _VER_ASSIGN_RE.finditer(text):
        start = max(0, m.start() - _NAME_CONTEXT_WINDOW)
        context = re.sub(r"[^a-z0-9]", "", text[start:m.start()].lower())
        if token in context:
            hits.add(m.group(1))
    return next(iter(hits)) if len(hits) == 1 else None


# 배너에서 라이브러리 이름을 뽑는다: `/*! Chart.js v3.9.1 */` → `Chart.js`
_BANNER_NAME_RE = re.compile(r"^[\s/*!]*([A-Za-z][\w.\-]{1,40})", re.MULTILINE)


def banner_name_candidates(text: str, filename_name: str) -> tuple[str, ...]:
    """레지스트리로 검증할 이름 후보를 우선순위 순으로 만든다.

    파일명만 믿으면 틀린다 — 실측: `chart.min.js` 는 **Chart.js** 인데 파일명 기준
    이름은 `chart` 이고, npm 의 `chart` 는 전혀 다른 패키지다(최신 0.1.2). 그대로
    조회하면 "이상 없음"이 나와 **조용한 초록불**이 된다. 배너가 선언한 이름
    (`Chart.js` → `chart.js`)을 후보에 넣어 레지스트리가 고르게 한다.
    """
    cands: list[str] = []

    head = text[:_BANNER_SCAN_BYTES]
    if head.lstrip().startswith("/*"):
        end = head.find("*/")
        banner = head[: end if end != -1 else len(head)]
        m = _BANNER_NAME_RE.search(banner)
        if m:
            raw = m.group(1).strip(".-_")
            for cand in (raw.lower(), _strip_dist_tokens(raw.lower())):
                if cand and cand not in cands:
                    cands.append(cand)

    for cand in (filename_name.lower(), _strip_dist_tokens(filename_name.lower())):
        if cand and cand not in cands:
            cands.append(cand)
    return tuple(cands)


def identify_vendor_bundle(path: str, text: str) -> VendorBundle:
    """벤더 번들 1건을 식별한다. 버전을 확신할 수 없으면 ``version=None``.

    ``path`` 는 리포트에 실릴 상대경로, ``text`` 는 파일 내용(전체 또는 충분히 긴 앞부분).
    """
    name = component_name_from_filename(path)
    cands = banner_name_candidates(text, name)

    ver = _version_from_filename(path)
    if ver:
        return VendorBundle(path=path, name=name, version=ver,
                            evidence="파일명에 버전 표기", name_candidates=cands)

    ver = _version_from_banner(text, name)
    if ver:
        return VendorBundle(path=path, name=name, version=ver,
                            evidence="선두 배너 주석", name_candidates=cands)

    ver = _version_from_self_assignment(text, name)
    if ver:
        return VendorBundle(
            path=path, name=name, version=ver,
            evidence=f"본문 `{name}.version` 대입", name_candidates=cands,
        )

    return VendorBundle(path=path, name=name, version=None,
                        evidence="버전 표기를 찾지 못함", name_candidates=cands)


async def resolve_npm_component(
    candidates: list[str] | tuple[str, ...],
    version: str,
    *,
    timeout: float = 10.0,
) -> tuple[str | None, str]:
    """후보 이름 중 **그 버전이 실제로 존재하는** npm 패키지를 고른다.

    반환 ``(이름 | None, 상태)``. 상태는 ``verified`` · ``no_match`` · ``unverified``.
    ``unverified`` 는 오프라인·통신 실패로 확인하지 못한 것이며 **'맞다'는 뜻이 아니다.**
    """
    import os

    import httpx

    if os.environ.get("GVSKB_MODE", "").lower() == "offline":
        return (candidates[0] if candidates else None), "unverified"

    unreachable = False
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for name in candidates:
            try:
                resp = await client.get(f"https://registry.npmjs.org/{name}")
            except httpx.HTTPError:
                unreachable = True
                continue
            if resp.status_code != 200:
                continue
            try:
                versions = (resp.json() or {}).get("versions") or {}
            except ValueError:
                unreachable = True
                continue
            if version in versions:
                return name, "verified"
    if unreachable:
        return (candidates[0] if candidates else None), "unverified"
    return None, "no_match"


async def audit_vendor_bundles(
    bundles: list[dict],
    *,
    env_grade: str | None = None,
) -> dict:
    """식별된 벤더 번들을 npm 컴포넌트로 취약점 검사한다 → audit dict 1건.

    버전이 확정된 것만 조회하고, **버전 미상은 '판정 불가'로 남긴다**(추측 금지).
    CLI(`--check-deps`)와 MCP(`scan_vendor_bundles`)가 같은 경로를 쓰도록 여기 둔다.
    """
    from .check_package import audit_manifest
    from .installed_packages import to_requirements_text

    # 파일명으로 뽑은 이름을 그대로 믿지 않는다 — 그 버전이 레지스트리에 실재하는
    # 후보만 검사한다. 실측: `chart.min.js`(Chart.js 3.9.1)를 npm `chart` 로 조회하면
    # 그 버전이 없는데도 `checked_clean`(이상 없음)이 나왔다 — 조용한 초록불이다.
    identified: list[dict] = []
    mismatched: list[dict] = []
    for b in bundles:
        if not b.get("version"):
            continue
        cands = b.get("name_candidates") or [b["name"]]
        resolved, status = await resolve_npm_component(cands, str(b["version"]))
        if status == "no_match" or not resolved:
            mismatched.append(b)
            continue
        item = {**b, "name": resolved, "identity": status}
        if resolved != b["name"]:
            item["renamed_from"] = b["name"]
        identified.append(item)
    # 버전 미상을 '판정 불가'로 올릴지는 **벤더라는 근거의 세기**로 가른다.
    # 파일명 `.min.`(detected_by="name")은 작성자가 배포본 라이브러리를 넣었다는
    # 명시적 신호이므로 판정 불가로 남긴다. 반면 이름은 평범한데 내용만 미니파이드인
    # 것(detected_by="content")은 프로젝트 자체 번들일 수 있어, 매번 노란불을 켜면
    # 경고 피로만 만든다(원칙 6) — 제외 목록에는 남지만 위험으로 올리지 않는다.
    unknown = [
        b for b in bundles
        if not b.get("version") and b.get("detected_by", "name") == "name"
    ]

    if identified:
        audit = await audit_manifest(
            to_requirements_text(
                [{"name": b["name"], "version": b["version"]} for b in identified],
                ecosystem="npm",
            ),
            ecosystem="npm", limit=len(identified), env_grade=env_grade,
        )
    else:
        audit = {
            "ecosystem": "npm", "verdict": "review_required",
            "requires_review": True, "parsed_count": 0, "checked_count": 0,
            "unchecked_count": 0, "blocked": False, "checks": [],
        }

    # 식별 근거를 함께 싣는다 — 파일명·본문 기반 **추정**이므로 검토자가 원본을
    # 열어 확인할 수 있어야 한다(도구의 주장 ≠ 확인된 사실).
    by_name = {b["name"].lower(): b for b in identified}
    for c in audit.get("checks", []):
        b = by_name.get(str(c.get("name", "")).lower())
        if b:
            c["vendor_bundle_path"] = b["path"]
            c["vendor_bundle_evidence"] = b["evidence"]
            if b.get("renamed_from"):
                c["vendor_bundle_evidence"] += (
                    f" · 파일명은 `{b['renamed_from']}` 이나 레지스트리 대조로 확정"
                )
            # 확인하지 못한 것을 확인한 것처럼 두지 않는다(오프라인·통신 실패).
            if b.get("identity") == "unverified":
                c["requires_review"] = True
                c["note"] = (
                    (c.get("note") or "")
                    + " 벤더 번들 식별을 레지스트리로 확인하지 못했습니다 — 다른 "
                      "라이브러리일 수 있습니다('안전' 아님)."
                ).strip()

    # 레지스트리에 그 이름·버전이 없다 = 우리 추정이 틀렸다. '이상 없음'이 아니라
    # 판정 불가로 남긴다 — 엉뚱한 패키지의 결과를 그 파일의 결과로 말하면 안 된다.
    for b in mismatched:
        audit.setdefault("checks", []).append({
            "name": b["name"], "version": b.get("version"), "checked": False,
            "verdict": "unchecked", "requires_review": True,
            "is_malicious_package": False, "vulnerability_count": 0,
            "note": (
                f"{b['path']} — 추정한 `{b['name']}@{b.get('version')}` 이(가) npm 에 없습니다. "
                f"다른 라이브러리일 수 있어 검사하지 못했습니다(후보: "
                f"{', '.join(b.get('name_candidates') or [b['name']])})"
            ),
            "vendor_bundle_path": b["path"],
            "vendor_bundle_evidence": b.get("evidence", ""),
        })
    if mismatched:
        audit["unchecked_count"] = int(audit.get("unchecked_count") or 0) + len(mismatched)
        audit["parsed_count"] = int(audit.get("parsed_count") or 0) + len(mismatched)
        audit["requires_review"] = True

    for b in unknown:
        audit.setdefault("checks", []).append({
            "name": b["name"], "version": None, "checked": False,
            "verdict": "unchecked", "requires_review": True,
            "is_malicious_package": False, "vulnerability_count": 0,
            "note": (
                f"{b['path']} — 버전을 확정하지 못해 취약점을 검사하지 못했습니다(판정 불가)"
            ),
            "vendor_bundle_path": b["path"],
            "vendor_bundle_evidence": b["evidence"],
        })
    if unknown:
        audit["unchecked_count"] = int(audit.get("unchecked_count") or 0) + len(unknown)
        audit["parsed_count"] = int(audit.get("parsed_count") or 0) + len(unknown)
        audit["requires_review"] = True

    audit["manifest"] = "<벤더 번들: *.min.js>"
    audit["source"] = "vendor-bundle"
    return audit
