"""벤더링된 프런트엔드 라이브러리(``*.min.js``) 식별 — 컴포넌트 취약점 검사용.

**왜 필요한가.** 이전에는 파일명에 ``.min.`` 이 들어가면 '빌드 산출물'로 보고 조용히
제외했다. 그런데 ``static/`` 에 직접 떨궈진 ``*.min.js`` 는 빌드 출력이 아니라
**벤더링된 서드파티 라이브러리**다. 매니페스트(``package.json``)도 ``node_modules``
도 없는 프로젝트에서는 SCA 발견 경로가 하나도 걸리지 않아 *아무도 그 파일을 보지
않는* 상태가 된다.

실측(응소ON, 2026-08-03): ``static/xlsx.full.min.js`` 는 SheetJS ``xlsx 0.18.5`` 로,
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

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "version": self.version,
            "evidence": self.evidence,
            "ecosystem": self.ecosystem,
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


def identify_vendor_bundle(path: str, text: str) -> VendorBundle:
    """벤더 번들 1건을 식별한다. 버전을 확신할 수 없으면 ``version=None``.

    ``path`` 는 리포트에 실릴 상대경로, ``text`` 는 파일 내용(전체 또는 충분히 긴 앞부분).
    """
    name = component_name_from_filename(path)

    ver = _version_from_filename(path)
    if ver:
        return VendorBundle(path=path, name=name, version=ver, evidence="파일명에 버전 표기")

    ver = _version_from_banner(text, name)
    if ver:
        return VendorBundle(path=path, name=name, version=ver, evidence="선두 배너 주석")

    ver = _version_from_self_assignment(text, name)
    if ver:
        return VendorBundle(
            path=path, name=name, version=ver,
            evidence=f"본문 `{name}.version` 대입",
        )

    return VendorBundle(path=path, name=name, version=None, evidence="버전 표기를 찾지 못함")


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

    identified = [b for b in bundles if b.get("version")]
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
