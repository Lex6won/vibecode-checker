"""SBOM — 만들기(CycloneDX)와 읽기(CycloneDX·SPDX).

## 왜 필요한가

우리 룰과 문서는 *"SBOM·의존성 매니페스트로 확인하세요"* 라고 **안내는 하면서
정작 도구는 SBOM 을 만들지도 읽지도 못했다**(실측 2026-08-08). 공공 조달이
SBOM 제출을 요구하기 시작한 상황에서 실질적인 공백이었다.

두 방향이 다 필요하다:

- **만들기** — 검사 결과를 CycloneDX 로 내보내 제출·보관한다. 우리가 이미 갖고
  있는 것(purl · 버전 · 라이선스 · 취약점 · 권고 버전)을 표준 형식으로 옮기는
  일이라 새로 알아내야 할 것이 없다.
- **읽기** — 조달·협력사가 건네준 SBOM 을 그대로 검사한다. 소스가 없어도
  컴포넌트 목록만 있으면 취약점을 대조할 수 있다.

## 정직성 규약

SBOM 은 "이 소프트웨어에 무엇이 들어 있나"를 **증명하는 문서**다. 그래서 이
모듈은 두 가지를 절대 하지 않는다:

1. **판정하지 못한 것을 빼지 않는다.** 조회 실패·판정 불가 컴포넌트도 그대로
   싣고, `properties` 에 사유를 남긴다. 빠지면 받는 쪽은 "그 패키지를 안 쓴다"로
   읽는다 — 없는 것과 안 본 것은 다르다(라운드 13에서 배운 것).
2. **누가 언제 무엇으로 판정했는지 각인한다.** 엔진 버전과 **룰셋 버전**을 함께
   넣는다. 둘 중 하나만 있으면 재현 가능한 것처럼 보이는 착시가 생긴다.

## 만들지 않는 것

파일 해시(무결성)는 넣지 않는다. 우리는 패키지 **메타데이터**를 조회할 뿐
아티팩트를 내려받아 해싱하지 않기 때문이다. 넣을 수 없는 값을 빈칸으로 두는
대신 아예 필드를 만들지 않는다 — 빈 해시는 "확인했는데 없다"로 읽힌다.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"

#: OSV/우리 판정 심각도 → CycloneDX ratings 의 severity 어휘
_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "NONE": "none", "UNKNOWN": "unknown",
}

_PURL_RE = re.compile(r"^pkg:(?P<eco>[^/]+)/(?P<rest>.+)$")


# ---------------------------------------------------------------------------
# 만들기 — 검사 결과 → CycloneDX
# ---------------------------------------------------------------------------

_PATH_SEP_RE = re.compile(r"[\\/]+")


def project_name(target: str, explicit: str | None = None) -> str:
    """SBOM 에 실을 프로젝트 이름 — **경로는 싣지 않는다**.

    SBOM 은 조달처·발주처로 나가는 **반출 문서**다. 반입 번들은 코드 조각과 파일
    경로를 허용목록으로 막아 두는데(`tools/registry_bundle.py`) SBOM 에는 그
    방어가 없었다 — 더 멀리 나가는 쪽에 방어가 없었으니 방향이 뒤집혀 있었다.
    실측(2026-08-09)에서 이렇게 나갔다::

        "name": "C:\\\\Users\\\\<사용자명>\\\\AppData\\\\Local\\\\Temp\\\\...\\\\lexdiff"

    사용자명·세션 ID·디렉터리 구조가 문서에 남는다. 여러 기관의 SBOM 이 한 곳에
    모이면 **남의 기관 내부 구조**까지 함께 모인다.

    막는 자리를 CLI 가 아니라 **문서 생성기**로 잡는다 — 호출자가 늘어도(MCP·웹)
    방어가 따라온다. 값을 고르는 책임은 소비자가 아니라 생산자에게 있다.

    ``explicit`` (``--project-name``)은 그대로 쓴다 — 사용자가 직접 고른 이름이고,
    구분자를 포함한 정식 명칭(예: ``경기도/법령비교``)을 쪼개면 뜻이 상한다.
    """
    if explicit and explicit.strip():
        return explicit.strip()
    raw = (target or "").strip().rstrip("\\/")
    if not raw:
        return "project"
    name = _PATH_SEP_RE.split(raw)[-1]
    # `C:` 만 남는 경우(드라이브 루트를 검사) — 드라이브 문자는 이름이 아니다.
    return name if name and not name.endswith(":") else "project"


def _purl(check: dict) -> str:
    eco = str(check.get("ecosystem") or "generic")
    name = str(check.get("name") or "")
    ver = check.get("version")
    return f"pkg:{eco}/{name}" + (f"@{ver}" if ver else "")


def _serial_number(components: list[dict]) -> str:
    """내용에서 유도한 결정적 serial.

    난수 UUID 를 쓰면 같은 입력에 매번 다른 문서가 나와 **두 SBOM 이 같은지
    비교할 수 없다.** 조달·감사에서 필요한 것은 유일성보다 재현성이다.
    """
    blob = json.dumps([c.get("purl") for c in components], sort_keys=True)
    digest = hashlib.blake2b(blob.encode("utf-8"), digest_size=16).hexdigest()
    return (f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}"
            f"-{digest[16:20]}-{digest[20:32]}")


def _license_entry(check: dict) -> list[dict] | None:
    meta = check.get("registry_metadata") or {}
    name = meta.get("license") or check.get("license")
    if not name or not isinstance(name, str):
        return None
    # SPDX id 인지 자유 문자열인지 우리가 판정하지 않는다 — `name` 으로 넣으면
    # 받는 쪽이 자기 기준으로 해석한다. 억지로 `id` 에 넣으면 스키마 위반이 된다.
    return [{"license": {"name": name}}]


def _properties(check: dict) -> list[dict]:
    """우리 판정을 CycloneDX 표준 필드로 옮길 수 없는 것들.

    **판정 불가·조회 실패를 여기에 반드시 남긴다.** 컴포넌트만 싣고 사유를
    빼면 받는 쪽은 전부 검사된 것으로 읽는다.
    """
    out: list[dict] = []

    def put(key: str, value: Any) -> None:
        if value not in (None, "", [], {}):
            out.append({"name": f"gvskb:{key}", "value": str(value)})

    put("verdict", check.get("verdict"))
    put("checked", "true" if check.get("checked") else "false")
    if check.get("error"):
        put("error", check["error"])
    if check.get("requires_review"):
        put("requires_review", "true")
    if check.get("offline"):
        put("offline", "true")
    put("recommended_version", check.get("recommended_version"))
    if check.get("in_kev"):
        put("in_kev", "true")
    if not check.get("version_exact", True):
        put("version_exact", "false")
    return out


def _component(check: dict) -> dict:
    comp: dict = {
        "type": "library",
        "bom-ref": _purl(check),
        "name": str(check.get("name") or "(unknown)"),
        "purl": _purl(check),
    }
    if check.get("version"):
        comp["version"] = str(check["version"])
    if lic := _license_entry(check):
        comp["licenses"] = lic
    if props := _properties(check):
        comp["properties"] = props
    return comp


def _vulnerabilities(check: dict) -> list[dict]:
    out: list[dict] = []
    ref = _purl(check)
    for adv in check.get("advisories") or []:
        if not isinstance(adv, dict):
            continue
        vid = adv.get("id") or adv.get("advisory_id")
        if not vid:
            continue
        entry: dict = {
            "bom-ref": f"{ref}#{vid}",
            "id": str(vid),
            "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
            "affects": [{"ref": ref}],
        }
        rating: dict = {"source": {"name": "OSV"}}
        sev = _SEVERITY_MAP.get(str(adv.get("severity") or "").upper())
        if sev:
            rating["severity"] = sev
        if vector := adv.get("cvss_vector"):
            rating["vector"] = str(vector)
            rating["method"] = "CVSSv31" if "CVSS:3.1" in str(vector) else "other"
        if len(rating) > 1:
            entry["ratings"] = [rating]
        if summary := adv.get("summary"):
            entry["description"] = str(summary)
        if refs := adv.get("references"):
            entry["advisories"] = [{"url": str(u)} for u in refs if u]
        if fixed := check.get("recommended_version"):
            entry["recommendation"] = f"{check.get('name')} {fixed} 이상으로 올리세요."
        out.append(entry)
    return out


def to_cyclonedx(
    dependency_audit: dict | None,
    *,
    target: str = "",
    engine_version: str | None = None,
    ruleset_version: str | None = None,
    ruleset_digest: str | None = None,
    generated_at: str | None = None,
    name: str | None = None,
) -> dict:
    """의존성 검사 결과 → CycloneDX 1.6 문서(dict).

    `dependency_audit` 은 `{"audits": [...]}` 묶음 또는 단일 감사 결과를 받는다.

    `target` 은 검사 경로라 **그대로 싣지 않는다** — `project_name` 이 마지막
    구간만 남긴다. `name`(CLI `--project-name`)을 주면 그 값을 쓴다.
    """
    audits = _audit_list(dependency_audit)
    checks: list[dict] = []
    for a in audits:
        checks.extend(c for c in (a.get("checks") or []) if isinstance(c, dict))

    # 같은 패키지가 매니페스트·설치본·번들에 겹쳐 나올 수 있다. purl 로 묶되
    # **판정이 더 무거운 쪽**을 남긴다(중복 계상 제거는 리포트에서 배운 것).
    by_ref: dict[str, dict] = {}
    weight = {"malicious": 5, "vulnerable": 4, "not_found": 3, "error": 2,
              "requires_review": 1, "checked_clean": 0}
    for c in checks:
        ref = _purl(c)
        prev = by_ref.get(ref)
        if prev is None or weight.get(str(c.get("verdict")), 0) > weight.get(
                str(prev.get("verdict")), 0):
            by_ref[ref] = c

    ordered = [by_ref[k] for k in sorted(by_ref)]
    components = [_component(c) for c in ordered]
    vulns: list[dict] = []
    for c in ordered:
        vulns.extend(_vulnerabilities(c))

    truncated = sum(int(a.get("truncated_count") or 0) for a in audits)
    unchecked = sum(1 for c in ordered if not c.get("checked"))

    tool: dict = {"type": "application", "name": "gvskb",
                  "author": "vibecode-checker"}
    if engine_version:
        tool["version"] = engine_version

    # 판정 기준을 문서에 각인한다 — 엔진과 룰셋을 **쌍으로**. 한쪽만 있으면
    # 재현 가능한 것처럼 보이는 착시가 생긴다.
    props = [{"name": "gvskb:component_count", "value": str(len(components))},
             {"name": "gvskb:unchecked_count", "value": str(unchecked)}]
    if truncated:
        props.append({"name": "gvskb:truncated_count", "value": str(truncated)})
    if ruleset_version:
        props.append({"name": "gvskb:ruleset_version", "value": ruleset_version})
    if ruleset_digest:
        props.append({"name": "gvskb:ruleset_digest", "value": ruleset_digest})
    if unchecked or truncated:
        props.append({
            "name": "gvskb:coverage_notice",
            "value": (
                f"검사되지 않은 컴포넌트 {unchecked}개"
                + (f", 상한에 걸려 목록에서 빠진 컴포넌트 {truncated}개" if truncated else "")
                + " — '판정 불가'는 '안전'이 아닙니다."
            ),
        })

    doc: dict = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(components),
        "version": 1,
        "metadata": {
            "timestamp": generated_at or datetime.now(timezone.utc).isoformat(
                timespec="seconds"),
            "tools": {"components": [tool]},
            "properties": props,
        },
        "components": components,
    }
    if target or name:
        label = project_name(target, name)
        doc["metadata"]["component"] = {
            "type": "application", "name": label, "bom-ref": f"root:{label}",
        }
    if vulns:
        doc["vulnerabilities"] = vulns
    return doc


def _audit_list(dependency_audit: dict | None) -> list[dict]:
    if not dependency_audit:
        return []
    inner = dependency_audit.get("audits")
    if isinstance(inner, list):
        return [a for a in inner if isinstance(a, dict)]
    return [dependency_audit]


# ---------------------------------------------------------------------------
# 읽기 — CycloneDX·SPDX → 패키지 목록
# ---------------------------------------------------------------------------

class SbomParseError(ValueError):
    """SBOM 을 읽지 못했다. **사용자 잘못처럼 보이지 않게** 사유를 담는다."""


def parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """`pkg:npm/@scope/name@1.2.3` → (ecosystem, name, version)."""
    m = _PURL_RE.match(str(purl or "").strip())
    if not m:
        return None
    eco = m.group("eco").lower()
    rest = m.group("rest").split("?", 1)[0].split("#", 1)[0]
    # 버전은 **마지막** `@` 뒤 — npm 스코프(`@scope/name`)의 앞 `@` 와 헷갈리면 안 된다.
    if "@" in rest[1:]:
        idx = rest.rindex("@")
        name, version = rest[:idx], rest[idx + 1:]
    else:
        name, version = rest, None
    return eco, name, (version or None)


#: SBOM 의 생태계 표기 → 우리 조회 생태계
_ECO_ALIASES = {
    "pypi": "pypi", "python": "pypi", "pip": "pypi",
    "npm": "npm", "node": "npm",
    "maven": "maven", "golang": "go", "go": "go",
    "cargo": "crates.io", "crates": "crates.io",
    "nuget": "nuget", "gem": "rubygems", "rubygems": "rubygems",
    "composer": "packagist", "packagist": "packagist",
}


def parse_sbom(text: str) -> dict:
    """CycloneDX 또는 SPDX(JSON) → `{"format", "packages", "skipped"}`.

    `packages` 는 `check_package` 가 그대로 받을 수 있는 모양이다.
    **읽지 못한 항목은 버리지 않고 `skipped` 에 사유와 함께 남긴다** — 조용히
    빠지면 "그 컴포넌트는 안전하다"로 읽힌다.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SbomParseError(
            f"JSON 으로 읽을 수 없습니다({exc.lineno}행): {exc.msg}. "
            "CycloneDX 또는 SPDX 의 **JSON** 형식이어야 합니다"
            "(XML·tag-value 형식은 아직 지원하지 않습니다)."
        ) from exc
    if not isinstance(doc, dict):
        raise SbomParseError("최상위가 객체가 아닙니다 — SBOM 파일이 맞는지 확인하세요.")

    if doc.get("bomFormat") == BOM_FORMAT or "components" in doc:
        return _parse_cyclonedx(doc)
    if doc.get("spdxVersion") or "packages" in doc:
        return _parse_spdx(doc)
    raise SbomParseError(
        "CycloneDX(`bomFormat`)도 SPDX(`spdxVersion`)도 아닙니다. "
        "지원 형식: CycloneDX JSON · SPDX JSON."
    )


def _norm_eco(eco: str | None) -> str | None:
    if not eco:
        return None
    return _ECO_ALIASES.get(eco.lower())


def _parse_cyclonedx(doc: dict) -> dict:
    packages, skipped = [], []
    for comp in doc.get("components") or []:
        if not isinstance(comp, dict):
            continue
        label = comp.get("name") or comp.get("purl") or "(이름 없음)"
        parsed = parse_purl(comp.get("purl") or "")
        if parsed:
            eco_raw, name, version = parsed
            eco = _norm_eco(eco_raw)
            version = version or comp.get("version")
        else:
            eco, name, version = None, comp.get("name"), comp.get("version")
        if not eco:
            skipped.append({"name": str(label), "reason": (
                "생태계를 알 수 없습니다 — `purl`(pkg:npm/… 형태)이 없거나 "
                "지원하지 않는 생태계입니다")})
            continue
        if not version:
            skipped.append({"name": str(label), "reason": (
                "버전이 없습니다 — 버전 없이는 취약점 여부를 판정할 수 없습니다")})
            continue
        packages.append({"name": str(name), "version": str(version),
                         "ecosystem": eco, "version_exact": True})
    return {"format": "cyclonedx", "spec_version": doc.get("specVersion"),
            "packages": packages, "skipped": skipped}


def _parse_spdx(doc: dict) -> dict:
    packages, skipped = [], []
    for pkg in doc.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        label = pkg.get("name") or pkg.get("SPDXID") or "(이름 없음)"
        purl = None
        for ref in pkg.get("externalRefs") or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        parsed = parse_purl(purl or "")
        if parsed:
            eco_raw, name, version = parsed
            eco = _norm_eco(eco_raw)
            version = version or pkg.get("versionInfo")
        else:
            eco, name, version = None, pkg.get("name"), pkg.get("versionInfo")
        if not eco:
            skipped.append({"name": str(label), "reason": (
                "생태계를 알 수 없습니다 — `externalRefs` 에 purl 이 없습니다")})
            continue
        if not version or str(version).upper() == "NOASSERTION":
            skipped.append({"name": str(label), "reason": (
                "버전이 없습니다(NOASSERTION 포함) — 취약점 여부를 판정할 수 없습니다")})
            continue
        packages.append({"name": str(name), "version": str(version),
                         "ecosystem": eco, "version_exact": True})
    return {"format": "spdx", "spec_version": doc.get("spdxVersion"),
            "packages": packages, "skipped": skipped}
