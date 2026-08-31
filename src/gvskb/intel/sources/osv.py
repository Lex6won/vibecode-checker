"""OSV.dev — malicious-package advisories **and** the full vulnerability set.

OSV publishes per-ecosystem zip dumps at
``https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip``.
These contain every advisory for the ecosystem as individual JSON files.

두 개의 캐시 소스가 이 모듈에서 나온다:

- ``osv-malicious`` — ``MAL-`` 접두 악성 패키지 목록(기존 스키마 유지: affected 를
  ``{package, ecosystem}`` 로 평탄화). check_package 오프라인 악성 대조가 소비한다.
- ``osv-vulns`` — **MAL- 이 아닌 전체 취약점**(CVE/GHSA/PYSEC…)을 버전 범위
  (``affected[].ranges``·``versions``)까지 보존해 담는다. 예전에는 이 데이터를
  통째로 버려서 **망분리 환경이 구조적으로 CVE 를 볼 수 없었다**(pillow 12.2.0
  취약점 26건이 오프라인에서 '이상 없음'으로 통과한 실측 사고의 근본 원인).
  실측(2026-08-31): 정규화 후 PyPI 25.7MB · npm 6.2MB — 반입 번들에 담을 수 있는
  크기다. 구조는 OSV 원형(중첩 ``affected[].package.name``)을 유지해
  ``_advisory_rows``/``_max_cve_from_vulns`` 등 온라인 경로의 해석기를 그대로 쓴다.

같은 zip 을 두 소스가 각각 내려받으면 하루 2×256MB 다운로드가 된다 — 어댑터가
공유하는 다운로드·파싱 결과를 **클라이언트 객체 기준으로 메모이즈**한다
(``update_sources`` 는 모든 어댑터에 같은 클라이언트를 넘기므로 1회만 받는다).

Defaults are conservative to respect agency network budgets:

- **PyPI** (~34 MB compressed) is fetched by default.
- **npm** (~220 MB) is fetched only when ``GVSKB_OSV_INCLUDE_NPM`` is set to a
  truthy value, since first-sync on a slow agency link can be painful.
  (저장소의 일일 GitHub Actions 는 이 변수를 켜고 돌므로 배포 번들에는 npm 이
  포함된다 — opt-in 은 개인 PC 의 수동 update-intel 을 위한 보호막이다.)

Fetch failures degrade quietly: the adapter returns whatever advisories it
managed to collect so the rest of the cache refresh continues.
"""
from __future__ import annotations

import io
import json
import os
import weakref
import zipfile
from typing import Iterable

from .base import HttpFetcher, SourceAdapter, register_source

GCS_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"

# Ecosystems we may pull from. Order is intentional: PyPI is small and always on.
# Public so that consumers (check_package 의 커버리지 공백 안내)can tell "이 생태계는
# 기본 수집 대상인데 캐시가 없다" 와 "이 생태계는 opt-in 이라 안 담겼다" 를 구분한다 —
# 섞으면 PyPI 를 물어본 담당자에게 "npm 을 켜라"는 엉뚱한 안내가 나간다.
DEFAULT_ECOSYSTEMS: tuple[str, ...] = ("PyPI",)
OPT_IN_ECOSYSTEMS: tuple[str, ...] = ("npm",)

# 하위 호환 별칭 (기존 내부 참조·테스트용)
_DEFAULT_ECOSYSTEMS = DEFAULT_ECOSYSTEMS
_OPT_IN_ECOSYSTEMS = OPT_IN_ECOSYSTEMS

_KEEP = ("id", "summary", "modified", "published", "aliases", "affected")
_TRUTHY = {"1", "true", "yes", "on"}

#: 취약점(비-MAL) 항목의 references 보존 상한 — 조치 안내에 쓸 만한 것 우선.
_REF_KEEP = 4
_REF_PRIORITY = {"ADVISORY": 0, "FIX": 1, "WEB": 2, "PACKAGE": 3, "REPORT": 4}


def _selected_ecosystems() -> tuple[str, ...]:
    """Decide which ecosystems to download this run."""
    selected = list(_DEFAULT_ECOSYSTEMS)
    if os.environ.get("GVSKB_OSV_INCLUDE_NPM", "").lower() in _TRUTHY:
        for eco in _OPT_IN_ECOSYSTEMS:
            if eco not in selected:
                selected.append(eco)
    return tuple(selected)


def _zip_url(ecosystem: str) -> str:
    return f"{GCS_BASE_URL}/{ecosystem}/all.zip"


def _normalize(vuln: dict) -> dict:
    """Trim a raw OSV entry to the fields ``check_package`` actually reads."""
    out: dict = {k: vuln.get(k) for k in _KEEP if k in vuln}
    aff = vuln.get("affected") or []
    out["affected"] = [
        {
            "package": (a.get("package") or {}).get("name"),
            "ecosystem": (a.get("package") or {}).get("ecosystem"),
        }
        for a in aff
        if a.get("package")
    ]
    return out


def _normalize_vuln(vuln: dict) -> dict:
    """비-MAL 취약점을 **버전 범위를 보존한 채** OSV 원형 구조로 다듬는다.

    ``affected[].package`` 를 평탄화하지 않는 이유: 온라인 경로의 해석기
    (``_advisory_fix_ranges``·``_advisory_rows``·``_max_cve_from_vulns``)가
    중첩 구조를 읽는다 — 오프라인만을 위한 별도 파서를 만들면 두 경로의 판정이
    갈라진다. ranges 는 버전 비교가 가능한 SEMVER/ECOSYSTEM 만 남긴다(GIT 은
    커밋 해시라 로컬에서 대소 비교가 불가능하다).
    """
    out: dict = {
        "id": vuln.get("id"),
        "summary": (vuln.get("summary") or (vuln.get("details") or "")[:200])[:300],
        "modified": vuln.get("modified"),
        "aliases": [str(a) for a in (vuln.get("aliases") or [])[:10]],
        "severity": [s for s in (vuln.get("severity") or []) if isinstance(s, dict)],
    }
    ds = (vuln.get("database_specific") or {}).get("severity")
    if ds:
        out["database_specific"] = {"severity": ds}
    refs = sorted(
        (r for r in (vuln.get("references") or []) if isinstance(r, dict) and r.get("url")),
        key=lambda r: _REF_PRIORITY.get(str(r.get("type") or "").upper(), 9),
    )
    if refs:
        out["references"] = [
            {"type": r.get("type"), "url": r.get("url")} for r in refs[:_REF_KEEP]
        ]
    affected: list[dict] = []
    for a in vuln.get("affected") or []:
        pkg = a.get("package") or {}
        if not pkg.get("name"):
            continue
        rec: dict = {"package": {"name": pkg.get("name"), "ecosystem": pkg.get("ecosystem")}}
        ranges = []
        for rng in a.get("ranges") or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            events = [
                {k: v for k, v in ev.items() if k in ("introduced", "fixed", "last_affected", "limit")}
                for ev in (rng.get("events") or [])
                if isinstance(ev, dict)
            ]
            events = [ev for ev in events if ev]
            if events:
                ranges.append({"type": rng.get("type"), "events": events})
        if ranges:
            rec["ranges"] = ranges
        vers = a.get("versions") or []
        if vers:
            # PYSEC 계열은 ranges 없이 versions 열거만 주는 경우가 많다(실측:
            # PyPI affected 당 중앙값 24개) — 버리면 그 advisory 는 매칭 불가가 된다.
            rec["versions"] = [str(v) for v in vers]
        es = (a.get("ecosystem_specific") or {}).get("severity")
        if es:
            rec["ecosystem_specific"] = {"severity": es}
        affected.append(rec)
    out["affected"] = affected
    return out


def _iter_entries(zip_bytes: bytes) -> Iterable[dict]:
    """Yield raw advisory dicts from an OSV ecosystem zip dump."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return
    with zf:
        for info in zf.infolist():
            filename = info.filename.rsplit("/", 1)[-1]
            if not filename.endswith(".json"):
                continue
            try:
                with zf.open(info) as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, KeyError, OSError):
                continue
            if isinstance(data, dict):
                yield data


# 같은 프로세스에서 같은 클라이언트로 두 어댑터가 돌 때(=update_sources) zip 을
# 한 번만 받기 위한 공유 저장소. 클라이언트가 닫히고 GC 되면 함께 비워진다 —
# 테스트가 서로 다른 FakeClient 를 쓰면 자연히 격리된다.
_SHARED: "weakref.WeakKeyDictionary[object, dict]" = weakref.WeakKeyDictionary()


def _collect(client: HttpFetcher) -> dict:
    """Download selected ecosystem zip(s) once and split MAL / non-MAL entries."""
    ecosystems = _selected_ecosystems()
    try:
        memo = _SHARED.get(client)
    except TypeError:  # weakref 를 지원하지 않는 클라이언트 — 메모 없이 진행
        memo = None
    if memo is not None and tuple(memo.get("ecosystems") or ()) == ecosystems:
        return memo

    mal: dict[str, dict] = {}
    vulns: dict[str, dict] = {}
    for eco in ecosystems:
        url = _zip_url(eco)
        try:
            resp = client.get(url)
            resp.raise_for_status()
            content = getattr(resp, "content", None)
            if content is None:
                content = resp.read() if hasattr(resp, "read") else b""
        except Exception:
            continue
        for data in _iter_entries(content):
            vid = str(data.get("id", ""))
            if not vid:
                continue
            if vid.startswith("MAL-"):
                if vid not in mal:
                    mal[vid] = _normalize(data)
            else:
                # withdrawn advisory 는 판정 근거로 쓰면 안 된다 — 철회된 오보로
                # 차단·경고가 나가면 그 오탐은 다음 갱신까지 회수되지 않는다.
                if data.get("withdrawn"):
                    continue
                if vid not in vulns:
                    vulns[vid] = _normalize_vuln(data)

    result = {
        "ecosystems": ecosystems,
        "mal": list(mal.values()),
        "vulns": list(vulns.values()),
    }
    try:
        _SHARED[client] = result
    except TypeError:
        pass
    return result


def fetch_osv_malicious(client: HttpFetcher) -> tuple[str, list[dict]]:
    """Download OSV ecosystem zip(s) and return all MAL-prefix advisories.

    The first ecosystem URL is reported back so the cache envelope records a
    meaningful origin. Network or parsing failures for individual ecosystems
    are swallowed — partial results beat a failed refresh.
    """
    primary_url = _zip_url(_selected_ecosystems()[0])
    return primary_url, _collect(client)["mal"]


def fetch_osv_vulns(client: HttpFetcher) -> tuple[str, list[dict]]:
    """비-MAL 전체 취약점(버전 범위 포함) — 오프라인 CVE 대조의 원천 데이터."""
    primary_url = _zip_url(_selected_ecosystems()[0])
    return primary_url, _collect(client)["vulns"]


register_source(SourceAdapter(
    id="osv-malicious",
    description=(
        "OSV.dev malicious-package advisories (MAL- prefix). Default ecosystem: PyPI; "
        "set GVSKB_OSV_INCLUDE_NPM=1 to also download the npm dataset (~220 MB)."
    ),
    fetch=fetch_osv_malicious,
    ecosystems=lambda: list(_selected_ecosystems()),
))

register_source(SourceAdapter(
    id="osv-vulns",
    description=(
        "OSV.dev full vulnerability advisories (non-MAL) with version ranges — "
        "enables offline CVE matching. Same ecosystem selection as osv-malicious."
    ),
    fetch=fetch_osv_vulns,
    ecosystems=lambda: list(_selected_ecosystems()),
))
