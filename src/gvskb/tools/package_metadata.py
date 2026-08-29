"""공식 패키지 저장소 메타데이터 수집 — 실재확인·쿨다운·라이선스·설치스크립트.

VCPS 위협모델의 T1(오염된 신규 버전)·T2(이름 위장)를 처음으로 커버하는 원천이다:

- **실재 확인(C4-EXISTENCE)**: pypi.org / registry.npmjs.org 404 → 존재하지 않음.
  LLM 이 지어낸 패키지명(슬롭스쿼팅)이 "취약점 0건 = 깨끗함"으로 보이던
  역효과를 없앤다. 존재하지 않음이 가장 위험한 신호다.
- **쿨다운(C1)**: 버전 발행 시각 → 경과일. 탈취 계정발 오염 버전은 보통 수 시간
  ~수 일 내 삭제되므로, 발행 직후 버전을 기다리는 것이 최고 효율 방어다.
- **라이선스(LIC)·설치 스크립트(C2)**: 같은 응답에서 나오는 부수 신호.

전송 데이터는 패키지명뿐이다(소스 코드·기관 정보 미전송). ``GVSKB_MODE=offline``
이면 아무것도 조회하지 않고 exists=None('미확인')을 정직하게 반환한다.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx

from ..schema import PackageRegistryMetadata

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
NPM_REGISTRY_URL = "https://registry.npmjs.org/{name}"

# npm 설치 스크립트 훅 — preinstall 은 보안 점검보다 먼저 실행된다(VCPS C2 근거).
_NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")


def _is_offline() -> bool:
    return os.environ.get("GVSKB_MODE", "").lower() == "offline"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _age_days(iso_ts: str | None) -> int | None:
    if not iso_ts:
        return None
    try:
        ts = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - ts).days)
    except (ValueError, TypeError):
        return None


def _offline_metadata() -> PackageRegistryMetadata:
    return PackageRegistryMetadata(
        exists=None,
        source="offline (no lookup)",
        fetched_at=_now_iso(),
        error=(
            "GVSKB_MODE=offline — 공식 저장소 실재·발행일을 확인하지 못했습니다. "
            "존재 미확인은 '안전'이 아닙니다(슬롭스쿼팅 가능성 잔존)."
        ),
    )


def _pep440_key(v: str) -> str:
    """느슨한 PEP 440 정규화 키 — 소문자, 구분자 통일, 후행 `.0` 제거.

    `1.0` · `1.0.0` · `v1.0` · `1.0.0.0` → `1`. 정확한 구현(packaging)을 의존성에
    더하지 않으려는 최소 규칙이며, 존재 여부 비교에만 쓴다.
    """
    s = v.strip().lower().lstrip("v")
    s = s.replace("_", ".").replace("-", ".")
    head, sep, tail = s.partition("+")             # local version 은 버린다
    parts = head.split(".")
    # 숫자 세그먼트 앞 0 제거, 후행 0 세그먼트 제거(릴리스 부분만)
    norm = [p.lstrip("0") or "0" if p.isdigit() else p for p in parts]
    while len(norm) > 1 and norm[-1] == "0":
        norm.pop()
    return ".".join(norm)


def _match_release_key(queried: str, releases: dict) -> str | None:
    if queried in releases:
        return queried
    key = _pep440_key(queried)
    for k in releases:
        if _pep440_key(k) == key:
            return k
    return None


def _parse_pypi(data: dict, version: str | None) -> PackageRegistryMetadata:
    info = data.get("info") or {}
    latest = info.get("version")
    queried = version or latest

    # 발행 시각: 해당 버전 파일들의 최초 업로드 시각. releases 는 {버전: [파일...]}.
    releases = data.get("releases") or {}
    version_published = None
    # 버전을 콕 집어 물었는데 releases 에 없으면 그 버전은 존재하지 않는다 —
    # 발행일 None 으로 흡수되던 신호를 별도 필드로 낸다. 비교는 PEP 440 정규화로
    # 한다: `httpx>=0.27` 의 `0.27` 은 releases 의 `0.27.0` 과 같은 버전인데 문자열
    # 비교로 "요청 버전 없음(high)"이 됐다(재점검 2026-08-29, 체커 자기 pyproject).
    matched = _match_release_key(queried, releases) if queried else None
    files = (releases.get(matched) if matched else None) or []
    version_exists = (matched is not None) if (version and releases) else None
    times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
    if times:
        version_published = min(times)

    # 최초 발행: 전체 릴리스에서 가장 이른 업로드(신생 패키지 탐지 근거).
    first_published = None
    all_times = [
        f.get("upload_time_iso_8601")
        for fl in releases.values() if isinstance(fl, list)
        for f in fl if f.get("upload_time_iso_8601")
    ]
    if all_times:
        first_published = min(all_times)

    # 라이선스: PEP 639 license_expression 우선, 없으면 license, 없으면 classifier.
    lic = (info.get("license_expression") or "").strip() or (info.get("license") or "").strip()
    if not lic or len(lic) > 120:  # 라이선스 전문을 통째로 넣은 경우 — classifier 로 대체
        for c in info.get("classifiers") or []:
            if c.startswith("License ::"):
                lic = c.split("::")[-1].strip()
                break
    return PackageRegistryMetadata(
        exists=True,
        latest_version=latest,
        queried_version=queried,
        version_exists=version_exists,
        version_published_at=version_published,
        version_age_days=_age_days(version_published),
        first_published_at=first_published,
        package_age_days=_age_days(first_published),
        license=lic or None,
        install_scripts="unknown",  # PyPI 는 미개봉 검사 — sdist 실행 코드 여부 판단 불가(정직하게 unknown)
        source="pypi.org JSON API",
        fetched_at=_now_iso(),
    )


def _parse_npm(data: dict, version: str | None) -> PackageRegistryMetadata:
    latest = (data.get("dist-tags") or {}).get("latest")
    queried = version or latest
    time_map = data.get("time") or {}
    version_published = time_map.get(queried)
    first_published = time_map.get("created")

    lic = data.get("license")
    if isinstance(lic, dict):  # 구형 표기 {"type": "MIT", ...}
        lic = lic.get("type")

    versions_doc = data.get("versions") or {}
    ver_doc = versions_doc.get(queried) or {}
    version_exists = (queried in versions_doc) if (version and versions_doc) else None
    scripts = ver_doc.get("scripts") or {}
    hook_names = [h for h in _NPM_INSTALL_HOOKS if h in scripts]
    install_scripts = "present" if hook_names else ("none" if ver_doc else "unknown")

    return PackageRegistryMetadata(
        exists=True,
        latest_version=latest,
        queried_version=queried,
        version_exists=version_exists,
        version_published_at=version_published,
        version_age_days=_age_days(version_published),
        first_published_at=first_published,
        package_age_days=_age_days(first_published),
        license=str(lic) if lic else None,
        install_scripts=install_scripts,
        install_script_names=hook_names,
        deprecated=bool(ver_doc.get("deprecated")) if ver_doc else None,
        source="registry.npmjs.org",
        fetched_at=_now_iso(),
    )


async def fetch_registry_metadata(
    name: str,
    ecosystem: str = "pypi",
    version: str | None = None,
    timeout: float = 10.0,
) -> PackageRegistryMetadata:
    """공식 저장소에서 메타데이터 1건을 조회한다. 실패는 exists=None(미확인)."""
    if _is_offline():
        return _offline_metadata()

    eco = ecosystem.lower()
    url = (PYPI_JSON_URL if eco == "pypi" else NPM_REGISTRY_URL).format(name=name)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        return PackageRegistryMetadata(
            exists=None,
            source=url,
            fetched_at=_now_iso(),
            error=f"저장소 조회 실패(실재 미확인 — '안전' 아님): {exc!s}",
        )

    if resp.status_code == 404:
        # 존재하지 않는 패키지 — 슬롭스쿼팅(AI 가 지어낸 이름)의 1차 신호.
        return PackageRegistryMetadata(
            exists=False,
            queried_version=version,
            source=url,
            fetched_at=_now_iso(),
        )
    if resp.status_code != 200:
        return PackageRegistryMetadata(
            exists=None,
            source=url,
            fetched_at=_now_iso(),
            error=f"저장소 응답 이상(HTTP {resp.status_code}) — 실재 미확인",
        )

    try:
        data = resp.json()
    except ValueError as exc:
        return PackageRegistryMetadata(
            exists=None, source=url, fetched_at=_now_iso(),
            error=f"저장소 응답 파싱 실패 — 실재 미확인: {exc!s}",
        )

    try:
        return _parse_pypi(data, version) if eco == "pypi" else _parse_npm(data, version)
    except Exception as exc:  # noqa: BLE001 — 파싱 결함이 검사 전체를 막으면 안 된다
        return PackageRegistryMetadata(
            exists=True,  # 200 응답 = 실재는 확인됨. 상세 메타만 실패.
            source=url, fetched_at=_now_iso(),
            error=f"메타데이터 해석 실패(실재는 확인됨): {exc!s}",
        )
