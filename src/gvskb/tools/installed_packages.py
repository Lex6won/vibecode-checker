"""설치된 패키지 인벤토리 — 매니페스트에 없는 실제 사용 패키지를 찾는다.

왜 필요한가(실측 근거): 상용 SCA 도구와 비교했을 때 유일하게 밀린 축이었다.
``requirements.txt`` 에 10개만 적혀 있어도 가상환경에는 전이 의존성까지 수십
개가 설치돼 있고, **취약점은 대개 그 전이 의존성에 있다**. 매니페스트만 보면
"의존성 10건 이상 없음"이라는 거짓 안심을 준다.

읽는 대상(설치 흔적, 실행하지 않음):

- ``*.dist-info/METADATA`` — pip 설치본의 표준 메타데이터(Name/Version/License)
- ``*.egg-info/PKG-INFO`` — 구형 설치본
- ``*.whl`` 파일명 — 오프라인 반입용 휠(설치 전이라도 반입 목록으로 유효)
- ``node_modules/*/package.json`` — npm 설치본

전부 **정적 텍스트 읽기**이며 패키지를 임포트·실행하지 않는다.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# 휠 파일명 규격: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
_WHEEL_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.\-]+?)-(?P<version>\d[A-Za-z0-9_.!+]*?)"
                       r"(?:-\d[^-]*)?-(?:py|cp|pp|ip|jy)[^-]*-", re.IGNORECASE)

# 스캔에서 건너뛸 디렉터리(캐시·빌드 산출물). site-packages 는 **일부러 본다**.
_SKIP_DIRS = {".git", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}

MAX_PACKAGES_DEFAULT = 300


def _normalize(name: str) -> str:
    """PEP 503 이름 정규화 — dist-info(``et_xmlfile``)와 휠 파일명(``et-xmlfile``)이
    같은 패키지로 합쳐지게 한다(정규화하지 않으면 같은 패키지가 두 번 잡힌다)."""
    return re.sub(r"[-_.]+", "-", str(name)).strip("-").lower()


def _parse_metadata_text(text: str) -> dict[str, str | None]:
    """METADATA/PKG-INFO 헤더에서 이름·버전·라이선스를 뽑는다."""
    name = version = license_ = None
    for raw in text.splitlines():
        if not raw.strip():
            break                      # 헤더 끝(본문 시작)
        low = raw.lower()
        if low.startswith("name:") and name is None:
            name = raw.split(":", 1)[1].strip()
        elif low.startswith("version:") and version is None:
            version = raw.split(":", 1)[1].strip()
        elif low.startswith("license-expression:") and license_ is None:
            license_ = raw.split(":", 1)[1].strip()
        elif low.startswith("license:") and license_ is None:
            license_ = raw.split(":", 1)[1].strip()
        elif low.startswith("classifier: license ::") and license_ is None:
            license_ = raw.split("::")[-1].strip()
    return {"name": name, "version": version, "license": license_}


def _iter_candidate_files(root: Path, max_files: int = 20000):
    """설치 흔적 후보 파일을 순회한다(파일 수 상한으로 폭주 방지)."""
    seen = 0
    for path in root.rglob("*"):
        seen += 1
        if seen > max_files:
            return
        if path.is_dir():
            continue
        parts = set(path.parts)
        if parts & _SKIP_DIRS:
            continue
        name = path.name
        if name in {"METADATA", "PKG-INFO"} and (
            path.parent.name.endswith(".dist-info") or path.parent.name.endswith(".egg-info")
        ):
            yield ("metadata", path)
        elif name.endswith(".whl"):
            yield ("wheel", path)
        elif name == "package.json" and path.parent.parent.name == "node_modules":
            yield ("npm", path)


def collect_installed_packages(
    root: str | Path,
    *,
    limit: int = MAX_PACKAGES_DEFAULT,
) -> dict:
    """설치 흔적을 훑어 (생태계별) 패키지 목록을 만든다.

    반환: ``{"pypi": [{name, version, license, source}], "npm": [...], "stats": {...}}``
    같은 (이름, 버전)은 한 번만 담는다.
    """
    base = Path(root)
    pypi: dict[tuple[str, str | None], dict] = {}
    npm: dict[tuple[str, str | None], dict] = {}
    stats = {"metadata": 0, "wheel": 0, "npm": 0, "unparsed": 0}

    if not base.exists():
        return {"pypi": [], "npm": [], "stats": stats, "root": str(base),
                "error": "경로가 없습니다"}

    for kind, path in _iter_candidate_files(base):
        try:
            if kind == "metadata":
                info = _parse_metadata_text(path.read_text(encoding="utf-8", errors="replace")[:8000])
                if info["name"]:
                    stats["metadata"] += 1
                    key = (_normalize(info["name"]), info["version"])
                    pypi.setdefault(key, {**info, "source": "dist-info"})
                else:
                    stats["unparsed"] += 1
            elif kind == "wheel":
                m = _WHEEL_RE.match(path.name)
                if m:
                    stats["wheel"] += 1
                    key = (_normalize(m.group("name")), m.group("version"))
                    pypi.setdefault(key, {"name": m.group("name"), "version": m.group("version"),
                                          "license": None, "source": "wheel"})
                else:
                    stats["unparsed"] += 1
            elif kind == "npm":
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                nm, ver = data.get("name"), data.get("version")
                if nm:
                    stats["npm"] += 1
                    lic = data.get("license")
                    if isinstance(lic, dict):
                        lic = lic.get("type")
                    npm.setdefault((_normalize(nm), ver),
                                   {"name": nm, "version": ver,
                                    "license": str(lic) if lic else None, "source": "node_modules"})
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            stats["unparsed"] += 1
            continue

    def _cap(d: dict) -> list[dict]:
        items = sorted(d.values(), key=lambda x: (str(x.get("name") or "").lower()))
        return items[:limit]

    return {
        "pypi": _cap(pypi),
        "npm": _cap(npm),
        "stats": {**stats, "pypi_total": len(pypi), "npm_total": len(npm), "limit": limit},
        "root": str(base),
    }


def to_requirements_text(packages: list[dict]) -> str:
    """수집 결과를 requirements 형식으로 바꿔 기존 audit_manifest 로 넘긴다."""
    lines = []
    for p in packages:
        name = str(p.get("name") or "").strip()
        if not name:
            continue
        ver = p.get("version")
        lines.append(f"{name}=={ver}" if ver else name)
    return "\n".join(lines)
