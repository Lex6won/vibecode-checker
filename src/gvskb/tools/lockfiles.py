"""락파일 파서 — 전이 의존성까지 검사 범위에 넣는다.

**왜 필요한가.** 실무 취약점은 대부분 *전이 의존성*에 있는데, 전이 의존성은
매니페스트(`requirements.txt`·`package.json`)에 적히지 않고 락파일에만 있다.
Flask 하나를 적으면 Werkzeug·Jinja2·click 이 딸려 오고, CVE 는 그 아래에서 나온다.
매니페스트만 검사하고 "의존성 검사 통과"를 보여 주면 트리의 일부만 본 것을
전부 본 것처럼 알리는 셈이다 — 조용한 초록불이다.

**버전 정확도.** 매니페스트의 `^18.2.0`·`>=2.28` 은 범위 표기라 **어떤 버전이
설치될지 확정되지 않는다.** 락파일은 정확히 고정된 버전을 담는다. 기관 레지스트리는
`(생태계, 이름, 버전)` 정확 일치로 판정을 저장하므로, 확정 버전이 없으면 조회도
저장도 불가능하다.

**설치 후 검사와의 차이.** `scan_installed_packages` 도 정확한 버전을 주지만 그건
*설치 후*다. VCPS C1·C2 의 목적은 "설치 전 차단"이므로 락파일 경로가 따로 필요하다.

지원 형식(우선순위 순): package-lock.json · uv.lock · poetry.lock ·
pnpm-lock.yaml · yarn.lock

패키지 매니저를 실행하지 않고 **텍스트만** 읽는다.
"""
from __future__ import annotations

import json
import re
import tomllib
from typing import Literal

import yaml

Ecosystem = Literal["pypi", "npm"]

# 형식 판별 — 내용 기반. 파일명은 신뢰하지 않는다(사용자가 텍스트만 붙여넣을 수 있음).
# 순서가 중요하다: pnpm-lock.yaml 에도 lockfileVersion 이 있으므로 JSON 여부를
# 먼저 가른다.
_FORMATS: tuple[tuple[str, str, str], ...] = (
    # (format_id, ecosystem, 판별 힌트)
    ("package-lock.json", "npm", '"lockfileVersion"'),
    ("pnpm-lock.yaml", "npm", "lockfileVersion:"),
    ("yarn.lock", "npm", "# yarn lockfile"),
    ("poetry.lock", "pypi", "[[package]]"),
    ("uv.lock", "pypi", "[[package]]"),
)


def detect_format(text: str, filename: str = "") -> tuple[str, str] | None:
    """(format_id, ecosystem) 또는 None.

    파일명이 있으면 우선 쓰고(가장 확실함), 없으면 내용으로 판별한다.
    """
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for fmt, eco, _ in _FORMATS:
        if name == fmt:
            return fmt, eco
    head = text[:4000]
    if '"lockfileVersion"' in head:
        return "package-lock.json", "npm"
    if head.lstrip().startswith("# yarn lockfile") or "# yarn lockfile" in head[:200]:
        return "yarn.lock", "npm"
    if "__metadata:" in head:
        return "yarn.lock", "npm"   # yarn berry(v2+)는 YAML 이고 헤더 주석이 없다
    if re.search(r"^lockfileVersion:", head, re.MULTILINE):
        return "pnpm-lock.yaml", "npm"
    if "[[package]]" in head:
        # poetry 와 uv 는 둘 다 [[package]] 를 쓴다. 구분이 안 되면 poetry 로 본다 —
        # 파싱 로직이 동일하므로 판정에 영향이 없고, 표기만 달라진다.
        return ("uv.lock" if "requires-dist" in text[:20000] else "poetry.lock"), "pypi"
    return None


def _dedupe(packages: list[dict]) -> list[dict]:
    """(이름, 버전) 중복 제거 — 락파일은 같은 패키지를 여러 경로에 담는다.

    이름만으로 합치지 않는 이유: 같은 패키지의 **서로 다른 버전**이 동시에 설치되는
    일이 npm 에서 흔하고, 취약한 쪽이 하나라도 있으면 위험은 실재한다.
    """
    seen: set[tuple[str, str | None]] = set()
    out: list[dict] = []
    for p in packages:
        key = (str(p.get("name") or ""), p.get("version"))
        if not key[0] or key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _parse_package_lock(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    # v2·v3: packages 는 설치 경로를 키로 갖는다("" = 루트 프로젝트 자신).
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for path, meta in pkgs.items():
            if not path or not isinstance(meta, dict):
                continue  # "" 는 프로젝트 자신 — 의존성이 아니다
            # node_modules/a/node_modules/b → b (중첩 설치)
            name = meta.get("name") or path.split("node_modules/")[-1]
            if meta.get("link"):
                continue  # 워크스페이스 심볼릭 링크 — 실제 패키지는 별도 항목에 있다
            out.append({"name": str(name), "version": meta.get("version")})
    # v1: dependencies 가 중첩 트리
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        def walk(node: dict) -> None:
            for name, meta in node.items():
                if not isinstance(meta, dict):
                    continue
                out.append({"name": str(name), "version": meta.get("version")})
                child = meta.get("dependencies")
                if isinstance(child, dict):
                    walk(child)
        walk(deps)
    return _dedupe(out)


def _parse_toml_packages(text: str) -> list[dict]:
    """poetry.lock · uv.lock — 둘 다 [[package]] 배열에 name/version 을 담는다."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    out = [
        {"name": str(p.get("name")), "version": p.get("version")}
        for p in (data.get("package") or [])
        if isinstance(p, dict) and p.get("name")
    ]
    return _dedupe(out)


# pnpm 은 버전대별로 키 형식이 다르다:
#   v6 이하: /foo/1.2.3            ·  /@scope/foo/1.2.3
#   v9 이상: /foo@1.2.3            ·  /@scope/foo@1.2.3
# 뒤에 peer 해시가 붙기도 한다: /foo@1.2.3(react@18.0.0)
#
# 두 가지가 파싱을 망가뜨린다(실측으로 잡힘):
#  ① 스코프 패키지에서 슬래시 규칙을 먼저 대면 `/@babel/core@7.24.0` 이
#     이름=@babel · 버전=core@7.24.0 으로 잘못 쪼개진다 → @ 규칙을 먼저 댄다.
#  ② peer 해시의 `@18.0.0` 때문에 탐욕 매칭이 뒤쪽 @ 를 잡는다
#     → 이름 부분을 게으르게(`*?`) 두고, **버전은 숫자로 시작**해야 한다고 못박는다.
_PNPM_AT = re.compile(r"^/?(?P<name>(?:@[^/]+/)?[^/@][^/]*?)@(?P<version>\d[^(\s:]*)")
_PNPM_SLASH = re.compile(r"^/(?P<name>(?:@[^/]+/)?[^/]+)/(?P<version>\d[^/(\s:]*)")


def _parse_pnpm(text: str) -> list[dict]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
    out: list[dict] = []
    for section in ("packages", "snapshots"):
        node = data.get(section)
        if not isinstance(node, dict):
            continue
        for key, meta in node.items():
            k = str(key)
            m = _PNPM_AT.match(k) or _PNPM_SLASH.match(k)
            if m:
                out.append({"name": m.group("name"), "version": m.group("version")})
                continue
            # 키에서 못 읽으면 값 쪽 메타데이터를 본다.
            if isinstance(meta, dict) and meta.get("name") and meta.get("version"):
                out.append({"name": str(meta["name"]), "version": str(meta["version"])})
    return _dedupe(out)


# yarn v1 클래식:
#   "@babel/core@^7.0.0", "@babel/core@^7.1.0":
#     version "7.1.0"
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _parse_yarn(text: str) -> list[dict]:
    # berry(v2+)는 YAML 이다 — __metadata 키로 구분한다.
    if "__metadata:" in text[:4000]:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            return []
        out: list[dict] = []
        if isinstance(data, dict):
            for key, meta in data.items():
                if str(key).startswith("__") or not isinstance(meta, dict):
                    continue
                name = str(key).split("@npm:")[0].split(",")[0].strip().strip('"')
                # "@scope/pkg@npm:^1.0.0" → "@scope/pkg"
                if meta.get("version"):
                    out.append({"name": name, "version": str(meta["version"])})
        return _dedupe(out)

    out = []
    current: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            # 항목 헤더 — 여러 스펙이 콤마로 나열될 수 있다. 첫 것에서 이름만 뽑는다.
            spec = raw.split(",")[0].strip().rstrip(":").strip('"')
            # "@scope/pkg@^1.0.0" → "@scope/pkg" / "pkg@^1.0.0" → "pkg"
            at = spec.rfind("@")
            current = spec[:at] if at > 0 else spec
            continue
        m = _YARN_VERSION.match(raw)
        if m and current:
            out.append({"name": current, "version": m.group(1)})
            current = None
    return _dedupe(out)


_PARSERS = {
    "package-lock.json": _parse_package_lock,
    "poetry.lock": _parse_toml_packages,
    "uv.lock": _parse_toml_packages,
    "pnpm-lock.yaml": _parse_pnpm,
    "yarn.lock": _parse_yarn,
}


def parse_lockfile(text: str, filename: str = "") -> dict | None:
    """락파일 → ``{format, ecosystem, packages}``. 형식을 못 알아보면 None.

    파싱은 되었으나 패키지가 0건이면 ``packages: []`` 를 그대로 돌려준다 —
    **0건을 '이상 없음'으로 바꾸지 않는다.** 호출자가 '검사되지 않음'으로
    다뤄야 한다.
    """
    detected = detect_format(text, filename)
    if detected is None:
        return None
    fmt, eco = detected
    packages = _PARSERS[fmt](text)
    return {"format": fmt, "ecosystem": eco, "packages": packages}
