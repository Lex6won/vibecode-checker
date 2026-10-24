"""프로젝트 런타임 버전 판정 — Node.js·Python·Electron·Next.js 가 EOL 이거나 보안 수정판 미만인가.

왜(38차, 2026-10-24)
--------------------
`diagnostics.runtime_freshness` 는 **체커 자신의** 파이썬만 본다. 검사 대상 프로젝트가 `node:20-alpine`
(2026-04-30 EOL) 위에서 돌거나 Next.js 16.0.x(RSC 수정판 16.2.5 미만)를 쓰는지는 아무도 보지 않았다.
2026-10-21 Node.js 보안 릴리스(Brotli 디코더 RCE 등 10 CVE)는 지원 라인에만 수정이 들어간다 — EOL 라인은
영원히 취약하다.

기준값은 ``config/runtime-baselines.yaml``(날짜 박힌 사본). 보고서는 ``as_of`` 를 함께 적는다 —
"언제 기준으로 낡았다고 했는가"가 없는 판정은 시간이 지나면 거짓말이 된다.

읽는 자리: `.nvmrc` · `.node-version` · `.python-version` · `.tool-versions` · `runtime.txt` · `package.json`
(`engines.node`·`electron`·`next`) · `pyproject.toml`(`requires-python`) · `Dockerfile*`(`FROM node:/python:`)
· 워크플로 `setup-node`/`setup-python` 의 버전. 범위 표기(`>=18`, `^20.1`)는 **하한**을 본다 — 설치될 수 있는
가장 낮은 버전이 판정 대상이다. `lts/*`·`latest` 처럼 수치가 없으면 판정하지 않는다(미확정이지 안전이 아니다).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

import yaml

from ..schema import Finding
from .regex_scanner import build_finding, lookup_rule, redact_evidence

RULE_EOL = "GOV-RUNTIME-EOL-001"
RULE_OUTDATED = "GOV-RUNTIME-OUTDATED-001"
ENGINE = "runtime-version"
RULE_IDS = (RULE_EOL, RULE_OUTDATED)

_DEFAULT_BASELINES = {
    "as_of": "2026-10-24",
    "node": {
        "eol": {"18": "2025-04-30", "20": "2026-04-30", "22": "2027-04-30", "24": "2028-04-30", "26": "2029-04-30"},
        "min_secure": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"},
        "min_secure_reason": "2026-10-21 Node.js 보안 릴리스",
    },
    "python": {
        "eol": {"3.8": "2024-10-07", "3.9": "2025-10-31", "3.10": "2026-10-31", "3.11": "2027-10-31",
                "3.12": "2028-10-31", "3.13": "2029-10-31", "3.14": "2030-10-31"},
        "eol_soon_days": 90,
    },
    "electron": {"supported_majors": [39, 40, 41], "note": ""},
    "next": {"min_secure": {"15": "15.5.16", "16": "16.2.5"}, "eol_below_major": 15, "min_secure_reason": "2026-04~05 RSC 수정판"},
}
_CACHE: dict | None = None


def _resolve_path() -> Path | None:
    override = os.environ.get("GVSKB_RUNTIME_BASELINES")
    if override:
        return Path(override)
    pkg_root = Path(__file__).resolve().parent.parent
    for cand in (pkg_root.parent.parent / "config" / "runtime-baselines.yaml",
                 pkg_root / "config" / "runtime-baselines.yaml"):
        if cand.is_file():
            return cand
    return None


def load_baselines() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    data: dict = {}
    p = _resolve_path()
    if p is not None:
        try:
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, yaml.YAMLError):
            data = {}
    merged = dict(_DEFAULT_BASELINES)
    for k, v in data.items():
        merged[k] = v
    _CACHE = merged
    return merged


# ---------------------------------------------------------------------------
# 버전 파싱
# ---------------------------------------------------------------------------

_VER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_version(spec: str) -> tuple[int, ...] | None:
    """범위·접두어가 섞인 표기에서 **가장 낮은** 수치 버전을 뽑는다. 수치가 없으면 None."""
    s = spec.strip().strip("\"'").lower()
    s = re.sub(r"^(?:v|node|nodejs|python|=|\^|~|>=|>)\s*", "", s)
    if not s or s.startswith(("lts", "latest", "current", "*", "x", "node", "stable", "system")):
        return None
    # "18 || >=20" · ">=18 <21" → 모든 수치 중 최소. "20.x" → 20
    nums = [tuple(int(g) for g in m.groups() if g is not None) for m in _VER_RE.finditer(s)]
    nums = [n for n in nums if n and n[0] < 1000]
    return min(nums) if nums else None


def _ver_tuple(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    la = a + (0,) * (3 - len(a))
    lb = b + (0,) * (3 - len(b))
    return la < lb


@dataclass
class Pin:
    runtime: str        # node | python | electron | next
    spec: str           # 원문
    line: int
    where: str          # 예: Dockerfile FROM · engines.node


# ---------------------------------------------------------------------------
# 추출기 — 파일 종류별
# ---------------------------------------------------------------------------

_DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)", re.I | re.M)
_IMAGE_RE = re.compile(r"^(?:[\w.-]+(?::\d+)?/)?(?:library/)?(?P<name>node|python)(?::(?P<tag>[^@\s]+))?", re.I)


def pins_from_dockerfile(text: str) -> list[Pin]:
    out: list[Pin] = []
    for m in _DOCKER_FROM_RE.finditer(text):
        img = m.group("image")
        im = _IMAGE_RE.match(img)
        if not im or not im.group("tag"):
            continue
        tag = im.group("tag")
        out.append(Pin(im.group("name").lower(), tag, text.count("\n", 0, m.start()) + 1, f"Dockerfile FROM {img}"))
    return out


def pins_from_package_json(data) -> list[Pin]:
    out: list[Pin] = []
    if not isinstance(data, dict):
        return out
    engines = data.get("engines") if isinstance(data.get("engines"), dict) else {}
    if isinstance(engines.get("node"), str):
        out.append(Pin("node", engines["node"], 1, "engines.node"))
    deps = {}
    for key in ("dependencies", "devDependencies"):
        if isinstance(data.get(key), dict):
            deps.update(data[key])
    for pkg, rt in (("electron", "electron"), ("next", "next")):
        v = deps.get(pkg)
        if isinstance(v, str):
            out.append(Pin(rt, v, 1, f"package.json {pkg}"))
    return out


def pins_from_version_file(name: str, text: str) -> list[Pin]:
    low = name.lower()
    first = next((ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")), "")
    if not first:
        return []
    if low in (".nvmrc", ".node-version"):
        return [Pin("node", first, 1, name)]
    if low == ".python-version":
        return [Pin("python", first, 1, name)]
    if low == "runtime.txt":
        return [Pin("python", first, 1, name)] if "python" in first.lower() else []
    if low == ".tool-versions":
        out: list[Pin] = []
        for i, ln in enumerate(text.splitlines(), start=1):
            parts = ln.split()
            if len(parts) >= 2 and parts[0].lower() in ("nodejs", "node"):
                out.append(Pin("node", parts[1], i, ".tool-versions nodejs"))
            elif len(parts) >= 2 and parts[0].lower() == "python":
                out.append(Pin("python", parts[1], i, ".tool-versions python"))
        return out
    return []


def pins_from_pyproject(text: str) -> list[Pin]:
    m = re.search(r'^\s*requires-python\s*=\s*"([^"]+)"', text, re.M)
    return [Pin("python", m.group(1), text.count("\n", 0, m.start()) + 1, "pyproject requires-python")] if m else []


def pins_from_workflow(text: str) -> list[Pin]:
    out: list[Pin] = []
    for m in re.finditer(r"^\s*node-version:\s*['\"]?([^'\"\n#]+)", text, re.M):
        out.append(Pin("node", m.group(1).strip(), text.count("\n", 0, m.start()) + 1, "workflow setup-node"))
    for m in re.finditer(r"^\s*python-version:\s*['\"]?([^'\"\n#]+)", text, re.M):
        out.append(Pin("python", m.group(1).strip(), text.count("\n", 0, m.start()) + 1, "workflow setup-python"))
    return out


# ---------------------------------------------------------------------------
# 판정
# ---------------------------------------------------------------------------

def _emit(rule_id: str, *, rel: str, line: int, evidence: str) -> Finding | None:
    rule = lookup_rule(rule_id)
    if rule is None:
        return None
    return build_finding(rule, filename=rel, line_no=max(1, line), evidence=redact_evidence(evidence)[:240],
                         engine=ENGINE, confidence="likely")


def _today() -> date:
    env = os.environ.get("GVSKB_TODAY")
    if env:
        try:
            return date.fromisoformat(env)
        except ValueError:
            pass
    return date.today()


def judge_pins(pins: list[Pin], rel: str) -> list[Finding]:
    """핀 목록 → 발견. 같은 파일·같은 런타임은 가장 낮은 버전 1건만 올린다."""
    base = load_baselines()
    as_of = base.get("as_of", "?")
    today = _today()
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for pin in pins:
        ver = _parse_version(pin.spec)
        if ver is None:
            continue
        key = (pin.runtime, "")
        if pin.runtime == "node":
            node = base["node"]
            major = str(ver[0])
            eol_date = node["eol"].get(major)
            if eol_date is None and ver[0] < min(int(k) for k in node["eol"]):
                eol_date = "지원 목록 이전"
            if eol_date and (eol_date == "지원 목록 이전" or date.fromisoformat(eol_date) <= today):
                key = ("node", "eol")
                if key not in seen:
                    seen.add(key)
                    f = _emit(RULE_EOL, rel=rel, line=pin.line,
                              evidence=f"{pin.where}: Node.js {pin.spec} → 메이저 {major} 지원 종료({eol_date}) — 보안 수정 없음 (기준 {as_of})")
                    if f:
                        out.append(f)
                continue
            ms = node.get("min_secure", {}).get(major)
            if ms and len(ver) >= 3 and _lt(ver, _ver_tuple(ms)):
                key = ("node", "outdated")
                if key not in seen:
                    seen.add(key)
                    f = _emit(RULE_OUTDATED, rel=rel, line=pin.line,
                              evidence=f"{pin.where}: Node.js {pin.spec} < 최소 보안 릴리스 {ms} — {node.get('min_secure_reason', '')} (기준 {as_of})")
                    if f:
                        out.append(f)
        elif pin.runtime == "python":
            py = base["python"]
            mm = f"{ver[0]}.{ver[1]}" if len(ver) >= 2 else None
            if mm is None:
                continue
            eol_date = py["eol"].get(mm)
            known = sorted(py["eol"], key=lambda k: _ver_tuple(k))
            if eol_date is None and _lt(ver, _ver_tuple(known[0])):
                eol_date = "지원 목록 이전"
            if eol_date is None:
                continue
            soon = int(py.get("eol_soon_days", 90))
            if eol_date == "지원 목록 이전" or date.fromisoformat(eol_date) <= today:
                key = ("python", "eol")
                if key not in seen:
                    seen.add(key)
                    f = _emit(RULE_EOL, rel=rel, line=pin.line,
                              evidence=f"{pin.where}: Python {pin.spec} → {mm} 지원 종료({eol_date}) (기준 {as_of})")
                    if f:
                        out.append(f)
            elif date.fromisoformat(eol_date) <= today + timedelta(days=soon):
                key = ("python", "eol-soon")
                if key not in seen:
                    seen.add(key)
                    f = _emit(RULE_EOL, rel=rel, line=pin.line,
                              evidence=f"{pin.where}: Python {pin.spec} → {mm} 지원 종료 임박({eol_date}, {(date.fromisoformat(eol_date) - today).days}일 뒤) — 교체 계획 필요 (기준 {as_of})")
                    if f:
                        out.append(f)
        elif pin.runtime == "electron":
            el = base["electron"]
            supported = [int(x) for x in el.get("supported_majors", [])]
            if supported and ver[0] < min(supported):
                key = ("electron", "eol")
                if key not in seen:
                    seen.add(key)
                    f = _emit(RULE_EOL, rel=rel, line=pin.line,
                              evidence=f"{pin.where}: Electron {pin.spec} → 메이저 {ver[0]} 은 지원 밖(지원: {', '.join(map(str, supported))}). "
                                       f"내장 Chromium·Node 도 함께 낡는다 — PC 의 node -v 와 무관 (기준 {as_of})")
                    if f:
                        out.append(f)
        elif pin.runtime == "next":
            nx = base["next"]
            major = str(ver[0])
            if ver[0] < int(nx.get("eol_below_major", 0)):
                key = ("next", "eol")
                if key not in seen:
                    seen.add(key)
                    f = _emit(RULE_EOL, rel=rel, line=pin.line,
                              evidence=f"{pin.where}: Next.js {pin.spec} → 메이저 {major} 는 보안 수정 대상 밖 (기준 {as_of})")
                    if f:
                        out.append(f)
                continue
            ms = nx.get("min_secure", {}).get(major)
            if ms and len(ver) >= 2 and _lt(ver, _ver_tuple(ms)):
                key = ("next", "outdated")
                if key not in seen:
                    seen.add(key)
                    f = _emit(RULE_OUTDATED, rel=rel, line=pin.line,
                              evidence=f"{pin.where}: Next.js {pin.spec} < 수정판 {ms} — {nx.get('min_secure_reason', '')} (기준 {as_of})")
                    if f:
                        out.append(f)
    return out
