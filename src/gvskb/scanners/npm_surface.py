"""npm 설치 표면 판정 — 프로젝트 자신의 설치 훅 · 락파일의 훅 패키지 · 출처(resolved) · .npmrc.

왜(38차, 2026-10-24)
--------------------
기존 SCA 는 **레지스트리 메타데이터**에서만 설치 훅을 봤다(`package_metadata.py`). 그러면 (1) 프로젝트
자신의 `package.json` 훅, (2) 락파일에만 있는 전이 의존성의 훅, (3) 레지스트리 밖 호스트에서 받는 패키지,
(4) 무결성(integrity) 결손은 보이지 않는다. 2025-08 ~ 2026-08 npm 웜은 전부 설치 훅으로 실행됐고,
npm 12 가 훅을 기본 비활성으로 바꿨지만 공공기관 PC 의 npm 은 대부분 그 이전이다.

훅 **존재**는 악성 판정이 아니다 — `config/install-scripts-allow.yaml` 에 없는 패키지만 검토 신호(likely)로,
한 락파일에 **한 건**으로 묶어 올린다. 프로젝트 자신의 훅이 네트워크·인터프리터 코드 실행이면 confirmed.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ..schema import Finding
from .regex_scanner import build_finding, lookup_rule, redact_evidence

RULE_INSTALL_HOOK = "GOV-NPM-INSTALL-HOOK-001"
RULE_LOCK_SOURCE = "GOV-NPM-LOCK-SOURCE-001"
ENGINE = "npm-surface"
RULE_IDS = (RULE_INSTALL_HOOK, RULE_LOCK_SOURCE)

_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")
_NET_RE = re.compile(r"\b(?:curl|wget|iwr|Invoke-WebRequest|iex|Invoke-Expression|certutil|bitsadmin)\b", re.I)
_INTERP_RE = re.compile(r"\b(?:node\s+-e|node\s+--eval|python3?\s+-c|bash\s+-c|sh\s+-c|powershell[^\n]*-(?:enc|EncodedCommand)|bun\s+(?:x|run)?\s|npx\s+-y|npx\s+--yes)", re.I)
_DECODE_RE = re.compile(r"base64|atob\(|Buffer\.from\([^)]*,\s*['\"](?:base64|hex)", re.I)
_URL_DEP_RE = re.compile(r"^(?:git\+|github:|gitlab:|bitbucket:|git://|https?://|file:|link:|workspace:)", re.I)
_MAX_LIST = 8


# ---------------------------------------------------------------------------
# 허용 목록
# ---------------------------------------------------------------------------

_DEFAULT_ALLOW = {
    "packages": ["sharp", "esbuild", "fsevents", "@swc/core", "@parcel/watcher", "unrs-resolver", "better-sqlite3",
                 "sqlite3", "bcrypt", "node-sass", "sass-embedded", "canvas", "bufferutil", "utf-8-validate",
                 "cpu-features", "ssh2", "lightningcss", "@tailwindcss/oxide", "@rollup/rollup-*", "@next/swc-*",
                 "@biomejs/biome", "@sentry/cli", "turbo", "workerd", "@cloudflare/workerd-*", "protobufjs", "core-js",
                 "core-js-pure", "puppeteer", "playwright", "playwright-core", "cypress", "electron", "@electron/*",
                 "husky", "prisma", "@prisma/engines", "@prisma/client", "nx", "@nx/*", "msw", "patch-package"],
    "project_script_commands": ["husky", "patch-package", "node-gyp", "prisma", "electron-builder", "electron-rebuild",
                                "tsc", "ngcc", "playwright install", "puppeteer browsers", "opencollective",
                                "npm run build", "pnpm run build", "yarn build", "npm run compile"],
    "registry_hosts": ["registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"],
}
_ALLOW_CACHE: dict | None = None


def _resolve_allow_path() -> Path | None:
    override = os.environ.get("GVSKB_INSTALL_SCRIPTS_ALLOW")
    if override:
        return Path(override)
    pkg_root = Path(__file__).resolve().parent.parent
    for cand in (pkg_root.parent.parent / "config" / "install-scripts-allow.yaml",
                 pkg_root / "config" / "install-scripts-allow.yaml"):
        if cand.is_file():
            return cand
    return None


def load_allowlist() -> dict:
    global _ALLOW_CACHE
    if _ALLOW_CACHE is not None:
        return _ALLOW_CACHE
    data: dict = {}
    path = _resolve_allow_path()
    if path is not None:
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, yaml.YAMLError):
            data = {}
    merged = {k: list(data.get(k) or _DEFAULT_ALLOW[k]) for k in _DEFAULT_ALLOW}
    _ALLOW_CACHE = merged
    return merged


def _allowed_package(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pat) for pat in load_allowlist()["packages"])


def _allowed_project_command(cmd: str) -> bool:
    low = cmd.lower()
    return any(tok.lower() in low for tok in load_allowlist()["project_script_commands"])


# ---------------------------------------------------------------------------
# 판정기
# ---------------------------------------------------------------------------

def _emit(rule_id: str, *, rel: str, line: int, evidence: str, confidence: str) -> Finding | None:
    rule = lookup_rule(rule_id)
    if rule is None:
        return None
    return build_finding(rule, filename=rel, line_no=max(1, line), evidence=redact_evidence(evidence)[:240],
                         engine=ENGINE, confidence=confidence)


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def judge_package_json(data, text: str, rel: str) -> list[Finding]:
    """프로젝트 자신의 설치 훅 + 레지스트리 밖 의존성 선언."""
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for hook in _HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        if _NET_RE.search(cmd) or _INTERP_RE.search(cmd) or _DECODE_RE.search(cmd):
            conf, why = "confirmed", "네트워크·인터프리터 코드·디코딩 실행"
        elif _allowed_project_command(cmd):
            continue
        else:
            conf, why = "likely", "허용 목록에 없는 명령"
        f = _emit(RULE_INSTALL_HOOK, rel=rel, line=_line_of(text, f'"{hook}"'),
                  evidence=f"scripts.{hook}: {cmd.strip()[:120]} — {why}", confidence=conf)
        if f:
            out.append(f)
    url_deps: list[str] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, spec in block.items():
                if isinstance(spec, str) and _URL_DEP_RE.match(spec.strip()) and not spec.strip().lower().startswith(("workspace:", "link:")):
                    url_deps.append(f"{name}: {spec.strip()[:60]}")
    if url_deps:
        f = _emit(RULE_LOCK_SOURCE, rel=rel, line=_line_of(text, url_deps[0].split(":")[0]),
                  evidence=f"레지스트리 밖 의존성 {len(url_deps)}건(git/URL/파일): " + " · ".join(url_deps[:_MAX_LIST]),
                  confidence="likely")
        if f:
            out.append(f)
    return out


def _lock_hook_packages_npm(data: dict) -> list[str]:
    pkgs = data.get("packages")
    out: list[str] = []
    if isinstance(pkgs, dict):
        for path, meta in pkgs.items():
            if not path or not isinstance(meta, dict) or not meta.get("hasInstallScript"):
                continue
            name = str(meta.get("name") or path.split("node_modules/")[-1])
            out.append(f"{name}@{meta.get('version') or '?'}")
    deps = data.get("dependencies")   # v1
    if isinstance(deps, dict) and not out:
        def walk(node: dict) -> None:
            for name, meta in node.items():
                if isinstance(meta, dict):
                    if meta.get("hasInstallScript") or meta.get("requiresBuild"):
                        out.append(f"{name}@{meta.get('version') or '?'}")
                    if isinstance(meta.get("dependencies"), dict):
                        walk(meta["dependencies"])
        walk(deps)
    return out


def _lock_sources_npm(data: dict) -> tuple[dict[str, int], int, list[str]]:
    """(호스트별 건수, integrity 결손 수, URL/git 의존성 예)."""
    hosts: dict[str, int] = {}
    missing = 0
    odd: list[str] = []
    pkgs = data.get("packages") if isinstance(data.get("packages"), dict) else {}
    for path, meta in pkgs.items():
        if not path or not isinstance(meta, dict) or meta.get("link"):
            continue
        resolved = str(meta.get("resolved") or "")
        if not resolved:
            continue
        if resolved.startswith(("git+", "git://", "github:")) or (resolved.startswith("http") and not resolved.endswith(".tgz")):
            odd.append(f"{path.split('node_modules/')[-1]} ← {resolved[:70]}")
            continue   # git/URL 출처는 그 자체로 한 항목 — 호스트 집계에 다시 세지 않는다(integrity 도 애초에 없다)
        host = urlparse(resolved).hostname or resolved.split("/")[0]
        hosts[host] = hosts.get(host, 0) + 1
        if not meta.get("integrity") and resolved.startswith("http"):
            missing += 1
    return hosts, missing, odd


def judge_package_lock(data, text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    hooked = [p for p in _lock_hook_packages_npm(data) if not _allowed_package(p.rsplit("@", 1)[0])]
    if hooked:
        more = f" 외 {len(hooked) - _MAX_LIST}건" if len(hooked) > _MAX_LIST else ""
        f = _emit(RULE_INSTALL_HOOK, rel=rel, line=_line_of(text, '"hasInstallScript"'),
                  evidence=f"설치 훅이 있는 패키지 {len(hooked)}건(허용 목록 밖): " + " · ".join(hooked[:_MAX_LIST]) + more,
                  confidence="likely")
        if f:
            out.append(f)
    hosts, missing, odd = _lock_sources_npm(data)
    allowed_hosts = set(load_allowlist()["registry_hosts"])
    foreign = {h: n for h, n in hosts.items() if h and h not in allowed_hosts}
    notes: list[str] = []
    if foreign:
        notes.append("비승인 호스트 " + " · ".join(f"{h}({n})" for h, n in sorted(foreign.items(), key=lambda kv: -kv[1])[:4]))
    if odd:
        notes.append(f"git/URL 출처 {len(odd)}건: " + " · ".join(odd[:3]))
    if missing:
        notes.append(f"integrity 없는 패키지 {missing}건")
    if notes:
        f = _emit(RULE_LOCK_SOURCE, rel=rel, line=_line_of(text, '"resolved"'), evidence=" / ".join(notes), confidence="likely")
        if f:
            out.append(f)
    return out


def judge_pnpm_lock(data, text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    hooked: list[str] = []
    foreign: dict[str, int] = {}
    allowed_hosts = set(load_allowlist()["registry_hosts"])
    for section in ("packages", "snapshots"):
        node = data.get(section)
        if not isinstance(node, dict):
            continue
        for key, meta in node.items():
            if not isinstance(meta, dict):
                continue
            k = str(key).lstrip("/")
            name = k.rsplit("@", 1)[0] if "@" in k[1:] else k
            if meta.get("requiresBuild") and not _allowed_package(name):
                hooked.append(k)
            res = meta.get("resolution") if isinstance(meta.get("resolution"), dict) else {}
            tarball = str(res.get("tarball") or "")
            if tarball:
                host = urlparse(tarball).hostname or ""
                if host and host not in allowed_hosts:
                    foreign[host] = foreign.get(host, 0) + 1
            if res.get("type") == "git" or res.get("repo"):
                foreign["(git)"] = foreign.get("(git)", 0) + 1
    if hooked:
        hooked = sorted(set(hooked))
        more = f" 외 {len(hooked) - _MAX_LIST}건" if len(hooked) > _MAX_LIST else ""
        f = _emit(RULE_INSTALL_HOOK, rel=rel, line=_line_of(text, "requiresBuild"),
                  evidence=f"빌드·설치 훅 패키지 {len(hooked)}건(허용 목록 밖): " + " · ".join(hooked[:_MAX_LIST]) + more, confidence="likely")
        if f:
            out.append(f)
    if foreign:
        f = _emit(RULE_LOCK_SOURCE, rel=rel, line=_line_of(text, "tarball"),
                  evidence="레지스트리 밖 출처: " + " · ".join(f"{h}({n})" for h, n in sorted(foreign.items(), key=lambda kv: -kv[1])[:4]),
                  confidence="likely")
        if f:
            out.append(f)
    return out


def judge_yarn_lock(text: str, rel: str) -> list[Finding]:
    """yarn v1 은 훅 플래그가 없다 — 출처(resolved)만 본다."""
    out: list[Finding] = []
    allowed_hosts = set(load_allowlist()["registry_hosts"])
    foreign: dict[str, int] = {}
    for m in re.finditer(r'^\s+resolved\s+"?([^"\s#]+)', text, re.M):
        url = m.group(1)
        host = urlparse(url).hostname or ""
        if url.startswith(("git+", "git://", "github:")):
            foreign["(git)"] = foreign.get("(git)", 0) + 1
        elif host and host not in allowed_hosts:
            foreign[host] = foreign.get(host, 0) + 1
    if foreign:
        f = _emit(RULE_LOCK_SOURCE, rel=rel, line=1,
                  evidence="레지스트리 밖 출처: " + " · ".join(f"{h}({n})" for h, n in sorted(foreign.items(), key=lambda kv: -kv[1])[:4]),
                  confidence="likely")
        if f:
            out.append(f)
    return out


def judge_npmrc(text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    allowed_hosts = set(load_allowlist()["registry_hosts"])
    for i, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith((";", "#")):
            continue
        key, _, val = s.partition("=")
        key, val = key.strip().lower(), val.strip()
        if key == "ignore-scripts" and val.lower() == "false":
            f = _emit(RULE_INSTALL_HOOK, rel=rel, line=i, evidence="ignore-scripts=false — 설치 훅을 명시적으로 켬", confidence="likely")
            if f:
                out.append(f)
        elif key.endswith("registry") and val:
            host = urlparse(val).hostname or ""
            if val.lower().startswith("http://"):
                f = _emit(RULE_LOCK_SOURCE, rel=rel, line=i, evidence=f"{key}={val[:60]} — 평문 HTTP 레지스트리(중간자가 패키지를 바꿀 수 있음)", confidence="confirmed")
                if f:
                    out.append(f)
            elif host and host not in allowed_hosts:
                f = _emit(RULE_LOCK_SOURCE, rel=rel, line=i, evidence=f"{key}={val[:60]} — 허용 목록 밖 레지스트리(기관 미러면 허용 목록에 등록)", confidence="likely")
                if f:
                    out.append(f)
    return out


def load_json_lenient(text: str):
    return json.loads(text.lstrip(chr(0xFEFF)))
