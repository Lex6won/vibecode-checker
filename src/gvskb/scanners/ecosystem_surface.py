"""생태계별 보안 설정 판정 — Electron · VS Code 확장 · Chrome 확장 · MCP 서버 소스 (40차, 2026-10-25).

해당 생태계 의존성이 **있을 때만** 켜진다(`detect_ecosystems`). 평범한 Python/JS 업무 앱에는 비용 0.
설정·구조 해석 중심이라 값이 곧 판정인 것은 confirmed, 보강 권고는 likely(경고)로 둔다. 어떤 파일도 실행하지 않는다.

- Electron: 렌더러에 Node 권한을 주는 webPreferences · preload 가 ipcRenderer/require 를 통째로 노출 · 권한 있는
  ipcMain 핸들러의 발신자 검증 부재 · shell.openExternal 미검증 · fuses·CSP 등 배포 강화 누락.
- VS Code 확장: 확장 호스트는 VS Code 와 같은 권한이다 — 저장소 설정값이 명령으로 실행되는가, Workspace Trust,
  webview CSP, 메시지 경계를 본다(manifest 권한 모델이 없으므로 Chrome 식으로 보지 않는다).
- Chrome 확장: 광범위 권한 + 민감 API, 응답 보안 헤더 제거 규칙, 발신자 검증 없는 메시지 경계, 원격 코드 로드.
- MCP 서버: 도구 인자가 검증 없이 실행·파일·SQL·요청에 닿는가, HTTP 전송의 바인딩·Origin, 토큰 패스스루.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..schema import Finding, SkippedFile
from .regex_scanner import build_finding, lookup_rule, redact_evidence

ENGINE = "ecosystem-surface"
CATEGORY = "platform-security"
RULE_ELECTRON_WEBPREFS = "GOV-ELECTRON-WEBPREFS-001"
RULE_ELECTRON_IPC = "GOV-ELECTRON-IPC-BRIDGE-001"
RULE_ELECTRON_HARDENING = "GOV-ELECTRON-HARDENING-001"
RULE_VSCODE_TRUST = "GOV-VSCODE-EXT-TRUST-001"
RULE_CHROME_PERMISSION = "GOV-CHROME-EXT-PERMISSION-001"
RULE_CHROME_HEADER = "GOV-CHROME-EXT-HEADER-STRIP-001"
RULE_CHROME_MESSAGE = "GOV-CHROME-EXT-MESSAGE-001"
RULE_MCP_SERVER = "GOV-MCP-SERVER-001"
RULE_IDS = (RULE_ELECTRON_WEBPREFS, RULE_ELECTRON_IPC, RULE_ELECTRON_HARDENING, RULE_VSCODE_TRUST,
            RULE_CHROME_PERMISSION, RULE_CHROME_HEADER, RULE_CHROME_MESSAGE, RULE_MCP_SERVER)

_HARD_EXCLUDE = frozenset({".git", "node_modules", "dist", "build", "out", ".next", "__pycache__", ".venv", "venv",
                           ".cache", ".turbo", ".check-reports", "coverage", "vendor"})
_JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
_PY = (".py",)
_MAX_BYTES = 2_000_000
PolicyFn = Callable[[list[Finding], str], list[Finding]]


@dataclass
class EcoEntry:
    path: str
    kind: str
    parsed: bool = True
    note: str = ""
    finding_count: int = 0

    def as_dict(self) -> dict:
        return {"path": self.path, "kind": self.kind, "parsed": self.parsed, "note": self.note,
                "finding_count": self.finding_count}


@dataclass
class EcoResult:
    active: set[str] = field(default_factory=set)
    entries: list[EcoEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


def _read(p: Path) -> str | None:
    try:
        if p.stat().st_size > _MAX_BYTES:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _emit(rule_id: str, *, rel: str, line: int, evidence: str, confidence: str) -> Finding | None:
    rule = lookup_rule(rule_id)
    if rule is None:
        return None
    return build_finding(rule, filename=rel, line_no=max(1, line), evidence=redact_evidence(evidence)[:240],
                         engine=ENGINE, confidence=confidence)


def _ln(text: str, m: re.Match | int) -> int:
    pos = m if isinstance(m, int) else m.start()
    return text.count("\n", 0, pos) + 1


def _window(text: str, pos: int, before: int = 2, after: int = 12) -> str:
    lines = text.splitlines()
    ln = text.count("\n", 0, pos)
    return "\n".join(lines[max(0, ln - before): ln + after + 1])


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _HARD_EXCLUDE]
        for name in filenames:
            yield Path(dirpath) / name


# ---------------------------------------------------------------------------
# 활성 생태계 판정
# ---------------------------------------------------------------------------

def _json(text: str):
    try:
        return json.loads(text.lstrip(chr(0xFEFF)))
    except ValueError:
        return None


def detect_ecosystems(root: Path) -> tuple[set[str], list[tuple[Path, str]]]:
    """(활성 집합, 매니페스트 목록). package.json 의존성·engines, manifest.json, Python 의존성으로 판정."""
    active: set[str] = set()
    manifests: list[tuple[Path, str]] = []
    for p in _walk(root):
        low = p.name.lower()
        if low == "package.json":
            data = _json(_read(p) or "")
            if not isinstance(data, dict):
                continue
            deps = {}
            for k in ("dependencies", "devDependencies", "peerDependencies"):
                if isinstance(data.get(k), dict):
                    deps.update(data[k])
            if "electron" in deps:
                active.add("electron")
                manifests.append((p, "electron-manifest"))
            if isinstance(data.get("engines"), dict) and "vscode" in data["engines"]:
                active.add("vscode-ext")
                manifests.append((p, "vscode-manifest"))
            if "@modelcontextprotocol/sdk" in deps or "fastmcp" in deps:
                active.add("mcp-server")
        elif low == "manifest.json":
            data = _json(_read(p) or "")
            if isinstance(data, dict) and "manifest_version" in data and ("permissions" in data or "background" in data
                                                                            or "content_scripts" in data or "action" in data
                                                                            or "browser_action" in data):
                active.add("chrome-ext")
                manifests.append((p, "chrome-manifest"))
        elif low in ("requirements.txt", "pyproject.toml") or (low.startswith("requirements") and low.endswith(".txt")):
            text = (_read(p) or "").lower()
            if re.search(r"^\s*(?:fastmcp|mcp)\b", text, re.M) or '"fastmcp' in text or '"mcp' in text or "fastmcp" in text:
                active.add("mcp-server")
        elif low in ("forge.config.js", "forge.config.ts", "electron-builder.yml", "electron-builder.json", "electron-builder.config.js"):
            manifests.append((p, "electron-builder"))
    return active, manifests


# ---------------------------------------------------------------------------
# Electron
# ---------------------------------------------------------------------------

_BW_RE = re.compile(r"new\s+BrowserWindow\s*\(")
_REMOTE_LOAD_RE = re.compile(r"\bloadURL\s*\(\s*['\"`]https?://(?!localhost|127\.0\.0\.1)", re.I)
_WEBPREF_BAD = (
    (re.compile(r"\bnodeIntegration\s*:\s*true"), "nodeIntegration: true"),
    (re.compile(r"\bcontextIsolation\s*:\s*false"), "contextIsolation: false"),
    (re.compile(r"\bsandbox\s*:\s*false"), "sandbox: false"),
    (re.compile(r"\bwebSecurity\s*:\s*false"), "webSecurity: false"),
    (re.compile(r"\ballowRunningInsecureContent\s*:\s*true"), "allowRunningInsecureContent: true"),
    (re.compile(r"\bnodeIntegrationInWorker\s*:\s*true|\bnodeIntegrationInSubFrames\s*:\s*true"), "nodeIntegrationIn(Worker|SubFrames): true"),
    (re.compile(r"\bexperimentalFeatures\s*:\s*true"), "experimentalFeatures: true"),
    (re.compile(r"\bwebviewTag\s*:\s*true"), "webviewTag: true"),
)
_BRIDGE_WHOLESALE = re.compile(
    r"exposeInMainWorld\s*\(\s*['\"][\w$]+['\"]\s*,\s*(?:ipcRenderer\b|require\b|process\b|\{[^}]*\b(?:ipcRenderer|require|process|shell|fs)\s*[,}])",
)
_BRIDGE_GENERIC_CHANNEL = re.compile(
    r"exposeInMainWorld[\s\S]{0,400}?\(\s*(?:channel|ch|name|event|evt)\s*,[^)]*\)\s*=>\s*ipcRenderer\s*\.\s*(?:send|invoke|sendSync)\s*\(\s*(?:channel|ch|name|event|evt)\b",
)
_IPC_HANDLER_RE = re.compile(r"ipcMain\s*\.\s*(?:handle|on|handleOnce|once)\s*\(\s*['\"`][^'\"`]+['\"`]\s*,")
_PRIV_API_RE = re.compile(
    r"\bfs\s*\.\s*(?:readFile|writeFile|unlink|rm|rmdir|readdir|createWriteStream)\w*\s*\(|\bchild_process\b|\bexec(?:Sync|File)?\s*\(|\bspawn\s*\(|"
    r"\bshell\s*\.\s*(?:openExternal|openPath|trashItem)\s*\(|\bdialog\s*\.\s*show\w+Sync\s*\(|\bfetch\s*\(|\bnet\s*\.\s*request\s*\(",
)
_SENDER_CHECK_RE = re.compile(r"senderFrame|event\s*\.\s*sender\s*\.\s*getURL|sender\s*\.\s*getURL|new\s+URL\s*\(\s*(?:event|e)\s*\.\s*sender|validateSender|isTrustedSender|allowedOrigins|ALLOWED_ORIGINS")
_OPEN_EXTERNAL_RE = re.compile(r"shell\s*\.\s*openExternal\s*\(\s*(?!['\"`]https?://)([^)'\"`][^)]*)\)")
_PROTO_CHECK_RE = re.compile(r"startsWith\s*\(\s*['\"]https?:|new\s+URL\s*\([^)]*\)\s*\.\s*protocol|protocol\s*(?:===?|!==?)\s*['\"]https?:|ALLOWED_PROTOCOLS|isSafeUrl|isAllowedUrl")
_DEVTOOLS_MODE_RE = re.compile(r"openDevTools\s*\(\s*\{[^}]*\bmode\s*:\s*(?!['\"])[\w.$\[\]]+")
_WINDOW_OPEN_HANDLER_RE = re.compile(r"setWindowOpenHandler|will-navigate|will-redirect")
_CSP_RE = re.compile(r"Content-Security-Policy", re.I)
_PERMISSION_HANDLER_RE = re.compile(r"setPermissionRequestHandler|setPermissionCheckHandler")
_FUSES_RE = re.compile(r"FuseV1Options|@electron/fuses|flipFuses|FusesPlugin", re.I)
_FUSE_KEYS = ("RunAsNode", "EnableNodeOptionsEnvironmentVariable", "EnableNodeCliInspectArguments", "OnlyLoadAppFromAsar",
              "EnableEmbeddedAsarIntegrityValidation")


def judge_electron_source(text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    remote = _REMOTE_LOAD_RE.search(text) is not None
    # 1) webPreferences
    for m in _BW_RE.finditer(text):
        win = _window(text, m.start(), 0, 40)
        bad = [label for pat, label in _WEBPREF_BAD if pat.search(win)]
        if not bad:
            continue
        conf = "confirmed" if remote else "likely"
        ev = f"BrowserWindow webPreferences: {', '.join(bad)}" + (" + 원격 URL 로드" if remote else " (로컬 콘텐츠만 — 원격 로드 시 차단)")
        f = _emit(RULE_ELECTRON_WEBPREFS, rel=rel, line=_ln(text, m), evidence=ev, confidence=conf)
        if f:
            out.append(f)
    # 2) preload bridge
    m = _BRIDGE_WHOLESALE.search(text)
    if m:
        f = _emit(RULE_ELECTRON_IPC, rel=rel, line=_ln(text, m), evidence="contextBridge 가 ipcRenderer/require/process/shell/fs 를 통째로 노출", confidence="confirmed")
        if f:
            out.append(f)
    m = _BRIDGE_GENERIC_CHANNEL.search(text)
    if m:
        f = _emit(RULE_ELECTRON_IPC, rel=rel, line=_ln(text, m), evidence="contextBridge 가 채널명을 인자로 받는 범용 send/invoke 래퍼를 노출(모든 IPC 채널 개방)", confidence="confirmed")
        if f:
            out.append(f)
    # 3) ipcMain privileged handler without sender validation
    for m in _IPC_HANDLER_RE.finditer(text):
        win = _window(text, m.start(), 0, 25)
        if _PRIV_API_RE.search(win) and not _SENDER_CHECK_RE.search(win) and not _SENDER_CHECK_RE.search(text[:m.start()][-1500:]):
            f = _emit(RULE_ELECTRON_IPC, rel=rel, line=_ln(text, m),
                      evidence="ipcMain 핸들러가 파일·프로세스·외부 요청 API 를 호출하지만 발신자(senderFrame) 검증이 없음", confidence="likely")
            if f:
                out.append(f)
            break   # 파일당 1건
    # 4) shell.openExternal(변수) without protocol check
    m = _OPEN_EXTERNAL_RE.search(text)
    if m and not _PROTO_CHECK_RE.search(_window(text, m.start(), 8, 2)):
        f = _emit(RULE_ELECTRON_IPC, rel=rel, line=_ln(text, m), evidence="shell.openExternal 에 비상수 URL — 프로토콜 허용 목록 검사 없음(file:/javascript: 등 통과 가능)", confidence="likely")
        if f:
            out.append(f)
    # 5) openDevTools mode from variable
    m = _DEVTOOLS_MODE_RE.search(text)
    if m:
        f = _emit(RULE_ELECTRON_IPC, rel=rel, line=_ln(text, m), evidence="webContents.openDevTools 의 mode 가 비상수 — 입력이 닿으면 DevTools 컨텍스트 코드 실행", confidence="likely")
        if f:
            out.append(f)
    # 6) hardening with remote content
    if remote:
        gaps = []
        if not _WINDOW_OPEN_HANDLER_RE.search(text):
            gaps.append("setWindowOpenHandler/will-navigate 없음")
        if not _PERMISSION_HANDLER_RE.search(text):
            gaps.append("setPermissionRequestHandler 없음")
        if gaps:
            f = _emit(RULE_ELECTRON_HARDENING, rel=rel, line=_ln(text, _REMOTE_LOAD_RE.search(text)),
                      evidence="원격 콘텐츠 로드 + " + " · ".join(gaps), confidence="likely")
            if f:
                out.append(f)
    return out


def judge_electron_builder(text: str, rel: str) -> list[Finding]:
    if not _FUSES_RE.search(text):
        f = _emit(RULE_ELECTRON_HARDENING, rel=rel, line=1,
                  evidence="빌드 설정에 Electron fuses 미설정(RunAsNode·NodeOptions·Inspect 끄기, OnlyLoadAppFromAsar·ASAR 무결성 켜기)", confidence="likely")
        return [f] if f else []
    missing = [k for k in _FUSE_KEYS if k not in text]
    if missing:
        f = _emit(RULE_ELECTRON_HARDENING, rel=rel, line=_ln(text, _FUSES_RE.search(text)),
                  evidence="fuses 설정에 빠진 항목: " + ", ".join(missing), confidence="likely")
        return [f] if f else []
    return []


# ---------------------------------------------------------------------------
# VS Code 확장
# ---------------------------------------------------------------------------

_VS_CONFIG_GET = re.compile(r"getConfiguration\s*\([^)]*\)\s*\.\s*get\s*(?:<[^>]+>)?\s*\(\s*['\"]([\w.]*(?:path|command|cmd|args|executable|binary|shell|script)[\w.]*)['\"]", re.I)
_VS_EXEC = re.compile(r"\b(?:exec|execSync|execFile|spawn|spawnSync)\s*\(|terminal\s*\.\s*sendText\s*\(|createTerminal\s*\(\s*\{[^}]*shellPath", re.I)
_VS_WEBVIEW_SCRIPTS = re.compile(r"enableScripts\s*:\s*true")
_VS_WEBVIEW_HTML_CONCAT = re.compile(r"webview\s*\.\s*html\s*=\s*(?:`[^`]*\$\{|[^;]*\+\s*[\w.$]+)")
_VS_MSG_HANDLER = re.compile(r"onDidReceiveMessage\s*\(")
_VS_STARTUP = re.compile(r"\bactivationEvents\b")


def judge_vscode_manifest(data: dict, text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    events = data.get("activationEvents") if isinstance(data.get("activationEvents"), list) else []
    if any(e in ("*", "onStartupFinished") for e in events):
        f = _emit(RULE_VSCODE_TRUST, rel=rel, line=_ln(text, text.find("activationEvents")),
                  evidence=f"activationEvents {[e for e in events if e in ('*', 'onStartupFinished')]} — 모든 워크스페이스에서 즉시 활성(신뢰하지 않은 폴더 포함)", confidence="likely")
        if f:
            out.append(f)
    caps = data.get("capabilities") if isinstance(data.get("capabilities"), dict) else {}
    utw = caps.get("untrustedWorkspaces") if isinstance(caps.get("untrustedWorkspaces"), dict) else None
    if utw is None:
        f = _emit(RULE_VSCODE_TRUST, rel=rel, line=1, evidence="capabilities.untrustedWorkspaces 미선언 — Workspace Trust 동작이 기본값(제한 모드에서 비활성)에 의존", confidence="pattern-only")
        if f:
            out.append(f)
    elif utw.get("supported") is True:
        f = _emit(RULE_VSCODE_TRUST, rel=rel, line=_ln(text, text.find("untrustedWorkspaces")),
                  evidence="untrustedWorkspaces.supported = true — 신뢰하지 않은 저장소의 설정값이 확장에 그대로 들어감(소스에서 설정→실행 경로 확인)", confidence="likely")
        if f:
            out.append(f)
    packs = []
    for key in ("extensionPack", "extensionDependencies"):
        v = data.get(key)
        if isinstance(v, list):
            packs += [str(x) for x in v]
    if packs:
        f = _emit(RULE_VSCODE_TRUST, rel=rel, line=_ln(text, text.find("extensionPack") if "extensionPack" in text else text.find("extensionDependencies")),
                  evidence=f"extensionPack/extensionDependencies {len(packs)}개 — 설치 시 함께 끌려오는 확장(승인 목록 대조 필요): " + ", ".join(packs[:6]), confidence="pattern-only")
        if f:
            out.append(f)
    return out


def judge_vscode_source(text: str, rel: str, *, untrusted_supported: bool) -> list[Finding]:
    out: list[Finding] = []
    m = _VS_CONFIG_GET.search(text)
    if m and _VS_EXEC.search(text):
        conf = "confirmed" if untrusted_supported else "likely"
        f = _emit(RULE_VSCODE_TRUST, rel=rel, line=_ln(text, m),
                  evidence=f"워크스페이스 설정값 `{m.group(1)}` 을 읽는 파일이 프로세스/터미널 실행도 함 — 저장소 .vscode/settings.json 으로 실행 경로 조작 가능"
                           + (" (untrustedWorkspaces.supported=true)" if untrusted_supported else ""), confidence=conf)
        if f:
            out.append(f)
    if _VS_WEBVIEW_SCRIPTS.search(text):
        if not _CSP_RE.search(text):
            f = _emit(RULE_VSCODE_TRUST, rel=rel, line=_ln(text, _VS_WEBVIEW_SCRIPTS.search(text)), evidence="webview enableScripts: true 인데 Content-Security-Policy 메타가 없음", confidence="likely")
            if f:
                out.append(f)
        m2 = _VS_WEBVIEW_HTML_CONCAT.search(text)
        if m2:
            f = _emit(RULE_VSCODE_TRUST, rel=rel, line=_ln(text, m2), evidence="webview.html 을 문자열 결합/보간으로 조립 — 외부 값이 스크립트로 들어갈 수 있음", confidence="likely")
            if f:
                out.append(f)
    m3 = _VS_MSG_HANDLER.search(text)
    if m3 and _VS_EXEC.search(_window(text, m3.start(), 0, 30)):
        f = _emit(RULE_VSCODE_TRUST, rel=rel, line=_ln(text, m3), evidence="onDidReceiveMessage 핸들러 근처에서 프로세스/터미널 실행 — 메시지 필드 검증·분기 확인", confidence="likely")
        if f:
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Chrome 확장
# ---------------------------------------------------------------------------

_SENSITIVE_PERMS = {"cookies", "webRequest", "webRequestBlocking", "scripting", "tabs", "history", "clipboardRead",
                    "nativeMessaging", "debugger", "declarativeNetRequest", "declarativeNetRequestWithHostAccess", "management", "proxy"}
_SECURITY_HEADERS = ("content-security-policy", "x-frame-options", "strict-transport-security", "content-security-policy-report-only")
_CH_HEADER_STRIP_SRC = re.compile(
    r"(?:header|name)\s*:\s*['\"](?:content-security-policy|x-frame-options|strict-transport-security)['\"][^}]{0,120}?(?:operation\s*:\s*['\"]remove['\"]|value\s*:\s*['\"]\s*['\"])"
    r"|responseHeaders[\s\S]{0,300}?(?:filter|splice|delete)[^\n]{0,80}(?:content-security-policy|x-frame-options|strict-transport-security)",
    re.I,
)
_CH_REMOTE_CODE = re.compile(r"<script[^>]+src\s*=\s*['\"]https?://|import\s*\(\s*['\"`]https?://|\beval\s*\(\s*(?:await\s+)?(?:fetch|xhr|resp)|new\s+Function\s*\([^)]*(?:fetch|resp|data)", re.I)
_CH_MSG_HANDLER = re.compile(r"runtime\s*\.\s*onMessage(?:External)?\s*\.\s*addListener\s*\(")
_CH_SENDER_CHECK = re.compile(r"sender\s*\.\s*(?:id|origin|url|tab)\b|chrome\s*\.\s*runtime\s*\.\s*id\b|ALLOWED_(?:ORIGINS|SENDERS|IDS)")
_CH_SENSITIVE_API = re.compile(r"chrome\s*\.\s*(?:cookies|scripting|tabs\s*\.\s*(?:executeScript|captureVisibleTab)|history|storage|debugger|downloads)\s*\.|\bfetch\s*\(", re.I)
_WEBSTORE_UPDATE = re.compile(r"clients2\.google\.com/service/update2/crx|edge\.microsoft\.com/extensionwebstorebase|addons\.mozilla\.org", re.I)


def judge_chrome_manifest(data: dict, text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    mv = data.get("manifest_version")
    if mv == 2:
        f = _emit(RULE_CHROME_PERMISSION, rel=rel, line=_ln(text, text.find("manifest_version")), evidence="manifest_version 2 — Chrome 지원 종료·스토어 거부 대상", confidence="likely")
        if f:
            out.append(f)
    perms = set(str(x) for x in (data.get("permissions") or []) if isinstance(x, str))
    hosts = [str(x) for x in (data.get("host_permissions") or []) if isinstance(x, str)]
    for cs in data.get("content_scripts") or []:
        if isinstance(cs, dict):
            hosts += [str(x) for x in (cs.get("matches") or []) if isinstance(x, str)]
    if mv == 2:
        hosts += [p for p in perms if "://" in p or p == "<all_urls>"]
    broad = [h for h in hosts if h == "<all_urls>" or re.match(r"^\*://\*/|^https?://\*/", h)]
    sens = sorted(perms & _SENSITIVE_PERMS)
    if broad and len(sens) >= 2:
        f = _emit(RULE_CHROME_PERMISSION, rel=rel, line=_ln(text, text.find(broad[0]) if broad[0] in text else 1),
                  evidence=f"광역 호스트 권한({broad[0]}) + 민감 권한 {len(sens)}개({', '.join(sens[:5])}) — 모든 사이트의 쿠키·스크립트·탭에 닿음", confidence="likely")
        if f:
            out.append(f)
    ec = data.get("externally_connectable") if isinstance(data.get("externally_connectable"), dict) else {}
    ec_matches = [str(x) for x in (ec.get("matches") or []) if isinstance(x, str)]
    ec_ids = [str(x) for x in (ec.get("ids") or []) if isinstance(x, str)]
    if any(m in ("*://*/*", "https://*/*", "http://*/*", "<all_urls>") for m in ec_matches) or "*" in ec_ids:
        f = _emit(RULE_CHROME_PERMISSION, rel=rel, line=_ln(text, text.find("externally_connectable")),
                  evidence="externally_connectable 이 모든 사이트/확장에 열림 — 어느 웹페이지든 확장에 메시지를 보낼 수 있음", confidence="confirmed")
        if f:
            out.append(f)
    csp = data.get("content_security_policy")
    csp_text = json.dumps(csp, ensure_ascii=False) if csp is not None else ""
    if "unsafe-eval" in csp_text or re.search(r"script-src[^;\"']*https?://", csp_text):
        f = _emit(RULE_CHROME_HEADER, rel=rel, line=_ln(text, text.find("content_security_policy")),
                  evidence="확장 CSP 에 unsafe-eval 또는 원격 script-src — 원격 코드 실행 허용", confidence="confirmed")
        if f:
            out.append(f)
    upd = str(data.get("update_url") or "")
    if upd and not _WEBSTORE_UPDATE.search(upd):
        f = _emit(RULE_CHROME_PERMISSION, rel=rel, line=_ln(text, text.find("update_url")), evidence=f"update_url 이 공식 스토어가 아님({upd[:60]}) — 사이드로드 자동 업데이트", confidence="likely")
        if f:
            out.append(f)
    return out


def judge_chrome_rules_json(data, text: str, rel: str) -> list[Finding]:
    """declarativeNetRequest 규칙 파일 — 응답 보안 헤더 제거."""
    out: list[Finding] = []
    rules = data if isinstance(data, list) else (data.get("rules") if isinstance(data, dict) else None)
    if not isinstance(rules, list):
        return out
    for r in rules:
        action = r.get("action") if isinstance(r, dict) else None
        if not isinstance(action, dict):
            continue
        for h in action.get("responseHeaders") or []:
            if isinstance(h, dict) and str(h.get("header", "")).lower() in _SECURITY_HEADERS and str(h.get("operation", "")).lower() in ("remove", "set"):
                f = _emit(RULE_CHROME_HEADER, rel=rel, line=_ln(text, text.find(str(h.get("header")))),
                          evidence=f"declarativeNetRequest 가 응답의 {h.get('header')} 를 {h.get('operation')} — 방문 사이트의 보안 헤더를 벗김", confidence="confirmed")
                if f:
                    out.append(f)
                break
    return out


def judge_chrome_source(text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    m = _CH_HEADER_STRIP_SRC.search(text)
    if m:
        f = _emit(RULE_CHROME_HEADER, rel=rel, line=_ln(text, m), evidence="코드가 응답의 보안 헤더(CSP/X-Frame-Options/HSTS)를 제거·비움", confidence="confirmed")
        if f:
            out.append(f)
    m = _CH_REMOTE_CODE.search(text)
    if m:
        f = _emit(RULE_CHROME_HEADER, rel=rel, line=_ln(text, m), evidence="원격 코드 로드/실행(원격 script src · import(https) · fetch→eval) — MV3 금지, 사후 페이로드 교체 경로", confidence="confirmed")
        if f:
            out.append(f)
    for m in _CH_MSG_HANDLER.finditer(text):
        win = _window(text, m.start(), 0, 25)
        if _CH_SENSITIVE_API.search(win) and not _CH_SENDER_CHECK.search(win):
            ext = "External" in m.group(0)
            f = _emit(RULE_CHROME_MESSAGE, rel=rel, line=_ln(text, m),
                      evidence=f"runtime.onMessage{'External' if ext else ''} 핸들러가 sender 검증 없이 민감 API/네트워크 호출", confidence="confirmed" if ext else "likely")
            if f:
                out.append(f)
            break
    return out


# ---------------------------------------------------------------------------
# MCP 서버 소스
# ---------------------------------------------------------------------------

_MCP_IMPORT = re.compile(r"@modelcontextprotocol/sdk|from\s+(?:fastmcp|mcp)\b|import\s+(?:fastmcp|mcp)\b")
_MCP_TOOL_DEF = re.compile(r"@(?:mcp|server|app)\s*\.\s*tool\s*\(|server\s*\.\s*(?:tool|registerTool|setRequestHandler)\s*\(|@tool\b")
_MCP_ARG_SINK_PY = re.compile(r"(?:subprocess\s*\.\s*(?:run|Popen|call|check_output)|os\s*\.\s*(?:system|popen)|\beval\s*\(|\bexec\s*\()\s*\(?[^)\n]{0,80}\b(?:shell\s*=\s*True|f['\"]|\+\s*\w+|\.format\()")
_MCP_ARG_SINK_JS = re.compile(r"\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|[^,)]*\+\s*\w|args\s*\.|params\s*\.|request\s*\.\s*params)")
_MCP_PATH_SINK = re.compile(r"(?:open|readFile(?:Sync)?|writeFile(?:Sync)?|Path)\s*\(\s*(?:args?|params|arguments|request\.params\.arguments)\s*[.\[]")
_MCP_HTTP_BIND = re.compile(r"host\s*=\s*['\"]0\.0\.0\.0['\"]|listen\s*\(\s*\d+\s*,\s*['\"]0\.0\.0\.0['\"]|--host\s+0\.0\.0\.0|transport\s*=\s*['\"](?:sse|streamable-http|http)['\"]|StreamableHTTPServerTransport|SSEServerTransport")
_MCP_ORIGIN_CHECK = re.compile(r"\bOrigin\b|allowedOrigins|enableDnsRebindingProtection|allowedHosts|TrustedHost", re.I)
_MCP_TOKEN_PASSTHROUGH = re.compile(r"(?:headers|Authorization)\s*\[?\s*['\"]?authorization['\"]?\s*\]?[\s\S]{0,200}?(?:fetch|requests\.(?:get|post)|httpx|axios)\s*\(", re.I)
_MCP_OAUTH_META_FROM_INPUT = re.compile(r"\.well-known/(?:oauth-authorization-server|openid-configuration)[^\n]{0,60}(?:\+\s*\w|\$\{|\.format\(|%s)|(?:\$\{|\+\s*)\w+[^\n]{0,40}\.well-known/oauth", re.I)
_MCP_READONLY_LIE = re.compile(r"readOnlyHint\s*:\s*true[\s\S]{0,600}?(?:writeFile|unlink|rm\b|DELETE\s+FROM|UPDATE\s+\w+\s+SET|subprocess|exec\s*\()", re.I)


def judge_mcp_source(text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    # MCP SDK 를 실제로 import 하는 파일만 — `@tool` 토큰만으로 켜면 패턴 문자열을 담은 무관한 파일(개밥먹기: 체커의 ast_scanner.py)까지 판정한다.
    if not _MCP_IMPORT.search(text):
        return out
    is_py = rel.lower().endswith(".py")
    sink = (_MCP_ARG_SINK_PY if is_py else _MCP_ARG_SINK_JS).search(text)
    if sink:
        f = _emit(RULE_MCP_SERVER, rel=rel, line=_ln(text, sink), evidence="MCP 도구 모듈에서 동적 명령 조립이 프로세스 실행에 닿음(도구 인자 → 셸)", confidence="confirmed")
        if f:
            out.append(f)
    m = _MCP_PATH_SINK.search(text)
    if m:
        f = _emit(RULE_MCP_SERVER, rel=rel, line=_ln(text, m), evidence="도구 인자가 검증 없이 파일 경로로 열림(경로 허용 목록·정규화 확인)", confidence="likely")
        if f:
            out.append(f)
    m = _MCP_HTTP_BIND.search(text)
    if m and not _MCP_ORIGIN_CHECK.search(text):
        f = _emit(RULE_MCP_SERVER, rel=rel, line=_ln(text, m), evidence="HTTP/SSE 전송(또는 0.0.0.0 바인딩)인데 Origin/허용 호스트 검증이 없음 — 로컬 서버 DNS 리바인딩", confidence="likely")
        if f:
            out.append(f)
    m = _MCP_TOKEN_PASSTHROUGH.search(text)
    if m:
        f = _emit(RULE_MCP_SERVER, rel=rel, line=_ln(text, m), evidence="클라이언트 Authorization 헤더를 상위 API 요청에 그대로 전달(토큰 패스스루)", confidence="likely")
        if f:
            out.append(f)
    m = _MCP_OAUTH_META_FROM_INPUT.search(text)
    if m:
        f = _emit(RULE_MCP_SERVER, rel=rel, line=_ln(text, m), evidence="OAuth 메타데이터(.well-known) 조회 URL 이 입력으로 조립됨 — 내부망·메타데이터 주소 SSRF", confidence="likely")
        if f:
            out.append(f)
    m = _MCP_READONLY_LIE.search(text)
    if m:
        f = _emit(RULE_MCP_SERVER, rel=rel, line=_ln(text, m), evidence="readOnlyHint: true 로 선언된 도구 근처에 쓰기·삭제·실행 호출 — 힌트가 사실과 다름", confidence="likely")
        if f:
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# 수집기
# ---------------------------------------------------------------------------

def collect_ecosystem_surface(root: Path, *, policy: PolicyFn) -> EcoResult:
    res = EcoResult()
    root = Path(root)
    if not root.is_dir():
        return res
    active, manifests = detect_ecosystems(root)
    res.active = active
    if not active and not manifests:
        return res
    untrusted_supported = False
    seen: set[str] = set()

    def add(p: Path, kind: str, findings: list[Finding], parsed: bool = True, note: str = "") -> None:
        rel = _rel(p, root)
        if rel in seen:
            return
        seen.add(rel)
        findings = policy(findings, rel)
        res.findings.extend(findings)
        res.entries.append(EcoEntry(path=rel, kind=kind, parsed=parsed, note=note, finding_count=len(findings)))

    # 1) 매니페스트·빌드 설정
    for p, kind in manifests:
        text = _read(p)
        if text is None:
            add(p, kind, [], parsed=False, note="읽기 실패/상한 초과")
            continue
        try:
            if kind == "vscode-manifest":
                data = _json(text) or {}
                caps = data.get("capabilities") if isinstance(data.get("capabilities"), dict) else {}
                utw = caps.get("untrustedWorkspaces") if isinstance(caps.get("untrustedWorkspaces"), dict) else {}
                untrusted_supported = untrusted_supported or (utw.get("supported") is True)
                add(p, kind, judge_vscode_manifest(data, text, _rel(p, root)))
            elif kind == "chrome-manifest":
                add(p, kind, judge_chrome_manifest(_json(text) or {}, text, _rel(p, root)))
            elif kind == "electron-builder":
                add(p, kind, judge_electron_builder(text, _rel(p, root)))
            else:
                add(p, kind, [])
        except Exception as exc:  # noqa: BLE001
            add(p, kind, [], parsed=False, note=f"해석 실패: {type(exc).__name__}")
    # 2) 소스
    for p in _walk(root):
        suf = p.suffix.lower()
        if suf not in _JS and suf not in _PY and not (p.name.lower().endswith(".json") and "chrome-ext" in active):
            continue
        text = _read(p)
        if text is None:
            continue
        rel = _rel(p, root)
        findings: list[Finding] = []
        kind = None
        try:
            if "electron" in active and suf in _JS and re.search(r"\b(?:BrowserWindow|contextBridge|ipcMain|ipcRenderer|shell\.openExternal|webContents)\b", text):
                findings += judge_electron_source(text, rel)
                kind = "electron-src"
            if "vscode-ext" in active and suf in _JS and "vscode" in text:
                findings += judge_vscode_source(text, rel, untrusted_supported=untrusted_supported)
                kind = kind or "vscode-ext-src"
            if "chrome-ext" in active:
                if suf in _JS and re.search(r"\bchrome\s*\.\s*\w+|\bbrowser\s*\.\s*\w+", text):
                    findings += judge_chrome_source(text, rel)
                    kind = kind or "chrome-ext-src"
                elif suf == ".json" and p.name.lower() != "manifest.json" and '"responseHeaders"' in text:
                    findings += judge_chrome_rules_json(_json(text), text, rel)
                    kind = kind or "chrome-dnr-rules"
            if "mcp-server" in active and (suf in _JS or suf in _PY):
                mcp_f = judge_mcp_source(text, rel)
                if mcp_f or (_MCP_IMPORT.search(text) and _MCP_TOOL_DEF.search(text)):
                    findings += mcp_f
                    kind = kind or "mcp-server-src"
        except Exception as exc:  # noqa: BLE001
            add(p, kind or "ecosystem-src", [], parsed=False, note=f"해석 실패: {type(exc).__name__}")
            continue
        if kind is not None:
            add(p, kind, findings)
    return res
