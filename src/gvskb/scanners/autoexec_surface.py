"""자동 실행 표면 인벤토리 — 저장소를 **열거나, 에이전트 세션을 켜거나, 파이썬을 기동하면** 실행되는 자리.

왜 따로 보나(37차, 2026-10-24)
------------------------------
일반 소스 스캔은 오탐을 억제하기 위해 `.vscode`·`.idea` 같은 IDE 디렉터리를 제외하고,
`.md`·`.pth` 같은 확장자를 읽지 않는다. 그 선택은 옳다 — 그런데 2026년 공급망 사고는 **바로
그 자리**를 골랐다.

- 2026-08 npm 웜(keyv 계열): `.vscode/tasks.json` 의 폴더 열기 자동 실행 task 와
  `.claude/settings.json` 의 세션 시작 훅이 **서로를 다시 실행**하는 사슬.
- 2026-10 PyPI(litellm 1.107.0): `site-packages` 의 `*.pth` + `sitecustomize.py` — import 없이
  **모든 파이썬 기동**에서 실행.
- 에이전트 지시 파일(CLAUDE.md 등)에 보이지 않는 문자로 숨긴 지시(hidden_text 엔진이 본다).

그래서 일반 스캔의 제외 규칙은 **그대로 두고**, 이 모듈이 정해진 이름·경로를 **제외 규칙과
무관하게** 찾아 **파서로만** 읽는다. 어떤 경우에도 설정이 가리키는 명령을 실행하지 않는다
(그 보장은 tests/test_round37_autoexec_surface.py 가 고정한다).

판정의 자리
-----------
- 설정 값 자체가 판정인 것(`bypassPermissions`, `autoApprove`, `runOn: folderOpen` + 네트워크
  명령)은 **confirmed**. 출처 추적이 필요 없다.
- 폴더 열기 task 가 `npm run watch` 같은 평범한 명령이면 **likely** — 근거 정책이 경고로 내린다.
- 해석기가 없는 파일(워크플로 YAML 등)은 **인벤토리에만** 남긴다. "읽었다"와 "판정했다"를 섞지 않는다.
- 파싱에 실패한 파일은 `skipped` 에 사유를 남긴다 — 깨끗함이 아니라 미검사다.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..schema import Finding, SkippedFile
from .hidden_text import scan_hidden_text
from .regex_scanner import build_finding, lookup_rule, redact_evidence

RULE_IDE_TASK = "GOV-AUTOEXEC-IDE-TASK-001"
RULE_AGENT_HOOK = "GOV-AUTOEXEC-AGENT-HOOK-001"
RULE_AGENT_PERMISSION = "GOV-AGENT-CONFIG-PERMISSION-001"
RULE_MCP_CONFIG = "GOV-MCP-CONFIG-001"
RULE_PY_STARTUP = "GOV-AUTOEXEC-PYTHON-STARTUP-001"
ENGINE = "autoexec-surface"

# 인프라·캐시 디렉터리 — 여기는 어떤 경우에도 들어가지 않는다(수천 파일, 자체 코드 없음).
# `.vscode`·`.claude`·`.cursor`·`.github` 는 **의도적으로 없다** — 이 모듈이 보려는 자리다.
_HARD_EXCLUDE = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".cache", ".turbo",
    ".parcel-cache", ".check-reports", "dist", "build", "out", "target", ".next", ".nuxt",
})
# 가상환경 — 통째로 걷지 않고 `site-packages` 의 기동 파일만 본다(litellm 경로).
_VENV_NAMES = frozenset({".venv", "venv", "env", ".env", "virtualenv", ".virtualenv"})

_AGENT_INSTRUCTION_NAMES = frozenset({
    "claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules",
    "copilot-instructions.md",
})
_SCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".py", ".bat", ".cmd")

# 명령 위험 분류 — 네트워크에서 받아 실행 / 인터프리터에 문자열 코드 / 인코딩된 명령.
_NET_RE = re.compile(
    r"\b(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|iex|Invoke-Expression|bitsadmin"
    r"|certutil\s+-urlcache|scp|nc|ncat|Start-BitsTransfer)\b",
    re.IGNORECASE,
)
_INTERP_RE = re.compile(
    r"\b(?:node\s+-e|node\s+--eval|python3?\s+-c|bash\s+-c|sh\s+-c|zsh\s+-c|cmd(?:\.exe)?\s+/c"
    r"|powershell(?:\.exe)?\s+.*-(?:enc|EncodedCommand|e)\b|pwsh\s+.*-(?:enc|EncodedCommand)\b"
    r"|bun\s+(?:x|run)?|npx\s+|deno\s+run|uvx\s+|pipx\s+run)",
    re.IGNORECASE,
)
_SHELL_WRAPPERS = frozenset({"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "curl", "wget"})
_UNPINNED_RUNNER_RE = re.compile(r"^(?:npx|bunx|uvx|pipx)$", re.IGNORECASE)
_CLAUDE_HOOK_EVENTS = (
    "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SubagentStop",
    "Notification", "PreCompact", "SessionEnd",
)
# .pth 허용 목록 — 가상환경·setuptools·네임스페이스 패키지가 정상적으로 두는 `import` 줄.
_PTH_ALLOW_NAMES = frozenset({"_virtualenv.pth", "distutils-precedence.pth", "easy-install.pth", "setuptools.pth"})
_PTH_ALLOW_SUFFIX = ("-nspkg.pth",)
_PTH_ALLOW_PREFIX = ("__editable__",)
_SURFACE_MAX_BYTES = 512_000     # 설정 파일 하나의 상한 — 이보다 크면 해석하지 않고 미검사로 기록
_JSONC_LINE_COMMENT = re.compile(r"//[^\n]*")
_JSONC_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_JSONC_TRAILING_COMMA = re.compile(r",(\s*[}\]])")

PolicyFn = Callable[[list[Finding], str], list[Finding]]
ScanCodeFn = Callable[[str, str], list[Finding]]


@dataclass
class SurfaceEntry:
    path: str
    kind: str
    parsed: bool = True
    note: str = ""
    finding_count: int = 0

    def as_dict(self) -> dict:
        return {"path": self.path, "kind": self.kind, "parsed": self.parsed,
                "note": self.note, "finding_count": self.finding_count}


@dataclass
class SurfaceResult:
    entries: list[SurfaceEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 파서 — 실행하지 않는다
# ---------------------------------------------------------------------------

def _strip_jsonc(text: str) -> str:
    """VS Code 계열 JSON(주석·후행 쉼표 허용)을 표준 JSON 으로. 문자열 안의 `//` 는 지키지 않아도
    된다 — 실패하면 미검사로 기록되고, 그 사실이 보고서에 남는다(조용히 통과하지 않는다)."""
    out: list[str] = []
    i, n, quote = 0, len(text), ""
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch == '"':
            quote = ch
            out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(ch)
        i += 1
    return _JSONC_TRAILING_COMMA.sub(r"\1", "".join(out))


def _load_jsonc(text: str):
    text = text.lstrip(chr(0xFEFF))
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(_strip_jsonc(text))


def _load_toml(text: str):
    import tomllib
    return tomllib.loads(text)


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(p).replace("\\", "/")


def _read(p: Path) -> tuple[str | None, str]:
    """(본문, 실패 사유). 실패는 **사유를 남긴다** — 실측(2026-10-24, 이 PC)에서 보안 소프트웨어가
    알려진 악성 지표 문구가 든 파일의 읽기를 EINVAL 로 막았다. 그 파일은 '깨끗함'이 아니라 '읽지 못함'이고,
    심사자는 왜 못 읽었는지(크기·권한·차단)를 알아야 한다."""
    try:
        size = p.stat().st_size
    except OSError as exc:
        return None, f"stat 실패(errno {exc.errno})"
    if size > _SURFACE_MAX_BYTES:
        return None, f"크기 상한 초과({size:,} > {_SURFACE_MAX_BYTES:,} bytes)"
    try:
        return p.read_text(encoding="utf-8", errors="replace"), ""
    except OSError as exc:
        hint = " — 보안 소프트웨어가 차단했을 수 있음(알려진 악성 지표 가능)" if exc.errno == 22 else ""
        return None, f"읽기 실패(errno {exc.errno}){hint}"


def _as_command_string(value) -> str:
    """`command` + `args` 를 사람이 읽는 한 줄로. 실행용이 아니라 **판정·증거용**이다."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    if isinstance(value, dict):
        cmd = value.get("command") or value.get("cmd") or ""
        args = value.get("args") or []
        return _as_command_string([cmd, *args] if isinstance(args, list) else [cmd, args])
    return str(value) if value is not None else ""


def _repo_script_in(cmd: str, root: Path) -> Path | None:
    """명령 문자열이 가리키는 **저장소 안 스크립트** — 존재하면 그 경로."""
    for tok in re.split(r"[\s'\"`]+", cmd):
        tok = tok.strip()
        if not tok or not tok.lower().endswith(_SCRIPT_SUFFIXES):
            continue
        tok = tok.replace("${workspaceFolder}", ".").replace("${workspaceRoot}", ".").replace("$CLAUDE_PROJECT_DIR", ".")
        # `./x` 접두사만 벗긴다 — `lstrip("./")` 는 `.claude/…` 의 앞 점까지 지워 스크립트를 못 찾는다.
        while tok.startswith(("./", ".\\")):
            tok = tok[2:]
        cand = (root / tok).resolve() if not Path(tok).is_absolute() else Path(tok)
        try:
            cand.relative_to(root.resolve())
        except ValueError:
            continue
        if cand.is_file():
            return cand
    return None


def _command_risk(cmd: str, root: Path) -> tuple[str, Path | None]:
    """'network' | 'interpreter' | 'repo-script' | 'other' 와 가리키는 저장소 스크립트."""
    if _NET_RE.search(cmd):
        return "network", _repo_script_in(cmd, root)
    if _INTERP_RE.search(cmd):
        return "interpreter", _repo_script_in(cmd, root)
    script = _repo_script_in(cmd, root)
    if script is not None:
        return "repo-script", script
    return "other", None


def _chain_note(script: Path, root: Path) -> str:
    """가리키는 스크립트가 **다른 자동 실행 자리**를 다시 건드리면 사슬로 표시한다(2026-08 웜 수법)."""
    text, _why = _read(script)
    if not text:
        return ""
    hits = []
    for marker in (".vscode/", ".claude/", "tasks.json", "settings.json", ".cursor/", ".mcp.json"):
        if marker in text:
            hits.append(marker)
    if _NET_RE.search(text) or re.search(r"\bbun\b|\bnpx\b", text):
        hits.append("다운로드·외부 실행")
    return f" → 사슬: `{_rel(script, root)}` 가 {', '.join(dict.fromkeys(hits))} 를 건드림" if hits else ""


def _emit(rule_id: str, *, rel: str, line: int, evidence: str, confidence: str) -> Finding | None:
    rule = lookup_rule(rule_id)
    if rule is None:
        return None
    return build_finding(rule, filename=rel, line_no=max(1, line), evidence=redact_evidence(evidence)[:240],
                         engine=ENGINE, confidence=confidence)


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


# ---------------------------------------------------------------------------
# 판정기 — 파일 종류별
# ---------------------------------------------------------------------------

def _judge_vscode_tasks(data, text: str, rel: str, root: Path) -> list[Finding]:
    out: list[Finding] = []
    tasks = data.get("tasks") if isinstance(data, dict) else None
    for task in tasks or []:
        if not isinstance(task, dict):
            continue
        run_on = ((task.get("runOptions") or {}).get("runOn") if isinstance(task.get("runOptions"), dict) else None)
        if run_on != "folderOpen":
            continue
        cmd = _as_command_string({"command": task.get("command", ""), "args": task.get("args", [])})
        if not cmd.strip() and isinstance(task.get("script"), str):
            cmd = f"npm run {task['script']}"
        risk, script = _command_risk(cmd, root)
        label = str(task.get("label") or task.get("taskName") or "?")
        chain = _chain_note(script, root) if script is not None else ""
        confirmed = risk in {"network", "interpreter", "repo-script"}
        ev = f"task `{label}` runOn=folderOpen → {cmd.strip() or '(명령 없음)'} [{risk}]{chain}"
        f = _emit(RULE_IDE_TASK, rel=rel, line=_line_of(text, "folderOpen"), evidence=ev,
                  confidence="confirmed" if confirmed else "likely")
        if f:
            out.append(f)
    return out


def _judge_vscode_settings(data, text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    checks = (
        ("chat.tools.autoApprove", lambda v: v is True, "에이전트 도구 호출 자동 승인(사용자 확인 생략)"),
        ("chat.tools.terminal.autoApprove", lambda v: isinstance(v, dict) and any(bool(x) is True for x in v.values()),
         "터미널 명령 자동 승인 목록"),
        ("task.allowAutomaticTasks", lambda v: str(v).lower() == "on", "폴더 열기 자동 task 허용"),
        ("security.workspace.trust.enabled", lambda v: v is False, "Workspace Trust 비활성(저장소 설정이 바로 실행됨)"),
    )
    for key, pred, why in checks:
        if key in data and pred(data[key]):
            f = _emit(RULE_AGENT_PERMISSION, rel=rel, line=_line_of(text, key),
                      evidence=f"{key} = {json.dumps(data[key], ensure_ascii=False)[:80]} — {why}", confidence="confirmed")
            if f:
                out.append(f)
    return out


def _judge_claude_settings(data, text: str, rel: str, root: Path) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            if event not in _CLAUDE_HOOK_EVENTS or not isinstance(entries, list):
                continue
            for entry in entries:
                inner = entry.get("hooks") if isinstance(entry, dict) else None
                for h in (inner if isinstance(inner, list) else [entry]):
                    if not isinstance(h, dict):
                        continue
                    cmd = str(h.get("command") or "")
                    if not cmd.strip():
                        continue
                    risk, script = _command_risk(cmd, root)
                    chain = _chain_note(script, root) if script is not None else ""
                    confirmed = risk in {"network", "interpreter", "repo-script"}
                    ev = f"hooks.{event} → {cmd.strip()} [{risk}]{chain}"
                    f = _emit(RULE_AGENT_HOOK, rel=rel, line=_line_of(text, event), evidence=ev,
                              confidence="confirmed" if confirmed else "likely")
                    if f:
                        out.append(f)
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        f = _emit(RULE_AGENT_PERMISSION, rel=rel, line=_line_of(text, "bypassPermissions"),
                  evidence="permissions.defaultMode = bypassPermissions — 모든 도구 호출을 확인 없이 실행", confidence="confirmed")
        if f:
            out.append(f)
    allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
    broad = [a for a in allow if isinstance(a, str) and re.fullmatch(r"Bash(?:\(\*(?::\*)?\))?", a.strip())]
    if broad:
        f = _emit(RULE_AGENT_PERMISSION, rel=rel, line=_line_of(text, broad[0]),
                  evidence=f"permissions.allow 에 `{broad[0]}` — 인자 제한 없는 셸 전체 허용", confidence="confirmed")
        if f:
            out.append(f)
    if data.get("enableAllProjectMcpServers") is True:
        f = _emit(RULE_AGENT_PERMISSION, rel=rel, line=_line_of(text, "enableAllProjectMcpServers"),
                  evidence="enableAllProjectMcpServers = true — 저장소의 MCP 서버를 확인 없이 전부 기동", confidence="confirmed")
        if f:
            out.append(f)
    return out


def _mcp_servers(data) -> dict:
    if not isinstance(data, dict):
        return {}
    for key in ("mcpServers", "servers", "mcp_servers"):
        v = data.get(key)
        if isinstance(v, dict):
            return v
    # .gemini/settings.json 처럼 중첩되거나 .codex/config.toml 의 [mcp_servers.x]
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return {}


def _judge_mcp_config(data, text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    for name, spec in _mcp_servers(data).items():
        if not isinstance(spec, dict):
            continue
        line = _line_of(text, str(name))
        cmd = str(spec.get("command") or "").strip()
        args = spec.get("args") if isinstance(spec.get("args"), list) else []
        args_s = [str(a) for a in args]
        full = " ".join([cmd, *args_s]).strip()
        base = os.path.basename(cmd).lower()
        if base in _SHELL_WRAPPERS or any(a in ("-c", "-enc", "-EncodedCommand", "/c") for a in args_s):
            f = _emit(RULE_MCP_CONFIG, rel=rel, line=line,
                      evidence=f"서버 `{name}`: 셸·다운로드 명령으로 기동 → {full}", confidence="confirmed")
            if f:
                out.append(f)
        elif _UNPINNED_RUNNER_RE.match(base):
            pkg = next((a for a in args_s if not a.startswith("-")), "")
            pinned = ("@" in pkg[1:]) or ("==" in pkg) or ("@" in pkg and not pkg.startswith("@"))
            if pkg and not pinned:
                f = _emit(RULE_MCP_CONFIG, rel=rel, line=line,
                          evidence=f"서버 `{name}`: `{base} {pkg}` — 버전 미고정 패키지를 매 기동마다 받아 실행", confidence="likely")
                if f:
                    out.append(f)
        for key in ("autoApprove", "alwaysAllow"):
            v = spec.get(key)
            if (isinstance(v, list) and v) or v is True:
                f = _emit(RULE_MCP_CONFIG, rel=rel, line=line,
                          evidence=f"서버 `{name}`: {key} = {json.dumps(v, ensure_ascii=False)[:60]} — 도구 호출 확인 생략", confidence="confirmed")
                if f:
                    out.append(f)
        if spec.get("trust") is True:
            f = _emit(RULE_MCP_CONFIG, rel=rel, line=line, evidence=f"서버 `{name}`: trust = true — 도구 호출 확인 생략", confidence="confirmed")
            if f:
                out.append(f)
        url = str(spec.get("url") or spec.get("serverUrl") or "")
        if url.lower().startswith("http://") and not re.match(r"http://(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?:[:/]|$)", url, re.I):
            f = _emit(RULE_MCP_CONFIG, rel=rel, line=line, evidence=f"서버 `{name}`: 평문 HTTP 원격 MCP → {url[:80]}", confidence="confirmed")
            if f:
                out.append(f)
    return out


def _judge_pth(text: str, rel: str, name: str) -> list[Finding]:
    low = name.lower()
    if low in _PTH_ALLOW_NAMES or low.endswith(_PTH_ALLOW_SUFFIX) or low.startswith(_PTH_ALLOW_PREFIX):
        return []
    for i, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if s.startswith("import ") or s.startswith("import\t"):
            f = _emit(RULE_PY_STARTUP, rel=rel, line=i,
                      evidence=f".pth 의 import 줄 — 모든 파이썬 기동에서 실행: {s[:120]}", confidence="confirmed")
            return [f] if f else []
    return []


def _judge_sitecustomize(text: str, rel: str) -> list[Finding]:
    first = next((ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")), "")
    f = _emit(RULE_PY_STARTUP, rel=rel, line=1,
              evidence=f"{Path(rel).name} 존재 — 인터프리터 기동마다 실행되는 파일. 첫 문장: {first[:100] or '(비어 있음)'}",
              confidence="confirmed")
    return [f] if f else []


# ---------------------------------------------------------------------------
# 수집
# ---------------------------------------------------------------------------

def _classify_path(rel: str, name: str) -> str | None:
    """이 파일이 자동 실행 표면의 어느 종류인가. None 이면 관심 없음."""
    low = name.lower()
    parts = rel.lower().split("/")
    in_vscode = ".vscode" in parts
    in_claude = ".claude" in parts
    in_cursor = ".cursor" in parts
    if in_vscode and low == "tasks.json":
        return "vscode-tasks"
    if in_vscode and low == "settings.json":
        return "vscode-settings"
    if (in_vscode or in_cursor or len(parts) == 1) and low == "mcp.json" or low == ".mcp.json":
        return "mcp-config"
    if in_claude and low in {"settings.json", "settings.local.json"}:
        return "claude-settings"
    if ".gemini" in parts and low == "settings.json":
        return "mcp-config"
    if ".codex" in parts and low == "config.toml":
        return "mcp-config"
    if low in _AGENT_INSTRUCTION_NAMES or (in_cursor and "rules" in parts and low.endswith(".md")) \
            or (in_claude and low.endswith(".md")):
        return "agent-instructions"
    if (in_vscode or in_claude or in_cursor) and low.endswith(_SCRIPT_SUFFIXES):
        return "ide-script"
    if low.endswith(".pth"):
        return "python-pth"
    if low in {"sitecustomize.py", "usercustomize.py"}:
        return "python-startup"
    if ".github" in parts and "workflows" in parts and low.endswith((".yml", ".yaml")):
        return "workflow"
    return None


def _iter_surface_files(root: Path):
    """제외 규칙과 무관한 자체 걷기. 가상환경은 site-packages 의 기동 파일만 들춘다."""
    for dirpath, dirnames, filenames in os.walk(root):
        kept = []
        for d in dirnames:
            if d in _HARD_EXCLUDE:
                continue
            if d in _VENV_NAMES or d == "site-packages":
                base = Path(dirpath) / d
                sps = [base] if d == "site-packages" else [*base.glob("Lib/site-packages"), *base.glob("lib/python*/site-packages")]
                for sp in sps:
                    try:
                        for p in sp.iterdir():
                            if p.is_file() and (p.suffix.lower() == ".pth" or p.name.lower() in {"sitecustomize.py", "usercustomize.py"}):
                                yield p
                    except OSError:
                        continue
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in filenames:
            yield Path(dirpath) / name


def collect_autoexec_surface(
    root: Path,
    *,
    policy: PolicyFn,
    scan_code: ScanCodeFn | None = None,
    already_scanned: set[str] | frozenset[str] | None = None,
) -> SurfaceResult:
    """루트 아래 자동 실행 표면을 찾아 해석·판정한다. 어떤 파일도 실행하지 않는다.

    ``policy(findings, rel)`` 는 스캐너의 경로 단위 판정 계층(프로파일·테스트 경로·근거 정책)이다 —
    여기서 만든 발견도 같은 계층을 탄다. ``scan_code(text, rel)`` 가 있으면 IDE 디렉터리 안
    스크립트(일반 스캔이 제외하는 자리)에 전체 엔진을 돌린다. ``already_scanned`` 에 있는 경로
    (루트의 `.mcp.json`·워크플로 YAML 처럼 일반 스캔이 이미 본 파일)는 숨은 문자 검사를 다시 하지
    않는다 — 같은 발견이 두 번 올라오면 '2개 문제'로 읽힌다.
    """
    res = SurfaceResult()
    root = Path(root)
    if not root.is_dir():
        return res
    seen = {s.replace("\\", "/") for s in (already_scanned or ())}
    for p in _iter_surface_files(root):
        if p.is_symlink():
            continue
        rel = _rel(p, root)
        kind = _classify_path(rel, p.name)
        if kind is None:
            continue
        entry = SurfaceEntry(path=rel, kind=kind)
        text, why = _read(p)
        if text is None:
            entry.parsed = False
            entry.note = why
            res.skipped.append(SkippedFile(path=rel, reason=f"자동 실행 표면({kind}) — {why}: 검사되지 않았습니다"))
            res.entries.append(entry)
            continue
        findings: list[Finding] = []
        try:
            if kind in {"vscode-tasks", "vscode-settings", "claude-settings", "mcp-config"}:
                data = _load_toml(text) if p.suffix.lower() == ".toml" else _load_jsonc(text)
                if kind == "vscode-tasks":
                    findings += _judge_vscode_tasks(data, text, rel, root)
                elif kind == "vscode-settings":
                    findings += _judge_vscode_settings(data, text, rel)
                elif kind == "claude-settings":
                    findings += _judge_claude_settings(data, text, rel, root)
                findings += _judge_mcp_config(data, text, rel)
            elif kind == "python-pth":
                findings += _judge_pth(text, rel, p.name)
            elif kind == "python-startup":
                findings += _judge_sitecustomize(text, rel)
            elif kind == "ide-script" and scan_code is not None and rel not in seen:
                findings += scan_code(text, rel)
            # agent-instructions · workflow: 인벤토리 + 숨은 문자만(37차 범위)
            if kind != "ide-script" and rel not in seen:   # ide-script 는 scan_code 의 hidden-text 엔진이 봤다
                findings += scan_hidden_text(text, filename=rel)
        except Exception as exc:  # noqa: BLE001 — 설정 파일 하나의 오류가 검사를 멈추면 안 된다
            entry.parsed = False
            entry.note = f"해석 실패: {type(exc).__name__}"
            res.skipped.append(SkippedFile(
                path=rel, reason=f"자동 실행 표면({kind}) — 해석 실패({type(exc).__name__}): 검사되지 않았습니다",
            ))
            res.entries.append(entry)
            continue
        findings = policy(findings, rel)
        entry.finding_count = len(findings)
        res.findings.extend(findings)
        if rel not in seen:
            res.scanned.append(rel)
        res.entries.append(entry)
    return res
