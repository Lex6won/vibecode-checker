"""에이전트·공급망 행위 판정 — 소스에서 "무엇을 하는가"를 본다 (39차, 2026-10-24).

37·38차는 설정·매니페스트를 구조로 읽었다(값이 곧 판정). 39차는 실행 소스의 **행위**를 본다:

- ① 코드가 피해자 PC 의 AI 코딩 CLI 를 "대화 없이 + 확인 생략" 으로 몰래 호출(Nx·Trivy 확장 사고).
- ② 자격증명이 있는 자리 여러 곳을 읽고 **그 결과를 밖으로 보낸다**(스틸러 — Shai-Hulud·litellm).
- ③ 명령·주소를 받아오는 숨은 채널(dead-drop→실행, webhook, DNS, 맥락 밖 블록체인 RPC).

정밀도 원칙: **하나로는 올리지 않는다.** 서랍을 뒤지는 것만으로는(백업 도구도 그렇다), AI CLI 를
부르는 것만으로는(CI 자동화도 그렇다) 안 된다 — **수집 + 전송**, **CLI + 확인 생략** 처럼 둘 이상이
결합할 때만 차단으로 올린다. 증거에는 분류명·개수·필드명만 남기고 비밀값·원문은 싣지 않는다.

이 엔진은 regex·토큰 기반이다(언어 무관, 망분리 PC 에 파서 반입 없음). 값의 출처를 변수까지
추적하지는 않는다 — 그 정밀화(JS 파일 간 흐름)는 "C 결정(tree-sitter)" 과제다. 지금은 **같은 파일
안의 결합**으로 판정하고, 결합이 약하면 경고로 둔다.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..schema import Finding
from .base import ScannerAdapter
from .regex_scanner import build_finding, lookup_rule

CATEGORY = "agent-supply-chain"
ENGINE = "agent-surface"
RULE_CLI_ABUSE = "GOV-AGENT-CLI-ABUSE-001"
RULE_CRED_EXFIL = "GOV-AGENT-CRED-EXFIL-001"
RULE_C2_CHANNEL = "GOV-AGENT-C2-CHANNEL-001"
RULE_IDS = (RULE_CLI_ABUSE, RULE_CRED_EXFIL, RULE_C2_CHANNEL)

_SOURCE_SUFFIXES = (".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts",
                    ".sh", ".bash", ".zsh", ".ps1", ".vue", ".svelte")

# ---------------------------------------------------------------------------
# ① AI CLI 오용 — 설정표(config/ai-cli-flags.yaml)로 분리
# ---------------------------------------------------------------------------

_DEFAULT_FLAGS = {
    "cli_names": ["claude", "gemini", "codex", "copilot", "q", "kiro", "cursor-agent", "aider",
                  "opencode", "goose", "continue", "cline", "amp"],
    "noninteractive_tokens": ["-p", "--print", "--prompt", "--message", "--input", "exec", "run",
                              "chat", "--non-interactive", "--no-interactive", "--headless", "--batch"],
    "permission_skip_tokens": ["--dangerously-skip-permissions", "--yolo", "--trust-all-tools",
                               "--trust-all", "--allow-all", "--auto-approve", "--auto-accept",
                               "--no-confirm", "--no-approval", "--skip-permissions", "--bypass-permissions",
                               "--force", "--full-auto", "--sandbox=danger-full-access",
                               "--approval-mode=never", "--permission-mode=bypasspermissions", "--yes"],
    "background_tokens": ["detached", "nohup", "start /b", "-windowstyle hidden", "disown", "setsid",
                          ">/dev/null", "2>&1", "stdio: 'ignore'", 'stdio: "ignore"'],
}
_FLAGS_CACHE: dict | None = None


def _load_flags() -> dict:
    global _FLAGS_CACHE
    if _FLAGS_CACHE is not None:
        return _FLAGS_CACHE
    data: dict = {}
    override = os.environ.get("GVSKB_AI_CLI_FLAGS")
    pkg_root = Path(__file__).resolve().parent.parent
    cands = [Path(override)] if override else [
        pkg_root.parent.parent / "config" / "ai-cli-flags.yaml",
        pkg_root / "config" / "ai-cli-flags.yaml",
    ]
    for c in cands:
        try:
            if c.is_file():
                loaded = yaml.safe_load(c.read_text(encoding="utf-8")) or {}
                if isinstance(loaded, dict):
                    data = loaded
                    break
        except (OSError, yaml.YAMLError):
            continue
    merged = {k: list(data.get(k) or _DEFAULT_FLAGS[k]) for k in _DEFAULT_FLAGS}
    _FLAGS_CACHE = merged
    return merged


# 프로세스를 띄우는 자리 — 이 근처에서 CLI 이름이 나오면 "코드가 CLI 를 부른다".
_SPAWN_RE = re.compile(
    r"\b(?:child_process|execa|execSync|execFile(?:Sync)?|spawn(?:Sync)?|fork)\b"
    r"|\bsubprocess\s*\.\s*(?:run|call|Popen|check_output|check_call)\b"
    r"|\bos\s*\.\s*(?:system|popen)\b|(?<![\w.])exec\s*\("
    r"|\bStart-Process\b|\bInvoke-Expression\b",
    re.IGNORECASE,
)


def _tok_in(hay: str, tokens: list[str]) -> list[str]:
    out = []
    low = hay.lower()
    for t in tokens:
        tl = t.lower()
        # 옵션(-/-- 로 시작)·경로 토큰은 부분일치, 짧은 하위명령은 단어 경계로.
        if tl.startswith("-") or "/" in tl or ">" in tl or " " in tl or ":" in tl:
            if tl in low:
                out.append(t)
        elif re.search(r"(?<![\w-])" + re.escape(tl) + r"(?![\w-])", low):
            out.append(t)
    return out


def _cli_name_hit(window: str, names: list[str]) -> str | None:
    for n in names:
        # CLI 이름이 문자열·인자 토큰으로 등장(따옴표·공백·슬래시 경계).
        if re.search(r"""(?<=[\'"])""" + re.escape(n) + r"""(?:\.exe|\.cmd)?(?![\w.-])""", window, re.IGNORECASE):
            return n
    return None


def judge_ai_cli_invocation(code: str, rel: str) -> list[Finding]:
    flags = _load_flags()
    out: list[Finding] = []
    lines = code.splitlines()
    n = len(lines)
    seen_lines: set[int] = set()
    for i, line in enumerate(lines):
        if not _SPAWN_RE.search(line):
            continue
        # 한 명령이 여러 줄에 걸칠 수 있다 — 앞뒤 2줄 창으로 본다.
        window = "\n".join(lines[max(0, i - 1): min(n, i + 3)])
        cli = _cli_name_hit(window, flags["cli_names"])
        if cli is None:
            continue
        skip = _tok_in(window, flags["permission_skip_tokens"])
        noninter = _tok_in(window, flags["noninteractive_tokens"])
        if not skip and not noninter:
            continue
        bg = _tok_in(window, flags["background_tokens"])
        line_no = i + 1
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        if skip and (noninter or True):
            conf = "confirmed"
            why = f"AI CLI `{cli}` 를 확인 생략 옵션으로 실행"
        elif noninter:
            conf = "likely"
            why = f"AI CLI `{cli}` 를 비대화식으로 실행(확인 생략 옵션은 없음 — CI 정상 용례 가능)"
        else:
            continue
        if bg:
            why += " · 백그라운드·출력 은폐"
        rule = lookup_rule(RULE_CLI_ABUSE)
        if rule is None:
            continue
        out.append(build_finding(rule, filename=rel, line_no=line_no,
                                 evidence=why, engine=ENGINE, confidence=conf))
    return out


# ---------------------------------------------------------------------------
# ② 자격증명 수집 + 외부 전송 결합
# ---------------------------------------------------------------------------

# 수집 신호 — "이런 자리를 읽는다". 분류명만 증거에 남긴다(경로·값은 싣지 않음).
_COLLECT: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\.ssh[/\\]id_|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b"), "ssh-key"),
    (re.compile(r"\.aws[/\\]credentials"), "aws-cred"),
    (re.compile(r"\.config[/\\]gcloud|application_default_credentials\.json"), "gcp-cred"),
    (re.compile(r"\.azure[/\\](?:accessTokens|msal_token_cache)"), "azure-cred"),
    (re.compile(r"\.kube[/\\]config"), "kube-config"),
    (re.compile(r"\.docker[/\\]config\.json"), "docker-cred"),
    (re.compile(r"expanduser\([^)]*\.npmrc|[~$][/\\]\.npmrc|\.pypirc|\.netrc\b|\.git-credentials"), "pkg-token"),
    (re.compile(r"\.config[/\\]gh[/\\]hosts|gh\s+auth\s+token"), "gh-token"),
    (re.compile(r"\.claude(?:\.json|[/\\])|\.codex[/\\]|\.cursor[/\\]|\.gemini[/\\]|\.continue[/\\]|\.aider"), "ai-tool-cred"),
    (re.compile(r"Login\s*Data|\bCookies\b.*(?:sqlite|SELECT)|moz_cookies|places\.sqlite|Local\s+State"), "browser-store"),
    (re.compile(r"/proc/\d+/environ|/proc/self/environ"), "proc-environ"),
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com"), "cloud-metadata"),
    (re.compile(r"dict\s*\(\s*os\.environ|os\.environ\s*\.\s*(?:copy|items)\s*\(|JSON\.stringify\s*\(\s*process\.env|\{\s*\.\.\.process\.env|Object\.(?:entries|keys)\s*\(\s*process\.env"), "env-dump"),
    (re.compile(r"login\.keychain|secretstorage|SecretService|libsecret|wallet\.dat"), "keystore"),
)
# 전송 신호 — "밖으로 보낸다". 이것만으로는 거의 모든 앱이 걸리므로 수집과 결합할 때만 의미.
_TRANSMIT = re.compile(
    r"\b(?:requests|httpx|urllib3?|aiohttp)\s*\.\s*(?:post|put|request|urlopen)\b"
    r"|urllib\.request\.urlopen|\bfetch\s*\(|\baxios\s*(?:\.\s*(?:post|put|request)|\s*\()"
    r"|\bgot\s*\.\s*(?:post|put)|\bhttp2?\s*\.\s*request\b|XMLHttpRequest|navigator\.sendBeacon"
    r"|\bsocket\s*\.\s*(?:connect|send(?:all|to)?)\b|\bnet\s*\.\s*(?:connect|Socket)\b"
    r"|\bsmtplib\b|\bgh\s+api\b|\bgit\s+push\b|\bcurl\b|\bInvoke-RestMethod\b|\bInvoke-WebRequest\b",
    re.IGNORECASE,
)
# 은닉 신호 — 수집 결과를 포장·위장. 결합되면 확신도를 올린다.
_STAGING = re.compile(
    r"\bAES\b|\bRSA\b|Fernet|cryptography\.hazmat|crypto\.(?:create(?:Cipher|Hmac)|publicEncrypt)"
    r"|base64\.(?:b64encode|urlsafe_b64encode)|Buffer\.from\([^)]*\)\.toString\(\s*['\"]base64"
    r"|btoa\s*\(|zlib\.(?:compress|gzip)|gzip\.compress"
    r"|User-?Agent['\"]?\s*[:=]\s*['\"](?:Mozilla/4|MSIE)"      # 구형 UA 위조
    r"|/healthcheck|/telemetry|/sentry|/analytics\b|/ping\b",
    re.IGNORECASE,
)
_MAX_LABELS = 6


def judge_credential_exfil(code: str, rel: str) -> list[Finding]:
    labels: list[str] = []
    first_line = 0
    for pat, label in _COLLECT:
        m = pat.search(code)
        if m:
            labels.append(label)
            ln = code.count("\n", 0, m.start()) + 1
            if first_line == 0 or ln < first_line:
                first_line = ln
    labels = sorted(set(labels))
    transmit = _TRANSMIT.search(code) is not None
    staging = _STAGING.search(code) is not None
    rule = lookup_rule(RULE_CRED_EXFIL)
    if rule is None:
        return []
    # 수집 3종 이상 + 전송 → 결합. 은닉까지 있으면 확정.
    if len(labels) >= 3 and transmit:
        conf = "confirmed" if staging else "likely"
        ev = (f"자격증명 수집 {len(labels)}종({', '.join(labels[:_MAX_LABELS])}"
              + (" 외" if len(labels) > _MAX_LABELS else "") + ") + 외부 전송"
              + (" + 포장/위장" if staging else ""))
        return [build_finding(rule, filename=rel, line_no=max(1, first_line), evidence=ev,
                              engine=ENGINE, confidence=conf)]
    # 수집만 많으면(전송 없음) 정보성 경고 — dotfile 백업 도구 등 정상 용례가 있다.
    if len(labels) >= 4:
        ev = (f"자격증명 자리 {len(labels)}종 접근({', '.join(labels[:_MAX_LABELS])}"
              + (" 외" if len(labels) > _MAX_LABELS else "") + ") — 외부 전송은 확인 안 됨")
        f = build_finding(rule, filename=rel, line_no=max(1, first_line), evidence=ev,
                          engine=ENGINE, confidence="pattern-only")
        return [f]
    return []


# ---------------------------------------------------------------------------
# ③ 맥락 밖 명령 수신 채널(C2)
# ---------------------------------------------------------------------------

# dead-drop: 공개 텍스트 호스트에서 받아 **바로 실행**. 맥락과 무관하게 강한 신호.
_DEADDROP_HOST = re.compile(
    r"raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com/raw|hastebin|ghostbin"
    r"|docs\.google\.com/document|script\.google\.com|api\.telegram\.org/bot[^/]+/getUpdates",
    re.IGNORECASE,
)
_EXEC_SINK = re.compile(
    r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|\bFunction\s*\(|child_process|subprocess|os\.system"
    r"|\bexecSync\b|\bspawn\b|vm\.runInContext",
    re.IGNORECASE,
)
# webhook — 하드코딩된 수신 URL. 전송(②)과 결합하면 유출 경로.
_WEBHOOK = re.compile(
    r"discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot[0-9]+:[\w-]+|hooks\.slack\.com/services/",
    re.IGNORECASE,
)
# 블록체인 RPC — 민원·업무 앱 맥락에서는 설명이 필요하다(차단은 안 하고 경고).
_CHAIN = re.compile(
    r"\beth_call\b|\beth_sendRawTransaction\b|getAccountInfo|JsonRpcProvider|new\s+ethers\b"
    r"|from\s+web3|require\(\s*['\"]web3|@solana/web3|infura\.io|alchemy\.com/v2|cloudflare-eth\.com",
    re.IGNORECASE,
)
# DNS 로 받은 값을 명령·주소로 — DNS 터널/C2.
_DNS_C2 = re.compile(
    r"(?:dns\s*\.\s*resolveTxt|dns\.resolver|resolve\s*\(\s*[^,]+,\s*['\"]TXT|nslookup\b).{0,120}"
    r"(?:eval|exec|system|spawn|fetch|requests\.|urlopen|connect)",
    re.IGNORECASE | re.DOTALL,
)


def _line_of(code: str, m: re.Match) -> int:
    return code.count("\n", 0, m.start()) + 1


def _window(code: str, pos: int, before: int = 3, after: int = 6) -> str:
    """pos 가 있는 줄의 앞 before·뒤 after 줄 — '받아서 바로 실행'은 같은 문장이나 바로 근처에 있다."""
    lines = code.splitlines()
    ln = code.count("\n", 0, pos)
    return "\n".join(lines[max(0, ln - before): ln + after + 1])


def judge_c2_channel(code: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    rule = lookup_rule(RULE_C2_CHANNEL)
    if rule is None:
        return out

    def emit(line: int, ev: str, conf: str) -> None:
        out.append(build_finding(rule, filename=rel, line_no=max(1, line), evidence=ev,
                                 engine=ENGINE, confidence=conf))

    dd = _DEADDROP_HOST.search(code)
    if dd and _EXEC_SINK.search(_window(code, dd.start())):
        emit(_line_of(code, dd), f"공개 텍스트 호스트({dd.group(0)[:40]})에서 받아 실행(dead-drop) — 코드를 받아 돌리는 경로", "confirmed")
    wh = _WEBHOOK.search(code)
    if wh:
        host = re.sub(r"(webhooks/|bot)[\w:/-]+", r"\1…", wh.group(0))
        transmit = _TRANSMIT.search(code) is not None
        emit(_line_of(code, wh), f"하드코딩된 메신저 webhook 수신 URL({host})" + (" + 외부 전송" if transmit else ""),
             "likely" if transmit else "pattern-only")
    dns = _DNS_C2.search(code)
    if dns:
        emit(_line_of(code, dns), "DNS 응답(TXT 등)을 명령·주소로 사용 — DNS 기반 채널", "likely")
    ch = _CHAIN.search(code)
    if ch:
        emit(_line_of(code, ch), f"블록체인 RPC 호출({ch.group(0)[:30]}) — 업무 앱 맥락이 아니면 명령 수신 채널일 수 있음(의존성·용도 확인)", "pattern-only")
    return out


# ---------------------------------------------------------------------------
# 어댑터
# ---------------------------------------------------------------------------

@dataclass
class _Ctx:
    has_blockchain_dep: bool = field(default=False)


#: 정규식·패턴 **정의** 줄. 보안 도구(이 체커 자신 포함)의 소스는 수집 경로·전송 함수 이름을 패턴
#: 원문으로 나열하므로 "수집 + 전송"이 한 파일에 전부 들어 있다(41차 자기 검사에서 확인). 패턴 정의
#: 줄은 실행이 아니다 — 실제 호출 줄은 그대로 남으므로 공격 코드의 탐지는 줄지 않는다.
_PATTERN_DEF_LINE = re.compile(
    r"re\.compile\(|new\s+RegExp\(|\bRegExp\(|\br['\"].*(?:\\[bsdw.]|\(\?:|\[\^)",
)


def _mask_pattern_definition_lines(code: str) -> str:
    """패턴 정의 줄을 빈 줄로 바꾼다(줄 번호 보존). 해당 줄이 없으면 원문을 그대로 돌려준다."""
    if not _PATTERN_DEF_LINE.search(code):
        return code
    return "\n".join("" if _PATTERN_DEF_LINE.search(ln) else ln for ln in code.split("\n"))


def scan_agent_surface(code: str, *, filename: str = "<memory>") -> list[Finding]:
    out: list[Finding] = []
    code = _mask_pattern_definition_lines(code)
    out += judge_ai_cli_invocation(code, filename)
    out += judge_credential_exfil(code, filename)
    out += judge_c2_channel(code, filename)
    return out


class AgentSurfaceScanner(ScannerAdapter):
    """`_ADAPTERS` 에 등록 — 실행 소스의 에이전트·공급망 **행위** 판정(39차)."""

    name = "agent-surface"

    def scan(
        self,
        code: str,
        *,
        filename: str = "<memory>",
        language: str | None = None,
        scenario: str | None = None,
        profile: str = "public-default-strict",
        categories: set[str] | None = None,
    ) -> list[Finding]:
        if categories and CATEGORY not in categories:
            return []
        suffix = Path(filename).suffix.lower()
        # 데이터·마크업 파일은 보지 않는다(실행 소스만). 확장자 없으면(셸 스크립트 등) 본다.
        if suffix and suffix not in _SOURCE_SUFFIXES:
            return []
        return scan_agent_surface(code, filename=filename)
