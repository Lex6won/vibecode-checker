"""Public scanner facade.

Runs every registered ``ScannerAdapter`` and combines their findings into a
single ``ScanReport``. When two adapters report the same ``(rule_id, file,
line)`` the more precise engine wins (currently: python-ast > regex).

External callers should continue to use ``scan_code`` / ``scan_file`` /
``scan_path`` here; the per-engine adapters live in ``gvskb.scanners``.

Rules are still loaded once at import via the regex adapter. ``RULES`` and
``reload_rules`` are re-exported for backwards compatibility.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable

from .profiles import apply_profile, load_profile
from .scanners.ast_scanner import PythonAstScanner
from .scanners.js_taint import JsTaintScanner
from .scanners.external_surface import (
    dedupe_connections,
    extract_api_connections,
    extract_static_resources,
    inventory_packages,
)
from .scanners.regex_scanner import (
    RULES as RULES,
    RegexScanner,
    build_finding,
    lookup_rule,
    redact_evidence as _redact_evidence,
    reload_rules as _reload_runtime_rules,
)
from .scanners.semgrep_scanner import SemgrepScanner
from .schema import (
    Decision,
    ExternalConnection,
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
    SkippedFile,
)

# Adapter run order. Earlier adapters establish baseline findings; later
# adapters (more precise) can supersede them via dedup_findings. SemgrepScanner
# self-disables when the binary or rules dir is missing, so safe to include.
_ADAPTERS = [RegexScanner(), PythonAstScanner(), JsTaintScanner(), SemgrepScanner()]

# Engine precision ranking — higher number wins on collisions.
_ENGINE_PRECISION = {"regex": 0, "python-ast": 1, "js-taint": 1, "semgrep": 2}

SEVERITY_RANK = {
    Severity.low: 0,
    Severity.medium: 1,
    Severity.high: 2,
    Severity.critical: 3,
}


def reload_rules() -> int:
    """Reload the regex rule cache from disk. AST adapter follows along."""
    return _reload_runtime_rules()


def _provenance() -> dict:
    """분석 출처 각인 — 모든 ScanReport 에 엔진 버전·생성 시각(UTC)을 박는다.

    레지스트리·감사로그가 "어떤 엔진이 언제 판단했나"를 재현 가능하게 만드는
    최소 단위다. import 실패가 스캔을 막지 않도록 방어적으로 감싼다.
    """
    try:
        from gvskb import __version__
        ver: str | None = __version__
    except Exception:  # pragma: no cover - defensive
        ver = None
    from datetime import datetime, timezone
    return {
        "engine_version": ver,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _current_scan_mode() -> str | None:
    """Honest mode marker for the report — set only in offline (air-gapped) mode.

    Online is the implicit default (``None``), so normal reports are unchanged.
    In offline mode dependency/intel checks run against a local cache only, so
    the report must say so — an unchecked package is 'not judged', not 'safe'.
    """
    return "offline" if os.environ.get("GVSKB_MODE", "").lower() == "offline" else None


def _intel_freshness() -> dict | None:
    """오프라인 모드에서 리포트에 실릴 인텔 캐시 기준일(source_id → 날짜).

    보안팀이 "몇 월 며칠 캐시 기준의 판정인지"를 리포트만 보고 알 수 있어야
    반입 주기를 판단할 수 있다. 온라인 모드는 실시간 조회이므로 None.
    로드 실패는 스캔을 막지 않는다 — 기준일 표기만 생략된다.
    """
    if _current_scan_mode() != "offline":
        return None
    try:
        from .intel.cache import IntelCache
        cache = IntelCache()
        fresh: dict[str, str] = {}
        for sid in cache.list_sources():
            entry = cache.load(sid)  # sha256 재검증 포함 — 변조 캐시는 표기하지 않음
            if entry is not None and entry.fetched_at:
                fresh[sid] = entry.fetched_at[:10]  # 날짜만 — 리포트 가독성
        return fresh or None
    except Exception:  # noqa: BLE001 — 표기 실패가 검사를 막으면 안 된다
        return None


def _highest(findings: Iterable[Finding]) -> Severity | None:
    highest: Severity | None = None
    for finding in findings:
        if highest is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]:
            highest = finding.severity
    return highest


def _summary(findings: list[Finding]) -> ScanSummary:
    by_severity = {s.value: 0 for s in Severity}
    by_decision = {d.value: 0 for d in Decision}
    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_decision[finding.decision.value] += 1
    return ScanSummary(
        finding_count=len(findings),
        by_severity=by_severity,
        by_decision=by_decision,
        highest_severity=_highest(findings),
        blocked=any(f.decision == Decision.block for f in findings),
    )


# AST 엔진이 파일을 성공적으로 파싱했다면, 같은 주제를 다루는 **줄 단위 regex
# 결과는 버린다**. regex 는 삽입 값의 출처(사용자 입력 vs 개발자 상수)를 알 수
# 없어 상수 기반 SQL 조립을 치명 위험으로 잘못 올렸고(실측 오탐), AST 는 그
# 구분을 한다. 파싱 실패 시에만 regex 가 예비 수단으로 남는다.
_AST_OWNED_RULE_IDS = frozenset({
    "GOV-SQL-INJECTION-001",
    "GOV-SQL-DDL-DYNAMIC-001",
    "GOV-LLM-PROMPT-INJECTION-001",
})


def _drop_regex_when_ast_owns(findings: list[Finding], ast_parsed: bool) -> list[Finding]:
    if not ast_parsed:
        return findings
    return [
        f for f in findings
        if not (f.engine == "regex" and f.rule_id in _AST_OWNED_RULE_IDS)
    ]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep the most precise engine's finding for each (rule_id, file, line)."""
    best: dict[tuple[str, str, int], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.location.file, f.location.line)
        prev = best.get(key)
        if prev is None:
            best[key] = f
        elif _ENGINE_PRECISION.get(f.engine, 0) > _ENGINE_PRECISION.get(prev.engine, 0):
            best[key] = f
    return list(best.values())


def scan_code(
    code: str,
    *,
    filename: str = "<memory>",
    language: str | None = None,
    scenario: str | None = None,
    profile: str = "public-default-strict",
    categories: set[str] | None = None,
) -> ScanReport:
    raw: list[Finding] = []
    for adapter in _ADAPTERS:
        raw.extend(adapter.scan(
            code,
            filename=filename,
            language=language,
            scenario=scenario,
            profile=profile,
            categories=categories,
        ))
    from .scanners.ast_scanner import python_ast_parsed
    raw = _drop_regex_when_ast_owns(raw, python_ast_parsed(code, filename, language))
    findings = _dedupe(raw)

    # Apply scenario-bound policy: decision overrides + severity_min filter.
    profile_spec = load_profile(profile)
    findings = apply_profile(findings, profile_spec)

    return ScanReport(
        target=filename,
        language=language,
        scenario=scenario,
        profile=profile,
        summary=_summary(findings),
        findings=findings,
        # 인메모리 조각도 "이 파일을 검사함"으로 기록 — 발견 0이 "검사 안 됨"이
        # 아니라 "위험 없음"으로 올바르게 결론나게 한다.
        scanned_files=[filename],
        external_surface=dedupe_connections(
            extract_api_connections(code, filename) + extract_static_resources(code, filename)
        ),
        scan_mode=_current_scan_mode(),
        intel_freshness=_intel_freshness(),
        **_provenance(),
    )


def scan_file(path: str | Path, *, language: str | None = None, scenario: str | None = None) -> ScanReport:
    p = Path(path)
    # utf-8-sig — BOM 제거(그대로 두면 AST 파싱이 실패한다).
    return scan_code(p.read_text(encoding="utf-8-sig"), filename=str(p), language=language, scenario=scenario)


# ---------------------------------------------------------------------------
# Directory / path scanning — unchanged from the pre-adapter version
# ---------------------------------------------------------------------------

DEFAULT_INCLUDE_EXTS: frozenset[str] = frozenset({
    ".py", ".pyw",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".scala",
    ".go", ".rs",
    ".rb", ".php",
    ".cs", ".vb",
    ".swift", ".m",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
    ".sql",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties",
    ".html", ".htm", ".xml",
    ".vue", ".svelte",
    ".tf", ".tfvars",
    ".dockerfile",
    # 자격증명·키 자재 — 실측에서 SSL **개인키**(*_key.pem)가 소스에 있는데
    # 확장자 목록에 없어 '검사조차 되지 않았다'. 확장자만으로도 위험 신호이며,
    # 내용(PEM 헤더)까지 보면 개인키 노출을 확정할 수 있다.
    ".pem", ".key", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".keystore",
    ".ppk", ".asc", ".gpg", ".kdbx",
})

# 파일 **이름**만으로 비밀 취급해야 하는 것들(확장자가 .txt 여도 검사한다).
# `.txt` 전면 스캔은 로그·문서까지 끌어들여 노이즈가 크므로 이름으로 선별한다.
_SECRET_FILENAME_RE = re.compile(
    r"(?:^|[._-])(?:password|passwd|pwd|secret|secrets|credential|credentials|"
    r"apikey|api[_-]?key|token|privatekey|private[_-]?key|id_rsa|id_dsa|id_ecdsa|id_ed25519)"
    r"(?:[._-]|$)",
    re.IGNORECASE,
)


def _is_secret_filename(name: str) -> bool:
    """이름만으로 비밀 자재로 봐야 하는 파일인가(password.txt, id_rsa 등)."""
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return bool(_SECRET_FILENAME_RE.search(name) or _SECRET_FILENAME_RE.search(stem))


# 비밀 파일에 담긴 "값처럼 보이는 것" — 긴 hex / base64 / 무작위 문자열.
# 32자 이상만 본다(짧은 값은 설정·식별자일 가능성이 높아 오탐이 된다).
_SECRET_VALUE_RE = re.compile(
    r"^[A-Za-z0-9+/=_\-]{32,}$"
)
_HEXLIKE_RE = re.compile(r"^[0-9a-fA-F]{32,}$")


def _looks_like_secret_material(text: str) -> tuple[bool, str]:
    """비밀 파일 내용이 '자격증명 값'으로 보이는가 → (판정, 근거 줄).

    파일명이 비밀을 뜻하는데 **내용이 긴 무작위 값 한 덩어리**면 그 값은 대개
    세션 서명키·API 키다. 주석·안내문만 있는 파일(예: "패스워드 없는 형태의
    인증서 파일입니다")은 제외해야 하므로 실제 값 형태만 본다.
    """
    for raw in text.splitlines()[:40]:      # 앞부분만 — 대용량 파일 방어
        line = raw.strip().strip("\"'")
        if not line or line.startswith(("#", "//", ";", "--")):
            continue
        # key=value 형태면 값 부분만 본다.
        if "=" in line and len(line.split("=", 1)[1].strip()) >= 32:
            line = line.split("=", 1)[1].strip().strip("\"'")
        if _HEXLIKE_RE.match(line) or _SECRET_VALUE_RE.match(line):
            return True, raw
    return False, ""

# 의존성 매니페스트/락파일 — regex 스캔으로는 취약 버전이 잡히지 않으므로
# SCA(check-package / scan_dependencies)로 보내야 한다. 디렉터리 스캔 중
# 만나면 스킵하되 그 사실을 안내로 남긴다. (package.json은 .json으로 이미 스캔됨)
_DEP_MANIFEST_NAMES: frozenset[str] = frozenset({
    "requirements.txt", "poetry.lock", "pipfile.lock", "uv.lock",
    "yarn.lock", "package-lock.json", "pnpm-lock.yaml",
})

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "env", ".env",
    "dist", "build", "out", "target",
    ".tox", ".nox",
    ".idea", ".vscode",
    "coverage", ".coverage", "htmlcov",
    "vendor", "third_party", "thirdparty",
    # 프런트엔드 빌드 출력·툴 캐시 — 모두 *생성물*이라 원본 소스가 아니다.
    # 미니파이드 번들을 스캔하면 룰이 import/토큰 단위로 대량 오탐을 낸다.
    ".next", ".nuxt", ".cache",
    # 이 도구가 만든 점검 보고서 — 반드시 제외해야 한다. 보고서에는 발견 사항의
    # **증거 문구가 인용**돼 있어(예: PEM 헤더), 다시 스캔하면 자기가 쓴 글을
    # 새 위험으로 잡는 자기 참조가 생긴다(실측: 재검사 때마다 발견이 2건씩 증식).
    ".check-reports",
    ".puppeteer-cache", ".tmp", "tmp", ".turbo", ".parcel-cache",
    ".svelte-kit", ".astro", ".vercel", ".netlify", ".output",
    ".angular", ".docusaurus", "storybook-static",
})

# 빌드 출력 디렉터리(이름 기준). DEFAULT_EXCLUDE_DIRS 의 부분집합으로, 이쪽은
# 제외하되 리포트에 "빌드 산출물 제외"로 *한 줄 기록*한다(정직성). 반대로
# .git/node_modules/__pycache__ 등 인프라 디렉터리는 조용히 제외한다.
_BUILD_OUTPUT_DIR_NAMES: frozenset[str] = frozenset({
    "dist", "build", "out", "target",
    ".next", ".nuxt",
    ".puppeteer-cache", ".tmp", "tmp", ".turbo", ".parcel-cache",
    ".svelte-kit", ".astro", ".vercel", ".netlify", ".output",
    ".angular", ".docusaurus", "storybook-static",
})

# 다중 세그먼트 빌드 출력 경로 — os.walk 는 디렉터리 *이름* 만 보므로
# "public/assets" 처럼 경로로만 식별되는 산출물은 상대경로 suffix 로 매칭한다.
# (소스의 "src/assets" 는 제외하지 않도록 "assets" 단독 이름은 막지 않는다.)
DEFAULT_EXCLUDE_PATH_SUFFIXES: tuple[str, ...] = (
    "public/assets",
    "static/assets",
    "public/build",
    "dist/assets",
    "build/static",
    "wwwroot/dist",
)

# 압축/번들 산출물로 스킵된 파일에 붙는 사유 마커. 리포트가 이 부분 문자열로
# "빌드 산출물 N건 제외" 한 줄을 집계한다(scanner→report 결합도 최소화).
BUILD_ARTIFACT_SKIP_REASON = "빌드 산출물(압축/번들) — 원본 소스 아님"

# 콘텐츠 해시가 박힌 빌드 파일명: app-3f9a2c1b.js, chunk.4F2A.css, main.min.js 등.
# Vite/webpack/rollup/esbuild 의 캐시버스팅 산출물을 파일명만으로 거른다.
_HASHED_ASSET_RE = re.compile(
    r"[.\-_][0-9a-f]{8,}\.(?:js|mjs|cjs|jsx|ts|tsx|css|map)$",
    re.IGNORECASE,
)

# single-line 초장문(미니파이드) 판정 기준.
_MINIFIED_MAX_LINE = 2000   # 한 줄이 이 길이를 넘으면 사람이 읽는 소스가 아님
_MINIFIED_AVG_LINE = 400    # 평균 줄 길이가 이만큼 큰 다줄 번들도 미니파이드로 본다
_MINIFIED_MIN_BYTES = 1000  # 너무 짧은 파일은 판정 제외(정상적인 한 줄 파일 보호)

DEFAULT_MAX_FILES = 500
DEFAULT_MAX_FILE_BYTES = 1_000_000


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _looks_like_build_artifact_name(name: str) -> bool:
    """파일명만으로 압축/번들 산출물을 식별한다(해시 파일명 · *.min.* )."""
    lower = name.lower()
    if ".min." in lower:
        return True
    return bool(_HASHED_ASSET_RE.search(lower))


def _looks_minified(text: str) -> bool:
    """내용 기반 미니파이드 판정: single-line 초장문 또는 평균 줄 과대."""
    if len(text) < _MINIFIED_MIN_BYTES:
        return False
    lines = text.splitlines() or [text]
    longest = max(len(ln) for ln in lines)
    if longest >= _MINIFIED_MAX_LINE:
        return True
    avg = len(text) / max(len(lines), 1)
    return avg >= _MINIFIED_AVG_LINE


def _path_is_excluded_suffix(rel_dir: str) -> bool:
    posix = rel_dir.replace("\\", "/").strip("/").lower()
    return any(posix == s or posix.endswith("/" + s) for s in DEFAULT_EXCLUDE_PATH_SUFFIXES)


def _rel(p: Path, root: Path, is_dir: bool) -> str:
    if not is_dir:
        return p.name
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def scan_path(
    path: str | Path,
    *,
    include_exts: set[str] | frozenset[str] | None = None,
    exclude_dirs: set[str] | frozenset[str] | None = None,
    scenario: str | None = None,
    profile: str = "public-default-strict",
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    caller: str = "",
) -> ScanReport:
    """Scan a file or directory tree on disk.

    ``caller`` 는 호출 주체 자율 신고 값(예: 'harness:auto') — 감사로그의
    caller 필드로 전달돼 레지스트리 request_type(AUTO/MANUAL) 구분 근거가 된다.
    """
    root = Path(path)
    inc = frozenset(e.lower() for e in (include_exts or DEFAULT_INCLUDE_EXTS))
    exc = frozenset(exclude_dirs or DEFAULT_EXCLUDE_DIRS)
    skipped: list[SkippedFile] = []
    external: list[ExternalConnection] = []          # 외부 연결 인벤토리 누적
    manifest_files: list[tuple[Path, str]] = []      # (경로, ecosystem) — 플러그인 목록용

    if not root.exists():
        return ScanReport(
            target=str(root),
            scenario=scenario,
            profile=profile,
            summary=_summary([]),
            findings=[],
            scanned_files=[],
            skipped_files=[SkippedFile(path=str(root), reason="path does not exist")],
            scan_mode=_current_scan_mode(),
            intel_freshness=_intel_freshness(),
            **_provenance(),
        )

    files_to_scan: list[Path] = []
    is_dir = root.is_dir()

    if root.is_file():
        files_to_scan = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            # 1) 이름 기반 제외 + 2) 경로 suffix 기반 제외(public/assets 등).
            # 빌드 출력 디렉터리는 제외하되 한 줄 기록하고, 인프라 디렉터리
            # (.git/node_modules 등)는 조용히 버린다.
            kept_dirs = []
            for d in dirnames:
                try:
                    rel_dir = str((Path(dirpath) / d).relative_to(root))
                except ValueError:
                    rel_dir = d
                is_build = d in _BUILD_OUTPUT_DIR_NAMES or _path_is_excluded_suffix(rel_dir)
                if is_build:
                    skipped.append(SkippedFile(
                        path=rel_dir.replace("\\", "/") + "/",
                        reason=BUILD_ARTIFACT_SKIP_REASON,
                    ))
                    continue
                if d in exc:
                    continue
                kept_dirs.append(d)
            dirnames[:] = kept_dirs
            for name in filenames:
                if len(files_to_scan) >= max_files:
                    break
                p = Path(dirpath) / name
                if name.lower() in _DEP_MANIFEST_NAMES:
                    skipped.append(SkippedFile(
                        path=_rel(p, root, is_dir),
                        reason="의존성 매니페스트 — 취약점은 `gvskb check-package` 또는 MCP `scan_dependencies`로 검사하세요",
                    ))
                    # 외부 연결 인벤토리용으로 *직접 의존성*만 읽는다(락파일 제외).
                    if name.lower() == "requirements.txt":
                        manifest_files.append((p, "pypi"))
                    continue
                if (
                    p.suffix.lower() not in inc
                    and name.lower() not in {"dockerfile", "makefile"}
                    and not _is_secret_filename(name)
                ):
                    # **조용히 버리지 않는다** — 검사 대상이 아닌 파일도 기록해야
                    # "검사했는데 깨끗함"과 "아예 안 봤음"이 구분된다. 실측에서
                    # ssl/ 디렉터리의 개인키가 스캔·제외 어디에도 없이 사라졌다.
                    skipped.append(SkippedFile(
                        path=_rel(p, root, is_dir),
                        reason=f"검사 대상 확장자 아님({p.suffix or '확장자 없음'}) — 검사되지 않았습니다",
                    ))
                    continue
                # 압축/번들 산출물(해시 파일명 · *.min.*)은 원본이 아니므로 스킵.
                # single-line 초장문(내용 기준)은 아래에서 텍스트 확인 후 거른다.
                if _looks_like_build_artifact_name(name):
                    skipped.append(SkippedFile(
                        path=_rel(p, root, is_dir),
                        reason=BUILD_ARTIFACT_SKIP_REASON,
                    ))
                    continue
                try:
                    size = p.stat().st_size
                except OSError as exc_io:
                    skipped.append(SkippedFile(path=_rel(p, root, is_dir), reason=f"stat error: {exc_io!s}"))
                    continue
                if size > max_file_bytes:
                    skipped.append(SkippedFile(path=_rel(p, root, is_dir), reason=f"too large ({size} bytes)"))
                    continue
                if size == 0:
                    continue
                files_to_scan.append(p)
            if len(files_to_scan) >= max_files:
                skipped.append(SkippedFile(path=str(root), reason=f"max_files={max_files} reached"))
                break

    all_findings: list[Finding] = []
    scanned: list[str] = []
    content_hashes: dict[str, list[str]] = {}   # 내용 해시 → 같은 내용 파일 경로들

    for f in files_to_scan:
        rel = _rel(f, root, is_dir)
        try:
            head = f.read_bytes()[:4096]
        except OSError as exc_io:
            skipped.append(SkippedFile(path=rel, reason=f"read error: {exc_io!s}"))
            continue
        if _looks_binary(head):
            skipped.append(SkippedFile(path=rel, reason="binary content (NUL detected)"))
            continue
        try:
            # utf-8-sig: BOM 을 **제거하고** 읽는다. utf-8 로 읽으면 BOM 이
            # U+FEFF 문자로 남아 `ast.parse` 가 SyntaxError 를 내고, AST 정밀
            # 엔진이 조용히 꺼진 채 regex 로만 검사된다(실측: Windows·한글
            # 환경에서 흔한 BOM 파일 2개에서 SQL 테인트 분석이 통째로 누락).
            text = f.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = f.read_text(encoding="cp949")
            except UnicodeDecodeError:
                skipped.append(SkippedFile(path=rel, reason="encoding: not utf-8 or cp949"))
                continue
        # single-line 초장문/평균 줄 과대 = 미니파이드 번들. 룰 대량 오탐의 원인.
        if _looks_minified(text):
            skipped.append(SkippedFile(path=rel, reason=BUILD_ARTIFACT_SKIP_REASON))
            continue
        # 내용 해시 — 같은 파일이 여러 경로에 복사돼 발견이 배수로 보이는 상황을
        # 리포트가 "동일 파일 N곳"으로 설명할 수 있게 한다(예: ssl/ 폴더 복제).
        content_hashes.setdefault(
            hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(), []
        ).append(rel)
        report = scan_code(text, filename=rel, scenario=scenario, profile=profile)
        all_findings.extend(report.findings)
        # 이름이 비밀을 뜻하는 파일에 값처럼 보이는 내용이 있으면 별도 발행.
        # 파일명 + 내용을 함께 봐야 하는 판정이라 regex 룰로는 만들 수 없다.
        if _is_secret_filename(f.name):
            hit, evidence_line = _looks_like_secret_material(text)
            if hit:
                keyfile_rule = lookup_rule("GOV-SECRET-KEYFILE-001")
                if keyfile_rule is not None:
                    all_findings.append(build_finding(
                        keyfile_rule, filename=rel, line_no=1,
                        evidence=_redact_evidence(evidence_line),
                        engine="secret-file",
                    ))
        scanned.append(rel)
        # 외부 연결 인벤토리: 코드의 외부 API 호출 + package.json 의 직접 의존성.
        external.extend(extract_api_connections(text, rel))
        external.extend(extract_static_resources(text, rel))
        if f.name.lower() == "package.json":
            external.extend(
                inventory_packages(parse_manifest_packages(text, "npm"), rel)
            )

    for mpath, eco in manifest_files:
        try:
            mtext = mpath.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
        external.extend(
            inventory_packages(parse_manifest_packages(mtext, eco), _rel(mpath, root, is_dir))
        )

    # 승인된 예외(.gvskb-exceptions.yaml) — 발견을 숨기지 않고 표시만 하며,
    # 요약(건수·차단)과 exit code 는 비억제 발견 기준으로 계산한다.
    from .suppressions import apply_suppressions, load_exceptions
    sup = apply_suppressions(all_findings, load_exceptions(root))
    active = [f for f in all_findings if not f.suppressed]
    suppression_summary = None
    if sup.applied or sup.expired or sup.invalid:
        suppression_summary = {
            "applied": sup.applied,
            "expired": sup.expired,
            "invalid": sup.invalid,
        }

    report = ScanReport(
        target=str(root),
        scenario=scenario,
        profile=profile,
        summary=_summary(active),
        findings=all_findings,
        scanned_files=scanned,
        skipped_files=skipped,
        external_surface=dedupe_connections(external),
        scan_mode=_current_scan_mode(),
        intel_freshness=_intel_freshness(),
        suppression_summary=suppression_summary,
        # 발견이 있는 파일 중 복제본만 기록한다(무관한 중복 파일은 소음).
        duplicate_files=[
            {"hash": h[:12], "paths": sorted(paths)}
            for h, paths in sorted(content_hashes.items())
            if len(paths) > 1 and any(f.location.file in paths for f in all_findings)
        ],
        **_provenance(),
    )
    # 감사로그(옵트인, GVSKB_AUDIT_DIR) — 공공 점검 이력 증빙. 실패해도 스캔은 계속.
    from .audit import record_scan
    record_scan(report, "scan_path", caller=caller)
    return report


def detect_secrets_and_pii(code: str, *, filename: str = "<memory>") -> ScanReport:
    return scan_code(
        code,
        filename=filename,
        categories={"privacy-public-sector", "secret-scanning", "public-sector-internal"},
    )


def path_level_rule_ids() -> tuple[str, ...]:
    """``scan_path`` 가 직접 발행하는 룰 — 파일명·내용을 **함께** 봐야 하는 것들.

    어댑터(regex/AST)가 아니라 경로 순회 단계에서 판정하므로 여기에 선언한다.
    선언이 없으면 patterns 도 없고 발행 주체도 없는 '침묵하는 룰'이 된다.
    """
    return ("GOV-SECRET-KEYFILE-001",)


def parse_manifest_packages(manifest_text: str, ecosystem: str) -> list[dict]:
    """Parse common dependency manifests without executing package managers.

    각 항목은 ``version_exact`` 를 함께 싣는다. ``requests>=2.28`` 은 "2.28 이상"이지
    "2.28"이 아니다 — 설치된 것은 2.31.0 일 수 있다. 예전에는 연산자를 버리고 경계값을
    구체 버전처럼 다뤄, 2.31.0 을 쓰는 프로젝트에 2.28 의 취약점을 보고할 수 있었고
    그 판정이 레지스트리에 "2.28 에 대한 사실"로 제출됐다.

    경계값 검사 자체는 남긴다 — "이 제약이 취약한 버전을 허용한다"는 것도 실제 신호다.
    다만 그것이 **관측이 아니라 가정**임을 값에 실어 뒤에서 구분할 수 있게 한다.
    """
    packages: list[dict] = []
    eco = ecosystem.lower()
    if eco == "pypi":
        for raw in manifest_text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.!*+-]+)?", line)
            if m:
                version, op = m.group(3), m.group(2)
                packages.append({
                    "name": m.group(1),
                    "version": version,
                    # ``===`` 는 정규식상 ``==`` + 남은 ``=`` 로 잡히지 않으므로 다루지 않는다.
                    # 와일드카드(``2.*``)는 고정이 아니다.
                    "version_exact": bool(version) and op == "==" and "*" not in version,
                })
    elif eco == "npm":
        try:
            data = json.loads(manifest_text)
        except json.JSONDecodeError:
            return packages
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(data.get(key, {}) or {})
        for name, spec in deps.items():
            raw_spec = str(spec) if spec else ""
            version = raw_spec.lstrip("^~") if raw_spec else None
            # npm 은 접두사가 없어야 고정이다. ``4.17.0`` 은 고정, ``^4.17.0``·``>=4``·
            # ``*``·``latest``·git URL 은 아니다.
            exact = bool(version) and raw_spec == version and re.fullmatch(
                r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?", version,   # 4.17.0-beta.1 도 고정이다
            ) is not None
            packages.append({"name": name, "version": version, "version_exact": exact})
    return packages


def suggest_fix(rule_id: str, unsafe_code: str | None = None) -> dict:
    matched = lookup_rule(rule_id)
    if not matched:
        return {
            "rule_id": rule_id,
            "can_suggest": False,
            "message": "알 수 없는 룰입니다. finding의 rule_id를 확인하세요.",
        }
    return {
        "rule_id": rule_id,
        "can_suggest": True,
        "plain_title": matched["plain_title"],
        "safe_fix": matched.get("fix"),
        "can_auto_fix": bool(matched.get("auto", False)),
        "unsafe_code_preview": _redact_evidence(unsafe_code or ""),
        "note": "자동 수정은 diff 미리보기 후 적용해야 하며, 업무 로직 변경은 담당자 확인이 필요합니다.",
    }
