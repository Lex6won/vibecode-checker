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

import json
import os
import re
from pathlib import Path
from typing import Iterable

from .profiles import apply_profile, load_profile
from .scanners.ast_scanner import PythonAstScanner
from .scanners.external_surface import (
    dedupe_connections,
    extract_api_connections,
    inventory_packages,
)
from .scanners.regex_scanner import (
    RULES as RULES,
    RegexScanner,
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
_ADAPTERS = [RegexScanner(), PythonAstScanner(), SemgrepScanner()]

# Engine precision ranking — higher number wins on collisions.
_ENGINE_PRECISION = {"regex": 0, "python-ast": 1, "semgrep": 2}

SEVERITY_RANK = {
    Severity.low: 0,
    Severity.medium: 1,
    Severity.high: 2,
    Severity.critical: 3,
}


def reload_rules() -> int:
    """Reload the regex rule cache from disk. AST adapter follows along."""
    return _reload_runtime_rules()


def _current_scan_mode() -> str | None:
    """Honest mode marker for the report — set only in offline (air-gapped) mode.

    Online is the implicit default (``None``), so normal reports are unchanged.
    In offline mode dependency/intel checks run against a local cache only, so
    the report must say so — an unchecked package is 'not judged', not 'safe'.
    """
    return "offline" if os.environ.get("GVSKB_MODE", "").lower() == "offline" else None


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
        external_surface=dedupe_connections(extract_api_connections(code, filename)),
        scan_mode=_current_scan_mode(),
    )


def scan_file(path: str | Path, *, language: str | None = None, scenario: str | None = None) -> ScanReport:
    p = Path(path)
    return scan_code(p.read_text(encoding="utf-8"), filename=str(p), language=language, scenario=scenario)


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
})

# 의존성 매니페스트/락파일 — regex 스캔으로는 취약 버전이 잡히지 않으므로
# SCA(check-package / scan_dependencies)로 보내야 한다. 디렉터리 스캔 중
# 만나면 스킵하되 그 사실을 안내로 남긴다. (package.json은 .json으로 이미 스캔됨)
_DEP_MANIFEST_NAMES: frozenset[str] = frozenset({
    "requirements.txt", "poetry.lock", "pipfile.lock",
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
) -> ScanReport:
    """Scan a file or directory tree on disk."""
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
                if p.suffix.lower() not in inc and name.lower() not in {"dockerfile", "makefile"}:
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
            text = f.read_text(encoding="utf-8")
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
        report = scan_code(text, filename=rel, scenario=scenario, profile=profile)
        all_findings.extend(report.findings)
        scanned.append(rel)
        # 외부 연결 인벤토리: 코드의 외부 API 호출 + package.json 의 직접 의존성.
        external.extend(extract_api_connections(text, rel))
        if f.name.lower() == "package.json":
            external.extend(
                inventory_packages(parse_manifest_packages(text, "npm"), rel)
            )

    for mpath, eco in manifest_files:
        try:
            mtext = mpath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        external.extend(
            inventory_packages(parse_manifest_packages(mtext, eco), _rel(mpath, root, is_dir))
        )

    report = ScanReport(
        target=str(root),
        scenario=scenario,
        profile=profile,
        summary=_summary(all_findings),
        findings=all_findings,
        scanned_files=scanned,
        skipped_files=skipped,
        external_surface=dedupe_connections(external),
        scan_mode=_current_scan_mode(),
    )
    # 감사로그(옵트인, GVSKB_AUDIT_DIR) — 공공 점검 이력 증빙. 실패해도 스캔은 계속.
    from .audit import record_scan
    record_scan(report, "scan_path")
    return report


def detect_secrets_and_pii(code: str, *, filename: str = "<memory>") -> ScanReport:
    return scan_code(
        code,
        filename=filename,
        categories={"privacy-public-sector", "secret-scanning", "public-sector-internal"},
    )


def parse_manifest_packages(manifest_text: str, ecosystem: str) -> list[dict[str, str | None]]:
    """Parse common dependency manifests without executing package managers."""
    packages: list[dict[str, str | None]] = []
    eco = ecosystem.lower()
    if eco == "pypi":
        for raw in manifest_text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.!*+-]+)?", line)
            if m:
                packages.append({"name": m.group(1), "version": m.group(3)})
    elif eco == "npm":
        try:
            data = json.loads(manifest_text)
        except json.JSONDecodeError:
            return packages
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(data.get(key, {}) or {})
        for name, version in deps.items():
            packages.append({"name": name, "version": str(version).lstrip("^~") if version else None})
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
