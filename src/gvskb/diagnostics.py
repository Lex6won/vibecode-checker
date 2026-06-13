"""런타임 환경 진단 — gvskb doctor / MCP server_status 공통 백엔드.

다음 정보를 한 곳에 모아 사용자가 자기 환경의 문제를 즉시 파악할 수 있게 합니다.

- Python·OS·플랫폼·인코딩
- 패키지 버전, import된 gvskb 경로
- 룰 디렉토리 해석 결과, 환경변수, 로드된 룰 수 (전체·런타임·realtime)
- OSV.dev 연결 가능 여부 (network 옵션)
- MCP 서버 import 가능 여부

각 항목은 status (OK / WARN / ERROR) 와 함께 반환되며, 가장 높은 심각도가
전체 진단 결과의 종료 코드를 결정합니다.
"""
from __future__ import annotations

import os
import platform
import sys
from collections.abc import Iterable
from importlib import metadata, resources
from pathlib import Path
from typing import Literal, TypedDict

Status = Literal["ok", "warn", "error"]

PKG_NAME = "vibecode-checker"

_OK: Status = "ok"
_WARN: Status = "warn"
_ERROR: Status = "error"


class CheckResult(TypedDict, total=False):
    name: str
    status: Status
    value: str | int | None
    note: str


def _check(name: str, status: Status, value: str | int | None = None, note: str = "") -> CheckResult:
    return {"name": name, "status": status, "value": value, "note": note}


def _package_version() -> str:
    try:
        return metadata.version(PKG_NAME)
    except metadata.PackageNotFoundError:
        return "unknown (editable install or not installed)"


def _gvskb_path() -> str:
    try:
        import gvskb  # local import to avoid circular at module load
        return str(Path(gvskb.__file__).resolve().parent)
    except Exception as exc:  # pragma: no cover - defensive
        return f"import failed: {exc!s}"


def _resolve_rules_dir() -> tuple[Path, str]:
    """Mirror the resolution order used by server.py and scanner.py."""
    override = os.environ.get("GVSKB_RULES_DIR")
    if override:
        return Path(override), "GVSKB_RULES_DIR env"
    try:
        import gvskb
        pkg_root = Path(gvskb.__file__).resolve().parent
        project_root = pkg_root.parent.parent
        repo_rules = project_root / "rules"
        if repo_rules.exists():
            return repo_rules, "repository checkout"
    except Exception:
        pass
    packaged = Path(str(resources.files("gvskb").joinpath("rules")))
    return packaged, "packaged (importlib.resources)"


def _utf8_capable() -> tuple[bool, str]:
    enc = (sys.stdout.encoding or "").lower()
    return ("utf" in enc, enc or "<unknown>")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_python() -> list[CheckResult]:
    return [
        _check("Python", _OK, sys.version.split()[0]),
        _check("OS", _OK, f"{platform.system()} {platform.release()}"),
        _check("Platform", _OK, platform.platform()),
    ]


def check_mode() -> list[CheckResult]:
    mode = os.environ.get("GVSKB_MODE", "").lower()
    if mode == "offline":
        return [_check("GVSKB_MODE", _OK, "offline",
                       note="망분리 정책 — 외부 API 호출 자동 건너뜀")]
    if mode in ("", "online", "online-restricted"):
        return [_check("GVSKB_MODE", _OK, mode or "<unset>",
                       note="외부 보안 API(OSV/NVD/KEV/EPSS) 호출 허용")]
    return [_check("GVSKB_MODE", _WARN, mode,
                   note="알려지지 않은 모드 — online | online-restricted | offline 중 하나 권장")]


def check_package() -> list[CheckResult]:
    return [
        _check("Package", _OK, _package_version(), note=PKG_NAME),
        _check("Module path", _OK, _gvskb_path()),
    ]


def check_encoding() -> list[CheckResult]:
    ok, enc = _utf8_capable()
    pythonioenc = os.environ.get("PYTHONIOENCODING", "")
    pythonutf8 = os.environ.get("PYTHONUTF8", "")
    results = [
        _check("stdout encoding", _OK if ok else _WARN, enc,
               note="" if ok else "한글 출력이 깨질 수 있습니다. PowerShell: chcp 65001; "
               "$env:PYTHONUTF8='1'; $env:PYTHONIOENCODING='utf-8'"),
        _check("PYTHONUTF8", _OK if pythonutf8 == "1" else _WARN,
               pythonutf8 or "<unset>",
               note="" if pythonutf8 == "1" else "Windows PowerShell 권장: $env:PYTHONUTF8='1'"),
        _check("PYTHONIOENCODING", _OK if pythonioenc else _WARN,
               pythonioenc or "<unset>",
               note="" if pythonioenc else "Windows PowerShell 권장: $env:PYTHONIOENCODING='utf-8'"),
    ]
    if platform.system() == "Windows":
        results.append(_check(
            "Windows shell hint",
            _OK,
            "chcp 65001; $env:PYTHONUTF8='1'; $env:PYTHONIOENCODING='utf-8'",
            note="영구 설정·MCP 연결·문제 해결: docs/windows_utf8.md",
        ))
    return results


def check_rules(*, expected_minimum: int = 20) -> list[CheckResult]:
    """Loaded rule counts. Below expected_minimum is treated as ERROR."""
    rules_dir, src = _resolve_rules_dir()
    override = os.environ.get("GVSKB_RULES_DIR", "")
    results: list[CheckResult] = [
        _check("Rules dir", _OK if rules_dir.exists() else _ERROR, str(rules_dir), note=f"source: {src}"),
        _check("GVSKB_RULES_DIR", _OK if override else _OK, override or "<unset>"),
    ]
    try:
        from .loader import load_all_rules
        rules = load_all_rules(rules_dir, strict=True)
    except Exception as exc:
        results.append(_check("Rule loader", _ERROR, "0", note=f"loader failed: {exc!s}"))
        return results

    total = len(rules)
    status: Status = _OK if total >= expected_minimum else _ERROR
    runtime_count = sum(1 for r in rules if r.detection and r.detection.patterns)
    realtime_count = sum(1 for r in rules if r.source_layer.value == "realtime")
    results.extend([
        _check("Total rules", status, total, note=f"minimum expected: {expected_minimum}"),
        _check("Runtime detection rules", _OK if runtime_count > 0 else _WARN, runtime_count),
        _check("Realtime source-layer rules", _OK, realtime_count),
    ])
    return results


def check_mcp_import() -> list[CheckResult]:
    try:
        from . import server  # noqa: F401
        return [_check("MCP server import", _OK, "gvskb.server")]
    except Exception as exc:
        return [_check("MCP server import", _ERROR, "failed", note=str(exc))]


def check_semgrep() -> list[CheckResult]:
    """Detect optional Semgrep adapter availability — WARN, never ERROR.

    Semgrep is optional: missing on native Windows is expected. The adapter
    self-disables; this check just tells the operator whether JS/TS gets the
    AST-precise engine or falls back to regex only.
    """
    try:
        from .scanners.semgrep_scanner import SemgrepScanner, supported_rule_ids
    except Exception as exc:
        return [_check("Semgrep adapter", _WARN, "import failed", note=str(exc))]

    scanner = SemgrepScanner()
    if scanner.is_available():
        rule_ids = list(supported_rule_ids())
        return [_check(
            "Semgrep adapter", _OK,
            f"{scanner.binary} ({len(rule_ids)} rules)",
        )]
    binary_present = bool(scanner.binary)
    rules_present = scanner.rules_dir.exists() and any(scanner.rules_dir.iterdir())
    if not binary_present and not rules_present:
        reason = "semgrep binary not on PATH, no rules/semgrep/ found"
    elif not binary_present:
        reason = "semgrep binary not on PATH (pip install semgrep on Linux/macOS/WSL)"
    else:
        reason = "rules/semgrep/ missing or empty"
    return [_check(
        "Semgrep adapter", _WARN, "disabled",
        note=f"{reason} — JS/TS는 regex 엔진만 사용됩니다.",
    )]


def check_osv(timeout: float = 3.0) -> list[CheckResult]:
    """Network probe. Returns WARN on failure — offline environments are valid."""
    try:
        import httpx
    except ImportError:
        return [_check("OSV.dev reachability", _WARN, "httpx not installed")]
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": "left-pad", "ecosystem": "npm"}},
            )
            if resp.status_code == 200:
                return [_check("OSV.dev reachability", _OK, "200")]
            return [_check("OSV.dev reachability", _WARN, str(resp.status_code))]
    except Exception as exc:
        return [_check(
            "OSV.dev reachability", _WARN, "unreachable",
            note=f"망분리 환경에서 정상일 수 있습니다 ({exc!s})",
        )]


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def run_diagnostics(*, network: bool = True, expected_minimum: int = 20) -> dict:
    """Run all checks and return a structured report."""
    checks: list[CheckResult] = []
    checks.extend(check_python())
    checks.extend(check_package())
    checks.extend(check_encoding())
    checks.extend(check_mode())
    checks.extend(check_rules(expected_minimum=expected_minimum))
    checks.extend(check_mcp_import())
    checks.extend(check_semgrep())
    # GVSKB_MODE=offline implies no network checks regardless of --offline flag
    offline_env = os.environ.get("GVSKB_MODE", "").lower() == "offline"
    if network and not offline_env:
        checks.extend(check_osv())
    else:
        reason = "GVSKB_MODE=offline" if offline_env else "--offline"
        checks.append(_check("OSV.dev reachability", _OK, f"skipped ({reason})"))

    overall = overall_status(c["status"] for c in checks)
    return {
        "overall": overall,
        "checks": checks,
        "summary": {
            "ok": sum(1 for c in checks if c["status"] == _OK),
            "warn": sum(1 for c in checks if c["status"] == _WARN),
            "error": sum(1 for c in checks if c["status"] == _ERROR),
        },
    }


def overall_status(statuses: Iterable[Status]) -> Status:
    sset = set(statuses)
    if _ERROR in sset:
        return _ERROR
    if _WARN in sset:
        return _WARN
    return _OK


def format_text_report(report: dict) -> str:
    lines = ["gvskb doctor — 진단 결과", ""]
    for c in report["checks"]:
        marker = {"ok": "[ OK ]", "warn": "[WARN]", "error": "[ERR ]"}[c["status"]]
        value = c.get("value")
        line = f"{marker}  {c['name']:32s}  {value if value is not None else ''}"
        lines.append(line.rstrip())
        if c.get("note"):
            lines.append(f"        └─ {c['note']}")
    s = report["summary"]
    lines.extend(["", f"요약: OK {s['ok']} · WARN {s['warn']} · ERROR {s['error']}",
                  f"종합 상태: {report['overall'].upper()}"])
    return "\n".join(lines)


# Lightweight subset for MCP server_status — no network probes, never raises.
def runtime_status_for_mcp() -> dict:
    rules_dir, src = _resolve_rules_dir()
    mode = os.environ.get("GVSKB_MODE", "").lower()
    info: dict = {
        "package_version": _package_version(),
        "module_path": _gvskb_path(),
        "rules_dir": str(rules_dir),
        "rules_dir_source": src,
        "GVSKB_RULES_DIR": os.environ.get("GVSKB_RULES_DIR", ""),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        # 운영 모드·인코딩·semgrep 상태 — MCP 클라이언트가 망분리/한글/엔진
        # 가용성을 한눈에 진단할 수 있도록 노출한다.
        "GVSKB_MODE": mode or "online",
        "offline_mode": mode == "offline",
        "encoding": {
            "PYTHONUTF8": os.environ.get("PYTHONUTF8", ""),
            "PYTHONIOENCODING": os.environ.get("PYTHONIOENCODING", ""),
            "stdout_encoding": (sys.stdout.encoding or ""),
        },
    }
    try:
        from .scanners.semgrep_scanner import SemgrepScanner
        info["semgrep_available"] = SemgrepScanner().is_available()
    except Exception:
        info["semgrep_available"] = False
    try:
        from .loader import load_all_rules
        rules = load_all_rules(rules_dir, strict=True)
        info.update({
            "total_rules": len(rules),
            "runtime_detection_rules": sum(1 for r in rules if r.detection and r.detection.patterns),
            "realtime_rules": sum(1 for r in rules if r.source_layer.value == "realtime"),
            "rules_loaded_ok": True,
        })
    except Exception as exc:
        info.update({"rules_loaded_ok": False, "rule_load_error": str(exc)})
    info["disclaimer"] = (
        "이 상태는 보안 보조 도구의 운영 진단입니다. 공공기관 운영 반영 전에는 "
        "기관 보안 담당자의 정책과 최신 법령·지침을 함께 확인하세요."
    )
    return info
