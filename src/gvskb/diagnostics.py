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
    """실행 중인 코드의 버전(gvskb.__version__) — 설치 메타데이터가 아니라 코드가 원천.

    과거 importlib.metadata 는 '예전에 pip 로 설치된 배포판'의 버전을 돌려줘,
    repo 체크아웃(PYTHONPATH=src)으로 실행 중일 때 실제 코드와 다른 버전을
    보고했다(감사 추적 오염). 실행 코드에 박힌 __version__ 을 우선한다.
    """
    try:
        from gvskb import __version__
        return __version__
    except Exception:  # pragma: no cover - defensive
        try:
            return metadata.version(PKG_NAME)
        except metadata.PackageNotFoundError:
            return "unknown (editable install or not installed)"


def check_install_consistency() -> list[CheckResult]:
    """실행 중인 코드와 설치본이 같은가 — "구버전이 현재 소스를 가리는" 사고 방지.

    실측 사고: site-packages 에 남은 구버전(0.1.0)이 개발 중인 소스를 가려
    ``python -m gvskb.cli`` 가 깨지고, MCP 에 등록하면 **구버전 룰로 검사**하게
    된다. 사용자는 최신 수정이 적용됐다고 믿는데 실제로는 아니므로, 조용한
    실패 중에서도 위험한 축에 든다.

    세 가지를 대조한다:
    1. 실행 코드의 ``__version__`` (= 진실)
    2. 설치 메타데이터 버전 (pip 가 아는 값)
    3. import 되는 모듈 경로가 site-packages 인지 소스 체크아웃인지
    """
    results: list[CheckResult] = []
    try:
        from gvskb import __version__ as code_version
    except Exception as exc:  # pragma: no cover - defensive
        return [_check("Install consistency", _ERROR, "import 실패", note=str(exc))]

    try:
        dist_version = metadata.version(PKG_NAME)
    except metadata.PackageNotFoundError:
        dist_version = ""

    module_path = _gvskb_path()
    from_site_packages = "site-packages" in module_path.replace("\\", "/")

    if dist_version and dist_version != code_version:
        results.append(_check(
            "Install consistency", _WARN, f"코드 {code_version} ≠ 설치본 {dist_version}",
            note=(
                "설치된 배포판과 실행 코드의 버전이 다릅니다. site-packages 의 구버전이 "
                "현재 소스를 가릴 수 있습니다 — `pip install -e .` 로 재설치하거나 "
                "구버전을 제거하세요(MCP 등록 전 필수)."
            ),
        ))
    else:
        results.append(_check(
            "Install consistency", _OK, code_version,
            note=f"module={module_path} ({'설치본' if from_site_packages else '소스 체크아웃'})",
        ))

    # sys.path 에 gvskb 사본이 여러 개면, PYTHONPATH 유무에 따라 **다른 버전이
    # 로드**된다. 지금 실행에서는 소스가 이겨도, MCP 를 PYTHONPATH 없이 등록하면
    # 구버전이 뜬다 — 사용자는 알아챌 방법이 없으므로 사본 존재 자체를 알린다.
    copies = _find_gvskb_copies()
    if len(copies) > 1:
        versions = {v for _, v in copies}
        detail = " · ".join(f"{v or '?'} @ {p}" for p, v in copies)
        results.append(_check(
            "Shadowing copies", _WARN if len(versions) > 1 else _OK,
            f"{len(copies)}곳",
            note=(
                f"gvskb 사본이 여러 곳에 있습니다: {detail}. "
                "지금은 앞선 경로가 이기지만, PYTHONPATH 없이 실행(예: MCP 등록)하면 "
                "다른 버전이 로드될 수 있습니다 — 구버전을 `pip uninstall vibecode-checker` "
                "후 `pip install -e .` 로 정리하세요."
                if len(versions) > 1 else f"동일 버전 사본 {len(copies)}곳: {detail}"
            ),
        ))

    # CLI 진입점이 실제로 import 되는지(= `python -m gvskb.cli` 가 동작하는지)
    for mod, label in (("gvskb.cli", "CLI"), ("gvskb.server", "MCP server")):
        try:
            import importlib
            importlib.import_module(mod)
            results.append(_check(f"Import: {mod}", _OK, "ok"))
        except Exception as exc:  # noqa: BLE001 — 어떤 실패든 진단으로 보고한다
            results.append(_check(
                f"Import: {mod}", _ERROR, "실패",
                note=f"{label} 진입점을 불러오지 못했습니다: {exc!s} — 재설치가 필요합니다.",
            ))
    return results


def install_problem() -> str | None:
    """설치 상태가 위험하면 사람이 읽을 경고문, 아니면 None.

    왜 필요한가(실측 사고): ``pip install .`` 로 먼저 설치된 구버전이
    site-packages 에 **물리 디렉터리**로 남아 있으면, 나중에 ``pip install -e .``
    를 해도 그 디렉터리가 editable 경로보다 먼저 잡힌다. 결과적으로 **최신 룰이
    적용됐다고 믿으면서 구버전으로 검사**하게 된다 — 조용한 실패 중 가장 위험한
    유형이라, 발견하면 즉시 크게 알린다.
    """
    try:
        from gvskb import __version__ as code_version
    except Exception:  # pragma: no cover - defensive
        return None

    copies = _find_gvskb_copies()
    other = [(p, v) for p, v in copies if v and v != code_version]
    if other:
        detail = " · ".join(f"{v} @ {p}" for p, v in other)
        return (
            f"gvskb 사본이 여러 버전으로 존재합니다 (실행 중: {code_version} · 다른 사본: {detail}). "
            "PYTHONPATH 유무에 따라 다른 버전이 로드되어 **구버전 룰로 검사**할 수 있습니다.\n"
            "        해결: pip uninstall -y vibecode-checker  →  pip install -e .  "
            "(그래도 남으면 site-packages 의 gvskb 폴더를 직접 지우세요)"
        )

    try:
        dist_version = metadata.version(PKG_NAME)
    except metadata.PackageNotFoundError:
        return None
    if dist_version != code_version:
        return (
            f"설치 메타데이터({dist_version})와 실행 코드({code_version})의 버전이 다릅니다. "
            "재설치가 필요합니다: pip uninstall -y vibecode-checker && pip install -e ."
        )
    return None


def warn_if_install_broken(*, stream=None) -> bool:
    """설치 문제가 있으면 stderr 에 크게 경고한다. 반환값은 '문제 있음' 여부.

    검사를 막지는 않는다 — 다만 **결과를 믿기 전에 사용자가 반드시 보게** 한다.
    """
    problem = install_problem()
    if not problem:
        return False
    out = stream or sys.stderr
    print(
        "[gvskb] ⚠⚠ 설치 상태 경고 — 이 결과는 최신 코드가 아닐 수 있습니다\n"
        f"        {problem}",
        file=out,
    )
    return True


def _find_gvskb_copies() -> list[tuple[str, str | None]]:
    """sys.path 상의 gvskb 패키지 사본들 — (경로, 버전). import 하지 않고 읽는다."""
    import re as _re

    found: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for entry in sys.path:
        if not entry:
            continue
        init = Path(entry) / "gvskb" / "__init__.py"
        try:
            if not init.is_file():
                continue
            resolved = str(init.parent.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            m = _re.search(r'__version__\s*=\s*["\']([^"\']+)["\']',
                           init.read_text(encoding="utf-8", errors="replace"))
            found.append((resolved, m.group(1) if m else None))
        except OSError:
            continue
    return found


def _gvskb_path() -> str:
    try:
        import gvskb  # local import to avoid circular at module load
        return str(Path(gvskb.__file__).resolve().parent)
    except Exception as exc:  # pragma: no cover - defensive
        return f"import failed: {exc!s}"


# ---------------------------------------------------------------------------
# 설치 신원(identity) — 버전 문자열은 신원이 아니다
#
# 실측 사고: ``__version__`` 이 7/31 이후 고정이라 그 뒤에 넣은 기능이 전부
# "0.3.0" 으로 보였다. 연동 하네스 하나가 **0.1.0 설치본**을 쓰고 있었는데,
# 증상(도구 호출 실패)으로 역추적하기 전까지 아무도 몰랐다. 버전이 아니라
# **커밋 SHA** 와 **도구 존재 여부**로 신원을 말하게 한다.
# ---------------------------------------------------------------------------

#: 이 릴리스가 제공하기로 한 MCP 도구 전체. 서버에 실제 등록된 목록과 대조해
#: 빠진 것을 ``missing_tools`` 로 알린다. 목록이 굳지 않도록(추가하고 매니페스트를
#: 잊는 것) 테스트가 실제 등록분과의 일치를 강제한다.
MCP_TOOL_MANIFEST: tuple[str, ...] = (
    "check_package",
    "detect_secrets_and_pii",
    "get_rule",
    "list_loaded_rules",
    "render_report",
    "save_report",
    "scan_code",
    "scan_dependencies",
    "scan_installed_packages",
    "scan_path",
    "scan_vendor_bundles",
    "search_rules",
    "server_status",
    "suggest_fix",
)


def _direct_url_metadata() -> dict:
    """pip 이 기록한 설치 출처(PEP 610 ``direct_url.json``). 없으면 빈 dict.

    ``pip install git+https://...`` 로 설치하면 ``vcs_info.commit_id`` 에 **정확한
    커밋 SHA** 가 남는다. 연동 하네스는 대개 이 방식으로 설치하므로, 낡은 설치본을
    식별하는 가장 신뢰할 수 있는 단서다.
    """
    import json

    try:
        dist = metadata.distribution(PKG_NAME)
    except metadata.PackageNotFoundError:
        return {}
    try:
        raw = dist.read_text("direct_url.json")
    except (OSError, ValueError):  # pragma: no cover - defensive
        return {}
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:  # pragma: no cover - defensive
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _git_head_commit(start: Path) -> tuple[str | None, str | None]:
    """소스 체크아웃의 HEAD 커밋 — ``git`` 프로세스를 띄우지 않고 파일만 읽는다.

    MCP 서버 안에서 호출되므로 외부 프로세스 실행은 피한다(느리고, 기관 PC 에서는
    막혀 있을 수 있다). 반환값은 (커밋 SHA, 브랜치명).
    """
    for base in (start, *start.parents):
        git = base / ".git"
        if git.is_file():  # worktree·submodule 은 "gitdir: <경로>" 파일
            try:
                pointer = git.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:  # pragma: no cover - defensive
                continue
            if pointer.startswith("gitdir:"):
                candidate = Path(pointer[len("gitdir:"):].strip())
                git = candidate if candidate.is_absolute() else (base / candidate)
        if not git.is_dir():
            continue
        try:
            head = (git / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if not head.startswith("ref:"):
            return (head or None), None  # detached HEAD
        ref = head[len("ref:"):].strip()
        branch = ref.rsplit("/", 1)[-1]
        try:
            return (git / ref).read_text(encoding="utf-8", errors="replace").strip(), branch
        except OSError:
            pass
        try:  # 느슨한 ref 가 없으면 packed-refs
            for line in (git / "packed-refs").read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith(("#", "^")):
                    continue
                sha, _, name = line.partition(" ")
                if name.strip() == ref:
                    return sha.strip(), branch
        except OSError:
            pass
        return None, branch
    return None, None


def install_identity() -> dict:
    """이 설치본이 **정확히 어느 코드인지**. 절대 예외를 던지지 않는다.

    ``commit_id`` 우선순위:

    1. pip 의 ``direct_url.json`` → ``vcs_info.commit_id`` (git URL 설치)
    2. 소스 체크아웃의 ``.git/HEAD`` (editable·개발 설치)
    3. 없음 — 이때는 ``commit_source`` 가 왜 모르는지와 해결책을 말한다
    """
    identity: dict = {
        "package_version": _package_version(),
        "commit_id": None,
        "commit_source": "unavailable",
        "requested_revision": None,
        "install_url": None,
        "editable": None,
        "branch": None,
    }
    try:
        direct = _direct_url_metadata()
        if direct:
            identity["install_url"] = direct.get("url")
            dir_info = direct.get("dir_info")
            if isinstance(dir_info, dict):
                identity["editable"] = bool(dir_info.get("editable"))
            vcs = direct.get("vcs_info")
            if isinstance(vcs, dict):
                commit = vcs.get("commit_id")
                identity["requested_revision"] = vcs.get("requested_revision")
                if commit:
                    identity["commit_id"] = commit
                    identity["commit_source"] = "direct_url.json (pip)"

        if not identity["commit_id"]:
            module_dir = Path(_gvskb_path())
            if module_dir.is_dir():
                commit, branch = _git_head_commit(module_dir)
                identity["branch"] = branch
                if commit:
                    identity["commit_id"] = commit
                    # 작업 트리에 커밋 안 된 수정이 있어도 알 수 없다 — 그대로 말한다.
                    identity["commit_source"] = "git checkout (작업 트리 변경분은 반영 안 됨)"
    except Exception as exc:  # pragma: no cover - 진단이 서버를 막으면 안 된다
        identity["error"] = str(exc)

    if not identity["commit_id"]:
        identity["note"] = (
            "커밋 SHA 를 알 수 없습니다(로컬 폴더에서 복사·설치된 사본으로 보입니다). "
            "설치본의 신원을 남기려면 `pip install git+<저장소 URL>@<브랜치>` 또는 "
            "저장소 체크아웃에서 `pip install -e .` 로 설치하세요."
        )
    identity["short_commit"] = (identity["commit_id"] or "")[:12] or None
    return identity


def mcp_tool_inventory() -> dict:
    """이 설치본이 **실제로 등록한** MCP 도구와, 매니페스트 대비 빠진 것.

    ``missing_tools`` 는 같은 릴리스 안에서의 등록 실패(선택 의존성 때문에 도구가
    조용히 빠지는 경우)를 잡는다. **낡은 설치본**은 매니페스트도 같이 낡으므로
    스스로는 알 수 없다 — 그래서 ``tools`` (실제 등록 목록)를 함께 노출한다.
    연동 상대가 자기가 필요한 도구 이름을 이 목록과 대조하면, 증상으로 역추적하지
    않고 **한 번의 호출로** 낡은 설치를 확인할 수 있다.
    """
    expected = list(MCP_TOOL_MANIFEST)
    try:
        from . import server
        registered = getattr(server, "REGISTERED_TOOLS", None)
        if registered is None:
            # 낡은 설치본에는 이 목록 자체가 없다 — 그 사실이 곧 신원 정보다.
            raise AttributeError(
                "server.REGISTERED_TOOLS 가 없습니다 — 이 설치본은 도구 재고를 "
                "보고하지 못하는 구버전입니다."
            )
        tools = sorted(registered)
    except Exception as exc:  # noqa: BLE001 — 진단은 어떤 실패도 보고로 바꾼다
        return {
            "tools": [],
            "tool_count": 0,
            "expected_tools": expected,
            # 도구를 못 세는 상황은 "빠진 것 없음"이 아니라 "전부 확인 불가"다.
            "missing_tools": expected,
            "unlisted_tools": [],
            "inventory_ok": False,
            "error": str(exc),
        }
    return {
        "tools": tools,
        "tool_count": len(tools),
        "expected_tools": expected,
        "missing_tools": sorted(set(expected) - set(tools)),
        "unlisted_tools": sorted(set(tools) - set(expected)),
        "inventory_ok": True,
    }


def check_install_identity() -> list[CheckResult]:
    """doctor 용 — 커밋 신원과 MCP 도구 재고를 사람이 읽는 형태로."""
    identity = install_identity()
    results: list[CheckResult] = []
    if identity["commit_id"]:
        results.append(_check(
            "Install commit", _OK, identity["short_commit"],
            note=f"출처: {identity['commit_source']}"
                 + (f" · branch={identity['branch']}" if identity.get("branch") else "")
                 + (f" · rev={identity['requested_revision']}" if identity.get("requested_revision") else ""),
        ))
    else:
        results.append(_check(
            "Install commit", _WARN, "unknown", note=identity.get("note", ""),
        ))

    inventory = mcp_tool_inventory()
    if not inventory["inventory_ok"]:
        results.append(_check(
            "MCP tools", _ERROR, "확인 불가",
            note=f"도구 목록을 읽지 못했습니다: {inventory.get('error', '')}",
        ))
        return results
    missing = inventory["missing_tools"]
    unlisted = inventory["unlisted_tools"]
    if missing:
        results.append(_check(
            "MCP tools", _ERROR, f"{inventory['tool_count']}/{len(MCP_TOOL_MANIFEST)}",
            note=("이 설치본에 없는 도구: " + ", ".join(missing)
                  + " — 재설치가 필요합니다(pip install -e . 또는 git URL 재설치)."),
        ))
    elif unlisted:
        results.append(_check(
            "MCP tools", _WARN, str(inventory["tool_count"]),
            note="매니페스트에 없는 도구: " + ", ".join(unlisted)
                 + " — diagnostics.MCP_TOOL_MANIFEST 를 갱신하세요.",
        ))
    else:
        results.append(_check("MCP tools", _OK, str(inventory["tool_count"])))
    return results


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


def check_intel_cache() -> list[CheckResult]:
    """인텔 캐시(악성 패키지·KEV) 존재·신선도 — 오프라인 운영의 1차 건강신호.

    망분리 PC에서 doctor가 전체 OK인데 check-package는 전건 판정불가인 상황을
    막는다: offline 모드에서 캐시가 없으면 WARN, 신선도 초과도 WARN.
    """
    try:
        from .intel.cache import IntelCache, intel_max_age_days
    except Exception as exc:  # pragma: no cover - defensive
        return [_check("Intel cache", _WARN, "unavailable", note=str(exc))]

    offline = os.environ.get("GVSKB_MODE", "").lower() == "offline"
    cache = IntelCache()
    results: list[CheckResult] = []
    for sid in ("osv-malicious", "cisa-kev"):
        entry = cache.load(sid)
        if entry is None:
            status = _WARN if offline else _OK
            note = (
                "캐시 없음 — offline에서는 check-package가 전부 '판정 불가'가 됩니다. "
                "외부망에서 `gvskb update-intel --all` 후 캐시를 반입하세요."
                if offline else "캐시 없음 (온라인은 실시간 OSV 조회를 사용)"
            )
            results.append(_check(f"Intel cache: {sid}", status, "missing", note=note))
            continue
        age = entry.age_days()
        stale = entry.is_stale()
        value = f"{entry.item_count} items · {'?' if age is None else age}일 경과"
        note = f"fetched_at={entry.fetched_at or '<unknown>'}"
        if entry.ecosystems:
            note += f" · ecosystems={','.join(entry.ecosystems)}"
        if stale:
            note += f" · ⚠ 신선도 기준({intel_max_age_days()}일) 초과 — update-intel 권장"
        results.append(_check(f"Intel cache: {sid}", _WARN if stale else _OK, value, note=note))

    # 자동 당김 설정 — 캐시가 낡았을 때 "왜 자동으로 안 채워지나"를 여기서 답한다.
    ap = _autopull_status_safe()
    if ap.get("enabled") is False:
        results.append(_check(
            "Intel auto-update", _WARN, "off",
            note="GVSKB_AUTO_UPDATE=off — 캐시를 수동(`gvskb update-intel`)으로 갱신해야 합니다.",
        ))
    elif ap.get("enabled"):
        src = ap.get("source_dir") or ap.get("source_url") or ""
        note = f"source={src}"
        if ap.get("last_attempt_at"):
            note += f" · 마지막 시도 {ap['last_attempt_at']}({ap.get('last_result', '?')})"
        status = _OK
        if offline and not ap.get("source_dir"):
            status = _WARN
            note += " · ⚠ 오프라인인데 GVSKB_INTEL_DIR 미설정 — 자동 갱신 경로 없음"
        results.append(_check("Intel auto-update", status, "on", note=note))
    return results


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
    checks.extend(check_install_consistency())
    checks.extend(check_install_identity())
    checks.extend(check_encoding())
    checks.extend(check_mode())
    checks.extend(check_rules(expected_minimum=expected_minimum))
    checks.extend(check_mcp_import())
    checks.extend(check_semgrep())
    checks.extend(check_intel_cache())
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


def _autopull_status_safe() -> dict:
    """자동 당김 상태(네트워크 호출 없음). 실패해도 진단 전체를 막지 않는다."""
    try:
        from .intel.autopull import autopull_status
        return autopull_status()
    except Exception as exc:  # pragma: no cover - defensive
        return {"enabled": None, "error": str(exc)}


# Lightweight subset for MCP server_status — no network probes, never raises.
def runtime_status_for_mcp() -> dict:
    rules_dir, src = _resolve_rules_dir()
    mode = os.environ.get("GVSKB_MODE", "").lower()
    identity = install_identity()
    inventory = mcp_tool_inventory()
    info: dict = {
        "package_version": _package_version(),
        # 버전 문자열은 신원이 아니다 — 어느 커밋인지, 어떤 도구가 있는지를 함께
        # 노출해 연동 상대가 낡은 설치를 증상 없이 바로 확인하게 한다.
        "commit_id": identity["commit_id"],
        "install_identity": identity,
        "mcp_tools": inventory["tools"],
        "missing_tools": inventory["missing_tools"],
        "unlisted_tools": inventory["unlisted_tools"],
        "tool_inventory_ok": inventory["inventory_ok"],
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
        # 중앙 예외 오버레이·VCPS 정책 파일 — 기관 배포(레지스트리 연계) 진단용.
        "GVSKB_EXCEPTIONS_DIR": os.environ.get("GVSKB_EXCEPTIONS_DIR", ""),
        "GVSKB_VCPS_RULES": os.environ.get("GVSKB_VCPS_RULES", ""),
        # 인텔 자동 당김 — 사용자가 수동 갱신을 기억하지 않아도 되게 하는 계층.
        "intel_autopull": _autopull_status_safe(),
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
    # 인텔 캐시 상태 — 에이전트가 오프라인에서 scan_dependencies 호출 전에
    # 캐시 존재·신선도를 확인하고 사용자에게 고지할 수 있게 한다.
    try:
        from .intel.cache import IntelCache
        cache = IntelCache()
        intel: dict = {}
        for sid in ("osv-malicious", "cisa-kev"):
            entry = cache.load(sid)
            if entry is None:
                intel[sid] = {"present": False}
            else:
                intel[sid] = {
                    "present": True,
                    "item_count": entry.item_count,
                    "fetched_at": entry.fetched_at,
                    "age_days": entry.age_days(),
                    "stale": entry.is_stale(),
                    "ecosystems": entry.ecosystems,
                }
        info["intel_cache"] = intel
    except Exception as exc:  # pragma: no cover - defensive
        info["intel_cache"] = {"error": str(exc)}
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
    if not inventory["inventory_ok"]:
        info["tool_inventory_error"] = inventory.get("error", "")
    info["disclaimer"] = (
        "이 상태는 보안 보조 도구의 운영 진단입니다. 공공기관 운영 반영 전에는 "
        "기관 보안 담당자의 정책과 최신 법령·지침을 함께 확인하세요."
    )
    return info
