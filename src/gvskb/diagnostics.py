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

import hashlib
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
    "scan_sbom",
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
        # 소스 체크아웃일 때 "지금 디스크의 HEAD". ``commit_id`` 와 다르면
        # 돌고 있는 프로세스가 낡은 것이다 — ``runtime_freshness()`` 참고.
        "disk_commit_id": None,
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
                disk_commit, branch = _git_head_commit(module_dir)
                identity["branch"] = branch
                identity["disk_commit_id"] = disk_commit
                # **디스크가 아니라 메모리에 올라간 커밋**을 신원으로 삼는다.
                # 호출 시점의 .git/HEAD 를 그대로 답하면, 머지가 끝난 뒤에도 옛
                # 코드로 돌고 있는 프로세스가 스스로를 "최신"이라 보고한다
                # (2026-08-08 실측 사고 — 아래 freshness 절 주석 참고).
                loaded_commit = _LOADED_PROBE.get("commit_id") or disk_commit
                if loaded_commit:
                    identity["commit_id"] = loaded_commit
                    # 작업 트리에 커밋 안 된 수정이 있어도 알 수 없다 — 그대로 말한다.
                    identity["commit_source"] = (
                        "git checkout · 프로세스가 임포트한 시점"
                        " (작업 트리 변경분은 반영 안 됨)"
                    )
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


def package_result_contract() -> dict:
    """패키지 판정 결과의 **필드 계약** — 연동 상대가 대조할 수 있게 노출한다.

    **왜 필요한가(실측)**: 하네스의 설치 게이트가 결과에서 ``max_cve_severity`` ·
    ``severity`` · ``status`` · ``typosquat`` 를 읽고 있었다. 넷 다 우리 결과에 **없는
    이름**이라 항상 빈 값이 나왔고, 그 빈 값이 취약점 심각도 사다리의 입력이었다 —
    CRITICAL 취약점이 경고로 내려앉는데 **양쪽 다 아무 예외도 보지 못한다.**
    없는 필드를 읽는 것은 예외가 아니라 침묵이라서, 대조할 목록을 우리가 내놓지
    않으면 상대는 알아낼 방법이 없다.

    ``verdicts`` 를 함께 주는 이유도 같다 — 모르는 판정 문자열을 만난 게이트는
    보통 else 분기로 흘러 통과시킨다. 목록이 있으면 미리 맞출 수 있다.
    """
    from .schema import PackageCheckResult

    fields = sorted(PackageCheckResult.model_fields)
    verdicts: list[str] = []
    try:  # Literal 이 아니면(스키마 변경) 조용히 비운다 — 진단이 죽으면 안 된다
        from typing import get_args
        verdicts = sorted(str(v) for v in get_args(PackageCheckResult.model_fields["verdict"].annotation))
    except Exception:  # pragma: no cover - defensive
        verdicts = []
    return {
        "fields": fields,
        "verdicts": verdicts,
        # 게이트가 판정을 내리는 데 실제로 필요한 최소 집합. 이름이 바뀌면 여기서
        # 먼저 드러나야 한다(테스트가 이 목록과 실제 필드의 일치를 강제한다).
        "decision_fields": [
            "verdict", "verdict_severity", "checked", "requires_review",
            "is_malicious_package", "vulnerability_count", "max_cve",
            "in_kev", "kev_checked", "version_exact", "recommended_version",
        ],
        "note": (
            "게이트·하네스는 이 목록에 있는 이름만 읽으세요. 없는 이름을 읽으면 예외가 "
            "아니라 빈 값이 돌아오고, 그 빈 값이 판정을 조용히 낮춥니다."
        ),
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

    # 디스크가 최신이어도 **돌고 있는 프로세스**가 낡았을 수 있다. doctor 는 짧게
    # 살다 죽는 프로세스라 대개 OK 지만, 서버와 같은 진단을 쓰게 해 둔다.
    fresh = runtime_freshness()
    if fresh["process_stale"]:
        results.append(_check(
            "Runtime freshness", _WARN, "stale",
            note=" · ".join(fresh["reasons"]) + " — " + fresh["remedy"],
        ))
    else:
        results.append(_check(
            "Runtime freshness", _OK, "current",
            note="메모리에 올라간 코드·룰이 디스크와 같습니다",
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


# ---------------------------------------------------------------------------
# 프로세스 신선도(freshness) — "디스크가 최신인가"가 아니라 "메모리가 최신인가"
#
# 실측 사고(2026-08-08): 룰 3종의 과탐을 고쳐 머지까지 끝냈는데 MCP 서버는 계속
# 옛 룰로 판정했다. 그런데 ``server_status`` 는 ``commit_id`` 를 **호출 시점의**
# ``.git/HEAD`` 에서 읽으므로 최신 커밋을 답했고, ``total_rules`` 도 인텔 캐시
# 때문에 늘어나 최신처럼 보였다. 결국 사용자가 판별용 코드를 직접 짜서야 낡음을
# 알았다 — 도구가 먼저 말했어야 하는 것이다.
#
# gvskb 는 룰을 ``server.py`` 임포트 시점에 한 번 읽고(``RULES = load_all_rules``)
# 파이썬 코드도 그때 고정된다. MCP 서버는 한 번 뜨면 며칠씩 살아 있으므로,
# **신원의 기준 시점은 프로세스 시작이지 호출 시점이 아니다.**
# ---------------------------------------------------------------------------

#: 지문에 넣을 확장자 — 판정을 바꿀 수 있는 파일만. 룰은 .md(YAML 프런트매터),
#: 코드는 .py. 리포트 템플릿·캐시는 판정을 바꾸지 않으므로 넣지 않는다.
_FINGERPRINT_SUFFIXES = (".py", ".md", ".yaml", ".yml")

#: 낡은 프로세스를 만났을 때 사용자가 할 일. '재설치'가 아니라 '재시작'이라는
#: 점을 못 박는다 — 실제로 재설치만 반복하다 시간을 버린 사례가 있었다.
_STALE_REMEDY = (
    "MCP 서버 **프로세스를 재시작**하세요(재설치가 아니라 재시작입니다). "
    "gvskb 는 룰과 파이썬 코드를 프로세스 시작 시점에 한 번 읽으므로, 저장소를 "
    "갱신하거나 재설치해도 이미 돌고 있는 프로세스에는 반영되지 않습니다. "
    "편집기의 MCP '재연결'이 프로세스를 그대로 두는 경우가 있으니, 재시작 뒤 "
    "이 값이 다시 false 인지 반드시 확인하세요."
)


def _tree_fingerprint(root: Path) -> dict:
    """코드·룰 트리의 지문 — **내용 해시**(실측 ~50ms, 프로세스당 한 번).

    처음에는 ``stat`` 만 읽어 (파일 수, 총 바이트, 최신 mtime) 을 썼는데,
    **탐지되지 않았다**: 룰 하나의 mtime 을 바꿔도 그 파일이 트리에서 가장
    최신이 아니면 ``max`` 가 그대로였고 크기도 그대로였다. 지문이 안 변한 채
    "최신"이라고 답하는, 고치려던 것과 똑같은 결함이다.

    내용 해시는 그 구멍이 없고, 덤으로 **mtime 만 흔들리는 상황**(OneDrive
    동기화, 같은 내용의 git checkout)에서 거짓 '낡음'을 내지 않는다. 경로도
    함께 넣어 파일 이름만 바뀐 경우도 잡는다.
    """
    digest = hashlib.blake2b(digest_size=16)
    files = 0
    total = 0
    try:
        for path in sorted(root.rglob("*")):
            if path.suffix.lower() not in _FINGERPRINT_SUFFIXES:
                continue
            try:
                data = path.read_bytes()
            except OSError:  # pragma: no cover - 경합·권한
                continue
            files += 1
            total += len(data)
            rel = str(path.relative_to(root)).replace("\\", "/")
            digest.update(rel.encode("utf-8", "replace"))
            digest.update(b"\0")
            digest.update(data)
    except OSError:  # pragma: no cover - defensive
        pass
    return {"files": files, "bytes": total, "digest": digest.hexdigest()}


def _freshness_probe() -> dict:
    """지금 이 순간 디스크의 코드·룰 상태. 절대 예외를 던지지 않는다."""
    probe: dict = {"commit_id": None, "code": None, "rules": None, "rules_dir": None}
    try:
        module_dir = Path(_gvskb_path())
        if module_dir.is_dir():
            probe["commit_id"] = _git_head_commit(module_dir)[0]
            probe["code"] = _tree_fingerprint(module_dir)
        rules_dir, _ = _resolve_rules_dir()
        probe["rules_dir"] = str(rules_dir)
        if rules_dir.is_dir():
            probe["rules"] = _tree_fingerprint(rules_dir)
    except Exception as exc:  # pragma: no cover - 진단이 서버를 막으면 안 된다
        probe["error"] = str(exc)
    return probe


#: 이 프로세스가 메모리에 올린 코드·룰의 지문. **임포트 시점에 한 번만** 찍는다.
#: 이 시점 이후의 디스크 변경은 재시작 전까지 판정에 반영되지 않는다.
_LOADED_PROBE: dict = _freshness_probe()


def runtime_freshness() -> dict:
    """돌고 있는 프로세스가 **디스크의 현재 코드·룰을 쓰고 있는가**.

    ``install_identity()`` 가 "저장소가 어느 커밋인가"를 답한다면, 이 함수는
    "그 커밋이 실제로 적용돼 있는가"를 답한다. 둘은 자주 어긋나며, 어긋난 줄
    모르고 낡은 룰의 결과를 최신으로 읽는 것이 실제 사고였다.

    거짓 '낡음'은 재시작 한 번으로 끝나지만, 거짓 '최신'은 틀린 판정을 그대로
    믿게 만든다. 그래서 애매하면 낡음 쪽으로 기운다.
    """
    now = _freshness_probe()
    loaded_commit = _LOADED_PROBE.get("commit_id")
    disk_commit = now.get("commit_id")
    reasons: list[str] = []
    if loaded_commit and disk_commit and loaded_commit != disk_commit:
        reasons.append(
            f"커밋이 프로세스 시작 시점 {loaded_commit[:12]} 에서 "
            f"현재 {disk_commit[:12]} 로 바뀌었습니다"
        )
    before, after = _LOADED_PROBE.get("code"), now.get("code")
    if before and after and before != after:
        reasons.append("소스 코드가 프로세스 시작 이후 수정되었습니다")
    # 룰은 **디렉터리가 바뀐 것**과 **내용이 바뀐 것**을 구분해서 말한다. 뭉뚱그려
    # "수정되었습니다" 라고 하면, GVSKB_RULES_DIR 을 바꾼 사용자가 있지도 않은
    # 파일 수정을 찾아 헤맨다. 둘 다 프로세스에 반영되지 않은 것은 같다.
    loaded_dir, now_dir = _LOADED_PROBE.get("rules_dir"), now.get("rules_dir")
    if loaded_dir and now_dir and loaded_dir != now_dir:
        reasons.append(
            f"룰 디렉터리가 프로세스 시작 시점 {loaded_dir} 에서 현재 {now_dir} 로 "
            "바뀌었습니다(GVSKB_RULES_DIR 확인) — 이 프로세스는 여전히 이전 경로의 "
            "룰로 판정합니다"
        )
    else:
        before, after = _LOADED_PROBE.get("rules"), now.get("rules")
        if before and after and before != after:
            reasons.append("룰 파일이 프로세스 시작 이후 수정되었습니다")
    return {
        "process_stale": bool(reasons),
        "reasons": reasons,
        "loaded_commit_id": loaded_commit,
        "disk_commit_id": disk_commit,
        "remedy": _STALE_REMEDY if reasons else "",
    }


def _mark_stale(freshness: dict, reason: str) -> None:
    """신선도 판정에 근거를 하나 더 붙인다(``remedy`` 도 함께 채운다).

    지문만으로는 못 보는 신호 — 예를 들어 메모리와 디스크의 **룰 개수 차이** —
    를 나중에 덧붙일 수 있게 한다. ``remedy`` 를 빠뜨리면 '낡았다'고만 하고
    무엇을 하라는 말이 없는 경고가 되므로 여기서 같이 채운다.
    """
    freshness["process_stale"] = True
    freshness.setdefault("reasons", []).append(reason)
    if not freshness.get("remedy"):
        freshness["remedy"] = _STALE_REMEDY


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
def _ruleset_status_safe() -> dict:
    """룰셋 버전·지문·드리프트 — 진단이 스캔이나 상태 조회를 막지 않게 감싼다.

    ``expected`` 는 소비자가 `GVSKB_EXPECT_RULESET` 로 고정한 값이고,
    ``pin_ok`` 는 실제와 맞는지다. 게이트를 붙인 쪽이 이 두 값만 보면
    "내가 기준으로 잡은 룰셋으로 판정되고 있는가"에 바로 답할 수 있다.
    """
    try:
        from . import ruleset as _ruleset
        from .loader import load_all_rules
        rules_dir, _ = _resolve_rules_dir()
        verdict = _ruleset.verify_lock(load_all_rules(rules_dir), rules_dir)
        expected = _ruleset.expected_from_env()
        return {
            "version": verdict["version"],
            "digest": verdict["actual"],
            "status": verdict["status"],
            "rule_count": verdict["rule_count"],
            "message": verdict["message"],
            "expected": expected,
            "pin_ok": _ruleset.pin_mismatch(verdict["version"], verdict["actual"]) is None,
        }
    except Exception as exc:  # pragma: no cover - 방어
        return {"version": None, "digest": None, "status": "unavailable",
                "rule_count": None, "message": f"룰셋 신원 확인 실패: {exc!s}",
                "expected": None, "pin_ok": None}


def runtime_status_for_mcp() -> dict:
    rules_dir, src = _resolve_rules_dir()
    mode = os.environ.get("GVSKB_MODE", "").lower()
    identity = install_identity()
    inventory = mcp_tool_inventory()
    freshness = runtime_freshness()
    info: dict = {
        "package_version": _package_version(),
        # 버전 문자열은 신원이 아니다 — 어느 커밋인지, 어떤 도구가 있는지를 함께
        # 노출해 연동 상대가 낡은 설치를 증상 없이 바로 확인하게 한다.
        "commit_id": identity["commit_id"],
        "install_identity": identity,
        # 디스크가 아니라 **이 프로세스**가 최신인지. commit_id 만 보면 머지 뒤에도
        # 옛 룰로 돌고 있는 서버가 "최신"으로 보인다 — 반드시 함께 읽으세요.
        "runtime_freshness": freshness,
        # 룰셋 신원 — 게이트 재현성. 연동 상대가 "우리가 기준으로 잡은 룰셋과
        # 같은가"를 물을 수 있어야 한다. commit_id 로는 부족하다: 같은 커밋에서도
        # GVSKB_RULES_DIR 로 다른 룰셋을 물릴 수 있기 때문이다.
        "ruleset": _ruleset_status_safe(),
        "mcp_tools": inventory["tools"],
        "missing_tools": inventory["missing_tools"],
        "unlisted_tools": inventory["unlisted_tools"],
        "tool_inventory_ok": inventory["inventory_ok"],
        # 결과 필드 계약 — 게이트가 없는 이름을 읽고 조용히 통과시키는 일을 막는다.
        "package_result_contract": package_result_contract(),
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
    # 룰 개수는 **메모리에 올라간 것**을 답한다. 디스크를 다시 읽어 세면, 옛 룰로
    # 판정 중인 프로세스가 최신 룰 수를 보고한다(2026-08-08 실측 — 인텔 캐시로
    # 늘어난 개수까지 겹쳐 최신처럼 보였다).
    # 출처는 ``gvskb.server.RULES`` — 서버가 임포트 시점에 한 번 읽어 둔 전체 룰이다.
    # (``gvskb.scanner.RULES`` 는 정규식 엔진용 컴파일 결과라 개수 의미가 다르다.)
    # ``sys.modules`` 만 들여다본다 — 여기서 server 를 임포트하면 CLI 에서 룰을
    # 두 번 읽게 된다.
    loaded_module = sys.modules.get("gvskb.server")
    in_memory = getattr(loaded_module, "RULES", None) if loaded_module is not None else None
    # 서버와 **같은 조건**으로 디스크를 읽어야 개수 비교가 성립한다. strict 가
    # 다르면 룰 하나가 망가진 날 '낡음' 오경보가 난다 — 없는 문제를 만드는 쪽이다.
    disk_strict = True if loaded_module is None else bool(getattr(loaded_module, "_STRICT_RULES", True))
    disk_dir = rules_dir if loaded_module is None else Path(getattr(loaded_module, "RULES_DIR", rules_dir))
    try:
        from .loader import load_all_rules
        disk_rules = load_all_rules(disk_dir, strict=disk_strict)
    except Exception as exc:
        disk_rules = None
        info.update({"rules_loaded_ok": False, "rule_load_error": str(exc)})
    rules = in_memory if in_memory is not None else disk_rules
    if rules is not None:
        info.update({
            "total_rules": len(rules),
            "runtime_detection_rules": sum(1 for r in rules if r.detection and r.detection.patterns),
            "realtime_rules": sum(1 for r in rules if r.source_layer.value == "realtime"),
            "rules_loaded_ok": info.get("rules_loaded_ok", True),
            "rule_count_source": (
                "메모리 — 이 프로세스가 실제 판정에 쓰는 룰"
                if in_memory is not None
                else "디스크 — 이 프로세스는 아직 룰을 로드하지 않았습니다"
            ),
        })
        if in_memory is not None and disk_rules is not None and len(in_memory) != len(disk_rules):
            info["disk_rule_count"] = len(disk_rules)
            _mark_stale(
                freshness,
                f"메모리의 룰 {len(in_memory)}개가 디스크의 {len(disk_rules)}개와 다릅니다",
            )
    if not inventory["inventory_ok"]:
        info["tool_inventory_error"] = inventory.get("error", "")
    info["disclaimer"] = (
        "이 상태는 보안 보조 도구의 운영 진단입니다. 공공기관 운영 반영 전에는 "
        "기관 보안 담당자의 정책과 최신 법령·지침을 함께 확인하세요."
    )
    return info
