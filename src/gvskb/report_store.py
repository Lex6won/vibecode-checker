"""보고서 저장 위치 규약 — "내 보고서가 어디 있지?"를 없앤다.

왜 필요한가: 기존에는 CLI ``-o`` 로 경로를 직접 지정해야만 파일이 남았고,
MCP ``render_report`` 는 문자열만 돌려줬다. 그래서 공무원이 AI 에이전트로
점검하면 **보고서가 채팅창에만 남고 어디에도 저장되지 않았다.** 결재 문서로
쓰는 도구에서 이건 치명적이다.

규약:

    <검사한 프로젝트>/.check-reports/2026-07-31_1530_보안점검.html
                                                            .md
                                                            .json

- **프로젝트 옆에 둔다**: 공무원이 확실히 아는 위치는 "내 프로젝트 폴더"다.
  홈 디렉터리(~/.gvskb)에 두면 결재 첨부 시 파일 탐색기로 찾지 못한다.
- **날짜·시각 파일명**: 조치 전/후 비교가 결재에 필요하므로 이력이 쌓여야 한다.
- **``GVSKB_REPORT_DIR``** 로 기관 공용 폴더(예: ``\\\\파일서버\\점검보고서``)를
  지정하면 보안담당자가 조직 전체 점검 이력을 한곳에서 본다.
- 검사 대상이 **파일 하나**이거나 쓰기 불가한 경로면 현재 작업 폴더로 물러난다
  (읽기 전용 매체·권한 없는 경로에서 검사가 실패하면 안 된다).
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

REPORT_DIR_NAME = ".check-reports"
REPORT_DIR_ENV = "GVSKB_REPORT_DIR"

#: 사용자 설정 파일. 환경변수는 **공무원이 쓸 수 있는 방법이 아니다** —
#: 실사용 지적(2026-08-09): *"점검 파일을 다운 받는 위치에 저장하는거지?
#: 근데 찾기가 너무 어려워. 별도로 폴더를 지정하게 해주면 좋겠어."*
#: `GVSKB_REPORT_DIR` 은 있었지만 Windows 에서 환경변수를 설정하려면
#: 시스템 속성 창을 열어야 한다. 사실상 없는 기능이었다.
CONFIG_FILENAME = "config.json"
CONFIG_KEY_REPORT_DIR = "report_dir"

# 파일명에 쓸 수 없는 문자(Windows 기준) — 프로젝트명이 들어갈 때 대비.
_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def config_path() -> Path:
    """사용자 설정 파일 위치. Windows 는 ``%APPDATA%\\gvskb\\config.json``."""
    override = os.environ.get("GVSKB_CONFIG_DIR", "").strip()
    if override:
        return Path(override) / CONFIG_FILENAME
    appdata = os.environ.get("APPDATA", "").strip()
    base = Path(appdata) if appdata else Path.home() / ".config"
    return base / "gvskb" / CONFIG_FILENAME


def read_config() -> dict:
    """설정을 읽는다. 없거나 깨졌으면 **조용히 빈 설정**으로 둔다.

    설정 파일이 깨졌다고 검사가 실패하면 안 된다 — 보고서를 어디 둘지는
    검사 결과의 정확성과 무관하다.
    """
    try:
        return json.loads(config_path().read_text(encoding="utf-8-sig")) or {}
    except (OSError, ValueError):
        return {}


def write_config(values: dict) -> Path:
    """설정을 저장하고 그 경로를 돌려준다."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(values, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def configured_report_dir() -> tuple[Path | None, str]:
    """설정된 보고서 폴더와 **그 근거**를 함께 돌려준다.

    근거를 함께 주는 이유: "왜 여기 저장됐지?"를 사용자가 되물을 수 있어야 한다.
    우선순위는 급한 것부터 — 일회성 지정 > 환경변수 > 설정 파일 > 규약 기본값.
    """
    env = os.environ.get(REPORT_DIR_ENV, "").strip()
    if env:
        return Path(env), f"환경변수 {REPORT_DIR_ENV}"
    saved = str(read_config().get(CONFIG_KEY_REPORT_DIR, "") or "").strip()
    if saved:
        return Path(saved), f"설정 파일({config_path()})"
    return None, f"기본값 — 검사한 폴더 안 {REPORT_DIR_NAME}/"


def _stamp(now: datetime | None = None) -> str:
    return (now or datetime.now()).strftime("%Y-%m-%d_%H%M")


def _safe(name: str) -> str:
    cleaned = _UNSAFE.sub("_", name).strip(" .")
    return cleaned or "project"


def project_label(target: str | Path) -> str:
    """검사 대상을 가리키는 짧은 이름(폴더명 또는 파일명)."""
    p = Path(target)
    name = p.name if p.name else p.resolve().name
    return _safe(name)[:40]


def report_dir_for(target: str | Path) -> Path:
    """이 검사 대상의 보고서를 둘 폴더. 지정이 있으면 그쪽이 우선."""
    configured, _ = configured_report_dir()
    if configured is not None:
        return configured
    p = Path(target)
    base = p if p.is_dir() else p.parent
    if str(base) in ("", "."):
        base = Path.cwd()
    return base / REPORT_DIR_NAME


def default_report_basename(
    target: str | Path,
    now: datetime | None = None,
    *,
    shared: bool | None = None,
) -> str:
    """확장자 없는 기본 파일명.

    - 프로젝트 옆(`.check-reports/`)이면 ``2026-07-31_1530_보안점검``
    - **공용 폴더로 모으면** ``2026-07-31_1530_사업이름_보안점검``

    공용 폴더에서 프로젝트 이름을 빼면 **어느 사업 보고서인지 파일명만 보고
    알 수 없다.** 여러 부서가 한 폴더에 쌓으면 그 순간 쓸모없어진다.
    프로젝트 옆에 둘 때는 폴더가 이미 맥락이므로 넣지 않는다(기존 이름 유지).

    ``shared`` 를 주면 그 값을 따른다 — ``--report-dir`` 처럼 **설정과 무관하게**
    한 번만 공용 폴더로 보내는 경우가 있고, 그때도 이름이 붙어야 한다.
    """
    if shared is None:
        shared = configured_report_dir()[0] is not None
    if not shared:
        return f"{_stamp(now)}_보안점검"
    return f"{_stamp(now)}_{project_label(target)}_보안점검"


def resolve_report_path(
    target: str | Path,
    *,
    explicit: str | None = None,
    now: datetime | None = None,
) -> Path:
    """저장할 기본 경로(확장자 없음)를 결정한다.

    explicit(사용자가 -o 로 준 값)이 있으면 그대로 존중한다 — 규약은 기본값일 뿐
    사용자의 선택을 덮어쓰지 않는다.
    """
    if explicit:
        return Path(explicit)
    return report_dir_for(target) / default_report_basename(target, now)


def ensure_writable(base_path: Path) -> tuple[Path, str | None]:
    """저장 폴더를 만든다. 실패하면 현재 폴더로 물러나고 사유를 함께 돌려준다.

    반환: ``(실제 사용할 기본 경로, 물러난 사유 또는 None)``
    """
    try:
        base_path.parent.mkdir(parents=True, exist_ok=True)
        probe = base_path.parent / ".gvskb-write-test"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return base_path, None
    except OSError as exc:
        fallback = Path.cwd() / REPORT_DIR_NAME / base_path.name
        try:
            fallback.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            fallback = Path.cwd() / base_path.name
        return fallback, f"원래 경로에 쓸 수 없어 현재 폴더에 저장합니다({exc.strerror or exc})"


def gitignore_hint() -> str:
    """저장소를 더럽히지 않도록 사용자에게 줄 안내 한 줄."""
    return f"저장소에 커밋하지 않으려면 .gitignore 에 `{REPORT_DIR_NAME}/` 를 추가하세요."
