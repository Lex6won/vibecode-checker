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

import os
import re
from datetime import datetime
from pathlib import Path

REPORT_DIR_NAME = ".check-reports"
REPORT_DIR_ENV = "GVSKB_REPORT_DIR"

# 파일명에 쓸 수 없는 문자(Windows 기준) — 프로젝트명이 들어갈 때 대비.
_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _stamp(now: datetime | None = None) -> str:
    return (now or datetime.now()).strftime("%Y-%m-%d_%H%M")


def _safe(name: str) -> str:
    cleaned = _UNSAFE.sub("_", name).strip(" .")
    return cleaned or "project"


def report_dir_for(target: str | Path) -> Path:
    """이 검사 대상의 보고서를 둘 폴더. 기관 지정(env)이 있으면 그쪽이 우선."""
    override = os.environ.get(REPORT_DIR_ENV, "").strip()
    if override:
        return Path(override)
    p = Path(target)
    base = p if p.is_dir() else p.parent
    if str(base) in ("", "."):
        base = Path.cwd()
    return base / REPORT_DIR_NAME


def default_report_basename(target: str | Path, now: datetime | None = None) -> str:
    """``2026-07-31_1530_보안점검`` — 확장자 없는 기본 파일명."""
    return f"{_stamp(now)}_보안점검"


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
