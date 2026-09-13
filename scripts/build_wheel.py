"""고정 커밋에서 재현 가능한 wheel 을 만들고, 설치본이 그 커밋임을 증명할 수 있게 한다.

    python scripts/build_wheel.py --out dist [--commit <40자 SHA>] [--allow-dirty]

무엇이 문제였나: 개발 PC 는 editable 설치라 `gvskb status` 가 git HEAD 로 커밋을
말했다. 그러나 서버에 wheel 로 설치하면 git 정보가 없어 **어느 커밋인지 말할 수
없다**. 그래서 빌드 스크립트가 커밋을 패키지 안(``gvskb/build_info.json``)에
기록하고, 설치본의 ``gvskb status --json`` 이 그것을 ``install_identity.commit_id``
로 돌려준다. 포털은 예상 커밋과 이 값을 대조한다.

절차:
1. 작업 트리가 깨끗한지(추적되지 않은 파일 포함) 확인 — 더러우면 중단
   (``--allow-dirty`` 는 로컬 실험용이며 build_info 에 dirty=true 가 남는다).
2. ``--commit`` 이 주어지면 HEAD 와 같은지 확인.
3. ``src/gvskb/build_info.json`` 을 쓰고 ``pip wheel . --no-deps`` 로 빌드.
4. build_info.json 을 지우고(작업 트리 복원), wheel 의 sha256 사이드카와
   ``<wheel>.build.json`` (commit·version·sha256·built_at) 을 남긴다.
5. wheel 안에 build_info.json 이 들어갔는지 검증.

설치 후 확인(서버·임시 venv 공통)::

    python -m pip install dist/vibecode_checker-<ver>-py3-none-any.whl
    gvskb status --json   # install_identity.commit_id == 빌드 커밋, install_digest.sha256 기록
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKAGE_DIR = REPO / "src" / "gvskb"
BUILD_INFO = PACKAGE_DIR / "build_info.json"


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, check=True, capture_output=True, text=True).stdout.strip()


def worktree_dirty() -> bool:
    return bool(_git("status", "--porcelain", "--untracked-files=all"))


def package_version() -> str:
    ns: dict = {}
    for line in (PACKAGE_DIR / "__init__.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__"):
            exec(line, ns)  # noqa: S102 — 저장소 자신의 한 줄
            return str(ns["__version__"])
    raise RuntimeError("__version__ 을 찾지 못했습니다")


def build_info_payload(commit: str, *, dirty: bool, version: str) -> dict:
    return {
        "build_commit": commit,
        "build_dirty": dirty,
        "package_version": version,
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "builder": "scripts/build_wheel.py",
    }


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def wheel_contains_build_info(wheel: Path) -> bool:
    with zipfile.ZipFile(wheel) as zf:
        return any(name == "gvskb/build_info.json" for name in zf.namelist())


def build(out_dir: Path, *, commit: str | None, allow_dirty: bool, python: str = sys.executable) -> dict:
    head = _git("rev-parse", "HEAD")
    if commit and commit != head:
        raise SystemExit(f"요청 커밋 {commit} 과 HEAD {head} 가 다릅니다 — 먼저 그 커밋을 체크아웃하세요.")
    dirty = worktree_dirty()
    if dirty and not allow_dirty:
        raise SystemExit("작업 트리에 커밋되지 않은 변경(추적되지 않은 파일 포함)이 있습니다 — "
                         "재현 가능한 wheel 이 아니므로 중단합니다(--allow-dirty 는 로컬 실험용).")
    version = package_version()
    info = build_info_payload(head, dirty=dirty, version=version)
    out_dir.mkdir(parents=True, exist_ok=True)
    BUILD_INFO.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        subprocess.run(
            [python, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(out_dir), "--quiet"],
            cwd=REPO, check=True,
        )
    finally:
        BUILD_INFO.unlink(missing_ok=True)
    wheels = sorted(out_dir.glob(f"vibecode_checker-{version}-*.whl"), key=lambda p: p.stat().st_mtime)
    if not wheels:
        raise SystemExit("wheel 이 만들어지지 않았습니다")
    wheel = wheels[-1]
    if not wheel_contains_build_info(wheel):
        raise SystemExit(f"{wheel.name} 안에 gvskb/build_info.json 이 없습니다 — 패키징 설정을 확인하세요.")
    digest = sha256_of(wheel)
    (out_dir / f"{wheel.name}.sha256").write_text(f"{digest}  {wheel.name}\n", encoding="utf-8")
    record = {**info, "wheel": wheel.name, "wheel_sha256": digest}
    (out_dir / f"{wheel.name}.build.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                                                      encoding="utf-8")
    return record


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="dist", help="wheel 출력 폴더")
    ap.add_argument("--commit", help="기대하는 커밋 SHA(HEAD 와 다르면 중단)")
    ap.add_argument("--allow-dirty", action="store_true", help="로컬 실험용 — 더러운 트리도 빌드(기록됨)")
    args = ap.parse_args(argv)
    record = build(Path(args.out), commit=args.commit, allow_dirty=args.allow_dirty)
    print(json.dumps(record, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
