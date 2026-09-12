#!/usr/bin/env python3
"""포털 계약 테스트가 쓰는 골든 fixture 를 다시 만든다.

포털(`vibecode-security-gate-portal`)은 체커 JSON 의 실제 모양에 맞춰 배포
판정을 내린다. 그 계약을 지키는지 확인하려면 **손으로 지어낸 JSON 이 아니라
체커가 실제로 내보낸 산출물**이 필요하다. 그 산출물이 골든 fixture 다::

    fixtures/checker-reports/gate-blocked-by-kev.json

그런데 fixture 는 한 번 만들어 두면 **조용히 낡는다.** 체커를 올렸는데 fixture
가 옛 형식이면 계약 테스트는 통과하는데 실제 연동은 깨져 있는 상태가 된다 —
그 테스트가 막으려던 바로 그 실패 유형이 테스트 자신에게 생기는 것이다.
그래서 재생성을 사람의 기억이 아니라 **이 스크립트에 고정**한다.

이 fixture 의 요점은 한 가지 조합이다.

    소스는 깨끗한데(finding_count = 0, summary.blocked = false)
    패키지 때문에 배포가 막힌다(gate.verdict = "blocked").

포털이 예전에 `summary.blocked` 만 보고 판정하던 시절, 바로 이 조합에서
**차단 대상을 통과로 읽었다.** 조합이 유지되지 않으면 fixture 는 이름만 남고
아무것도 검증하지 못하므로, 아래에서 그 조합을 매번 확인하고 깨지면 쓰지 않는다.

입력 데이터
-----------
소스와 의존성 감사를 **여기에 고정**한다. 바깥 파일이나 그때그때의 실행 환경에
의존하면 "재생성했더니 다른 게 나왔다"가 되고, fixture 가 무엇을 대표하는지
아무도 말할 수 없게 된다.

의존성 감사는 합성값이다 — 실제 CISA KEV 를 조회하지 않는다. 실제 목록은
바뀌므로 그것에 의존하면 재생성 결과가 그날의 인텔 상태에 좌우된다. 검증 대상은
KEV 데이터가 아니라 **KEV 근거가 있을 때 게이트가 무엇을 내놓는가** 이고,
그 계산은 여기서도 진짜 게이트 코드가 수행한다.

사용법
------
    python scripts/regenerate_portal_fixture.py \\
        --out ../vibecode-security-gate-portal/fixtures/checker-reports/gate-blocked-by-kev.json

`--out` 없이 실행하면 표준출력으로 내보낸다(차이만 보고 싶을 때).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

# 한글 Windows 기본 콘솔(cp949)에서 안내 문구가 깨지거나 죽지 않도록 고정한다.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from gvskb.gate import attach_gate  # noqa: E402
from gvskb.scanner import scan_file  # noqa: E402

#: 검사 대상 파일 이름. 결과의 ``target`` · ``scanned_files`` 에 그대로 남으므로
#: 절대경로가 아니라 이 이름이 되도록 작업 디렉터리를 옮겨 검사한다 — 그러지
#: 않으면 fixture 에 만든 사람의 PC 경로가 박힌다.
SOURCE_NAME = "a.py"

#: 아무 규칙에도 걸리지 않아야 하는 소스. 여기서 발견이 하나라도 나오면
#: fixture 의 전제('소스는 깨끗하다')가 깨진 것이므로 아래에서 중단한다.
SOURCE_TEXT = """def add(a, b):
    return a + b
"""

#: 고정 의존성 감사 — 배포를 막는 단 하나의 근거.
#: 체커가 패키지 감사에서 내보내는 모양 그대로다.
DEPENDENCY_AUDIT = {
    "audits": [
        {
            # 감사 자신의 blocked 는 게이트가 읽지 않는다(게이트는 컴포넌트 근거를
            # 직접 본다). 일부러 false 로 두어 그 성질까지 fixture 에 담는다.
            "blocked": False,
            "parsed_count": 1,
            "checked_count": 1,
            "unchecked_count": 0,
            "truncated_count": 0,
            "checks": [
                {
                    "name": "kevpkg",
                    "version": "1.0.0",
                    "ecosystem": "npm",
                    "checked": True,
                    "in_kev": True,
                    "vulnerability_count": 1,
                }
            ],
        }
    ]
}


def build_report() -> dict:
    """고정 입력으로 체커를 돌려 보고서를 만든다."""
    with tempfile.TemporaryDirectory(prefix="gvskb-portal-fixture-") as workspace:
        source = Path(workspace) / SOURCE_NAME
        source.write_text(SOURCE_TEXT, encoding="utf-8")
        previous = Path.cwd()
        try:
            # 상대 경로로 검사해야 target 이 "a.py" 로 남는다.
            os.chdir(workspace)
            report = scan_file(SOURCE_NAME)
        finally:
            os.chdir(previous)

    # 의존성 감사는 스캔이 끝난 뒤 붙고, 게이트는 **가장 마지막**에 계산한다.
    report.dependency_audit = DEPENDENCY_AUDIT
    attach_gate(report)
    return report.model_dump(mode="json")


def verify(payload: dict) -> list[str]:
    """이 산출물이 fixture 로서 의미가 있는지 확인한다.

    깨진 fixture 를 내보내는 것은 fixture 가 없는 것보다 나쁘다 — 검증했다는
    기록만 남고 실제로는 아무것도 검증하지 않기 때문이다.
    """
    problems: list[str] = []
    summary = payload.get("summary") or {}
    gate = payload.get("gate") or {}

    if summary.get("finding_count") != 0:
        problems.append(
            f"소스에서 발견이 나왔습니다(finding_count={summary.get('finding_count')}). "
            "이 fixture 는 '소스는 깨끗한데 패키지가 막는' 조합이어야 합니다."
        )
    if summary.get("blocked") is not False:
        problems.append(f"summary.blocked 가 false 가 아닙니다: {summary.get('blocked')!r}")
    if gate.get("verdict") != "blocked":
        problems.append(
            f"gate.verdict 가 'blocked' 가 아닙니다: {gate.get('verdict')!r}. "
            "패키지 근거로 배포가 막히는 상태여야 합니다."
        )
    if not gate.get("block_reasons"):
        problems.append("gate.block_reasons 가 비어 있습니다 — 차단 근거 없이 막힌 결과는 쓸 수 없습니다.")
    if gate.get("blocked_source") is not False:
        problems.append("gate.blocked_source 가 false 가 아닙니다 — 소스가 아니라 패키지가 막아야 합니다.")
    if gate.get("blocked_dependency") is not True:
        problems.append("gate.blocked_dependency 가 true 가 아닙니다.")
    if not payload.get("engine_version"):
        problems.append("engine_version 이 비어 있습니다 — 낡은 fixture 를 탐지할 수 없게 됩니다.")
    if not isinstance(payload.get("schema_version"), int):
        problems.append("schema_version 이 정수가 아닙니다.")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=None,
                        help="기록할 경로. 생략하면 표준출력으로 내보낸다.")
    args = parser.parse_args()

    payload = build_report()
    problems = verify(payload)
    if problems:
        print("fixture 를 만들지 못했습니다 — 전제가 깨졌습니다:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"기록했습니다: {args.out} (체커 {payload['engine_version']}, 계약 v{payload['schema_version']})",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
