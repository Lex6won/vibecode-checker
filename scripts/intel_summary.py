"""일일 인텔 갱신 잡의 소스별 상태표 — Job Summary 기록 + 게이트 판정.

    python scripts/intel_summary.py --cache-dir .gvskb-cache \\
        [--results intel-result.json] [--max-age-days 3] [--title "…"] [--json]

종료 코드: 0 = 문제 없음, 1 = 차단 문제(필수 소스 캐시 없음 · 정상본 없는 수집
실패 · 캐시 나이 초과). 표는 항상 stdout 에 쓴다 — 게이트 단계가 이를
$GITHUB_STEP_SUMMARY 에 이어 붙인다.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if (REPO / "src").is_dir():
    sys.path.insert(0, str(REPO / "src"))

from gvskb.intel.autopull import ESSENTIAL_SOURCES  # noqa: E402
from gvskb.intel.summary import (  # noqa: E402
    has_blocking_problem,
    load_results,
    render_markdown,
    summarize,
)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache-dir", required=True)
    ap.add_argument("--results", help="gvskb update-intel --json 출력 파일")
    ap.add_argument("--max-age-days", type=int, default=None,
                    help="이 나이를 넘는 캐시가 있으면 차단(연속 실패 감지)")
    ap.add_argument("--title", default="인텔 소스 상태")
    ap.add_argument("--json", action="store_true", help="표 대신 JSON")
    args = ap.parse_args(argv)

    summaries = summarize(
        Path(args.cache_dir),
        results=load_results(Path(args.results) if args.results else None),
        max_age_days=args.max_age_days,
    )
    if args.json:
        print(json.dumps([s.to_dict() for s in summaries], ensure_ascii=False, indent=2))
    else:
        print(render_markdown(summaries, title=args.title))
    return 1 if has_blocking_problem(summaries, essential=ESSENTIAL_SOURCES) else 0


if __name__ == "__main__":
    raise SystemExit(main())
