# -*- coding: utf-8 -*-
"""월간 인텔 초안 룰 다이제스트 — 사람이 카드를 하나하나 보지 않아도 되도록.

매월 1일 GitHub Actions가 실행해 rules/intel-proposed/ 상태를 요약한 마크다운을
stdout으로 출력하고, 워크플로가 이를 이슈로 게시한다. 유지관리자는 이슈 하나만
읽고 "우선 검토 후보"에 대해서만 승격 여부를 판단하면 된다.

우선 검토 후보 선정 기준(자동):
- severity: critical  → 랜섬웨어 캠페인 악용이 확인된 KEV (가장 시급)
- 만료 임박(30일 내) → 곧 자동 폐기되므로 승격하려면 지금 결정해야 함

사용: PYTHONPATH=src python scripts/intel_digest.py [rules/intel-proposed]
"""
from __future__ import annotations

import io
import re
import sys
from datetime import date, timedelta
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

_FM_FIELD = {
    "id": re.compile(r"^id:\s*(\S+)\s*$", re.M),
    "title": re.compile(r"^title_ko:\s*'?(.+?)'?\s*$", re.M),
    "status": re.compile(r"^status:\s*(\S+)\s*$", re.M),
    "severity": re.compile(r"^severity:\s*(\S+)\s*$", re.M),
    "verified_at": re.compile(r"^verified_at:\s*(\d{4}-\d{2}-\d{2})\s*$", re.M),
    "review_due": re.compile(r"^review_due:\s*(\d{4}-\d{2}-\d{2})\s*$", re.M),
}


def _parse(path: Path) -> dict:
    head = path.read_text(encoding="utf-8")[:4000]
    out = {"file": path.name}
    for key, rx in _FM_FIELD.items():
        m = rx.search(head)
        out[key] = m.group(1) if m else ""
    return out


def _d(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def main() -> int:
    rules_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rules/intel-proposed")
    today = date.today()
    soon = today + timedelta(days=30)

    cards = []
    if rules_dir.exists():
        cards = [_parse(p) for p in sorted(rules_dir.glob("INTEL-*.md"))]
    proposed = [c for c in cards if c["status"] == "proposed"]
    approved = [c for c in cards if c["status"] == "approved"]

    new_this_month = [c for c in proposed
                      if (d := _d(c["verified_at"])) and (today - d).days <= 31]
    expiring = [c for c in proposed
                if (d := _d(c["review_due"])) and today <= d <= soon]
    ransomware = [c for c in proposed if c["severity"] == "critical"]

    print(f"## 인텔 초안 룰 월간 다이제스트 — {today.isoformat()}")
    print()
    print("| 항목 | 수 |")
    print("|---|---|")
    print(f"| 대기 중 초안(proposed) | {len(proposed)} |")
    print(f"| 이번 달 신규 | {len(new_this_month)} |")
    print(f"| 30일 내 자동 폐기 예정 | {len(expiring)} |")
    print(f"| 승격 완료(approved) | {len(approved)} |")
    print()

    if not proposed:
        print("**이번 달 조치 필요 없음** — 대기 중 초안이 없습니다. "
              "(KEV 데이터는 캐시로 계속 판정에 반영되고 있습니다.)")
        return 0

    if ransomware:
        print("### 우선 검토 후보 — 랜섬웨어 악용 확인(critical)")
        print()
        print("승격할 가치가 가장 높은 카드입니다. 파일을 열어 `status: approved`로 "
              "바꾸면 지식 검색에서 확정 정보로 노출됩니다(코드 스캔에는 영향 없음).")
        print()
        for c in ransomware[:15]:
            print(f"- `{c['id']}` — {c['title']} (폐기 예정일 {c['review_due']})")
        print()

    if expiring:
        print("### 30일 내 자동 폐기 예정")
        print()
        print("승격하지 않으면 아래 카드는 기한이 지나 자동 삭제됩니다. "
              "**아무것도 하지 않아도 안전합니다** — 위협 데이터 자체는 캐시로 계속 반영됩니다.")
        print()
        for c in expiring[:20]:
            print(f"- `{c['id']}` — {c['title']} ({c['review_due']} 폐기)")
        print()

    print("---")
    print("*자동 생성 다이제스트입니다. 초안 카드는 스캐너에 집행되지 않으며(status 게이트), "
          "기한이 지나면 자동 폐기됩니다 — 이 이슈는 '승격할 것만 고르는' 용도입니다.*")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
