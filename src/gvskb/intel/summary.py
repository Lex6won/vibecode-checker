"""소스별 인텔 상태 요약 — 일일 갱신 잡의 Job Summary 와 최종 게이트가 읽는다.

무엇을 답하나: 소스마다 **캐시가 있는가 · 몇 건인가 · 언제 받았는가 · 데이터가
어느 기간을 덮는가 · 이번 실행에서 갱신됐는가(ok/warn/error)**. 갱신이 실패한
소스는 마지막 정상본이 남아 있으므로 "있다"와 "오늘 갱신됐다"를 구분해야 한다.
연속으로 며칠 실패하면 캐시 나이가 ``max_age_days`` 를 넘고, 그때 게이트가
빨간불을 낸다 — 하루 실패는 경고, 계속 실패는 오류.

커버리지 범위는 항목의 날짜 필드에서 계산한다(소스별 필드가 다르다). 누적
시작일은 따로 기록하지 않는다 — 범위의 최솟값이 곧 캐시에 남아 있는 가장 오래된
데이터이고, 그것이 실제로 의미 있는 값이다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .cache import IntelCache
from .sources.base import SOURCES

#: 소스별 커버리지 날짜 필드 — 범위(min~max)를 이 필드로 잰다.
COVERAGE_FIELD: dict[str, str] = {
    "nvd-recent": "lastModified",
    "epss-recent": "date",
    "cisa-kev": "dateAdded",
    "osv-vulns": "modified",
    "osv-malicious": "modified",
    "knvd-security-notice": "published_at",
    "knvd-public-vuln": "published_at",
}

#: 각 피드가 한 번에 최신 N 건만 주는 소스 — 요약에 "전체 DB 아님"을 명시한다.
WINDOWED_NOTE: dict[str, str] = {
    "knvd-security-notice": "피드는 최신 10건만 제공 — 누적분이며 KNVD 전체 DB 가 아님",
    "knvd-public-vuln": "피드는 최신 10건만 제공 — 누적분이며 KNVD 전체 DB 가 아님",
    "nvd-recent": "최근 7일 창을 매일 누적(상한 5만 건, 최신 수정분 우선)",
    "epss-recent": "최근 1일 창을 매일 누적",
}


@dataclass
class SourceSummary:
    source_id: str
    present: bool
    item_count: int = 0
    fetched_at: str = ""
    age_days: int | None = None
    coverage_min: str = ""
    coverage_max: str = ""
    refresh_status: str = ""      # 이번 실행의 갱신 결과(ok/warn/error) — 결과 파일이 있을 때
    refresh_error: str = ""
    note: str = ""
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id, "present": self.present, "item_count": self.item_count,
            "fetched_at": self.fetched_at, "age_days": self.age_days,
            "coverage_min": self.coverage_min, "coverage_max": self.coverage_max,
            "refresh_status": self.refresh_status, "refresh_error": self.refresh_error,
            "note": self.note, "problems": list(self.problems),
        }


def _coverage(items: list[dict], field_name: str) -> tuple[str, str]:
    values = [str(i.get(field_name)) for i in items if i.get(field_name)]
    if not values:
        return "", ""
    return min(values)[:10], max(values)[:10]


def summarize(
    cache_dir: Path,
    *,
    results: list[dict] | None = None,
    max_age_days: int | None = None,
    source_ids: list[str] | None = None,
) -> list[SourceSummary]:
    """소스별 요약. ``results`` 는 ``gvskb update-intel --json`` 출력(목록)."""
    cache = IntelCache(cache_dir)
    by_source = {str(r.get("source_id")): r for r in (results or []) if isinstance(r, dict)}
    out: list[SourceSummary] = []
    for sid in source_ids or list(SOURCES.keys()):
        entry = cache.load(sid)
        s = SourceSummary(source_id=sid, present=entry is not None, note=WINDOWED_NOTE.get(sid, ""))
        r = by_source.get(sid)
        if r is not None:
            s.refresh_status = str(r.get("status") or "")
            s.refresh_error = str(r.get("error") or "")
        if entry is None:
            s.problems.append("캐시 없음")
            if s.refresh_status == "error":
                s.problems.append(f"수집 실패(정상본 없음): {s.refresh_error}")
            out.append(s)
            continue
        s.item_count = entry.item_count
        s.fetched_at = entry.fetched_at
        s.age_days = entry.age_days()
        field_name = COVERAGE_FIELD.get(sid)
        if field_name:
            s.coverage_min, s.coverage_max = _coverage(entry.items, field_name)
        if s.refresh_status == "warn":
            s.problems.append(f"이번 갱신 실패 — 마지막 정상본 유지: {s.refresh_error}")
        if max_age_days is not None and (s.age_days is None or s.age_days > max_age_days):
            s.problems.append(f"캐시 나이 {s.age_days}일 > 허용 {max_age_days}일 — 연속 실패 의심")
        out.append(s)
    return out


def has_blocking_problem(summaries: list[SourceSummary], *, essential: tuple[str, ...] = ()) -> bool:
    """게이트 판정: 필수 소스 캐시 없음, 정상본 없는 수집 실패, 나이 초과 중 하나라도 있으면 True."""
    for s in summaries:
        if not s.present and (s.source_id in essential or s.refresh_status == "error"):
            return True
        if any("캐시 나이" in p for p in s.problems):
            return True
    return False


def render_markdown(summaries: list[SourceSummary], *, title: str = "인텔 소스 상태") -> str:
    lines = [f"### {title}", "",
             "| 소스 | 이번 갱신 | 항목 수 | 수집 시각(UTC) | 나이 | 커버리지 | 비고 |",
             "|---|---|---|---|---|---|---|"]
    marker = {"ok": "✅ ok", "warn": "⚠️ warn", "error": "❌ error", "": "—"}
    for s in summaries:
        cov = f"{s.coverage_min} ~ {s.coverage_max}" if s.coverage_min else "—"
        note = " · ".join([*s.problems, s.note] if s.note else s.problems) or "—"
        age = "—" if s.age_days is None else f"{s.age_days}일"
        lines.append(
            f"| `{s.source_id}` | {marker.get(s.refresh_status, s.refresh_status)} | "
            f"{s.item_count:,} | {s.fetched_at[:19] or '—'} | {age} | {cov} | {note} |"
        )
    return "\n".join(lines) + "\n"


def load_results(path: Path | None) -> list[dict]:
    if path is None or not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
