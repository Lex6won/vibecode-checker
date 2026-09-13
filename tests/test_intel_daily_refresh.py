"""일일 인텔 갱신의 누적 신뢰성 — 워크플로 구조, 소스별 상태표, 복원→수집→재게시 왕복.

배경(실측 2026-09-13): update-intel.yml 이 매번 빈 캐시에서 시작해 NVD·EPSS 의
병합 함수가 있어도 배포본은 한 번도 누적되지 않았다. 여기서는 워크플로 파일의
구조(복원 단계가 수집보다 앞, concurrency, 최소 권한, 정각 회피)를 YAML 로 검증하고,
Python 계층에서 "이전 번들 복원 후 새 수집분 병합 → 다시 export" 왕복을 실제로 돌린다.
GitHub 위의 실제 스케줄 실행은 로컬 테스트로 증명할 수 없다 — 병합 후
workflow_dispatch 로 확인해야 한다.
"""
from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from gvskb.intel import IntelCache, update_source
from gvskb.intel.autopull import ESSENTIAL_SOURCES
from gvskb.intel.bundle import export_bundle, import_bundle
from gvskb.intel.sources import knvd, nvd
from gvskb.intel.summary import has_blocking_problem, render_markdown, summarize

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "update-intel.yml"


# ---------------------------------------------------------------------------
# 워크플로 구조
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _steps(workflow: dict) -> list[dict]:
    return workflow["jobs"]["refresh"]["steps"]


def _step_index(steps: list[dict], step_id: str) -> int:
    for i, s in enumerate(steps):
        if s.get("id") == step_id:
            return i
    raise AssertionError(f"step id {step_id!r} 가 없다")


def test_workflow_restores_previous_bundle_before_refresh(workflow: dict) -> None:
    steps = _steps(workflow)
    restore, refresh, sources, bundle, verify, publish = (
        _step_index(steps, s) for s in ("restore", "refresh", "sources", "bundle", "verify", "publish")
    )
    assert restore < refresh < sources < bundle < verify < publish,         "복원 → 수집 → 게시 조건 게이트 → export → 반입 재검증 → 게시 순서여야 한다"
    run = steps[restore]["run"]
    assert 'gh release download "$PROD_TAG"' in run
    assert "sha256sum -c" in run, "이전 번들은 sha256 검증을 통과해야 반입한다"
    assert "gvskb intel-bundle import" in run
    assert "state=bootstrap" in run and "state=corrupt" in run and "state=restored" in run
    assert steps[refresh].get("if", "").strip() == "steps.restore.outcome == 'success'"


def test_workflow_does_not_publish_when_previous_bundle_is_corrupt(workflow: dict) -> None:
    steps = _steps(workflow)
    restore = steps[_step_index(steps, "restore")]
    assert restore.get("continue-on-error") is not True, "복원 실패는 잡을 멈춰야 새 번들을 덮어쓰지 않는다"
    refresh = steps[_step_index(steps, "refresh")]
    assert "steps.restore.outcome == 'success'" in refresh.get("if", "")
    # 게이트 → export → 재검증 → 게시가 사슬로 묶여 있어 앞 단계 실패 = 게시 없음.
    sources = steps[_step_index(steps, "sources")]
    assert "steps.refresh.outcome == 'success'" in sources.get("if", "")
    assert sources.get("continue-on-error") is not True, "게시 조건 게이트는 실패 시 잡을 멈춰야 한다"
    assert "steps.sources.outcome == 'success'" in steps[_step_index(steps, "bundle")].get("if", "")
    assert "steps.bundle.outcome == 'success'" in steps[_step_index(steps, "verify")].get("if", "")
    assert "steps.verify.outcome == 'success'" in steps[_step_index(steps, "publish")].get("if", "")


def test_workflow_gate_runs_before_publish_and_blocks_on_error_or_missing(workflow: dict) -> None:
    steps = _steps(workflow)
    sources = steps[_step_index(steps, "sources")]
    run = sources["run"]
    assert "--max-age-days" in run and "intel_summary.py" in run
    assert 'exit_code }}" = "2"' in run and "exit 1" in run, "정상본 없는 실패(exit 2)는 게시 전에 멈춰야 한다"
    assert '"$gate" != "0"' in run, "필수 소스 없음·나이 초과(요약 스크립트 exit 1)도 게시 전에 멈춰야 한다"
    verify = steps[_step_index(steps, "verify")]
    assert "gvskb intel-bundle import" in verify["run"] and "sha256sum -c" in verify["run"]


def test_workflow_channels_schedule_is_prod_and_dispatch_defaults_to_test(workflow: dict) -> None:
    triggers = workflow.get(True) or workflow.get("on")
    channel = triggers["workflow_dispatch"]["inputs"]["channel"]
    assert channel["default"] == "test" and set(channel["options"]) == {"test", "prod"}
    steps = _steps(workflow)
    decide = steps[_step_index(steps, "channel")]["run"]
    assert "github.event_name }}\" = \"schedule\"" in decide and "name=prod" in decide
    assert workflow["env"]["PROD_TAG"] == "intel-latest" and workflow["env"]["TEST_TAG"] == "intel-latest-test"
    # 복원은 채널과 무관하게 운영 번들에서 — 시험 채널은 별도 데이터 계보가 아니다.
    restore = steps[_step_index(steps, "restore")]["run"]
    assert 'gh release download "$PROD_TAG"' in restore and "TEST_TAG" not in restore
    # 룰 PR 은 운영 채널에서만.
    for sid in ("detect", "prtoken"):
        assert "steps.channel.outputs.name == 'prod'" in steps[_step_index(steps, sid)].get("if", "")
    publish = steps[_step_index(steps, "publish")]
    assert publish["env"]["TAG"] == "${{ steps.channel.outputs.tag }}"


def test_workflow_serializes_runs_and_avoids_top_of_hour(workflow: dict) -> None:
    assert workflow["concurrency"]["group"] == "update-intel"
    assert workflow["concurrency"]["cancel-in-progress"] is False
    # PyYAML 은 `on:` 키를 True 로 읽는다.
    triggers = workflow.get(True) or workflow.get("on")
    cron = triggers["schedule"][0]["cron"]
    assert cron.split()[0] != "0", f"정각 cron 은 지연·누락 위험 — {cron}"
    assert "workflow_dispatch" in triggers, "병합 후 실운영 확인은 수동 실행으로 한다"


def test_workflow_uses_least_privilege_and_no_actions_cache(workflow: dict) -> None:
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["refresh"]["permissions"] == {"contents": "write"}
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/cache" not in text, "Actions cache 를 유일한 보존 수단으로 쓰지 않는다"
    assert "NVD_API_KEY: ${{ secrets.NVD_API_KEY }}" in text


def test_workflow_records_per_source_status_and_gates(workflow: dict) -> None:
    steps = _steps(workflow)
    sources = steps[_step_index(steps, "sources")]
    assert "scripts/intel_summary.py" in sources["run"] and "--max-age-days" in sources["run"]
    gate = steps[-1]
    assert gate.get("if") == "always()"
    assert "REFRESH_RC" in gate["run"] and "VERIFY" in gate["run"]
    assert "exit 1" in gate["run"]


# ---------------------------------------------------------------------------
# 소스별 상태표
# ---------------------------------------------------------------------------

def _save(cache: IntelCache, sid: str, items: list[dict], *, fetched_days_ago: int | None = None) -> None:
    cache.save(sid, "https://example/test", items)
    if fetched_days_ago is not None:
        p = cache.path_for(sid)
        data = json.loads(p.read_text(encoding="utf-8"))
        data["fetched_at"] = (datetime.now(timezone.utc) - timedelta(days=fetched_days_ago)).isoformat(timespec="seconds")
        p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def test_summary_reports_freshness_count_coverage_and_refresh_status(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    _save(cache, "nvd-recent", [{"id": "CVE-1", "lastModified": "2026-09-01T00:00:00.000"},
                                {"id": "CVE-2", "lastModified": "2026-09-12T00:00:00.000"}])
    _save(cache, "knvd-public-vuln", [{"link": "https://knvd.krcert.or.kr/x", "published_at": "2026-08-30T00:00:00+00:00"}])
    results = [{"source_id": "nvd-recent", "status": "ok"},
               {"source_id": "knvd-public-vuln", "status": "warn", "error": "fetch failed: timeout"},
               {"source_id": "promote-kev", "status": "ok"}]
    rows = {s.source_id: s for s in summarize(tmp_path, results=results)}

    nvd_row = rows["nvd-recent"]
    assert nvd_row.present and nvd_row.item_count == 2 and nvd_row.refresh_status == "ok"
    assert (nvd_row.coverage_min, nvd_row.coverage_max) == ("2026-09-01", "2026-09-12")
    assert nvd_row.age_days == 0 and nvd_row.problems == []

    knvd_row = rows["knvd-public-vuln"]
    assert knvd_row.refresh_status == "warn"
    assert any("마지막 정상본 유지" in p for p in knvd_row.problems)
    assert "전체 DB 가 아님" in knvd_row.note

    assert rows["cisa-kev"].present is False and "캐시 없음" in rows["cisa-kev"].problems
    md = render_markdown(summarize(tmp_path, results=results))
    assert "| `nvd-recent` | ✅ ok | 2 |" in md and "전체 DB 가 아님" in md


def test_summary_gate_blocks_on_missing_essential_or_age_but_not_on_warn(tmp_path: Path) -> None:
    cache = IntelCache(tmp_path)
    for sid in ESSENTIAL_SOURCES:
        _save(cache, sid, [{"id": "x"}])
    _save(cache, "nvd-recent", [{"id": "CVE-1"}], fetched_days_ago=1)
    ok_rows = summarize(tmp_path, results=[{"source_id": "nvd-recent", "status": "warn", "error": "e"}], max_age_days=3)
    assert has_blocking_problem(ok_rows, essential=ESSENTIAL_SOURCES) is False, "하루 실패(정상본 유지)는 경고"

    _save(cache, "nvd-recent", [{"id": "CVE-1"}], fetched_days_ago=4)
    old_rows = summarize(tmp_path, max_age_days=3)
    assert has_blocking_problem(old_rows, essential=ESSENTIAL_SOURCES) is True, "연속 실패(나이 초과)는 오류"

    cache.path_for("cisa-kev").unlink()
    missing_rows = summarize(tmp_path)
    assert has_blocking_problem(missing_rows, essential=ESSENTIAL_SOURCES) is True, "필수 소스 없음은 오류"

    # 비필수 소스가 없고 이번 수집도 error 면(정상본 없는 실패) 오류
    _save(cache, "cisa-kev", [{"id": "x"}])
    err_rows = summarize(tmp_path, results=[{"source_id": "knvd-public-vuln", "status": "error", "error": "e"}])
    assert has_blocking_problem(err_rows, essential=ESSENTIAL_SOURCES) is True


def test_summary_script_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spec = importlib.util.spec_from_file_location("intel_summary", REPO / "scripts" / "intel_summary.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    cache = IntelCache(tmp_path)
    assert mod.main(["--cache-dir", str(tmp_path)]) == 1, "빈 캐시 = 필수 소스 없음"
    for sid in ESSENTIAL_SOURCES:
        _save(cache, sid, [{"id": "x"}])
    assert mod.main(["--cache-dir", str(tmp_path), "--max-age-days", "3"]) == 0
    out = capsys.readouterr().out
    assert "| 소스 |" in out and "`osv-vulns`" in out


# ---------------------------------------------------------------------------
# 왕복 — 이전 번들 복원 후 누적 수집, 손상 번들 거부
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, payload=None, content: bytes = b"", url: str | None = None) -> None:
        self._payload = payload
        self.content = content
        self.status_code = 200
        self.url = url
        self.headers: dict = {}

    def json(self):
        return self._payload


class _Client:
    """NVD 는 startIndex 기준 페이지, KNVD 는 URL 기준 본문을 돌려준다."""

    def __init__(self, nvd_items: list[dict], knvd_xml: bytes) -> None:
        self._nvd = nvd_items
        self._knvd = knvd_xml

    def get(self, url, params=None, headers=None):
        if url.startswith(nvd.NVD_API_URL):
            return _Resp({"resultsPerPage": len(self._nvd), "startIndex": 0,
                          "totalResults": len(self._nvd), "vulnerabilities": self._nvd})
        return _Resp(content=self._knvd, url=url)


def _nvd_item(cve: str, mod: str) -> dict:
    return {"cve": {"id": cve, "lastModified": mod, "vulnStatus": "Analyzed"}}


def _knvd_xml(title: str, link_id: str, cve: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
        f"<item><title>{cve} | {title}</title>"
        f"<link>https://knvd.krcert.or.kr/info/vuln/public/detail?id={link_id}</link>"
        f"<description>{cve}</description><pubDate>Mon, 07 Sep 2026 01:00:00 GMT</pubDate></item>"
        "</channel></rss>"
    ).encode("utf-8")


def test_restore_previous_bundle_then_accumulate_and_republish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)
    # 1일차: 빈 러너에서 수집 → 번들 게시
    day1 = IntelCache(tmp_path / "day1")
    c1 = _Client([_nvd_item("CVE-2026-00001", "2026-09-05T00:00:00.000")], _knvd_xml("1일차 공지", "d1", "CVE-2026-00001"))
    assert update_source("nvd-recent", cache=day1, client=c1).ok
    assert update_source("knvd-public-vuln", cache=day1, client=c1).ok
    bundle1 = tmp_path / "intel-latest.zip"
    assert export_bundle(bundle1, cache_dir=day1.cache_dir)["ok"]

    # 2일차: 새 러너 — 이전 번들 복원 후 그날 창(다른 항목)만 받는다
    day2 = IntelCache(tmp_path / "day2")
    restored = import_bundle(bundle1, cache_dir=day2.cache_dir)
    assert restored["ok"] and set(restored["sources"]) == {"nvd-recent", "knvd-public-vuln"}
    c2 = _Client([_nvd_item("CVE-2026-00002", "2026-09-12T00:00:00.000")], _knvd_xml("2일차 공지", "d2", "CVE-2026-00002"))
    assert update_source("nvd-recent", cache=day2, client=c2).ok
    assert update_source("knvd-public-vuln", cache=day2, client=c2).ok

    assert {i["id"] for i in day2.load("nvd-recent").items} == {"CVE-2026-00001", "CVE-2026-00002"}, \
        "이전 번들의 NVD 항목이 새 창 수집 뒤에도 남아야 누적이다"
    assert {i["link"][-2:] for i in day2.load("knvd-public-vuln").items} == {"d1", "d2"}, \
        "KNVD 는 피드가 최신 10건뿐이라 복원 없이는 과거 공지가 매일 사라진다"

    # 2일차 재게시 → 3일차 복원에서도 두 날치가 모두 보인다
    bundle2 = tmp_path / "intel-latest-2.zip"
    assert export_bundle(bundle2, cache_dir=day2.cache_dir)["ok"]
    day3 = IntelCache(tmp_path / "day3")
    assert import_bundle(bundle2, cache_dir=day3.cache_dir)["ok"]
    assert day3.load("nvd-recent").item_count == 2


def test_failed_source_keeps_restored_data_and_other_sources_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)
    prev = IntelCache(tmp_path / "prev")
    c1 = _Client([_nvd_item("CVE-2026-00001", "2026-09-05T00:00:00.000")], _knvd_xml("공지", "d1", "CVE-2026-00001"))
    update_source("nvd-recent", cache=prev, client=c1)
    update_source("knvd-public-vuln", cache=prev, client=c1)
    bundle = tmp_path / "b.zip"
    export_bundle(bundle, cache_dir=prev.cache_dir)

    today = IntelCache(tmp_path / "today")
    import_bundle(bundle, cache_dir=today.cache_dir)

    class Broken(_Client):
        def get(self, url, params=None, headers=None):
            if url.startswith(nvd.NVD_API_URL):
                raise ConnectionError("nvd down")
            return super().get(url, params=params, headers=headers)

    c2 = Broken([], _knvd_xml("새 공지", "d2", "CVE-2026-00002"))
    r_nvd = update_source("nvd-recent", cache=today, client=c2)
    r_knvd = update_source("knvd-public-vuln", cache=today, client=c2)
    assert r_nvd.status == "warn" and r_nvd.item_count == 1, "실패 소스는 마지막 정상본 유지"
    assert r_knvd.ok and today.load("knvd-public-vuln").item_count == 2, "다른 정상 소스는 갱신된다"
    assert today.load("nvd-recent").items[0]["id"] == "CVE-2026-00001"


def test_corrupted_previous_bundle_is_rejected_entirely(tmp_path: Path) -> None:
    prev = IntelCache(tmp_path / "prev")
    prev.save("nvd-recent", "u", [{"id": "CVE-1", "lastModified": "2026-09-01"}])
    bundle = tmp_path / "b.zip"
    export_bundle(bundle, cache_dir=prev.cache_dir)
    data = bytearray(bundle.read_bytes())
    data[len(data) // 2] ^= 0xFF          # 이동 중 손상
    bundle.write_bytes(bytes(data))
    res = import_bundle(bundle, cache_dir=tmp_path / "fresh")
    assert res["ok"] is False
    assert not (tmp_path / "fresh" / "nvd-recent.json").exists(), "부분 반입 없음"


def test_knvd_fixture_roundtrips_through_bundle(tmp_path: Path) -> None:
    fixture = REPO / "tests" / "fixtures" / "knvd_public_vuln_2026-09-13.xml"
    cache = IntelCache(tmp_path / "c")
    items = knvd.parse_knvd_rss(fixture.read_bytes(), feed_url=knvd.FEEDS["knvd-public-vuln"])
    cache.save("knvd-public-vuln", knvd.FEEDS["knvd-public-vuln"], items)
    bundle = tmp_path / "k.zip"
    assert export_bundle(bundle, cache_dir=cache.cache_dir)["ok"]
    back = IntelCache(tmp_path / "d")
    assert import_bundle(bundle, cache_dir=back.cache_dir)["ok"]
    assert back.load("knvd-public-vuln").items == items, "한글 제목·요약이 왕복 후 그대로다"
