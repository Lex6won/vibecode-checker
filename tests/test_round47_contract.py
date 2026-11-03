"""47차 — 게이트 소비자 계약(`gate_contract`) · 경량 인텔 상태(`intel_summary`/`peek`) · `status --json` 노출.

실측(2026-11-03): 포털은 자기 미완 사유로 `blocked` 를 `incomplete` 로 덮었고, 하네스는 종료코드 3 을 '차단'으로
적었으며, 둘 다 `--check-deps` 를 박아 두어 0.6 의 기본(local)과 신선도 게이트를 우회했다. 세 시스템이 같은
표를 보지 않아서 생긴 일이다. 이 테스트는 (1) 표가 체커 한 곳에서 나오고, (2) 표의 필드가 실제 gate dict 와
어긋나지 않으며, (3) 포털·하네스 저장소가 옆에 있으면 그 코드가 표와 같은지를 고정한다.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from gvskb import diagnostics
from gvskb.gate import gate_status
from gvskb.schema import ScanReport

REPO = Path(__file__).resolve().parent.parent
PORTAL = REPO.parent / "vibecode-security-gate-portal" / "src" / "scan-summary.mjs"
HARNESS_CANDIDATES = (
    REPO.parent / "vibecode-harness-github" / "lib" / "checker-evidence.mjs",
    REPO.parent / "vibecode-harness" / "lib" / "checker-evidence.mjs",
)


def _empty_report() -> ScanReport:
    return ScanReport.model_validate({
        "target": ".", "scanned_files": [], "skipped_files": [], "findings": [],
        "summary": {"finding_count": 0, "blocked": False, "by_severity": {}, "by_decision": {}},
    })


# ---------------------------------------------------------------------------
# 1. 계약 자체
# ---------------------------------------------------------------------------

def test_gate_contract_decision_fields_exist_in_real_gate() -> None:
    contract = diagnostics.gate_contract()
    gate = gate_status(_empty_report())
    missing = [f for f in contract["decision_fields"] if f not in gate]
    assert missing == [], f"계약에 적힌 필드가 실제 gate 에 없다: {missing}"


def test_gate_contract_verdicts_and_exit_codes_align() -> None:
    contract = diagnostics.gate_contract()
    assert set(contract["verdicts"]) == {"approved", "conditional", "blocked", "undetermined"}
    assert contract["exit_codes"] == {"approved": 0, "conditional": 1, "blocked": 2, "undetermined": 3}
    for consumer in ("harness", "portal"):
        table = contract["consumer_mapping"][consumer]
        assert set(table) == set(contract["verdicts"]), f"{consumer} 표가 verdict 전부를 덮지 않는다"
    # 핵심 규칙 — 차단은 차단, 판정 불가는 판정 불가. 어느 소비자도 이 둘을 뒤섞지 않는다.
    assert contract["consumer_mapping"]["harness"]["undetermined"] == "undetermined"
    assert contract["consumer_mapping"]["harness"]["blocked"] == "blocked"
    assert contract["consumer_mapping"]["portal"]["blocked"] == "blocked"
    assert contract["consumer_mapping"]["portal"]["undetermined"] == "incomplete"
    assert contract["deprecated_flags"] == {"--check-deps": "--deps online"}


def test_gate_contract_is_exposed_by_doctor_and_status(tmp_path: Path) -> None:
    info = diagnostics.runtime_status_for_mcp()
    assert info["gate_contract"]["verdicts"] == diagnostics.gate_contract()["verdicts"]
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONUTF8="1",
               GVSKB_CACHE_DIR=str(tmp_path / "nocache"))
    proc = subprocess.run([sys.executable, "-m", "gvskb.cli", "status", "--json"],
                          capture_output=True, text=True, encoding="utf-8", env=env, cwd=str(REPO))
    assert proc.returncode == 0, proc.stderr[-500:]
    payload = json.loads(proc.stdout)
    assert payload["gate_contract"]["consumer_mapping"]["portal"]["conditional"] == "needs_review"
    # 캐시가 없는 PC: 상태는 'missing' 이고, status 자체는 죽지 않는다(설치 판단 전에 불린다).
    assert payload["intel"]["state"] == "missing"
    assert set(payload["intel"]["missing"]) == {"osv-malicious", "osv-vulns", "cisa-kev"}


# ---------------------------------------------------------------------------
# 2. 경량 인텔 상태 — 본문을 열지 않는다
# ---------------------------------------------------------------------------

def test_peek_reads_stamp_without_parsing_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.intel.cache import IntelCache

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    cache = IntelCache(tmp_path)
    items = [{"id": f"X-{i}", "name": "pkg", "ecosystem": "PyPI"} for i in range(5000)]
    cache.save("osv-malicious", "test://", items, ecosystems=["PyPI"])
    # 첫 load 가 스탬프(수집 시각 포함)를 쓴다.
    assert cache.load("osv-malicious") is not None
    stamp = json.loads((tmp_path / "osv-malicious.json.verified").read_text(encoding="utf-8"))
    assert stamp["fetched_at"] and stamp["item_count"] == 5000

    # 본문이 깨져도 peek 는 스탬프(mtime·size 동일)로 답한다 — 상태 표시 전용임을 보이는 성질.
    # 단, 같은 mtime·size 를 유지해야 하므로 파일을 건드리지 않고 peek 만 호출한다.
    entry = cache.peek("osv-malicious")
    assert entry is not None and entry.items == [] and entry.item_count == 5000
    assert entry.fetched_at == stamp["fetched_at"]


def test_peek_falls_back_to_load_when_stamp_is_old_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.intel.cache import IntelCache, _stamp_path

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    cache = IntelCache(tmp_path)
    cache.save("cisa-kev", "test://", [{"cveID": "CVE-2026-1"}])
    p = cache.path_for("cisa-kev")
    st = p.stat()
    # 46차 형식 스탬프(수집 시각 없음)를 손으로 만든다.
    _stamp_path(p).write_text(json.dumps({"mtime_ns": st.st_mtime_ns, "size": st.st_size,
                                          "sha256": cache.load("cisa-kev").sha256}), encoding="utf-8")
    entry = cache.peek("cisa-kev")
    assert entry is not None and entry.fetched_at
    upgraded = json.loads(_stamp_path(p).read_text(encoding="utf-8"))
    assert "fetched_at" in upgraded, "peek 가 구형 스탬프를 새 형식으로 올려 적어야 다음부터 빠르다"


def test_intel_summary_states(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.intel.cache import IntelCache

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    assert diagnostics.intel_summary()["state"] == "missing"
    cache = IntelCache(tmp_path)
    for sid in ("osv-malicious", "osv-vulns", "cisa-kev"):
        cache.save(sid, "test://", [{"id": sid}])
    summary = diagnostics.intel_summary()
    assert summary["state"] == "ok" and summary["age_days"] == 0
    monkeypatch.setenv("GVSKB_INTEL_MAX_AGE_DAYS", "1")
    # 수집 시각을 3일 전으로 돌린 캐시 하나 → stale
    old = cache.load("cisa-kev")
    data = json.loads(cache.path_for("cisa-kev").read_text(encoding="utf-8"))
    data["fetched_at"] = "2020-01-01T00:00:00+00:00"
    cache.path_for("cisa-kev").write_text(json.dumps(data), encoding="utf-8")
    time.sleep(0.01)
    summary = diagnostics.intel_summary()
    assert summary["state"] == "stale" and summary["stale"] == ["cisa-kev"], summary
    assert old is not None


# ---------------------------------------------------------------------------
# 3. 옆에 있는 포털·하네스 코드가 표와 같은가
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not PORTAL.exists(), reason="포털 저장소가 옆에 없음(CI)")
def test_portal_table_equals_contract() -> None:
    text = PORTAL.read_text(encoding="utf-8")
    block = re.search(r"GATE_VERDICT_TO_DECISION\s*=\s*Object\.freeze\(\{(.*?)\}\)", text, re.S).group(1)
    table = dict(re.findall(r"(\w+):\s*\"(\w+)\"", block))
    assert table == diagnostics.gate_contract()["consumer_mapping"]["portal"]


@pytest.mark.skipif(not any(p.exists() for p in HARNESS_CANDIDATES), reason="하네스가 옆에 없음(CI)")
def test_harness_table_equals_contract() -> None:
    path = next(p for p in HARNESS_CANDIDATES if p.exists())
    text = path.read_text(encoding="utf-8")
    m = re.search(r"CHECKER_STATUS_BY_VERDICT\s*=\s*Object\.freeze\(\{(.*?)\}\)", text, re.S)
    assert m, "하네스 checker-evidence.mjs 에 CHECKER_STATUS_BY_VERDICT 표가 없다(47차 이전 하네스)"
    table = dict(re.findall(r"(\w+):\s*\"(\w+)\"", m.group(1)))
    assert table == diagnostics.gate_contract()["consumer_mapping"]["harness"]
    assert 'final_verdict: "review_required"' in text


# ---------------------------------------------------------------------------
# 4. 구 옵션 안내 — 결과·종료코드는 그대로, 한 줄만 알린다
# ---------------------------------------------------------------------------

def test_check_deps_alias_prints_notice_but_keeps_result(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONUTF8="1", GVSKB_MODE="offline")
    base = [sys.executable, "-m", "gvskb.cli", "scan", str(tmp_path), "--format", "json", "--stdout"]
    with_alias = subprocess.run([*base, "--check-deps"], capture_output=True, text=True, encoding="utf-8", env=env, cwd=str(REPO))
    without = subprocess.run(base, capture_output=True, text=True, encoding="utf-8", env=env, cwd=str(REPO))
    assert "--deps online" in with_alias.stderr and "--deps online" not in without.stderr
    assert with_alias.returncode == without.returncode
    a = json.loads(with_alias.stdout)
    b = json.loads(without.stdout)
    assert a["gate"]["verdict"] == b["gate"]["verdict"]
    # 망분리에서는 별칭(online 요청)도 local 로 내려가며, 그 사실이 기록에 남는다.
    assert a["dependency_check"]["mode"] == "local" and a["dependency_check"]["requested_mode"] == "online"
