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
    assert payload["gate_contract"]["exit_codes_by_fail_on"]["block"]["conditional"] == 0
    assert "blocked_dependency" in payload["gate_contract"]["decision_fields"]
    doctor = subprocess.run([sys.executable, "-m", "gvskb.cli", "doctor", "--json", "--offline"],
                            capture_output=True, text=True, encoding="utf-8", env=env, cwd=str(REPO))
    assert json.loads(doctor.stdout)["gate_contract"]["verdicts"] == payload["gate_contract"]["verdicts"]
    # 캐시가 없는 PC: 상태는 'missing' 이고, status 자체는 죽지 않는다(설치 판단 전에 불린다).
    assert payload["intel"]["state"] == "missing"
    assert set(payload["intel"]["missing"]) == {"osv-malicious", "osv-vulns", "cisa-kev"}


# ---------------------------------------------------------------------------
# 2. 경량 인텔 상태 — 본문을 열지 않는다
# ---------------------------------------------------------------------------

def test_peek_never_opens_body_and_never_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """peek_info 는 (1) json.loads 를 부르지 않고 (2) 캐시 폴더에 아무것도 쓰지 않는다(리뷰 M-2·L-2·L-4)."""
    import gvskb.intel.cache as cache_mod
    from gvskb.intel.cache import IntelCache

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    cache = IntelCache(tmp_path)
    items = [{"id": f"X-{i}", "name": "pkg", "ecosystem": "PyPI"} for i in range(5000)]
    cache.save("osv-malicious", "test://", items, ecosystems=["PyPI"])   # save 가 스탬프를 즉시 쓴다
    stamp = json.loads((tmp_path / "osv-malicious.json.verified").read_text(encoding="utf-8"))
    assert stamp["fetched_at"] and stamp["item_count"] == 5000

    before = sorted((q.name, q.stat().st_mtime_ns) for q in tmp_path.iterdir())
    calls = {"loads": 0}
    real_loads = cache_mod.json.loads

    def counting_loads(text, *a, **k):
        calls["loads"] += 1
        return real_loads(text, *a, **k)

    monkeypatch.setattr(cache_mod.json, "loads", counting_loads)
    info = cache.peek_info("osv-malicious")
    entry = cache.peek("osv-malicious")
    assert info["basis"] == "stamp" and info["stamp_mismatch"] is False
    assert entry is not None and entry.items == [] and entry.item_count == 5000
    # 스탬프(수십 바이트) 파싱만 허용 — 본문(수백 KB) 파싱은 0 회여야 한다.
    assert calls["loads"] <= 2, calls
    after = sorted((q.name, q.stat().st_mtime_ns) for q in tmp_path.iterdir())
    assert before == after, "peek 가 캐시 폴더에 썼다"


def test_peek_header_fallback_without_stamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """스탬프가 없으면(복사·다른 계정) 본문을 열지 않고 파일 머리에서만 읽는다 — basis=header."""
    from gvskb.intel.cache import IntelCache, _stamp_path

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    cache = IntelCache(tmp_path)
    cache.save("cisa-kev", "test://", [{"cveID": f"CVE-2026-{i}"} for i in range(3000)])
    _stamp_path(cache.path_for("cisa-kev")).unlink()
    info = cache.peek_info("cisa-kev")
    assert info["basis"] == "header" and info["fetched_at"] and info["item_count"] == 3000
    assert not _stamp_path(cache.path_for("cisa-kev")).exists(), "peek 는 스탬프를 만들지 않는다"
    summary = diagnostics.intel_summary()
    assert summary["basis"] in ("header", "mixed") and summary["verified"] is False


def test_peek_detects_stamp_body_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """스탬프만 고쳐 '최신'으로 꾸며도 파일 머리의 수집 시각과 대조해 들킨다(리뷰 M-1)."""
    from gvskb.intel.cache import IntelCache, _stamp_path

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    cache = IntelCache(tmp_path)
    cache.save("osv-vulns", "test://", [{"id": "V-1"}])
    p = cache.path_for("osv-vulns")
    stamp = json.loads(_stamp_path(p).read_text(encoding="utf-8"))
    stamp["fetched_at"] = "2099-01-01T00:00:00+00:00"
    stamp["item_count"] = 999999
    _stamp_path(p).write_text(json.dumps(stamp), encoding="utf-8")
    info = cache.peek_info("osv-vulns")
    assert info["stamp_mismatch"] is True and info["basis"] == "header"
    assert info["fetched_at"] != "2099-01-01T00:00:00+00:00" and info["item_count"] == 1
    summary = diagnostics.intel_summary()
    assert "osv-vulns" in summary["stamp_mismatch"]


def test_old_format_stamp_is_upgraded_by_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.intel.cache import IntelCache, _stamp_path

    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path))
    cache = IntelCache(tmp_path)
    cache.save("cisa-kev", "test://", [{"cveID": "CVE-2026-1"}])
    p = cache.path_for("cisa-kev")
    st = p.stat()
    # 46차 형식 스탬프(수집 시각 없음)를 손으로 만든다.
    _stamp_path(p).write_text(json.dumps({"mtime_ns": st.st_mtime_ns, "size": st.st_size,
                                          "sha256": cache.load("cisa-kev").sha256}), encoding="utf-8")
    assert cache.peek_info("cisa-kev")["basis"] == "header"      # 구형 스탬프는 머리로 폴백
    assert cache._load_uncached("cisa-kev", p) is not None        # 적재(판정 경로)가 스탬프를 올려 적는다
    upgraded = json.loads(_stamp_path(p).read_text(encoding="utf-8"))
    assert "fetched_at" in upgraded and cache.peek_info("cisa-kev")["basis"] == "stamp"


def test_corrupt_item_count_does_not_crash_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """item_count 는 sha 범위 밖이라 쉽게 깨진다 — 비정수여도 적재가 죽지 않는다(리뷰 L-3)."""
    from gvskb.intel.cache import IntelCache

    cache = IntelCache(tmp_path)
    cache.save("cisa-kev", "test://", [{"cveID": "CVE-2026-1"}])
    p = cache.path_for("cisa-kev")
    data = json.loads(p.read_text(encoding="utf-8"))
    data["item_count"] = "corrupt"
    p.write_text(json.dumps(data), encoding="utf-8")
    entry = cache.load("cisa-kev")
    assert entry is not None and entry.item_count == 0 and len(entry.items) == 1


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
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONUTF8="1", GVSKB_MODE="offline",
               GVSKB_CACHE_DIR=str(tmp_path / "nocache"))
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


# ---------------------------------------------------------------------------
# 5. 단건 조회(check-package)의 경로 선택 — 하네스 관찰 반영
# ---------------------------------------------------------------------------

def test_check_package_deps_local_and_env(tmp_path: Path) -> None:
    """`--deps local` 과 `GVSKB_DEPS_MODE=local` 은 네트워크 없이 로컬 캐시 경로를 타고 check_mode 를 남긴다."""
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONUTF8="1", GVSKB_CACHE_DIR=str(tmp_path / "nocache"))
    env.pop("GVSKB_MODE", None)
    env.pop("GVSKB_DEPS_MODE", None)
    base = [sys.executable, "-m", "gvskb.cli", "check-package", "requests", "--ecosystem", "pypi", "--version", "2.31.0"]
    a = subprocess.run([*base, "--deps", "local"], capture_output=True, text=True, encoding="utf-8", env=env, cwd=str(REPO))
    ra = json.loads(a.stdout)
    assert ra["check_mode"] == "local" and ra["checked"] is False and ra["offline"] is False
    b = subprocess.run(base, capture_output=True, text=True, encoding="utf-8", env=dict(env, GVSKB_DEPS_MODE="local"), cwd=str(REPO))
    rb = json.loads(b.stdout)
    assert rb["check_mode"] == "local"
    # 캐시가 없으면 판정 불가 → '안전' 아님(경고 코드). 소비자는 checked=false 를 incomplete 로 읽는다.
    assert a.returncode == 1 and b.returncode == 1


def test_single_check_mode_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    from gvskb.cli import _single_check_mode

    monkeypatch.delenv("GVSKB_DEPS_MODE", raising=False)
    assert _single_check_mode(None) is None            # 기본: 온라인(망분리면 impl 이 local 로)
    assert _single_check_mode("local") == "local"
    monkeypatch.setenv("GVSKB_DEPS_MODE", "local")
    assert _single_check_mode(None) == "local"
    monkeypatch.setenv("GVSKB_DEPS_MODE", "off")       # 단건 조회에 off 는 뜻이 없다
    assert _single_check_mode(None) is None
