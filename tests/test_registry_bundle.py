"""반입 번들 — 연동합의 §3(절대 전송 금지) · 회신 §3-2(형식).

**이 테스트가 지키는 것**: 망을 건너는 파일 안에 코드 조각과 파일 경로가 없다는 것.

리포트 전체를 올리면 ``findings[].evidence`` 와 ``scanned_files`` 가 레지스트리를
거친다. 서버가 나중에 파싱 범위를 좁혀도 소용없다 — 업로드 시점에 이미 지나갔다.
그래서 무엇을 보내도 되는지 판단하는 주체가 **소비자가 아니라 생산자**여야 하고,
그 판단이 이 테스트로 고정된다.

담는 방식이 '빼기'가 아니라 '허용한 것만 넣기'인 이유도 여기 있다. 제외 목록은
새 필드가 생길 때마다 뒤처지지만, 허용목록은 새 필드를 자동으로 막는다.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from gvskb.audit import CALLER_INVALID, _reset_caller_warnings_for_tests
from gvskb.tools.registry_bundle import (
    BUNDLE_SCHEMA,
    build_bundle,
    bundle_notice,
    write_bundle,
)


@pytest.fixture(autouse=True)
def _reset_warnings():
    _reset_caller_warnings_for_tests()
    yield
    _reset_caller_warnings_for_tests()


def _check(name: str, **kw) -> dict:
    base = {
        "name": name, "version": "1.0.0", "ecosystem": "pypi",
        "verdict": "not_found", "verdict_severity": "critical",
        "checked": True, "requires_review": True, "is_malicious_package": False,
    }
    base.update(kw)
    return base


def _audit(*checks: dict, **kw) -> dict:
    base = {
        "source_kind": "manifest",
        "manifest": "src/requirements.txt",   # 파일 경로 — 번들에 나가면 안 된다
        "checks": list(checks),
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# 형식 (회신 §3-2)
# ---------------------------------------------------------------------------


def test_bundle_has_the_shape_we_specified() -> None:
    b = build_bundle({"audits": [_audit(_check("requests"))]}, now_iso="2026-08-02T05:00:00Z")
    assert b["schema"] == BUNDLE_SCHEMA
    assert b["generated_at"] == "2026-08-02T05:00:00Z"
    assert b["client"].startswith("gvskb/")
    assert b["engine_commit"] is None   # 가짜 값을 채우느니 null 이 낫다
    assert b["items"][0]["source_scope"] == "manifest"
    assert set(b["items"][0]) == {"result", "caller", "source_scope"}


def test_lockfile_scope_is_labelled_as_such() -> None:
    """락파일 유래는 버전이 확정된 사실이라 심사 큐 정책이 다르다(합의 §5-C)."""
    b = build_bundle({"audits": [_audit(_check("requests"), source_kind="lockfile")]})
    assert b["items"][0]["source_scope"] == "lockfile"


def test_empty_audit_yields_an_empty_but_valid_bundle() -> None:
    b = build_bundle(None)
    assert b["schema"] == BUNDLE_SCHEMA
    assert b["items"] == []


# ---------------------------------------------------------------------------
# 절대 전송 금지 (합의 §3)
# ---------------------------------------------------------------------------


def test_no_file_paths_or_code_reach_the_bundle() -> None:
    """번들 어디에도 경로·코드 조각이 없어야 한다."""
    audit = _audit(_check("requests"))
    audit["source"] = "manifest"
    b = build_bundle({"audits": [audit]})
    blob = json.dumps(b, ensure_ascii=False)
    assert "src/requirements.txt" not in blob
    assert "manifest" not in b["items"][0]["result"]


def test_result_carries_only_schema_fields() -> None:
    """스키마에 없는 키는 통과하지 못한다 — 허용목록이라 새 필드도 자동으로 막힌다.

    검사 dict 에는 진행 중에 임시 키가 붙는다(note·caller·내부 경로 등). 지금
    안전하더라도, 나중에 누군가 경로가 담긴 필드를 덧붙였을 때 조용히 실려
    나가면 안 된다.
    """
    c = _check(
        "requests",
        note="사람에게 보여 줄 설명",                            # 스키마 필드 — 통과
        caller="cli:manual",                                  # 봉투가 따로 싣는다 — 중복 제거
        local_path="C:/Users/hong/project/requirements.txt",   # 미래의 실수를 흉내 낸 것
    )
    b = build_bundle({"audits": [_audit(c)]})
    result = b["items"][0]["result"]
    assert "local_path" not in result
    assert "caller" not in result
    assert result["name"] == "requests"          # 필요한 것은 남는다
    assert result["verdict"] == "not_found"
    assert result["note"] == "사람에게 보여 줄 설명"
    assert "hong" not in json.dumps(b, ensure_ascii=False)


def test_caller_in_bundle_is_validated() -> None:
    """봉투의 caller 도 검증을 거친다 — 번들은 지연된 제출이다."""
    b = build_bundle({"audits": [_audit(_check("requests"))]}, caller="DESKTOP-A1B2C3")
    assert b["items"][0]["caller"] == CALLER_INVALID


# ---------------------------------------------------------------------------
# 제출 필터 (§5-D) 와 installed 보류 (회신 §1)
# ---------------------------------------------------------------------------


def test_installed_derived_items_now_ship(monkeypatch: pytest.MonkeyPatch) -> None:
    """레지스트리가 enum 을 반영했으므로(2026-08-03 회신 §2) 보류를 풀었다.

    보류 장치 자체는 남겨 둔다 — 같은 상황(우리가 값을 늘렸는데 상대가 아직
    모름)이 다시 생길 때 쓸 자리다.
    """
    b = build_bundle({"audits": [
        _audit(_check("requests")),
        _audit(_check("urllib3"), _check("idna"), source="installed-inventory"),
    ]})
    assert sorted(i["result"]["name"] for i in b["items"]) == ["idna", "requests", "urllib3"]
    assert b["excluded"]["installed_pending_enum"] == 0
    assert "installed" in {i["source_scope"] for i in b["items"]}


def test_hold_switch_still_works_and_still_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    """보류를 켜면 빠지되 **몇 건인지 남는다**.

    조용히 빠지면 받는 쪽은 그 패키지를 우리가 쓰지 않는 것으로 읽는다.
    '없음'과 '안 보냄'은 다르다.
    """
    import gvskb.tools.registry_bundle as rb

    monkeypatch.setattr(rb, "INSTALLED_SCOPE_ON_HOLD", True)
    b = rb.build_bundle({"audits": [
        _audit(_check("requests")),
        _audit(_check("urllib3"), _check("idna"), source="installed-inventory"),
    ]})
    assert [i["result"]["name"] for i in b["items"]] == ["requests"]
    assert b["excluded"]["installed_pending_enum"] == 2
    assert "installed" not in {i["source_scope"] for i in b["items"]}


def test_per_check_scope_overrides_the_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    """설치본 안의 **직접 의존성**은 manifest 로 올라간다(레지스트리 요청 §3).

    이 구분이 없으면 심사 대기열이 구조적으로 빈다 — 매니페스트 경로는 경계값이라
    제출에서 걸리고, 설치본 경로는 전이 의존성과 뭉뚱그려져 큐에 안 올라간다.
    특히 not_found(슬롭스쿼팅 최강 신호)가 그 사이로 조용히 빠진다.
    """
    b = build_bundle({"audits": [_audit(
        _check("django", source_scope="manifest"),      # 매니페스트에 적힌 직접 의존성
        _check("asgiref", source_scope="installed"),    # 끌려온 전이 의존성
        source="installed-inventory",
    )]})
    scope = {i["result"]["name"]: i["source_scope"] for i in b["items"]}
    assert scope == {"django": "manifest", "asgiref": "installed"}


def test_same_package_from_two_paths_is_sent_once() -> None:
    """같은 사실을 두 번 보내면 상대 심사 큐만 늘어난다 — 사람이 봐야 하는 쪽을 남긴다."""
    b = build_bundle({"audits": [
        _audit(_check("requests")),                                        # manifest
        _audit(_check("requests", source_scope="installed"),
               source="installed-inventory"),
    ]})
    assert len(b["items"]) == 1
    assert b["items"][0]["source_scope"] == "manifest"   # 강등되면 큐에서 사라진다
    assert b["excluded"]["duplicates"] == 1


def test_submit_filter_excludes_versionless_and_our_own_verdicts() -> None:
    """버전 없는 것과 우리가 만든 판정은 관측이 아니다(합의 §5-D)."""
    b = build_bundle({"audits": [_audit(
        _check("requests"),
        _check("flask", version=None),                    # 버전 미확정
        _check("django", verdict="registry_approved"),    # 우리 답의 되돌림
        _check("celery", verdict="unknown"),              # 판정 아님
    )]})
    assert [i["result"]["name"] for i in b["items"]] == ["requests"]
    assert b["excluded"]["submit_filtered"] == 3


def test_notice_tells_the_operator_what_was_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """화면에서도 '번들이 전부가 아님'이 보여야 한다."""
    import gvskb.tools.registry_bundle as rb

    monkeypatch.setattr(rb, "INSTALLED_SCOPE_ON_HOLD", True)
    b = rb.build_bundle({"audits": [
        _audit(_check("requests")),
        _audit(_check("urllib3"), source="installed-inventory"),
    ]})
    line = rb.bundle_notice(b)
    assert "1건" in line
    assert "보류" in line and "installed" in line


def test_notice_breaks_down_by_scope() -> None:
    """무엇을 어떤 자격으로 보내는지 화면에 남는다 — 반출 심사자가 봐야 할 값이다."""
    line = bundle_notice(build_bundle({"audits": [_audit(
        _check("django", source_scope="manifest"),
        _check("asgiref", source_scope="installed"),
        source="installed-inventory",
    )]}))
    assert "manifest 1" in line and "installed 1" in line


# ---------------------------------------------------------------------------
# 무결성 — 망을 건너는 파일은 받는 쪽이 확인할 수 있어야 한다
# ---------------------------------------------------------------------------


def test_sha256_sidecar_matches_the_bytes_written(tmp_path: Path) -> None:
    b = build_bundle({"audits": [_audit(_check("requests"))]})
    path, sidecar = write_bundle(b, tmp_path / "sub" / "bundle.json")
    assert path.exists() and sidecar.name == "bundle.json.sha256"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert sidecar.read_text(encoding="utf-8").split()[0] == digest


def test_sidecar_is_lf_so_sha256sum_can_read_it(tmp_path: Path) -> None:
    """사이드카에 CR 이 섞이면 안 된다 — 실측으로 겪은 결함이다.

    Windows 에서 텍스트로 쓰면 줄바꿈이 CRLF 가 되고, 파일명 끝에 CR 이 붙어
    받는 쪽 `sha256sum -c` 가 "그런 파일 없음"으로 실패한다. 검증하라고 동봉한
    파일이 검증을 막으면 없느니만 못하다.
    """
    b = build_bundle({"audits": [_audit(_check("requests"))]})
    _path, sidecar = write_bundle(b, tmp_path / "bundle.json")
    raw = sidecar.read_bytes()
    assert b"\r" not in raw
    assert raw.decode("utf-8").endswith("  bundle.json\n")


def test_tampered_bundle_no_longer_matches_its_hash(tmp_path: Path) -> None:
    """해시가 실제로 변조를 잡는지 — 동봉만 하고 안 맞으면 의미가 없다."""
    b = build_bundle({"audits": [_audit(_check("requests"))]})
    path, sidecar = write_bundle(b, tmp_path / "bundle.json")
    recorded = sidecar.read_text(encoding="utf-8").split()[0]
    path.write_text(path.read_text(encoding="utf-8").replace("requests", "requests-evil"),
                    encoding="utf-8")
    assert hashlib.sha256(path.read_bytes()).hexdigest() != recorded


# ---------------------------------------------------------------------------
# CLI 배선 — 플래그가 실제로 파일을 남기는가
# ---------------------------------------------------------------------------


def _project(tmp_path: Path) -> Path:
    src = tmp_path / "proj"
    src.mkdir()
    (src / "app.py").write_text('print("ok")\n', encoding="utf-8")
    (src / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return src


def test_cli_writes_bundle_and_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`--registry-bundle` 이 번들과 .sha256 을 남긴다(회신 §3-2)."""
    from gvskb import cli

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    src = _project(tmp_path)
    out = tmp_path / "bundle.json"

    cli.main(["scan", str(src), "--check-deps", "--registry-bundle", str(out),
              "-o", str(tmp_path / "r.md")])

    assert out.exists()
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["schema"] == BUNDLE_SCHEMA
    sidecar = out.with_name("bundle.json.sha256")
    assert sidecar.read_text(encoding="utf-8").split()[0] == \
        hashlib.sha256(out.read_bytes()).hexdigest()


def test_cli_bundle_contains_no_scanned_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """실제 스캔을 거쳐도 경로가 새지 않는지 — 단위 테스트만으로는 부족하다."""
    from gvskb import cli

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    src = _project(tmp_path)
    out = tmp_path / "bundle.json"

    cli.main(["scan", str(src), "--check-deps", "--registry-bundle", str(out),
              "-o", str(tmp_path / "r.md")])

    blob = out.read_text(encoding="utf-8")
    assert "requirements.txt" not in blob
    assert "app.py" not in blob
    assert str(src) not in blob


def test_cli_stdout_only_run_leaves_no_bundle_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """화면 출력만 한 실행은 파일을 남기지 않는다.

    반출 심사 대상인 파일이 담당자 모르게 디스크에 생기면 안 된다.
    """
    from gvskb import cli

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    src = _project(tmp_path)

    cli.main(["scan", str(src), "--check-deps", "--format", "json"])

    assert list(src.rglob("*registry-bundle*")) == []


def test_cli_saved_report_gets_a_bundle_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """리포트를 저장하면 번들도 사이드카로 함께 남는다(회신 §3-2)."""
    from gvskb import cli

    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path / "cache"))
    src = _project(tmp_path)
    report = tmp_path / "보안점검.md"

    cli.main(["scan", str(src), "--check-deps", "-o", str(report)])

    sidecar = tmp_path / "보안점검.registry-bundle.json"
    assert sidecar.exists()
    assert (tmp_path / "보안점검.registry-bundle.json.sha256").exists()
