"""패키지 레지스트리 메타데이터 파서 + VCPS 정책 로더 테스트.

네트워크 없이 고정 픽스처로 파싱·판정 로직을 고정한다:
- PyPI JSON / npm packument 파싱 (발행일·라이선스·설치 스크립트)
- 쿨다운(C1) 판정 — E등급별 기준일, 발행일 미상은 ok=None('통과' 아님)
- 라이선스 허용목록(LIC) 판정
- GVSKB_VCPS_RULES 기관 정책팩 오버라이드
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gvskb.schema import PackageRegistryMetadata
from gvskb.tools.check_package import _evaluate_cooldown, _max_cve_from_vulns
from gvskb.tools.package_metadata import _age_days, _parse_npm, _parse_pypi
from gvskb.vcps import cooldown_days_for, license_verdict, load_vcps_config


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


@pytest.fixture(autouse=True)
def _clear_vcps_cache():
    """lru_cache 된 정책 로드를 테스트 간 격리한다."""
    load_vcps_config.cache_clear()
    yield
    load_vcps_config.cache_clear()


# ---------------------------------------------------------------------------
# PyPI 파싱
# ---------------------------------------------------------------------------


def test_parse_pypi_extracts_publish_dates_and_license() -> None:
    data = {
        "info": {"version": "2.0.0", "license_expression": "Apache-2.0", "classifiers": []},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": _iso_days_ago(400)}],
            "2.0.0": [{"upload_time_iso_8601": _iso_days_ago(2)}],
        },
    }
    meta = _parse_pypi(data, None)  # 버전 미지정 → 최신(2.0.0)
    assert meta.exists is True
    assert meta.latest_version == "2.0.0"
    assert meta.queried_version == "2.0.0"
    assert meta.version_age_days == 2          # 최신 버전은 이틀 전 발행
    assert meta.package_age_days == 400        # 최초 발행은 1.0.0 기준
    assert meta.license == "Apache-2.0"
    assert meta.install_scripts == "unknown"   # PyPI 는 미개봉 — 정직하게 unknown


def test_parse_pypi_license_falls_back_to_classifier() -> None:
    data = {
        "info": {
            "version": "1.0",
            "license": "x" * 300,  # 라이선스 전문을 통째로 넣은 경우
            "classifiers": ["License :: OSI Approved :: MIT License"],
        },
        "releases": {},
    }
    meta = _parse_pypi(data, None)
    assert meta.license == "MIT License"


def test_parse_pypi_specific_version_publish_date() -> None:
    data = {
        "info": {"version": "3.0.0"},
        "releases": {
            "2.5.0": [{"upload_time_iso_8601": _iso_days_ago(100)}],
            "3.0.0": [{"upload_time_iso_8601": _iso_days_ago(1)}],
        },
    }
    meta = _parse_pypi(data, "2.5.0")  # 옛 버전을 콕 집어 조회
    assert meta.queried_version == "2.5.0"
    assert meta.version_age_days == 100


# ---------------------------------------------------------------------------
# npm 파싱
# ---------------------------------------------------------------------------


def _npm_packument(scripts: dict | None = None, deprecated: str | None = None) -> dict:
    ver_doc: dict = {"scripts": scripts or {}}
    if deprecated:
        ver_doc["deprecated"] = deprecated
    return {
        "dist-tags": {"latest": "1.2.3"},
        "license": "MIT",
        "time": {"created": _iso_days_ago(500), "1.2.3": _iso_days_ago(3)},
        "versions": {"1.2.3": ver_doc},
    }


def test_parse_npm_detects_install_scripts() -> None:
    meta = _parse_npm(_npm_packument(scripts={"postinstall": "node evil.js", "test": "jest"}), None)
    assert meta.install_scripts == "present"
    assert meta.install_script_names == ["postinstall"]  # test 훅은 설치 훅이 아님
    assert meta.license == "MIT"
    assert meta.version_age_days == 3
    assert meta.package_age_days == 500


def test_parse_npm_no_install_scripts_is_none() -> None:
    meta = _parse_npm(_npm_packument(scripts={"build": "tsc"}), None)
    assert meta.install_scripts == "none"
    assert meta.install_script_names == []


def test_parse_npm_deprecated_flag() -> None:
    meta = _parse_npm(_npm_packument(deprecated="use other-pkg instead"), None)
    assert meta.deprecated is True


def test_parse_npm_license_object_form() -> None:
    data = _npm_packument()
    data["license"] = {"type": "BSD-3-Clause"}
    meta = _parse_npm(data, None)
    assert meta.license == "BSD-3-Clause"


# ---------------------------------------------------------------------------
# 쿨다운(C1) — E등급별 기준일
# ---------------------------------------------------------------------------


def _meta_with_age(days: int | None) -> PackageRegistryMetadata:
    return PackageRegistryMetadata(exists=True, version_age_days=days)


def test_cooldown_hold_when_version_too_new() -> None:
    cd = _evaluate_cooldown(_meta_with_age(2), env_grade=None)  # 기본 E1=7일
    assert cd.env_grade == "E1"
    assert cd.cooldown_days == 7
    assert cd.ok is False


def test_cooldown_ok_when_aged() -> None:
    cd = _evaluate_cooldown(_meta_with_age(30), env_grade="E1")
    assert cd.ok is True


def test_cooldown_grades_change_threshold() -> None:
    assert _evaluate_cooldown(_meta_with_age(5), "E0").ok is True    # E0=3일
    assert _evaluate_cooldown(_meta_with_age(5), "E1").ok is False   # E1=7일
    assert _evaluate_cooldown(_meta_with_age(13), "E2").ok is False  # E2=14일


def test_cooldown_unknown_publish_date_is_not_pass() -> None:
    """발행일 미상은 ok=None — '통과'가 아니라 '판정 불가'다."""
    cd = _evaluate_cooldown(_meta_with_age(None), "E1")
    assert cd.ok is None
    cd2 = _evaluate_cooldown(None, "E1")  # 메타데이터 자체가 없음(오프라인)
    assert cd2.ok is None


# ---------------------------------------------------------------------------
# max_cve 등급 산출 (C6)
# ---------------------------------------------------------------------------


def test_max_cve_none_when_no_vulns() -> None:
    assert _max_cve_from_vulns([]) == "NONE"


def test_max_cve_unknown_when_no_severity_info() -> None:
    """취약점은 있는데 심각도 표기가 없으면 UNKNOWN — '낮음'이 아니다."""
    assert _max_cve_from_vulns([{"id": "CVE-2026-1", "affected": []}]) == "UNKNOWN"


def test_max_cve_picks_highest_across_sources() -> None:
    vulns = [
        {"database_specific": {"severity": "MODERATE"}},          # → MEDIUM
        {"affected": [{"ecosystem_specific": {"severity": "CRITICAL"}}]},
    ]
    assert _max_cve_from_vulns(vulns) == "CRITICAL"


def test_max_cve_moderate_normalizes_to_medium() -> None:
    assert _max_cve_from_vulns([{"database_specific": {"severity": "MODERATE"}}]) == "MEDIUM"


# ---------------------------------------------------------------------------
# 라이선스 판정 (LIC)
# ---------------------------------------------------------------------------


def test_license_allowlist() -> None:
    assert license_verdict("MIT") == "allowed"
    assert license_verdict("Apache-2.0") == "allowed"
    assert license_verdict("MIT License") == "allowed"    # 서술형 관용 표기
    assert license_verdict("BSD-3-Clause") == "allowed"


def test_license_review_required_for_copyleft() -> None:
    assert license_verdict("GPL-3.0") == "review_required"
    assert license_verdict("AGPL-3.0-only") == "review_required"
    assert license_verdict("SSPL-1.0") == "review_required"


def test_license_unknown_when_missing_or_odd() -> None:
    assert license_verdict(None) == "unknown"
    assert license_verdict("") == "unknown"
    assert license_verdict("Proprietary EULA v7") == "unknown"


# ---------------------------------------------------------------------------
# 기관 정책팩 오버라이드 (GVSKB_VCPS_RULES)
# ---------------------------------------------------------------------------


def test_vcps_env_override_changes_cooldown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = tmp_path / "agency-rules.yaml"
    policy.write_text(
        "environments:\n"
        "  E1: { label: custom, cooldown_days: 21 }\n"
        "default_env: E1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GVSKB_VCPS_RULES", str(policy))
    load_vcps_config.cache_clear()
    days, grade = cooldown_days_for(None)
    assert (days, grade) == (21, "E1")


def test_vcps_broken_file_falls_back_to_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """정책 파일이 깨져도 검사는 내장 기본값으로 계속돼야 한다."""
    bad = tmp_path / "broken.yaml"
    bad.write_text(":::: not yaml [", encoding="utf-8")
    monkeypatch.setenv("GVSKB_VCPS_RULES", str(bad))
    load_vcps_config.cache_clear()
    days, grade = cooldown_days_for("E2")
    assert (days, grade) == (14, "E2")


def test_age_days_handles_bad_input() -> None:
    assert _age_days(None) is None
    assert _age_days("not-a-date") is None
    assert _age_days(_iso_days_ago(10)) == 10
