"""config/security_sources.yaml 메타데이터 품질 검증.

출처 매트릭스가 문서로만 살아 있지 않고 최소한의 품질 검사를 받도록 합니다.
새 출처를 추가하거나 기존 출처의 url·cadence를 수정할 때 누락된 필드를
즉시 발견하기 위함입니다.
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

SOURCES_FILE = Path(__file__).resolve().parent.parent / "config" / "security_sources.yaml"
URL_RE = re.compile(r"^https?://[A-Za-z0-9._-]+(?:/[^\s]*)?$")

# Top-level keys that contain a list of sources.
SECTIONS = ("legal_and_guidance", "international_standards", "vulnerability_sources")

# Allowed cadence vocabulary (extensible, but new vocab must be added intentionally).
ALLOWED_CADENCE = {
    "daily", "weekly", "monthly", "quarterly", "semiannual", "annual",
    "biennial", "irregular_release", "rolling_weekly",
    "daily_metadata_monthly_diff",
    "quarterly_or_notice_change",
    "annual_or_notice_change",
    "twice_daily_or_more",
    "every_4h_to_daily",
    "weekly_or_on_new_dependency",
    "on_build_or_release_verification",
    "on_package_install_and_daily_batch",
}


@pytest.fixture(scope="module")
def data() -> dict:
    return yaml.safe_load(SOURCES_FILE.read_text(encoding="utf-8"))


def test_top_level_keys_present(data: dict) -> None:
    assert "version" in data
    assert "principles" in data
    for section in SECTIONS:
        assert section in data, f"missing section: {section}"
        assert isinstance(data[section], list)
        assert data[section], f"section {section} is empty"


def test_all_sources_have_required_fields(data: dict) -> None:
    missing: list[str] = []
    for section in SECTIONS:
        for entry in data[section]:
            for field in ("id", "name", "url", "cadence"):
                if not entry.get(field):
                    missing.append(f"{section}:{entry.get('id', '<no-id>')} missing {field}")
    assert missing == [], "missing required fields:\n" + "\n".join(missing)


def test_all_urls_are_well_formed(data: dict) -> None:
    bad: list[str] = []
    for section in SECTIONS:
        for entry in data[section]:
            url = entry["url"]
            if not URL_RE.match(url):
                bad.append(f"{entry['id']}: {url}")
    assert bad == [], "malformed URLs:\n" + "\n".join(bad)


def test_all_cadence_values_in_allowed_vocabulary(data: dict) -> None:
    bad: list[str] = []
    for section in SECTIONS:
        for entry in data[section]:
            cadence = entry["cadence"]
            if cadence not in ALLOWED_CADENCE:
                bad.append(f"{entry['id']}: cadence='{cadence}' (extend ALLOWED_CADENCE intentionally)")
    assert bad == [], "unknown cadence values:\n" + "\n".join(bad)


def test_no_duplicate_source_ids(data: dict) -> None:
    seen: dict[str, str] = {}
    for section in SECTIONS:
        for entry in data[section]:
            sid = entry["id"]
            assert sid not in seen, f"duplicate source id {sid} in {section} and {seen[sid]}"
            seen[sid] = section


def test_vulnerability_sources_declare_endpoint_or_endpoints(data: dict) -> None:
    """Vulnerability feeds we actually query should declare their API surface."""
    # id의 부분 문자열이 'OSV', 'NVD', 'CISA-KEV', 'GITHUB-ADVISORY', 'FIRST-EPSS'인 경우 endpoint 권장.
    must_have_endpoint = {"OSV", "NVD"}
    missing: list[str] = []
    for entry in data["vulnerability_sources"]:
        if entry["id"] in must_have_endpoint:
            if not (entry.get("endpoint") or entry.get("endpoints")):
                missing.append(entry["id"])
    assert missing == [], f"sources without endpoint(s): {missing}"


def test_checked_at_not_more_than_one_year_old(data: dict) -> None:
    """legal/guidance 출처에 checked_at이 있으면 1년 이내여야 한다 (WARN 기준 강제)."""
    threshold = date.today() - timedelta(days=400)
    stale: list[str] = []
    for entry in data.get("legal_and_guidance", []):
        c = entry.get("checked_at")
        if c is None:
            continue
        if isinstance(c, str):
            c = date.fromisoformat(c)
        if c < threshold:
            stale.append(f"{entry['id']}: checked_at={c.isoformat()}")
    assert stale == [], "stale checked_at (>400 days):\n" + "\n".join(stale)


# Sources that genuinely don't have a single "latest version" anchor
# (rolling reference catalogs, on-demand APIs, federal coordination portals).
# Anything else must declare latest_known so we know what we're tracking against.
_LATEST_KNOWN_OPTIONAL = {
    "KR-LAW-EGOV",                       # 법령은 promulgated_at만 있어도 충분
    "KR-MOIS-SW-SECURE-CODING",          # 2021 정체, 별도 notes 필드로 추적
    "KR-KISA-KNVD",                      # 일간 회보 — single version 없음
    "NIST-SSDF-800-218", "NIST-SSDF-GENAI-800-218A", "NIST-AI-RMF-600-1",
    "CISA-SECURE-BY-DESIGN", "OWASP-CHEAT-SHEET-SERIES",  # 롤링 문서
    "OSV", "NVD", "CISA-KEV", "CVE-ORG", "GITHUB-ADVISORY", "FIRST-EPSS",
    "OPENSFF-SCORECARD", "SIGSTORE",     # 모두 rolling/on-demand 피드
}


def test_legal_and_international_sources_declare_latest_known(data: dict) -> None:
    """문서 형태 출처는 latest_known(버전·발행일 등)을 명시해야 한다.

    공공기관 협의 시 우리가 어느 시점의 가이드·표준을 인용하고 있는지 추적이
    가능해야 합니다. rolling 피드는 _LATEST_KNOWN_OPTIONAL로 예외.
    """
    missing: list[str] = []
    for section in ("legal_and_guidance", "international_standards"):
        for entry in data[section]:
            if entry["id"] in _LATEST_KNOWN_OPTIONAL:
                continue
            lk = entry.get("latest_known")
            if not lk:
                missing.append(f"{section}:{entry['id']}")
                continue
            # latest_known은 dict이어야 하고 비어있지 않아야 한다.
            if not isinstance(lk, dict) or not lk:
                missing.append(f"{section}:{entry['id']} (latest_known empty)")
    assert missing == [], "sources missing latest_known:\n" + "\n".join(missing)
