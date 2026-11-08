"""테스트 공통 — 네트워크를 치는 편의 장치는 기본으로 끈다.

`gvskb scan`·MCP `scan_path` 는 이제 결과에 '최신 릴리스 대조'를 새긴다(release_check).
테스트가 실제 GitHub 를 조회하면 결과가 날짜·망 상태에 따라 달라지므로 끈다.
필요한 테스트는 자기 fixture 에서 `GVSKB_UPDATE_CHECK` 를 지우고 fetch 를 모의한다.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_network_release_check(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GVSKB_UPDATE_CHECK", "off")


@pytest.fixture(autouse=True)
def _deterministic_intel_env(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory):
    """46차 — 패키지 검사가 기본이 되면서 **모든** scan 이 위협정보 캐시를 본다.

    개발 PC 의 `~/.gvskb/cache` 가 있으면 '신선/오래됨', CI 에는 없어 '없음'이 되어 같은 테스트가
    환경마다 다른 판정을 낸다. 기본은 **빈 캐시 폴더 + 자동 갱신 꺼짐**으로 고정한다. 캐시가 필요한
    테스트는 자기 fixture 에서 GVSKB_CACHE_DIR 을 다시 설정하고 채운다(monkeypatch 는 뒤의 setenv 가 이긴다).
    """
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(tmp_path_factory.mktemp("intel-cache")))
    monkeypatch.setenv("GVSKB_AUTO_UPDATE", "off")


@pytest.fixture(autouse=True)
def _no_osv_retry_wait(monkeypatch: pytest.MonkeyPatch):
    """0.6.4 — OSV 다운로드 재시도 대기(2·5초)를 시험에서는 생략한다. 재시도 횟수는 그대로 시험된다."""
    from gvskb.intel.sources import osv

    monkeypatch.setattr(osv, "_RETRY_DELAYS", (0.0, 0.0))
