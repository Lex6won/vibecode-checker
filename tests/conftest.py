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
