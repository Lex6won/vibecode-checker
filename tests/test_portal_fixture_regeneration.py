"""포털 골든 fixture 를 지금도 만들 수 있는지 확인한다.

포털은 체커 JSON 의 실제 모양에 맞춰 배포 판정을 내리고, 그 계약을
``fixtures/checker-reports/gate-blocked-by-kev.json`` 으로 고정해 검증한다.
그 fixture 는 이 저장소의 ``scripts/regenerate_portal_fixture.py`` 로 만든다.

두 저장소가 나뉘어 있으므로 역할도 나뉜다.

* 포털은 **fixture 가 낡았는지**(설치된 체커 버전과 다른지) 본다.
* 여기서는 **fixture 를 만들 수 있는지**, 만들었을 때 여전히 의미가 있는지 본다.
  체커 쪽 변경으로 재생성이 깨지면 포털이 아니라 이 테스트가 먼저 알려야 한다 —
  깨뜨린 쪽에서 잡는 편이 언제나 싸다.

fixture 의 요점은 한 조합이다: **소스는 깨끗한데 패키지 때문에 막힌다.**
포털이 예전에 ``summary.blocked`` 만 보고 판정하던 시절 바로 이 조합을 통과로
읽었다. 조합이 유지되지 않으면 fixture 는 이름만 남고 아무것도 검증하지 못한다.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "regenerate_portal_fixture.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("regenerate_portal_fixture", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def script():
    assert SCRIPT_PATH.is_file(), "재생성 스크립트가 없으면 fixture 는 사람의 기억에 의존하게 된다"
    return _load_script()


@pytest.fixture(scope="module")
def payload(script):
    return script.build_report()


def test_regeneration_still_produces_a_usable_fixture(script, payload) -> None:
    # 스크립트 자신의 전제 검사를 그대로 쓴다 — 기준이 두 벌이 되면 갈라진다.
    assert script.verify(payload) == []


def test_the_point_of_the_fixture_holds(payload) -> None:
    """소스는 깨끗한데 패키지가 막는다 — 이 조합이 fixture 의 존재 이유다."""
    assert payload["summary"]["finding_count"] == 0
    assert payload["summary"]["blocked"] is False
    assert payload["gate"]["verdict"] == "blocked"
    assert payload["gate"]["blocked_source"] is False
    assert payload["gate"]["blocked_dependency"] is True


def test_block_reason_names_the_package(payload) -> None:
    # 결론만 남기고 근거를 버리면 담당자가 무엇을 고쳐야 할지 알 수 없다.
    reasons = payload["gate"]["block_reasons"]
    assert reasons, "차단 근거가 비어 있으면 포털이 화면에 옮길 것이 없다"
    assert reasons[0]["package"] == "kevpkg"
    assert reasons[0]["criteria"], "무엇 때문에 막혔는지가 값으로 남아야 한다"


def test_contract_fields_the_portal_reads_are_present(payload) -> None:
    # 포털이 실제로 읽는 필드들. 하나라도 사라지면 연동이 조용히 깨진다.
    for field in ("schema_version", "engine_version", "summary", "gate", "coverage", "engines"):
        assert field in payload, f"포털이 읽는 필드가 없습니다: {field}"
    assert isinstance(payload["schema_version"], int)
    assert payload["engine_version"], "버전이 없으면 포털이 낡은 fixture 를 탐지할 수 없다"


def test_generator_metadata_names_the_checker_commit(script, payload) -> None:
    """버전만으로는 같은 0.3.0 안의 변경을 구분할 수 없다 — 커밋 해시가 함께 남아야 한다."""
    metadata = script.generator_metadata(payload)
    assert metadata["kind"] == "portal_fixture_generator"
    # 이 테스트는 저장소 안에서 돌므로 커밋 해시가 있어야 한다.
    assert isinstance(metadata["checker_commit"], str) and len(metadata["checker_commit"]) == 40
    assert metadata["engine_version"] == payload["engine_version"]
    assert metadata["schema_version"] == payload["schema_version"]
    assert len(metadata["generator_sha256"]) == 64
    assert metadata["checker_worktree_dirty"] in (True, False)


def test_metadata_sits_next_to_the_fixture(script, tmp_path) -> None:
    out = tmp_path / "gate-blocked-by-kev.json"
    assert script.metadata_path_for(out) == tmp_path / "gate-blocked-by-kev.meta.json"


def test_regeneration_refuses_to_write_a_meaningless_fixture(script, payload) -> None:
    """전제가 깨진 결과는 쓰지 않는다 — 깨진 fixture 는 없는 것보다 나쁘다.

    검증했다는 기록만 남고 실제로는 아무것도 검증하지 않기 때문이다.
    """
    broken = dict(payload)
    broken["summary"] = {**payload["summary"], "finding_count": 3}
    problems = script.verify(broken)
    assert problems, "소스에 발견이 있는 결과를 그대로 통과시키면 안 된다"
