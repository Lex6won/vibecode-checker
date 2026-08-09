"""SBOM — 만들기(CycloneDX)와 읽기(CycloneDX·SPDX).

우리 룰과 문서는 *"SBOM 으로 확인하세요"* 라고 **안내는 하면서 정작 도구는
SBOM 을 만들지도 읽지도 못했다**(실측 2026-08-08).

SBOM 은 "이 소프트웨어에 무엇이 들어 있나"를 **증명하는 문서**다. 그래서 이
파일이 가장 무겁게 지키는 것은 형식 적합성이 아니라 **정직성**이다:
판정하지 못한 것을 빼지 않는가 · 누가 무엇으로 판정했는지 적혀 있는가.
"""
from __future__ import annotations

import json

import pytest

from gvskb.sbom import SbomParseError, parse_purl, parse_sbom, to_cyclonedx


def _audit(*checks: dict, **kw) -> dict:
    base = {"checks": list(checks), "parsed_count": len(checks),
            "checked_count": len(checks), "unchecked_count": 0, "truncated_count": 0}
    base.update(kw)
    return {"audits": [base]}


def _check(name: str, version: str, **kw) -> dict:
    c = {"name": name, "version": version, "ecosystem": "npm",
         "checked": True, "verdict": "checked_clean", "version_exact": True}
    c.update(kw)
    return c


# ---------------------------------------------------------------------------
# 만들기 — 형식
# ---------------------------------------------------------------------------

def test_export_produces_valid_cyclonedx_skeleton() -> None:
    doc = to_cyclonedx(_audit(_check("lodash", "4.17.21")), target="myapp")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["name"] == "myapp"
    comp = doc["components"][0]
    assert comp["purl"] == "pkg:npm/lodash@4.17.21"
    assert comp["type"] == "library" and comp["version"] == "4.17.21"


def test_local_path_never_reaches_the_sbom() -> None:
    """SBOM 은 **반출 문서**다 — 검사한 PC 의 경로가 실리면 안 된다.

    실측(2026-08-09) `lexdiff` SBOM 에 이렇게 나갔다::

        "name": "C:\\Users\\<사용자명>\\AppData\\Local\\Temp\\...\\lexdiff"

    반입 번들은 경로를 허용목록으로 막아 두는데 SBOM 에는 그 방어가 없었다 —
    더 멀리 나가는 쪽이 더 헐거웠다. 이름과 `bom-ref` **둘 다** 본다(한쪽만
    고치고 다른 쪽으로 새던 결함이 이 저장소에 이미 있었다).

    픽스처의 사용자명·프로젝트명은 **전부 가상값**이다(`testuser`·`devuser`).
    이 저장소는 공개다 — 경로 유출을 막는 테스트가 정작 실제 사용자명을 공개
    이력에 남기면 같은 결함을 저지르는 것이다(이 커밋 작성 중 실제로 그럴 뻔했다).
    """
    win = r"C:\Users\testuser\AppData\Local\Temp\claude\sess-abc123\scratchpad\myapp"
    for target, expected in (
        (win, "myapp"),
        ("/home/devuser/works/민원챗봇/", "민원챗봇"),
        ("./sub/dir", "dir"),
        ("plain-name", "plain-name"),
        ("C:\\", "project"),          # 드라이브 문자는 이름이 아니다
        ("", "project"),
    ):
        doc = to_cyclonedx(_audit(_check("lodash", "4.17.21")), target=target)
        comp = doc["metadata"].get("component") or {"name": "project", "bom-ref": "root:project"}
        assert comp["name"] == expected, target
        assert comp["bom-ref"] == f"root:{expected}", target
        blob = json.dumps(doc, ensure_ascii=False)
        for leak in ("AppData", "testuser", "sess-abc123", "scratchpad", "devuser"):
            assert leak not in blob, f"{leak} 가 SBOM 에 남았다 ({target})"


def test_explicit_project_name_wins() -> None:
    """`--project-name` 은 사용자가 직접 고른 이름이므로 쪼개지 않는다."""
    doc = to_cyclonedx(
        _audit(_check("lodash", "4.17.21")),
        target=r"C:\Users\testuser\works\myapp", name="경기도/법령비교",
    )
    assert doc["metadata"]["component"]["name"] == "경기도/법령비교"


def test_serial_number_is_deterministic() -> None:
    """난수 UUID 면 같은 입력에 매번 다른 문서가 나와 **두 SBOM 을 비교할 수
    없다.** 조달·감사에 필요한 것은 유일성보다 재현성이다."""
    a = _audit(_check("a", "1.0"), _check("b", "2.0"))
    assert to_cyclonedx(a)["serialNumber"] == to_cyclonedx(a)["serialNumber"]
    assert to_cyclonedx(a)["serialNumber"] != to_cyclonedx(_audit(_check("c", "1.0")))["serialNumber"]


def test_vulnerabilities_carry_source_severity_and_fix() -> None:
    doc = to_cyclonedx(_audit(_check(
        "lodash", "4.17.20", verdict="vulnerable", recommended_version="4.17.21",
        advisories=[{"id": "GHSA-35jh-r3h4-6jhm", "severity": "HIGH",
                     "summary": "Command injection", "cvss_vector": "CVSS:3.1/AV:N/AC:L",
                     "references": ["https://example.invalid/a"]}])))
    v = doc["vulnerabilities"][0]
    assert v["id"] == "GHSA-35jh-r3h4-6jhm"
    assert v["source"]["name"] == "OSV" and "osv.dev" in v["source"]["url"]
    assert v["ratings"][0]["severity"] == "high"
    assert v["ratings"][0]["vector"] == "CVSS:3.1/AV:N/AC:L"
    assert v["affects"][0]["ref"] == "pkg:npm/lodash@4.17.20"
    assert "4.17.21" in v["recommendation"]


def test_duplicate_components_collapse_to_the_heavier_verdict() -> None:
    """같은 패키지가 매니페스트·설치본·번들에 겹쳐 나온다. 묶되 **더 무거운
    판정**을 남긴다 — 리포트의 중복 계상 제거와 같은 원칙이다."""
    doc = to_cyclonedx({"audits": [
        {"checks": [_check("lodash", "4.17.20")]},
        {"checks": [_check("lodash", "4.17.20", verdict="vulnerable")]},
    ]})
    assert len(doc["components"]) == 1
    props = {p["name"]: p["value"] for p in doc["components"][0]["properties"]}
    assert props["gvskb:verdict"] == "vulnerable"


# ---------------------------------------------------------------------------
# 만들기 — 정직성 (형식보다 이쪽이 중요하다)
# ---------------------------------------------------------------------------

def test_unchecked_components_are_kept_with_a_reason() -> None:
    """조회에 실패한 컴포넌트를 빼면 받는 쪽은 "그 패키지를 안 쓴다"로 읽는다.
    **없는 것과 안 본 것은 다르다.**"""
    doc = to_cyclonedx(_audit(
        _check("ok", "1.0"),
        _check("unknown", "2.0", checked=False, verdict="error",
               error="getaddrinfo failed"),
    ))
    assert len(doc["components"]) == 2, "판정 못 한 컴포넌트가 빠졌다"
    bad = next(c for c in doc["components"] if c["name"] == "unknown")
    props = {p["name"]: p["value"] for p in bad["properties"]}
    assert props["gvskb:checked"] == "false"
    assert "getaddrinfo" in props["gvskb:error"]


def test_coverage_notice_states_unchecked_and_truncated() -> None:
    doc = to_cyclonedx({"audits": [{
        "checks": [_check("a", "1.0"), _check("b", "2.0", checked=False, verdict="error")],
        "truncated_count": 42,
    }]})
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["gvskb:unchecked_count"] == "1"
    assert props["gvskb:truncated_count"] == "42"
    notice = props["gvskb:coverage_notice"]
    assert "검사되지 않은" in notice and "42" in notice
    assert "'안전'이 아닙니다" in notice


def test_engine_and_ruleset_are_stamped_together() -> None:
    """판정을 재현하려면 **엔진과 룰셋 둘 다** 필요하다. 한쪽만 적으면
    재현 가능한 것처럼 보이는 착시가 생긴다."""
    doc = to_cyclonedx(_audit(_check("a", "1.0")), engine_version="0.3.0",
                       ruleset_version="2026.08.4", ruleset_digest="abc123")
    tool = doc["metadata"]["tools"]["components"][0]
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert tool["name"] == "gvskb" and tool["version"] == "0.3.0"
    assert props["gvskb:ruleset_version"] == "2026.08.4"
    assert props["gvskb:ruleset_digest"] == "abc123"


def test_no_hash_field_is_fabricated() -> None:
    """우리는 아티팩트를 내려받아 해싱하지 않는다. 빈 해시를 넣으면
    "확인했는데 없다"로 읽히므로 **필드를 아예 만들지 않는다.**"""
    doc = to_cyclonedx(_audit(_check("a", "1.0")))
    assert "hashes" not in doc["components"][0]


def test_missing_license_does_not_produce_an_empty_entry() -> None:
    doc = to_cyclonedx(_audit(_check("a", "1.0")))
    assert "licenses" not in doc["components"][0]
    doc2 = to_cyclonedx(_audit(_check("a", "1.0", registry_metadata={"license": "MIT"})))
    assert doc2["components"][0]["licenses"][0]["license"]["name"] == "MIT"


# ---------------------------------------------------------------------------
# 읽기 — purl 파싱
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("purl, expected", [
    ("pkg:npm/lodash@4.17.21", ("npm", "lodash", "4.17.21")),
    ("pkg:npm/@scope/name@1.2.3", ("npm", "@scope/name", "1.2.3")),
    ("pkg:pypi/requests@2.31.0", ("pypi", "requests", "2.31.0")),
    ("pkg:npm/lodash", ("npm", "lodash", None)),
    ("pkg:npm/lodash@4.17.21?arch=x64", ("npm", "lodash", "4.17.21")),
])
def test_parse_purl(purl: str, expected: tuple) -> None:
    """npm 스코프의 앞 `@` 와 버전 구분자 `@` 를 헷갈리면 이름이 깨진다."""
    assert parse_purl(purl) == expected


def test_parse_purl_rejects_non_purl() -> None:
    assert parse_purl("lodash@4.17.21") is None
    assert parse_purl("") is None


# ---------------------------------------------------------------------------
# 읽기 — CycloneDX · SPDX
# ---------------------------------------------------------------------------

_CDX = json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "components": [
        {"type": "library", "name": "lodash", "version": "4.17.20",
         "purl": "pkg:npm/lodash@4.17.20"},
        {"type": "library", "name": "requests", "version": "2.19.0",
         "purl": "pkg:pypi/requests@2.19.0"},
        {"type": "library", "name": "버전없음", "purl": "pkg:npm/noversion"},
        {"type": "library", "name": "purl없음", "version": "1.0"},
    ],
})

_SPDX = json.dumps({
    "spdxVersion": "SPDX-2.3", "name": "t",
    "packages": [
        {"SPDXID": "SPDXRef-1", "name": "lodash", "versionInfo": "4.17.20",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
        {"SPDXID": "SPDXRef-2", "name": "noassert", "versionInfo": "NOASSERTION",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:npm/noassert"}]},
    ],
})


def test_parse_cyclonedx() -> None:
    got = parse_sbom(_CDX)
    assert got["format"] == "cyclonedx" and got["spec_version"] == "1.6"
    assert [(p["ecosystem"], p["name"], p["version"]) for p in got["packages"]] == [
        ("npm", "lodash", "4.17.20"), ("pypi", "requests", "2.19.0")]


def test_parse_spdx() -> None:
    got = parse_sbom(_SPDX)
    assert got["format"] == "spdx" and got["spec_version"] == "SPDX-2.3"
    assert [(p["ecosystem"], p["name"]) for p in got["packages"]] == [("npm", "lodash")]


@pytest.mark.parametrize("text, needle", [
    (_CDX, "버전이 없습니다"),
    (_CDX, "생태계를 알 수 없습니다"),
    (_SPDX, "NOASSERTION"),
])
def test_unreadable_components_are_reported_not_dropped(text: str, needle: str) -> None:
    """조용히 빠지면 "그 컴포넌트는 안전하다"로 읽힌다."""
    skipped = parse_sbom(text)["skipped"]
    assert skipped, "읽지 못한 컴포넌트가 기록되지 않았다"
    assert any(needle in s["reason"] for s in skipped), [s["reason"] for s in skipped]


def test_export_then_parse_round_trip() -> None:
    """우리가 만든 SBOM 을 우리가 읽지 못하면 둘 중 하나가 틀린 것이다."""
    doc = to_cyclonedx(_audit(_check("lodash", "4.17.21"),
                              _check("requests", "2.31.0", ecosystem="pypi")))
    got = parse_sbom(json.dumps(doc))
    assert {(p["ecosystem"], p["name"], p["version"]) for p in got["packages"]} == {
        ("npm", "lodash", "4.17.21"), ("pypi", "requests", "2.31.0")}
    assert not got["skipped"]


# ---------------------------------------------------------------------------
# 읽기 — 오류가 사용자 잘못처럼 보이지 않는가
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, needle", [
    ("not json at all", "JSON 으로 읽을 수 없습니다"),
    ("[1,2,3]", "최상위가 객체가 아닙니다"),
    ('{"hello": "world"}', "CycloneDX"),
])
def test_parse_errors_say_what_is_wrong(text: str, needle: str) -> None:
    with pytest.raises(SbomParseError) as exc:
        parse_sbom(text)
    assert needle in str(exc.value)


def test_xml_sbom_is_refused_with_a_clear_reason() -> None:
    """지원하지 않는 형식을 '깨진 파일'로 보고하면 사용자는 자기 파일을 의심한다."""
    with pytest.raises(SbomParseError) as exc:
        parse_sbom('<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>')
    assert "XML" in str(exc.value)


# ---------------------------------------------------------------------------
# CLI — 빈 SBOM 을 조용히 쓰지 않는가
# ---------------------------------------------------------------------------

def test_cli_refuses_to_write_an_empty_sbom(tmp_path, capsys) -> None:
    """컴포넌트 0개짜리 SBOM 은 "의존성이 없다"로 읽히는데, 실제로는 안 본 것이다."""
    import argparse

    from gvskb.cli import _emit_sbom
    from gvskb.scanner import scan_code

    out = tmp_path / "sbom.json"
    _emit_sbom(argparse.Namespace(sbom=str(out)), scan_code("x = 1\n", filename="a.py"))
    assert not out.exists()
    assert "--check-deps" in capsys.readouterr().err


def test_cli_writes_sbom_when_dependencies_were_checked(tmp_path) -> None:
    import argparse

    from gvskb.cli import _emit_sbom
    from gvskb.scanner import scan_code

    report = scan_code("x = 1\n", filename="a.py")
    report.dependency_audit = _audit(_check("lodash", "4.17.21"))
    out = tmp_path / "sbom.json"
    _emit_sbom(argparse.Namespace(sbom=str(out)), report)

    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"][0]["purl"] == "pkg:npm/lodash@4.17.21"
    # 스캔 결과의 판정 기준이 그대로 실려야 한다
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props.get("gvskb:ruleset_version") == report.ruleset_version
