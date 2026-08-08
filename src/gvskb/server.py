"""FastMCP entry point for the public-sector vibe-coding security guardrail."""
from __future__ import annotations

import os
import sys
from importlib import resources
from pathlib import Path
from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import Field

from .gate import gate_status
from .loader import load_all_rules
from .report import render_html as render_html_impl
from .report import render_markdown as render_markdown_impl
from .scanner import (
    detect_secrets_and_pii as detect_secrets_and_pii_impl,
    scan_code as scan_code_impl,
    scan_path as scan_path_impl,
    suggest_fix as suggest_fix_impl,
)
from .schema import ScanReport
from .audit import record_package_check, record_scan, safe_caller
from .search import simple_search
from .tools.check_package import audit_manifest, check_package_impl

PKG_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PKG_ROOT.parent.parent
_repo_rules_dir = PROJECT_ROOT / "rules"
_packaged_rules_dir = Path(str(resources.files("gvskb").joinpath("rules")))
RULES_DIR = Path(os.environ.get("GVSKB_RULES_DIR", _repo_rules_dir if _repo_rules_dir.exists() else _packaged_rules_dir))

print(f"[gvskb] loading rules from {RULES_DIR}", file=sys.stderr)
_STRICT_RULES = os.environ.get("GVSKB_STRICT_RULES", "").lower() in {"1", "true", "yes"}
RULES = load_all_rules(RULES_DIR, strict=_STRICT_RULES)
print(f"[gvskb] loaded {len(RULES)} rules", file=sys.stderr)

mcp = FastMCP(
    "vibecode-checker",
    instructions=(
        "공공기관 담당자가 AI 코딩 도구로 작성한 코드의 보안 위험을 빠르게 찾고, "
        "공무원이 이해할 수 있는 설명과 안전한 수정 방향을 제공하는 보안 점검 도구입니다.\n\n"
        "사용자가 '보안', '점검', '체크', '검토', '검사', '스캔', '안전한지' 같은 말과 함께 "
        "코드·파일·폴더를 가리키면 다음 순서로 처리하세요:\n"
        "1) 입력 형태에 따라:\n"
        "   - GitHub 등 원격 저장소 URL이면 먼저 `git clone --depth 1 <url>` 로 임시 폴더에 "
        "받은 뒤(절대 설치·빌드·실행하지 말고 정적 읽기만) 그 폴더를 scan_path 로 검사합니다.\n"
        "   - 로컬 파일·폴더 경로면 scan_path, 메모리의 코드 조각이면 scan_code 를 호출합니다.\n"
        "   - 단, GVSKB_MODE=offline(망분리)이면 clone(외부 통신)이 불가하므로 URL은 거부하고 "
        "사용자에게 외부망에서 받은 폴더를 반입하도록 안내합니다.\n"
        "2) 결과에 의존성 매니페스트(requirements.txt, package.json 등)가 '검사 제외'로 "
        "표시되면 scan_dependencies 로 패키지를 따로 검사하고, 그 결과를 scan 결과 JSON의 "
        "dependency_audit 필드에 넣은 뒤 render_report 를 호출하세요(보고서에 의존성 섹션이 "
        "함께 들어갑니다).\n"
        "2-1) 결과의 vendor_bundles 가 비어 있지 않으면 **반드시** scan_vendor_bundles 에 "
        "그 값을 그대로 넘겨 검사하세요. static/*.min.js 같은 벤더 라이브러리는 소스 룰 "
        "검사에서 제외되지만 알려진 취약점이 붙고, package.json 도 node_modules 도 없는 "
        "프로젝트에서는 이것이 유일한 컴포넌트 발견 경로입니다. 결과가 둘 다 있으면 "
        "dependency_audit 에 {\"audits\": [의존성결과, 벤더번들결과]} 형태로 합쳐 넣습니다.\n"
        "3) render_report 로 한국어 보고서를 만들어 사용자에게 보여줍니다. 이 도구는 "
        "**파일 저장까지 함께** 하므로(<검사한 경로>/.check-reports/), 반환값의 saved "
        "경로를 사용자에게 그대로 알려 주세요. **에이전트가 보고서를 별도 파일로 다시 "
        "저장하지 마세요** — 임의 위치·이름으로 만들면 기관의 점검 이력이 흩어집니다. "
        "HTML 을 인쇄하면 그대로 PDF 결재 문서가 됩니다.\n"
        "4) 발견 사항은 결과 JSON의 decision/severity 기준으로 '차단(block) → 치명·높음 → "
        "자동 수정 가능 → 나머지 경고' 순서로 정리하고, 각 항목의 safe_fix 를 그 순서대로 "
        "사용자에게 제안하세요.\n\n"
        "원칙: 검사된 파일이 0개면 '안전'이 아니라 경로·확장자를 확인하라는 뜻입니다. "
        "판정 불가(requires_review)는 안전을 의미하지 않습니다. critical/high 위험은 기관 "
        "정책에 따라 저장·커밋·배포 단계에서 차단해야 하며, 본 도구는 공식 보안적합성 검토를 "
        "대체하지 않습니다."
    ),
)


#: 실행환경 등급 파라미터 설명 — 의존성 계열 도구 4개가 같은 문장을 쓴다.
#:
#: 왜 "비워 두라"고 명시하는가(실측): 개인 PC 에서 돌린 검사가 보고서에
#: `E2(내부서버 공용)` 으로 찍혀 사용자가 "왜 내 PC 가 내부서버냐"고 물었다.
#: 이 도구는 환경을 **판별하지 않는다** — 에이전트가 넘긴 값이 그대로 결재
#: 문서에 실린다. 모르면서 값을 지어 넣으면 도구가 판단한 것처럼 보인다.
_ENV_GRADE_DESC = (
    "실행환경 등급 — 신규 버전 쿨다운 기준일만 정합니다(취약점·악성 판정에는 영향 없음): "
    "E0(개인PC 일회성, 3일) | E1(개인PC 반복도구, 7일, 기본) | E2(내부서버 공용, 14일). "
    "**사용자가 배포 환경을 명시하지 않으면 비워 두세요** — 도구가 자동 판별하지 않으며, "
    "넘긴 값이 보고서에 '검사 실행 시 지정'으로 그대로 기록됩니다."
)

#: 이 **설치본이 실제로 등록한** MCP 도구 이름. server_status 가 신원을 말하는 근거다.
#:
#: 왜 프레임워크에 묻지 않는가: fastmcp 의 도구 목록은 비동기(list_tools)라 MCP 도구
#: 안에서 부를 수 없고, 동기 접근 경로는 버전마다 바뀌는 사설 속성(_tool_manager →
#: _local_provider._components)이다. 진단이 프레임워크 내부 구조 변경에 조용히
#: 깨지면 안 되므로 등록 시점에 직접 남기고, **프레임워크의 실제 등록분과 같은지는
#: 테스트가 강제**한다(tests/test_doctor_and_validation.py).
REGISTERED_TOOLS: list[str] = []


def _tool(*decorator_args, **decorator_kwargs):
    """``@_tool()`` 과 동일하되, 등록한 도구 이름을 REGISTERED_TOOLS 에 남긴다."""
    decorate = mcp.tool(*decorator_args, **decorator_kwargs)

    def wrap(fn):
        registered = decorate(fn)
        REGISTERED_TOOLS.append(getattr(registered, "name", None) or fn.__name__)
        return registered

    return wrap


@_tool()
def search_rules(
    query: Annotated[str, Field(description="검색어(한국어·영어 키워드, 룰 제목·본문·태그 대상). 예: 'SQL 삽입', 'hardcoded secret'")],
    scenario: Annotated[str | None, Field(description="시나리오 태그로 필터. 값: web-app | data-pipeline | llm-integration | agent")] = None,
    language: Annotated[str | None, Field(description="프로그래밍 언어로 필터 (예: python, javascript)")] = None,
    severity_min: Annotated[
        Literal["low", "medium", "high", "critical"] | None,
        Field(description="이 심각도 이상만 반환"),
    ] = None,
    limit: Annotated[int, Field(description="최대 반환 건수 (기본 5)")] = 5,
    status: Annotated[
        Literal["approved", "proposed", "stale", "deprecated"] | None,
        Field(description="룰 상태로 필터. proposed=실시간 인텔이 자동 생성한 검토 대기 룰"),
    ] = None,
    approved_only: Annotated[bool, Field(description="True면 승인(approved)된 룰만 — 자동 생성 proposed 룰 제외")] = False,
) -> dict:
    """보안 가이드 룰(기준선 + 실시간 인텔)을 키워드로 검색합니다.

    특정 취약점 유형의 근거 규정·안전한 대안이 궁금할 때, 또는 스캔 결과의
    rule_id 외에 관련 룰을 더 찾고 싶을 때 사용하세요. 코드 검사가 목적이면
    이 도구가 아니라 scan_code / scan_path 를 씁니다.

    로컬에 적재된 룰만 조회하며 네트워크 호출이 없습니다. 반환되는 results의
    각 항목에는 rule_id가 있어 get_rule 로 전문을 조회할 수 있습니다.
    """
    results = simple_search(
        RULES,
        query=query,
        scenario=scenario,
        language=language,
        severity_min=severity_min,
        limit=limit,
        status=status,
        approved_only=approved_only,
    )
    return {
        "query": query,
        "filters": {
            "scenario": scenario,
            "language": language,
            "severity_min": severity_min,
            "status": status,
            "approved_only": approved_only,
        },
        "count": len(results),
        "results": [r.summary() for r in results],
        "disclaimer": "검색 결과는 보안 보조 자료입니다. 기관 정책과 최신 법령·지침을 함께 확인하세요.",
    }


@_tool()
def get_rule(
    rule_id: Annotated[str, Field(description="룰 ID (예: NIS-AI-M01, OWASP-LLM-2025-01). finding.rule_id 또는 search_rules 결과에서 얻음")],
) -> dict:
    """룰 ID로 보안 룰 전문(근거 출처·탐지 기준·안전한 수정 예시 포함)을 조회합니다.

    스캔 결과의 finding.rule_id 나 search_rules 결과의 rule_id 로 "왜 이게
    걸렸는지" 근거 규정과 상세 설명이 필요할 때 사용하세요. 네트워크 호출이
    없으며, 없는 ID면 {"error": "rule not found"} 를 반환합니다.
    """
    for rule in RULES:
        if rule.id == rule_id:
            return {
                **rule.model_dump(mode="json"),
                "disclaimer": "이 룰은 보안 보조 기준입니다. 최신 공식 원문과 기관 정책을 함께 확인하세요.",
            }
    return {"error": "rule not found", "rule_id": rule_id, "available_count": len(RULES)}


@_tool()
def scan_code(
    code: Annotated[str, Field(description="검사할 소스 코드 전문(파일이 아닌 텍스트). 파일·폴더는 scan_path 사용")],
    filename: Annotated[str, Field(description="표시용 파일명. 확장자로 언어를 추정하므로 알면 넣기 (예: app.py)")] = "<memory>",
    language: Annotated[str | None, Field(description="언어 강제 지정 (예: python, javascript). 미지정 시 확장자·내용으로 추정")] = None,
    scenario: Annotated[
        str | None,
        Field(description="용도 힌트 — 해당 시나리오 룰을 우선 적용. 값: web-app | data-pipeline | llm-integration | agent"),
    ] = None,
    profile: Annotated[
        str,
        Field(
            description="정책 프로파일 ID. 값: public-default-strict(기본·엄격) | "
            "civil-complaint-chatbot | internal-db-query | web-civil-service"
        ),
    ] = "public-default-strict",
    caller: Annotated[str | None, Field(description="호출 주체 자율 신고 (예: 'harness:auto'). 감사 구분용")] = None,
) -> dict:
    """코드 조각을 공공기관 보안 기준으로 점검(보안·검토·체크·검사)합니다.

    사용자가 메모리에 있는 코드(붙여넣은 스니펫, 방금 생성한 코드)가 "안전한지",
    개인정보·시크릿·SQL 삽입·위험한 코드 실행·LLM 위험이 있는지 묻거나, "보안
    점검/검토/체크"를 요청하면 이 도구를 사용하세요. 파일·폴더 경로라면 대신
    scan_path 를 씁니다.

    코드를 외부 API로 보내지 않습니다. 시크릿·개인정보는 마스킹된 짧은 증거만
    반환하며, 각 발견 사항에 why_it_matters(왜 위험한가)와 safe_fix(안전한 수정
    방향)가 함께 담깁니다.
    """
    report = scan_code_impl(
        code,
        filename=filename,
        language=language,
        scenario=scenario,
        profile=profile,
    )
    record_scan(report, "scan_code", caller=caller or "")  # 감사로그(옵트인) — scan_path는 스캐너가 직접 기록
    return report.model_dump(mode="json")


@_tool()
def detect_secrets_and_pii(
    code: Annotated[str, Field(description="검사할 소스 코드 또는 설정 파일 텍스트")],
    filename: Annotated[str, Field(description="표시용 파일명 (예: config.py, .env)")] = "<memory>",
) -> dict:
    """시크릿(API 키·비밀번호·토큰)과 한국형 개인정보(주민등록번호·전화번호 등),
    내부망 주소만 집중 탐지합니다.

    "이 코드에 키/개인정보 들어있어?"처럼 유출 항목만 빠르게 확인할 때 쓰는
    부분 집합 검사입니다. SQL 삽입·위험 명령 등 전체 보안 점검이 목적이면
    scan_code / scan_path 를 쓰세요(이 탐지를 포함합니다).

    코드를 외부로 보내지 않으며, 탐지된 값은 마스킹된 짧은 증거로만 반환합니다.
    """
    report = detect_secrets_and_pii_impl(code, filename=filename)
    record_scan(report, "detect_secrets_and_pii")
    return report.model_dump(mode="json")


@_tool()
async def check_package(
    name: Annotated[str, Field(description="패키지 이름 (예: requests, express). 버전 표기 없이 이름만")],
    ecosystem: Annotated[Literal["pypi", "npm"], Field(description="패키지 저장소: pypi(Python) | npm(Node.js)")] = "pypi",
    version: Annotated[str | None, Field(description="검사할 버전(권장). 미지정 시 전체 버전 이력 기준이라 판정이 보수적")] = None,
    env_grade: Annotated[
        Literal["E0", "E1", "E2"] | None,
        Field(description=_ENV_GRADE_DESC + " E3(대민·개인정보)는 바이브코딩 대상이 아니므로 받지 않음"),
    ] = None,
    caller: Annotated[str | None, Field(description="호출 주체 자율 신고 (예: 'harness:auto', 'registry:manual'). 감사 구분용")] = None,
) -> dict:
    """단일 패키지의 실재·취약점·악성·발행경과일(쿨다운)을 설치 전에 확인합니다.

    AI가 제안한 패키지를 pip/npm install 하기 전, 또는 이름이 수상한(오타
    스쿼팅 의심) 패키지를 확인할 때 사용하세요. 매니페스트 전체를 검사하려면
    scan_dependencies 를 씁니다.

    판정(verdict): not_found=저장소에 없음(AI가 지어낸 이름 의심, 차단 권고) |
    malicious=악성 | vulnerable=알려진 취약점 | cooldown_hold=발행 직후라 대기 권고 |
    checked_clean=이상 없음 | unknown/error=판정 불가('안전' 아님) |
    registry_rejected=기관 레지스트리가 차단 | registry_approved=기관 레지스트리가 승인.

    registry_* 는 이 도구의 관측이 아니라 **기관의 결정**입니다. 다만 malicious 는
    승인보다 위입니다 — 승인은 시점의 판단이고 위협 정보는 그 뒤에도 갱신됩니다.
    registry_approved 인데 checked=false 면 '승인은 받았으나 이번에 로컬 위협
    정보와 대조하지는 못했다'는 뜻입니다('안전 확인'이 아님).

    네트워크: 온라인이면 공식 저장소(pypi.org/registry.npmjs.org)와 OSV.dev에
    패키지명·버전만 전송합니다(코드 미전송). GVSKB_MODE=offline(망분리)이면 외부
    호출 없이 로컬 인텔 캐시로 대체하며, 실재·발행일은 '미확인'으로 표시됩니다.
    """
    result = await check_package_impl(name=name, ecosystem=ecosystem, version=version, env_grade=env_grade)
    # result 에 실린 caller 는 감사로그뿐 아니라 레지스트리 봉투의 result 로도
    # 그대로 나간다 — 검증은 감사 기록 직전이 아니라 **값이 들어오는 지점**에서
    # 해야 두 경로가 모두 덮인다(연동합의 §3 개인 식별자 금지).
    caller = safe_caller(caller or "")
    if caller:
        result["caller"] = caller
    record_package_check([result], tool="check_package", caller=caller, scope="single")
    return result


@_tool()
async def scan_dependencies(
    manifest_text: Annotated[
        str,
        Field(description="의존성 매니페스트 또는 **락파일**의 원문 텍스트. "
                          "매니페스트: requirements.txt·package.json / "
                          "락파일: package-lock.json·uv.lock·poetry.lock·pnpm-lock.yaml·yarn.lock"),
    ],
    ecosystem: Annotated[Literal["pypi", "npm"], Field(description="pypi | npm. 락파일이면 형식이 생태계를 확정하므로 이 값은 무시됩니다")] = "pypi",
    limit: Annotated[int | None, Field(description="검사할 최대 패키지 수. 미지정 시 형식에 맞춰 자동(매니페스트 20 · 락파일 500). 초과분은 truncated_count 로 표시")] = None,
    env_grade: Annotated[
        Literal["E0", "E1", "E2"] | None,
        Field(description=_ENV_GRADE_DESC),
    ] = None,
    caller: Annotated[str | None, Field(description="호출 주체 자율 신고 (예: 'harness:auto'). 감사 구분용")] = None,
) -> dict:
    """의존성 매니페스트를 파싱해 각 패키지의 실재·취약점·악성·쿨다운을 일괄 검사합니다.

    scan_path 결과에서 requirements.txt·package.json 이 '검사 제외'로 표시되면
    이 도구로 이어서 검사하세요.

    네트워크: 온라인이면 공식 저장소와 OSV.dev에 패키지명·버전만 전송합니다
    (소스 코드 미전송). GVSKB_MODE=offline(망분리)이면 외부 호출 없이 로컬 인텔
    캐시로 대체하며, 실재·발행일은 '미확인'으로 표시됩니다.

    **락파일을 넣으면 전이 의존성까지 검사합니다.** 실무 취약점은 대부분 매니페스트에
    적히지 않은 전이 의존성에 있으므로, 락파일이 있으면 그쪽을 넣는 편이 정확합니다
    (버전도 범위가 아니라 고정값이라 판정이 확실해집니다).

    결과를 scan_path 결과 JSON의 ``dependency_audit`` 필드에 넣어 render_report를
    호출하면 사람용 보고서에 '의존성 취약점' 섹션이 함께 렌더됩니다.

    ``truncated_count`` > 0 이면 limit 로 잘려 **검사되지 않은** 패키지가 있다는
    뜻입니다 — '이상 없음'이 아니므로 limit 를 올려 재검사하세요.
    """
    result = await audit_manifest(manifest_text, ecosystem=ecosystem, limit=limit, env_grade=env_grade)
    caller = safe_caller(caller or "")   # 봉투로도 나가는 값 — 진입 지점에서 검증
    if caller:
        result["caller"] = caller
    record_package_check(
        result.get("checks") or [], tool="scan_dependencies", caller=caller,
        # 레지스트리 심사 대기열 보호 — 락파일 유래 수백 건이 큐에 그대로 쌓이면
        # 담당자 일이 늘어 연동 목적과 정반대가 된다(연동합의 §5-C).
        scope="lockfile" if result.get("source_kind") == "lockfile" else "manifest",
        summary=result,
    )
    return result


@_tool()
async def scan_vendor_bundles(
    vendor_bundles: Annotated[
        list[dict],
        Field(description="scan_path 결과 JSON 의 `vendor_bundles` 값을 **그대로** 전달 "
                          "(직접 조립하지 말 것). 각 항목: {path, name, version, evidence, ecosystem}"),
    ],
    env_grade: Annotated[
        Literal["E0", "E1", "E2"] | None,
        Field(description=_ENV_GRADE_DESC),
    ] = None,
    caller: Annotated[str | None, Field(description="호출 주체 자율 신고 (예: 'harness:auto'). 감사 구분용")] = None,
) -> dict:
    """벤더링된 프런트엔드 라이브러리(`static/*.min.js`)의 컴포넌트 취약점을 검사합니다.

    scan_path 결과에 ``vendor_bundles`` 가 비어 있지 않으면 **반드시** 이 도구로
    이어서 검사하세요. 이 파일들은 소스 룰 검사에서는 제외되지만(미니파이드라
    오탐만 나옴) 그 자체가 프로젝트가 실행하는 남의 코드이고 알려진 취약점이 붙습니다.
    ``package.json`` 도 ``node_modules`` 도 없는 프로젝트에서는 **이것이 유일한
    컴포넌트 발견 경로**입니다(실측: `xlsx 0.18.5` → CVE-2023-30533 등).

    버전을 확정하지 못한 번들은 조회하지 않고 '판정 불가'로 남깁니다 — 추측한 버전으로
    취약점을 단정하지 않기 위해서입니다. **판정 불가는 '안전'이 아닙니다.**

    결과를 scan_path 결과 JSON 의 ``dependency_audit`` 에 넣어 render_report 를
    호출하세요. 이미 scan_dependencies 결과가 있다면
    ``{"audits": [<의존성 결과>, <이 결과>]}`` 형태로 합쳐 넣습니다.
    """
    from .tools.vendor_bundle import audit_vendor_bundles

    result = await audit_vendor_bundles(list(vendor_bundles or []), env_grade=env_grade)
    caller = safe_caller(caller or "")
    if caller:
        result["caller"] = caller
    record_package_check(
        result.get("checks") or [], tool="scan_vendor_bundles", caller=caller,
        scope="manifest", summary=result,
    )
    return result


@_tool()
def suggest_fix(
    rule_id: Annotated[str, Field(description="스캔 결과 finding.rule_id 값 (예: NIS-AI-M01)")],
    unsafe_code: Annotated[str | None, Field(description="문제가 된 코드 조각(선택). 넣으면 마스킹된 미리보기가 함께 반환됨")] = None,
) -> dict:
    """발견 사항(finding)에 대한 공무원 친화적 안전 수정 방향을 반환합니다.

    스캔 결과의 특정 finding을 "어떻게 고치죠?"라고 물을 때 rule_id로 호출하세요.
    쉬운 제목(plain_title), 안전한 수정 방향(safe_fix), 자동 수정 가능
    여부(can_auto_fix)를 돌려줍니다. 네트워크 호출이 없으며, 자동 수정은 diff
    미리보기 후 담당자 확인을 거쳐 적용해야 합니다.
    """
    return suggest_fix_impl(rule_id=rule_id, unsafe_code=unsafe_code)


@_tool()
def scan_path(
    path: Annotated[str, Field(description="검사할 로컬 파일 또는 폴더의 절대·상대 경로. 원격 URL 불가(먼저 clone)")],
    scenario: Annotated[
        str | None,
        Field(description="용도 힌트 — 해당 시나리오 룰을 우선 적용. 값: web-app | data-pipeline | llm-integration | agent"),
    ] = None,
    profile: Annotated[
        str,
        Field(
            description="정책 프로파일 ID. 값: public-default-strict(기본·엄격) | "
            "civil-complaint-chatbot | internal-db-query | web-civil-service"
        ),
    ] = "public-default-strict",
    max_files: Annotated[int, Field(description="최대 검사 파일 수 (기본 500). 초과분은 skipped_files에 사유와 함께 기록")] = 500,
    caller: Annotated[str | None, Field(description="호출 주체 자율 신고 (예: 'harness:auto'). 감사 구분용")] = None,
) -> dict:
    """파일 또는 폴더를 공공기관 보안 기준으로 점검(보안·검토·체크·검사)합니다.

    사용자가 "이 폴더/프로젝트 보안 점검해줘", "이 파일 검토/체크해줘", "안전한지
    검사해줘"처럼 로컬 경로를 가리키면 이 도구를 사용하세요. 메모리의 코드
    조각이면 대신 scan_code 를 씁니다. "기존 코드베이스 감사" 흐름의 진입점입니다.

    경로를 로컬에서 순회하며 빌드·vendor 디렉터리를 건너뛰고 바이너리는 무시하며,
    소스 코드를 외부 API로 전혀 보내지 않습니다. 각 발견 사항에는 why_it_matters
    와 safe_fix 가 포함됩니다. 검사 후 render_report 로 한국어 보고서를 만드세요.
    """
    report = scan_path_impl(
        path,
        scenario=scenario,
        profile=profile,
        max_files=max_files,
        caller=caller or "",
    )
    return report.model_dump(mode="json")


@_tool()
def render_report(
    report: Annotated[
        dict,
        Field(
            description="scan_code / scan_path 가 반환한 ScanReport JSON 을 그대로 전달 "
            "(필수 키: target, summary, findings — 직접 조립하지 말 것). "
            "scan_dependencies 결과가 있으면 dependency_audit 키에 넣어 병합 가능"
        ),
    ],
    format: Annotated[
        Literal["markdown", "html", "both", "sarif"],
        Field(description="markdown(기본) | html(자체 포함 단일 파일) | both | sarif(CI 연동용 SARIF 2.1.0)"),
    ] = "markdown",
    save: Annotated[
        bool,
        Field(description="파일로도 저장할지(기본 True). False 면 문자열만 반환합니다"),
    ] = True,
    output_dir: Annotated[
        str | None,
        Field(description="저장 폴더 지정(선택). 미지정 시 <검사한 경로>/.check-reports/"),
    ] = None,
) -> dict:
    """ScanReport(scan_code / scan_path 결과)를 한국어 보고서로 만들고 **파일로 저장**합니다.

    ⚠️ **중요 — 반환된 내용을 별도 파일로 다시 저장하지 마세요.**
    이 도구가 이미 표준 위치에 저장했습니다. 반환값의 ``saved`` 에 담긴 경로를
    사용자에게 그대로 알려 주세요. 에이전트가 임의 위치·이름으로 다시 저장하면
    조직의 점검 이력이 흩어져 나중에 찾을 수 없습니다.

    저장 규약: ``<검사한 경로>/.check-reports/YYYY-MM-DD_HHMM_보안점검.{html,md,json}``
    (기관 공용 폴더로 모으려면 환경변수 ``GVSKB_REPORT_DIR`` 을 설정합니다)

    형식:
    - format="markdown": Markdown 본문(기본)
    - format="html": 자체 포함 단일 HTML(외부 CDN·JS 없음, 인쇄→PDF·이메일 가능)
    - format="both": Markdown + HTML 모두
    - format="sarif": SARIF 2.1.0 (CI·보안도구 연동, GitHub code scanning 업로드)

    저장이 필요 없으면 ``save=False`` 로 문자열만 받습니다(파이프 연결 등).
    출력은 자체 완결적이라 비전공 이해관계자 공유나 내부 승인 기록 첨부에 적합합니다.
    """
    try:
        parsed = ScanReport.model_validate(report)
    except Exception as exc:
        return {"error": "invalid ScanReport", "detail": str(exc)}

    # 게이트 필드는 `gate_status` 한 곳에서만 계산한다. 예전에는
    # `summary.blocked`(=소스 발견만)를 그대로 내보내서, CRITICAL 취약 패키지가
    # 있어도 본문은 "배포 불가"인데 이 필드는 False 였다 — 하네스가 읽는 값이다.
    _gate = gate_status(parsed)
    out: dict = {
        "format": format,
        "finding_count": parsed.summary.finding_count,
        "blocked": _gate["blocked"],
        # 소스는 보조, 의존성은 게이트 — 연동 상대가 자기 정책을 세울 수 있게 나눈다.
        "blocked_source": _gate["blocked_source"],
        "blocked_dependency": _gate["blocked_dependency"],
        "gate_reason": _gate["reason"],
    }
    if format in ("markdown", "both"):
        md = render_markdown_impl(parsed)
        out["markdown"] = md
        out["content"] = md  # 하위 호환: 기존 호출자는 content(=markdown)를 읽음
    if format in ("html", "both"):
        out["html"] = render_html_impl(parsed)
    if format == "sarif":
        from .report import render_sarif
        out["sarif"] = render_sarif(parsed)

    # 기본으로 **파일까지 저장**한다. 문자열만 돌려주면 에이전트가 각자 자기
    # 방식으로 저장해(임의 폴더·임의 파일명) 조직의 점검 이력이 흩어진다.
    # 실측: 같은 MCP 를 쓰는 다른 에이전트가 규약과 다른 위치에 보고서를 만들었다.
    if save:
        saved = save_report(report=report, output_dir=output_dir)
        if "error" in saved:
            out["save_error"] = saved
        else:
            out["saved"] = saved["saved"]
            out["directory"] = saved["directory"]
            out["note"] = (
                "보고서를 아래 경로에 저장했습니다 — **별도 파일로 다시 저장하지 마세요.** "
                "사용자에게 이 경로를 그대로 알려 주세요."
            )
    return out


@_tool()
def save_report(
    report: Annotated[
        dict,
        Field(description="scan_code / scan_path 가 반환한 ScanReport JSON 그대로 (직접 조립 금지)"),
    ],
    output_dir: Annotated[
        str | None,
        Field(description="저장 폴더 지정(선택). 미지정 시 <검사한 경로>/.check-reports/ 에 저장"),
    ] = None,
) -> dict:
    """점검 보고서를 **파일로 저장**하고 저장 경로를 알려줍니다.

    render_report 는 본문 문자열만 돌려주므로, 그대로 두면 보고서가 대화창에만
    남고 사라집니다. 결재·보고에 첨부하려면 이 도구로 저장하세요.

    저장 규약: ``<검사한 프로젝트>/.check-reports/YYYY-MM-DD_HHMM_보안점검.{html,md,json}``
    - HTML: 인쇄하면 그대로 PDF 결재 문서가 됩니다(외부 CDN 없음)
    - MD: 텍스트 편집·재가공용
    - JSON: 재검사·이력 비교용 원본 데이터
    기관 공용 폴더로 모으려면 환경변수 ``GVSKB_REPORT_DIR`` 을 설정하세요.
    """
    import json as _json

    from .report_store import ensure_writable, gitignore_hint, resolve_report_path

    try:
        parsed = ScanReport.model_validate(report)
    except Exception as exc:
        return {"error": "invalid ScanReport", "detail": str(exc)}

    explicit = None
    if output_dir:
        from .report_store import default_report_basename
        explicit = str(Path(output_dir) / default_report_basename(parsed.target))
    base, fallback_note = ensure_writable(resolve_report_path(parsed.target, explicit=explicit))

    written: dict[str, str] = {}
    try:
        md_path = base.with_suffix(".md")
        html_path = base.with_suffix(".html")
        json_path = base.with_suffix(".json")
        md_path.write_text(render_markdown_impl(parsed), encoding="utf-8")
        html_path.write_text(render_html_impl(parsed), encoding="utf-8")
        json_path.write_text(
            _json.dumps(parsed.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        written = {"markdown": str(md_path), "html": str(html_path), "json": str(json_path)}
    except OSError as exc:
        return {"error": "저장 실패", "detail": str(exc), "attempted": str(base)}

    return {
        "saved": written,
        "directory": str(base.parent),
        "finding_count": parsed.summary.finding_count,
        "blocked": gate_status(parsed)["blocked"],
        "blocked_source": gate_status(parsed)["blocked_source"],
        "blocked_dependency": gate_status(parsed)["blocked_dependency"],
        "note": fallback_note or gitignore_hint(),
        "next": "HTML 파일을 열어 인쇄하면 그대로 PDF 결재 문서로 쓸 수 있습니다.",
    }


@_tool()
async def scan_installed_packages(
    path: Annotated[str, Field(description="프로젝트 폴더 경로. 하위의 .venv·*.whl·node_modules 설치 흔적을 훑습니다")],
    env_grade: Annotated[
        Literal["E0", "E1", "E2"] | None,
        Field(description=_ENV_GRADE_DESC),
    ] = None,
    limit: Annotated[int, Field(description="검사할 최대 패키지 수 (기본 100)")] = 100,
) -> dict:
    """**실제로 설치된** 패키지까지 훑어 취약점·라이선스를 검사합니다.

    scan_dependencies 는 requirements.txt·package.json 에 **적힌 것**만 봅니다.
    그런데 취약점은 대개 그 파일에 없는 **전이 의존성**에 있습니다. 이 도구는
    폴더 안의 설치 흔적을 직접 읽어 그 격차를 메웁니다:

    - `.venv`/site-packages 의 `*.dist-info/METADATA` (이름·버전·라이선스)
    - 오프라인 반입용 `*.whl` 파일명
    - `node_modules/*/package.json`

    패키지를 임포트·실행하지 않고 **메타데이터 텍스트만** 읽습니다. 네트워크는
    취약점 조회에만 쓰이며 패키지명·버전만 전송합니다(GVSKB_MODE=offline 이면
    로컬 인텔 캐시 사용). 라이선스 정보는 설치 메타데이터에서만 얻을 수 있어
    이 도구에서만 함께 반환됩니다.
    """
    from .tools.installed_packages import collect_installed_packages, to_requirements_text

    inv = collect_installed_packages(path, limit=limit)
    if inv.get("error"):
        return {"error": inv["error"], "path": path}

    audits = []
    for eco, pkgs in (("pypi", inv["pypi"]), ("npm", inv["npm"])):
        if not pkgs:
            continue
        audit = await audit_manifest(
            to_requirements_text(pkgs, ecosystem=eco), ecosystem=eco,
            limit=len(pkgs), env_grade=env_grade,
        )
        audit["manifest"] = f"<설치된 패키지: {eco}>"
        audit["source"] = "installed-inventory"
        # 이 도구는 매니페스트를 읽지 않으므로 직접 의존성을 가려낼 수 없다 —
        # 전부 `installed` 로 둔다. 직접/전이 구분이 필요하면
        # `scan_path --check-deps --include-installed` 경로를 쓸 것(그쪽은 매니페스트와
        # 대조한다). 여기서 임의로 `manifest` 를 붙이면 하네스 §4-0 의 차단 범위가
        # 근거 없이 넓어진다.
        for c in audit.get("checks", []):
            c["source_scope"] = "installed"
        lic_by_name = {str(p.get("name", "")).lower(): p.get("license") for p in pkgs}
        for c in audit.get("checks", []):
            lic = lic_by_name.get(str(c.get("name", "")).lower())
            if lic:
                meta = c.get("registry_metadata")
                if isinstance(meta, dict) and not meta.get("license"):
                    meta["license"] = lic
                    c["license_source"] = "installed-metadata"
        record_package_check(
            audit.get("checks") or [], tool="scan_installed_packages",
            scope="installed", summary=audit,
        )
        audits.append(audit)

    return {
        "path": path,
        "stats": inv["stats"],
        "audits": audits,
        "disclaimer": (
            "설치 흔적(dist-info·whl·node_modules)에서 읽은 목록입니다. "
            "패키지를 실행하지 않았으며, 취약점 조회에는 이름·버전만 전송됩니다. "
            "이 결과를 scan_path 결과의 dependency_audit 에 넣어 render_report 하면 "
            "보고서에 의존성 섹션으로 포함됩니다."
        ),
    }


@_tool()
def list_loaded_rules() -> dict:
    """현재 서버에 적재된 전체 보안 룰 목록(ID·제목·심각도·계층)을 반환합니다.

    디버깅·감사용입니다: 룰이 몇 개 적재됐는지, 특정 룰이 포함됐는지 확인할 때
    쓰세요. 룰 내용 검색은 search_rules, 전문 조회는 get_rule 이 적합합니다.
    네트워크 호출이 없습니다.
    """
    return {
        "count": len(RULES),
        "rules": [
            {
                "id": r.id,
                "title": r.title_ko,
                "severity": r.severity.value,
                "layer": r.source_layer.value,
                "domains": r.domains,
            }
            for r in RULES
        ],
    }


@_tool()
def server_status() -> dict:
    """Return runtime diagnostics: install identity, rules dir, rule counts, env.

    Use this from any MCP client (Claude, Cursor, Codex, ...) to verify the
    server is healthy and to see which rules are loaded. No network calls.

    설치 신원을 함께 돌려준다 — **버전 문자열만 믿지 마세요**:

    - ``runtime_freshness.process_stale`` — **먼저 이것을 보세요.** 돌고 있는
      프로세스가 디스크의 현재 코드·룰을 쓰고 있는지. ``true`` 면 판정 결과가
      낡은 룰에서 나온 것이므로, 결과를 해석하기 전에 ``remedy`` 대로 서버를
      **재시작**해야 한다(재설치가 아니다 — 룰과 코드는 프로세스 시작 시점에
      한 번만 읽힌다).
    - ``commit_id`` — 이 프로세스가 **임포트한 시점의** 커밋(pip
      ``direct_url.json`` 또는 소스 체크아웃의 ``.git/HEAD``). 디스크의 현재
      커밋은 ``install_identity.disk_commit_id`` 이고, 둘이 다르면 낡은 것이다.
      ``__version__`` 은 릴리스 사이에 고정돼 최근 변경분을 구분하지 못한다.
    - ``total_rules`` — **메모리에 올라간** 룰 수(``rule_count_source`` 로 출처
      표기). 디스크를 다시 읽은 수가 아니므로, 이 값이 늘었다고 최신인 것은
      아니다. 인텔 캐시 룰이 섞여 최신처럼 보인 사례가 있다.
    - ``mcp_tools`` / ``missing_tools`` — 이 설치본이 실제로 제공하는 도구 목록.
      필요한 도구 이름이 ``mcp_tools`` 에 없으면 **낡은 설치본**이므로,
      호출 실패 증상으로 역추적하지 말고 재설치하면 된다.
    """
    from .diagnostics import runtime_status_for_mcp
    return runtime_status_for_mcp()


@mcp.prompt(
    name="보안점검",
    description="폴더·파일·코드를 한국 공공기관 보안 기준으로 점검하고 한국어 보고서까지 만드는 표준 절차",
)
def security_review_prompt(target: str = "") -> str:
    """One-click standard flow: scan → (deps) → Korean report → prioritized fixes."""
    where = target.strip() or "사용자가 가리키는 폴더·파일, GitHub 저장소 URL, 또는 방금 작성한 코드"
    return (
        f"{where} 를 한국 공공기관 보안 기준으로 보안 점검해줘. 다음 순서로 진행해줘:\n"
        "1) GitHub 등 원격 URL이면 `git clone --depth 1 <url>` 로 임시 폴더에 받은 뒤"
        "(설치·실행 금지, 정적 읽기만) 그 폴더를 scan_path 로 검사한다. 로컬 경로(폴더·파일)면 "
        "scan_path, 메모리의 코드면 scan_code 를 호출한다. GVSKB_MODE=offline이면 URL은 "
        "거부하고 폴더 반입을 안내한다.\n"
        "2) 의존성 매니페스트가 '검사 제외'로 나오면 scan_dependencies 로 패키지도 검사한다.\n"
        "3) render_report 를 format='both' 로 호출해 한국어 Markdown + HTML 보고서를 만든다. "
        "이 도구가 표준 위치(.check-reports/)에 저장까지 하므로, 반환된 saved 경로를 "
        "사용자에게 알려 주고 **별도로 파일을 다시 만들지 않는다**.\n"
        "4) 발견 사항을 '차단(block) → 치명·높음 → 자동 수정 가능 → 나머지 경고' 순서로 "
        "정리하고, 각 항목의 safe_fix(안전한 수정 방향)를 그 순서대로 제안한다.\n"
        "주의: 검사된 파일이 0개면 '안전'이 아니라 경로·확장자를 확인하라는 뜻이고, "
        "requires_review(판정 불가)는 안전을 의미하지 않는다. 이 점검은 공식 보안적합성 "
        "검토를 대체하지 않는다는 점을 결과 끝에 한 줄로 덧붙인다."
    )


def _start_background_autopull() -> None:
    """서버 기동 시 인텔 캐시를 백그라운드로 점검·갱신한다.

    사용자가 `gvskb update-intel` 을 기억해 실행하지 않아도 최신 위협 인텔로
    검사하게 만드는 지점이다. 데몬 스레드로 돌려 서버 기동을 지연시키지 않고,
    실패해도 조용히 넘어간다(검사는 낡은 캐시로 계속되며 결과에 정직히 표시됨).
    GVSKB_AUTO_UPDATE=off 로 끌 수 있다.
    """
    import threading

    def _run() -> None:
        try:
            from .intel.autopull import maybe_auto_update
            maybe_auto_update()
        except Exception as exc:  # noqa: BLE001 — 갱신 실패가 서버를 죽이면 안 된다
            print(f"[gvskb] ⚠ 인텔 자동 갱신 중 오류(무시하고 계속): {exc}", file=sys.stderr)

    threading.Thread(target=_run, name="gvskb-autopull", daemon=True).start()


def main() -> None:
    # 구버전 사본이 현재 코드를 가리면 **구버전 룰로 검사**하게 된다.
    # MCP 는 사용자가 로그를 잘 보지 않으므로 기동 시 크게 남긴다(server_status
    # 에도 같은 내용이 노출된다).
    try:
        from .diagnostics import warn_if_install_broken
        warn_if_install_broken()
    except Exception as exc:  # pragma: no cover - 진단 실패가 서버를 막으면 안 된다
        print(f"[gvskb] ⚠ 설치 진단 실패(무시하고 계속): {exc}", file=sys.stderr)
    _start_background_autopull()
    mcp.run()


if __name__ == "__main__":
    main()