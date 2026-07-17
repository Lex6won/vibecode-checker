"""FastMCP entry point for the public-sector vibe-coding security guardrail."""
from __future__ import annotations

import os
import sys
from importlib import resources
from pathlib import Path
from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import Field

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
from .audit import record_scan
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
        "3) render_report 로 한국어 보고서를 만들어 사용자에게 보여줍니다. 사람이 읽을 "
        "보고서가 필요하면 format='html', 둘 다면 format='both' 를 씁니다.\n"
        "4) 발견 사항은 결과 JSON의 decision/severity 기준으로 '차단(block) → 치명·높음 → "
        "자동 수정 가능 → 나머지 경고' 순서로 정리하고, 각 항목의 safe_fix 를 그 순서대로 "
        "사용자에게 제안하세요.\n\n"
        "원칙: 검사된 파일이 0개면 '안전'이 아니라 경로·확장자를 확인하라는 뜻입니다. "
        "판정 불가(requires_review)는 안전을 의미하지 않습니다. critical/high 위험은 기관 "
        "정책에 따라 저장·커밋·배포 단계에서 차단해야 하며, 본 도구는 공식 보안적합성 검토를 "
        "대체하지 않습니다."
    ),
)


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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
    record_scan(report, "scan_code")  # 감사로그(옵트인) — scan_path는 스캐너가 직접 기록
    return report.model_dump(mode="json")


@mcp.tool()
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


@mcp.tool()
async def check_package(
    name: Annotated[str, Field(description="패키지 이름 (예: requests, express). 버전 표기 없이 이름만")],
    ecosystem: Annotated[Literal["pypi", "npm"], Field(description="패키지 저장소: pypi(Python) | npm(Node.js)")] = "pypi",
) -> dict:
    """단일 패키지의 알려진 취약점·악성 여부를 설치 전에 확인합니다.

    AI가 제안한 패키지를 pip/npm install 하기 전, 또는 이름이 수상한(오타
    스쿼팅 의심) 패키지를 확인할 때 사용하세요. 매니페스트 전체를 검사하려면
    scan_dependencies 를 씁니다.

    네트워크: 온라인이면 OSV.dev API에 패키지명·생태계만 전송합니다(코드 미전송).
    GVSKB_MODE=offline(망분리)이면 외부 호출 없이 로컬 인텔 캐시로 대체하며,
    캐시가 비어 있으면 판정 불가를 반환합니다 — 판정 불가는 '안전'이 아닙니다.
    """
    return await check_package_impl(name=name, ecosystem=ecosystem)


@mcp.tool()
async def scan_dependencies(
    manifest_text: Annotated[
        str,
        Field(description="의존성 매니페스트 파일의 원문 텍스트 — requirements.txt(pypi) 또는 package.json(npm). 락파일 불가"),
    ],
    ecosystem: Annotated[Literal["pypi", "npm"], Field(description="매니페스트 종류: pypi(requirements.txt) | npm(package.json)")] = "pypi",
    limit: Annotated[int, Field(description="검사할 최대 패키지 수 (기본 20). 초과분은 결과에 미검사로 표시")] = 20,
) -> dict:
    """의존성 매니페스트를 파싱해 각 패키지의 취약점·악성 여부를 일괄 검사합니다.

    scan_path 결과에서 requirements.txt·package.json 이 '검사 제외'로 표시되면
    이 도구로 이어서 검사하세요.

    네트워크: 온라인이면 OSV.dev에 패키지명·버전만 전송합니다(소스 코드 미전송).
    GVSKB_MODE=offline(망분리)이면 외부 호출 없이 로컬 인텔 캐시로 대체합니다.

    락파일(poetry.lock·yarn.lock 등)은 파싱하지 못하므로 verdict="unparsed"로
    정직하게 거절합니다 — 원본 매니페스트(requirements.txt·package.json)를 주세요.
    결과를 scan_path 결과 JSON의 ``dependency_audit`` 필드에 넣어 render_report를
    호출하면 사람용 보고서에 '의존성 취약점' 섹션이 함께 렌더됩니다.
    """
    return await audit_manifest(manifest_text, ecosystem=ecosystem, limit=limit)


@mcp.tool()
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


@mcp.tool()
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
    )
    return report.model_dump(mode="json")


@mcp.tool()
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
) -> dict:
    """ScanReport(scan_code / scan_path 결과)를 한국어 보고서로 렌더링합니다.

    사람이 읽고 결재·보고에 쓸 문서가 필요할 때 사용하세요.
    - format="markdown": Markdown 본문(기본)
    - format="html": 자체 포함 단일 HTML(외부 CDN·JS 없음, 인쇄→PDF·이메일 가능)
    - format="both": Markdown + HTML 모두
    - format="sarif": SARIF 2.1.0 (CI·보안도구 연동, GitHub code scanning 업로드)

    출력은 자체 완결적이라 비전공 이해관계자 공유나 내부 승인 기록 첨부에 적합합니다.
    """
    try:
        parsed = ScanReport.model_validate(report)
    except Exception as exc:
        return {"error": "invalid ScanReport", "detail": str(exc)}

    out: dict = {
        "format": format,
        "finding_count": parsed.summary.finding_count,
        "blocked": parsed.summary.blocked,
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
    return out


@mcp.tool()
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


@mcp.tool()
def server_status() -> dict:
    """Return runtime diagnostics: package version, rules dir, rule counts, env.

    Use this from any MCP client (Claude, Cursor, Codex, ...) to verify the
    server is healthy and to see which rules are loaded. No network calls.
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
        "3) render_report 를 format='both' 로 호출해 한국어 Markdown + HTML 보고서를 만든다.\n"
        "4) 발견 사항을 '차단(block) → 치명·높음 → 자동 수정 가능 → 나머지 경고' 순서로 "
        "정리하고, 각 항목의 safe_fix(안전한 수정 방향)를 그 순서대로 제안한다.\n"
        "주의: 검사된 파일이 0개면 '안전'이 아니라 경로·확장자를 확인하라는 뜻이고, "
        "requires_review(판정 불가)는 안전을 의미하지 않는다. 이 점검은 공식 보안적합성 "
        "검토를 대체하지 않는다는 점을 결과 끝에 한 줄로 덧붙인다."
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()