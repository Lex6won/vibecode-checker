"""FastMCP entry point for the public-sector vibe-coding security guardrail."""
from __future__ import annotations

import os
import sys
from importlib import resources
from pathlib import Path
from typing import Literal

from fastmcp import FastMCP

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
    query: str,
    scenario: str | None = None,
    language: str | None = None,
    severity_min: Literal["low", "medium", "high", "critical"] | None = None,
    limit: int = 5,
    status: Literal["approved", "proposed", "stale", "deprecated"] | None = None,
    approved_only: bool = False,
) -> dict:
    """Search baseline and realtime security guidance rules.

    Set ``approved_only=True`` to exclude auto-generated proposed rules from
    real-time intel feeds. Use ``status="proposed"`` to inspect pending rules.
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
def get_rule(rule_id: str) -> dict:
    """Return a rule by ID."""
    for rule in RULES:
        if rule.id == rule_id:
            return {
                **rule.model_dump(mode="json"),
                "disclaimer": "이 룰은 보안 보조 기준입니다. 최신 공식 원문과 기관 정책을 함께 확인하세요.",
            }
    return {"error": "rule not found", "rule_id": rule_id, "available_count": len(RULES)}


@mcp.tool()
def scan_code(
    code: str,
    filename: str = "<memory>",
    language: str | None = None,
    scenario: str | None = None,
    profile: str = "public-default-strict",
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
    return report.model_dump(mode="json")


@mcp.tool()
def detect_secrets_and_pii(code: str, filename: str = "<memory>") -> dict:
    """Detect secrets, Korean personal information, and internal network values."""
    report = detect_secrets_and_pii_impl(code, filename=filename)
    return report.model_dump(mode="json")


@mcp.tool()
async def check_package(
    name: str,
    ecosystem: Literal["pypi", "npm"] = "pypi",
) -> dict:
    """Check a package against OSV.dev before installing an AI-suggested dependency."""
    return await check_package_impl(name=name, ecosystem=ecosystem)


@mcp.tool()
async def scan_dependencies(
    manifest_text: str,
    ecosystem: Literal["pypi", "npm"] = "pypi",
    limit: int = 20,
) -> dict:
    """Parse a dependency manifest and check packages with OSV.dev.

    Only package names and versions are sent to OSV.dev. Source code is not sent.

    락파일(poetry.lock·yarn.lock 등)은 파싱하지 못하므로 verdict="unparsed"로
    정직하게 거절합니다 — 원본 매니페스트(requirements.txt·package.json)를 주세요.
    결과를 scan_path 결과 JSON의 ``dependency_audit`` 필드에 넣어 render_report를
    호출하면 사람용 보고서에 '의존성 취약점' 섹션이 함께 렌더됩니다.
    """
    return await audit_manifest(manifest_text, ecosystem=ecosystem, limit=limit)


@mcp.tool()
def suggest_fix(rule_id: str, unsafe_code: str | None = None) -> dict:
    """Return a public-officer-friendly safe-fix recommendation for a finding."""
    return suggest_fix_impl(rule_id=rule_id, unsafe_code=unsafe_code)


@mcp.tool()
def scan_path(
    path: str,
    scenario: str | None = None,
    profile: str = "public-default-strict",
    max_files: int = 500,
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
    report: dict,
    format: Literal["markdown", "html", "both"] = "markdown",
) -> dict:
    """ScanReport(scan_code / scan_path 결과)를 한국어 보고서로 렌더링합니다.

    사람이 읽고 결재·보고에 쓸 문서가 필요할 때 사용하세요.
    - format="markdown": Markdown 본문(기본)
    - format="html": 자체 포함 단일 HTML(외부 CDN·JS 없음, 인쇄→PDF·이메일 가능)
    - format="both": Markdown + HTML 모두

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
    return out


@mcp.tool()
def list_loaded_rules() -> dict:
    """List loaded guidance rules for debugging and audit."""
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