"""Data models for the public-sector vibe-coding security MCP."""
from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Status(str, Enum):
    approved = "approved"
    proposed = "proposed"
    stale = "stale"
    deprecated = "deprecated"


class SourceLayer(str, Enum):
    baseline = "baseline"
    realtime = "realtime"


class Decision(str, Enum):
    block = "block"
    warn = "warn"
    allow = "allow"


class RuleSource(BaseModel):
    publisher: str
    document: str
    version: str | None = None
    url: HttpUrl | None = None
    item: str | None = None


class RuleDetection(BaseModel):
    """Pattern-based detection metadata.

    The scanner reads this section so adding or tuning a rule does not require
    code changes. Each MD rule with a non-empty patterns list is treated as a
    scanner-runnable rule.
    """

    patterns: list[str] = Field(
        default_factory=list,
        description=(
            "Regex patterns (Python re syntax). Empty list means the rule is emitted by a "
            "dedicated engine (AST 등) or is reference-only."
        ),
    )
    exclude_patterns: list[str] = Field(
        default_factory=list,
        description=(
            "같은 줄에 이 패턴이 있으면 발견을 취소한다(맥락 오탐 제거). "
            "예: 안내 문구의 예시 IP('e.g. 192.168.1.100'). patterns 와 같은 flags 를 쓴다."
        ),
    )
    validators: list[str] = Field(
        default_factory=list,
        description=(
            "매치 뒤에 돌리는 값 검증기 이름. 정규식만으로는 '형태가 같은 남'을 "
            "걸러낼 수 없는 자리에 쓴다 — 예: rrn_checksum 은 주민등록번호 검증식"
            "(mod 11)을 실제로 계산해, 13자리 숫자이기만 한 값(Unix ms 타임스탬프 등)을 "
            "탈락시킨다. 등록된 이름만 허용하며 모든 검증기를 통과해야 발견이 남는다."
        ),
    )
    dedup_group: str | None = Field(
        default=None,
        description=(
            "같은 코드를 다른 각도로 보는 룰들의 묶음 이름. 같은 그룹의 룰이 "
            "같은 파일·같은 줄에 걸리면 하나만 남긴다(심각도 높은 쪽 우선). "
            "지정하지 않으면 중복 제거를 하지 않는다 — 서로 다른 주제의 룰이 "
            "우연히 같은 줄에 걸린 것을 임의로 지우지 않기 위해서다."
        ),
    )
    flags: list[Literal["IGNORECASE", "MULTILINE", "DOTALL"]] = Field(default_factory=list)
    confidence: Literal["confirmed", "likely", "pattern-only"] | None = Field(
        default=None,
        description=(
            "이 룰이 발행하는 발견의 근거 강도. 미지정이면 엔진이 추정한다"
            "(regex=pattern-only). 패턴 자체가 확증인 룰(예: PEM 개인키 헤더)은 "
            "'confirmed' 로 선언해 과소 표기를 막는다."
        ),
    )
    category: str | None = Field(
        default=None,
        description="Scanner category for filtering (e.g. privacy-public-sector, secret-scanning).",
    )
    why_it_matters: str | None = None
    public_sector_impact: list[str] = Field(default_factory=list)
    safe_fix: str | None = None
    references: list[str] = Field(default_factory=list)
    can_auto_fix: bool = False


CURRENT_RULE_SCHEMA_VERSION = 1


#: **노출 위험** 카테고리 — 값이 거기 적혀 있다는 사실 자체가 위험인 룰들.
#:
#: 이 프로젝트는 위험을 두 갈래로 나눈다.
#:
#: - **실행 위험**(주입·XSS·코드 실행) — 그 코드가 *돌아야* 위험하다.
#:   그래서 주석·데이터 파일처럼 실행되지 않는 자리에서는 의미가 없다.
#: - **노출 위험**(비밀값·개인정보·내부망 주소) — *적혀 있는 것만으로* 위험하다.
#:   주석이든 설정 파일이든 커밋되면 Git 이력에 영구히 남는다.
#:
#: 이 구분은 세 곳에서 쓰인다 — 주석 줄 건너뛰기 예외, 테스트 경로 감쇄 대상,
#: 데이터·설정 파일에서 계속 볼 룰. **한 곳에서 정의한다.**
#: 예전에는 같은 집합이 두 모듈에 따로 적혀 있었고, 둘 다 똑같이
#: ``public-sector-internal`` 이 빠져 있었다(실측 2026-08-09) — 내부망 IP 가
#: 테스트 픽스처에서 48건이 **차단**으로 올라왔다. 같은 목록을 두 곳에 적으면
#: 언젠가 어긋나고, 어긋난 쪽이 조용히 잘못된 판정을 낸다.
EXPOSURE_CATEGORIES: frozenset[str] = frozenset({
    "secret-scanning",
    "privacy-public-sector",
    "public-sector-internal",
})


class RuleExamples(BaseModel):
    """Code samples that pin per-rule precision / recall.

    Authors attach these next to the rule itself so the rule and its proof
    move together. A meta-test runs each sample through the scanner:
    - every ``positive`` snippet MUST be detected by this rule
    - every ``negative`` snippet MUST NOT trigger this rule (false positive guard)

    Public-sector reviewers can read the snippets directly to judge whether
    the rule's intent matches the implementation.
    """

    positive: list[str] = Field(
        default_factory=list,
        description="Snippets the rule MUST detect. One snippet per list item.",
    )
    negative: list[str] = Field(
        default_factory=list,
        description="Snippets the rule MUST NOT match (precision guard).",
    )
    language: str | None = Field(
        default=None,
        description="Optional scanner language hint. Falls back to rule.languages[0].",
    )


class Rule(BaseModel):
    id: str = Field(..., description="Example: NIS-AI-M01, OWASP-LLM-2025-01")
    schema_version: int = Field(
        default=CURRENT_RULE_SCHEMA_VERSION,
        description="Rule frontmatter schema version. Bump when adding required fields.",
    )
    title_ko: str
    title_en: str | None = None
    status: Status = Status.approved
    source_layer: SourceLayer = SourceLayer.baseline
    sources: list[RuleSource]
    cwe: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    scenarios: list[str] = Field(
        default_factory=list,
        description="Examples: data-pipeline, llm-integration, web-app, agent, package-install",
    )
    severity: Severity
    decision_default: Decision | None = None
    domains: list[str] = Field(default_factory=list)
    related_baseline: list[str] = Field(default_factory=list)
    verified_at: date
    review_due: date | None = None
    detection: RuleDetection | None = None
    examples: RuleExamples | None = None
    body: str = ""

    def summary(self) -> dict:
        return {
            "id": self.id,
            "title_ko": self.title_ko,
            "severity": self.severity.value,
            "status": self.status.value,
            "source_layer": self.source_layer.value,
            "sources": [s.publisher for s in self.sources],
            "scenarios": self.scenarios,
            "languages": self.languages,
            "domains": self.domains,
            "decision_default": self.decision_default.value if self.decision_default else None,
            "preview": self.body[:240].strip(),
        }


class CodeLocation(BaseModel):
    file: str
    line: int
    column: int | None = None
    end_line: int | None = None


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    plain_title: str
    severity: Severity
    decision: Decision
    category: str
    location: CodeLocation
    evidence: str = Field(default="", description="Short snippet, never a whole file")
    why_it_matters: str
    public_sector_impact: list[str] = Field(default_factory=list)
    safe_fix: str | None = None
    references: list[str] = Field(default_factory=list)
    can_auto_fix: bool = False
    requires_approval_to_bypass: bool = False
    confidence: Literal["confirmed", "likely", "pattern-only"] = Field(
        default="pattern-only",
        description=(
            "판정 근거의 강도 — 같은 심각도라도 근거가 다르면 대응이 달라야 한다. "
            "confirmed=데이터 흐름(테인트)이나 구조 분석으로 확인 · "
            "likely=구조 분석 기반이나 문맥 확인 권장 · "
            "pattern-only=문자열 패턴만 일치(값의 출처는 미확인 — 사람 확인 필요)"
        ),
    )
    engine: str = Field(
        default="regex",
        description="Detection engine: regex | python-ast | js-taint | semgrep | ...",
    )
    # 승인된 예외(.gvskb-exceptions.yaml) — 발견을 숨기지 않고 게이트만 통과.
    suppressed: bool = Field(
        default=False,
        description="승인된 예외로 억제됨 — 요약 건수·차단 판정에서 제외되지만 리포트에는 남는다",
    )
    suppress_reason: str | None = Field(
        default=None,
        description="억제 사유(원 사유 + 승인자 + 만료일). suppressed=True일 때만 존재",
    )
    # 심각도 감쇄 — 발견을 지우지 않고 등급만 낮춘다. 지우면 "왜 안 나왔지"를
    # 추적할 수 없고, 그대로 두면 가짜 값 때문에 배포가 막힌다.
    severity_adjusted: str | None = Field(
        default=None,
        description=(
            "원래 등급에서 낮춘 사유(예: '테스트 코드 경로 — 값이 실제 자격증명이 "
            "아닐 가능성이 높음'). 값이 있으면 리포트가 감쇄 사실을 함께 표시한다"
        ),
    )


class ExternalConnection(BaseModel):
    """외부로 데이터를 보낼 수 있는 지점(외부 API 호출 · 설치된 외부 플러그인).

    이것은 *위반(Finding)이 아니라 검토용 인벤토리*입니다 — 사용 자체는 금지가
    아니며, 전송 데이터에 개인정보·행정정보가 포함되는지 보안팀이 확인하도록
    목록화합니다. ``review_level`` 은 우선순위 표시용(warn=⚠ 우선 검토)이며 위험
    건수(finding_count)·CI 게이팅에는 영향을 주지 않습니다.
    """

    kind: Literal["api", "package", "resource"]
    target: str = Field(..., description="외부 호스트(api/resource) 또는 패키지명(플러그인)")
    category: str = Field(
        default="other",
        description="ai | analytics | error | payment | messaging | library | cdn | other",
    )
    airgap_impact: Literal["breaks", "egress"] | None = Field(
        default=None,
        description=(
            "폐쇄망(망분리) 배포 시 영향 — breaks: 외부 리소스(CDN 등) 로딩 실패로 "
            "화면·기능 파손 / egress: 외부로 데이터 전송 시도(차단되거나 정책 위반 소지) / "
            "None: 로컬 동작(영향 없음/미상)"
        ),
    )
    model: str | None = Field(default=None, description="AI 호출의 모델명(리터럴). 변수면 None")
    version: str | None = Field(default=None, description="패키지 버전 또는 API path 버전")
    location: str = Field(default="", description="file:line(api) 또는 매니페스트 파일(package)")
    data_summary: str = Field(default="", description="이용 정보 요약(카탈로그 + 인접 신호)")
    region: str | None = Field(default=None, description="국외 | 국내 | None(미상)")
    operator: str | None = Field(
        default=None,
        description="운영주체·국가(예: 'OpenAI(미국)') — 국외이전 검토는 '누구에게, 어느 나라로'가 특정돼야 함. None=미상(직접 확인)",
    )
    call_count: int = Field(default=1, description="같은 파일 내 호출 지점 수(api 전용). location은 첫 지점")
    pii_adjacent: bool = Field(default=False, description="같은 줄/근접에 개인정보 신호")
    context: Literal["runtime", "doc-or-installer"] = Field(
        default="runtime",
        description=(
            "이 연결이 나온 맥락. runtime=코드가 실제로 호출 · "
            "doc-or-installer=설치 안내 문서·설치 스크립트의 다운로드 링크. "
            "후자는 **운영 중 데이터 전송이 아니므로 국외이전 검토 대상이 아니다**."
        ),
    )
    review_level: Literal["info", "warn"] = "info"


class ScanSummary(BaseModel):
    finding_count: int
    by_severity: dict[str, int]
    by_decision: dict[str, int]
    highest_severity: Severity | None = None
    blocked: bool = False


class SkippedFile(BaseModel):
    path: str
    reason: str


# ---------------------------------------------------------------------------
# Policy / approval / audit — used by agencies that operationalize the tool.
# These models intentionally avoid storing raw code or PII: only hashes,
# rule IDs, redacted evidence, and identifiers.
# ---------------------------------------------------------------------------


class PolicyDecision(BaseModel):
    """A single decision row applied to one finding under a given profile."""

    rule_id: str
    profile: str
    decision: Decision
    reason: str = ""
    agency: str = ""
    requires_approval: bool = False
    expires_at: date | None = None


class BypassApproval(BaseModel):
    """A maintainer / security officer signing off on a temporary exception."""

    finding_id: str
    rule_id: str
    profile: str
    approver_role: str
    approver_id: str = Field(default="", description="agency-managed identifier; never an email")
    approved_at: date
    expires_at: date
    justification: str = Field(default="", max_length=1000)


class AuditEvent(BaseModel):
    """One JSONL audit row. Designed to be appended, never updated.

    The payload is hash-centric: we never store raw code or PII so that the
    audit trail itself does not become a new exfiltration target.
    """

    event_type: Literal[
        "scan", "block", "warn", "approve_bypass", "reload_rules", "update_intel",
        # 패키지 판정 — "언제 무엇을 허용·차단했는가"가 공공기관 감사 대상이다.
        # scan 계열 이벤트는 ScanReport 를 전제로 해 패키지 판정을 담지 못한다.
        "package_check", "package_check_batch",
    ]
    timestamp: str  # ISO-8601
    tool: str
    profile: str = ""
    rule_id: str = ""
    decision: Decision | None = None
    target_hash: str = Field(default="", description="sha256 of file path + content size, never the content itself")
    finding_id: str = ""
    redacted_evidence: str = ""
    user_role: str = ""
    agency: str = ""
    caller: str = Field(
        default="",
        description=(
            "호출 주체 식별자(예: 'harness:auto', 'registry:manual', 'cli'). "
            "레지스트리 request_type(AUTO/MANUAL) 구분의 근거 — 호출자가 자율 신고한 값. "
            "개인 식별자(이름·이메일·사번·PC명·IP)를 넣지 말 것 — 감사에 필요한 것은 "
            "'무엇이 호출했는가'이지 '누가'가 아니다."
        ),
    )
    # ── package_check 계열 전용 ───────────────────────────────────────────
    # 패키지명·버전은 해시하지 않고 그대로 남긴다. 이 값들은 비밀이 아니고,
    # "무엇을 허용·차단했는가"가 이 이벤트의 존재 이유이기 때문이다.
    package: str = Field(default="", description="pkg:pypi/requests@2.31.0 형태의 패키지 식별자")
    verdict: str = Field(default="", description="패키지 판정(PackageCheckResult.verdict) 또는 집계 판정")
    checked: bool | None = Field(
        default=None,
        description="취약점 검사가 실제 수행됐는가. False 는 '안전'이 아니라 '판정 못 함'",
    )


class ScanReport(BaseModel):
    target: str
    language: str | None = None
    scenario: str | None = None
    profile: str = "public-default-strict"
    summary: ScanSummary
    findings: list[Finding]
    scanned_files: list[str] = Field(default_factory=list)
    skipped_files: list[SkippedFile] = Field(default_factory=list)
    external_surface: list[ExternalConnection] = Field(
        default_factory=list,
        description="외부 연결 인벤토리(검토용) — 위험 건수와 분리. 비어있으면 섹션 미표시.",
    )
    # 실행 모드·인텔 기준일 — 상위(스캐너/서버)가 주입하는 선택 정보.
    # None이면 리포트에 아무것도 표시하지 않는다(역호환: 구버전 JSON도 그대로 파싱).
    scan_mode: str | None = Field(
        default=None,
        description="검사 실행 모드: 'online' | 'offline'(망분리). None이면 리포트에 미표시.",
    )
    # 분석 출처 증명(provenance) — "어떤 엔진이 언제 판단했나"를 결과에 각인해
    # 레지스트리·감사로그가 재현 가능한 근거를 갖게 한다. 구버전 JSON 역호환 위해 None 허용.
    engine_version: str | None = Field(
        default=None,
        description="검사를 수행한 gvskb 버전(gvskb.__version__). 스캐너가 생성 시 주입.",
    )
    generated_at: str | None = Field(
        default=None,
        description="이 결과가 생성된 시각(UTC ISO-8601). 스캐너가 생성 시 주입.",
    )
    # 룰셋 신원 — 게이트의 재현성 전제. 판정을 재현하려면 **엔진과 룰셋 둘 다**
    # 필요하다(엔진 코드가 바뀌어도 판정은 바뀐다). 한쪽만 적으면 재현 가능한
    # 것처럼 보이는 착시가 생기므로 반드시 쌍으로 노출한다.
    ruleset_version: str | None = Field(
        default=None,
        description="이 판정에 쓰인 룰셋 버전(rules/RULESET.lock). 선언이 없으면 None.",
    )
    ruleset_digest: str | None = Field(
        default=None,
        description="판정에 쓰이는 룰 필드만의 지문. 버전 선언이 없어도 비교에 쓸 수 있다.",
    )
    ruleset_drift: str | None = Field(
        default=None,
        description=(
            "룰이 바뀌었는데 버전이 그대로일 때의 설명. None이면 선언과 실제가 일치."
        ),
    )
    intel_freshness: dict | None = Field(
        default=None,
        description="의존성·인텔 캐시 기준일(예: {'advisory_db': '2026-06-01'}). None이면 미표시.",
    )
    dependency_audit: dict | None = Field(
        default=None,
        description=(
            "의존성(패키지) 취약점 검사 결과 — scan_dependencies/audit_manifest 반환값. "
            "단일 audit dict 또는 {'audits': [...]}(여러 매니페스트). None이면 섹션 미표시. "
            "보안팀이 코드+패키지 위험을 한 문서에서 보도록 리포트에 병합된다."
        ),
    )
    duplicate_files: list[dict] = Field(
        default_factory=list,
        description=(
            "내용이 완전히 같은 파일 묶음 — [{'hash': 'ab12…', 'paths': [...]}]. "
            "같은 인증서·키가 여러 경로에 복사돼 발견이 배수로 보이는 상황을 "
            "리포트가 '동일 파일 N곳'으로 설명하게 한다."
        ),
    )
    profile_fallback: dict | None = Field(
        default=None,
        description=(
            "요청한 프로파일을 찾지 못해 적용되지 않았을 때만 채워진다 — "
            "{'requested','applied','reason','available'}. 프로파일이 다르면 **판정 기준 "
            "자체가 다르므로**, 이를 표시하지 않으면 보고서가 근거를 틀리게 말한다."
        ),
    )
    vendor_bundles: list[dict] = Field(
        default_factory=list,
        description=(
            "벤더링된 프런트엔드 라이브러리(`*.min.js`) 식별 결과 — "
            "[{'path','name','version','evidence','ecosystem'}]. `version` 이 None 이면 "
            "'이름은 알지만 버전 미상'(판정 불가)이다. 소스 룰 검사에서는 제외하되 "
            "**컴포넌트 취약점 검사 대상**으로 넘겨 조용히 사라지지 않게 한다."
        ),
    )
    suppression_summary: dict | None = Field(
        default=None,
        description=(
            "승인된 예외(.gvskb-exceptions.yaml) 적용 요약 — "
            "{'applied': N, 'expired': [...], 'invalid': [...]}. None이면 예외 없음."
        ),
    )
    disclaimer: str = (
        "이 결과는 자동 보안 보조 검토입니다. 공공기관 운영 반영 전에는 기관 보안 담당자의 "
        "정책과 최신 법령·지침을 함께 확인해야 합니다."
    )


# ---------------------------------------------------------------------------
# Package check — check_package / scan_dependencies 의 통일 결과 스키마.
# 온라인(OSV 실조회)과 오프라인(로컬 캐시) 경로가 손조립 dict 로 서로 다른 키를
# 반환하던 문제를 없애고, 레지스트리(SafePackageRecord.checks)가 파싱 오류 없이
# 저장할 수 있는 단일 계약을 만든다. 모든 신규 필드는 기본값이 있어 역호환된다.
# ---------------------------------------------------------------------------


class PackageRegistryMetadata(BaseModel):
    """공식 패키지 저장소(pypi.org·registry.npmjs.org) 메타데이터 스냅샷.

    실재 확인(C4-EXISTENCE)·쿨다운(C1)·라이선스(LIC)·설치 스크립트(C2)의 원천.
    오프라인이거나 조회 실패면 exists=None — '미확인'이지 '안전'이 아니다.
    """

    exists: bool | None = Field(
        default=None,
        description="공식 저장소 실재 여부. None=미확인(오프라인·조회 실패) — '안전' 아님",
    )
    latest_version: str | None = None
    queried_version: str | None = Field(default=None, description="검사 대상 버전(미지정 시 최신)")
    version_exists: bool | None = Field(
        default=None,
        description="검사 대상 **버전**의 실재 여부. 패키지는 있어도 버전이 없으면 False. "
                    "None=버전 미지정 또는 미확인. 존재하지 않는 버전은 설치 불가·오타·조작 신호다",
    )
    version_published_at: str | None = Field(default=None, description="검사 대상 버전의 발행 시각(ISO)")
    version_age_days: int | None = Field(default=None, description="버전 발행 후 경과일 — 쿨다운 판정 근거")
    first_published_at: str | None = Field(default=None, description="패키지 최초 발행 시각(ISO) — 신생 탐지 근거")
    package_age_days: int | None = None
    license: str | None = None
    install_scripts: Literal["none", "present", "unknown"] = Field(
        default="unknown",
        description="설치 스크립트(preinstall/install/postinstall) 존재 여부. PyPI는 미개봉 검사라 unknown",
    )
    install_script_names: list[str] = Field(default_factory=list)
    deprecated: bool | None = Field(default=None, description="npm deprecated 표시 여부")
    source: str = Field(default="", description="메타데이터 출처(예: 'pypi.org JSON API')")
    fetched_at: str | None = Field(default=None, description="조회 시각(UTC ISO)")
    error: str | None = None


class CooldownCheck(BaseModel):
    """쿨다운(C1) 판정 — '발행 직후 버전은 기다렸다 쓴다'는 VCPS 핵심 통제."""

    cooldown_days: int = Field(description="적용된 대기 기준일(E등급·정책에서 결정)")
    env_grade: str | None = Field(default=None, description="적용된 실행환경 등급(E0~E2). None=기본값")
    version_age_days: int | None = None
    ok: bool | None = Field(
        default=None,
        description="True=경과일 충족, False=대기 필요(HOLD), None=발행일 미상으로 판정 불가",
    )


class PackageCheckResult(BaseModel):
    """check_package 1건의 통일 결과 — 온라인/오프라인 공통.

    verdict 사다리(우선순위순): malicious > registry_rejected > not_found >
    vulnerable > cooldown_hold > checked_stale > registry_approved >
    checked_clean > unknown > error. '판정 불가(unknown)'는 안전이 아니며
    requires_review=True 로 명시된다.

    ``registry_*`` 는 기관 레지스트리(gg-trusted-registry 등)의 **판정**이고
    나머지는 이 도구의 **관측**이다. 둘을 섞지 않는다:

    - ``registry_rejected`` 가 ``not_found`` 보다 위 — 기관의 명시적 차단이 더 강한 신호
    - ``registry_approved`` 가 ``checked_clean`` 보다 위 — 사람이 확인한 것이 자동 판정보다 강함
    - **``malicious`` 는 최상위** — 기관 승인도 로컬 악성 탐지를 덮지 못한다.
      승인은 시점의 판단이고 위협 정보는 그 뒤에도 갱신되기 때문이다.
    """

    name: str
    version: str | None = None
    version_exact: bool = Field(
        default=True,
        description=(
            "``version`` 이 **실제로 쓰이는 버전**인가, 아니면 매니페스트 제약의 경계값인가. "
            "``requests>=2.28`` 은 '2.28 이상'이지 '2.28'이 아니다 — 설치된 것은 2.31.0 일 수 "
            "있다. False 인 판정은 그 버전에 대한 **관측이 아니라 가정**이므로 레지스트리에 "
            "사실로 제출하지 않는다(연동합의 §5-D)."
        ),
    )
    ecosystem: str
    checked: bool = Field(default=False, description="취약점 검사가 실제 수행됐는가(실재확인과 별개)")
    verdict: Literal[
        "malicious", "not_found", "vulnerable", "cooldown_hold",
        # 이름·버전 신호 — 레지스트리 실재 여부와 **독립**으로 적용한다. 예전엔
        # 인기 패키지와 1자 차이 이름이라도 레지스트리에 존재하면 '이상 없음'으로
        # 통과했다(실측 2026-08-29: npm 의 `expresss` 는 실존하는 자리차지 패키지).
        # 스쿼터가 이름을 등록해 두면 휴리스틱이 정확히 그 상황에서 무력화됐다.
        "suspicious_name", "version_not_found",
        "checked_stale", "checked_clean", "unknown", "error",
        # 기관 레지스트리 판정 — 이 도구의 관측이 아니라 기관의 결정이다.
        "registry_approved", "registry_rejected",
    ] = "unknown"
    verdict_severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    requires_review: bool = True
    offline: bool = False
    # 실재·메타데이터 (VCPS C4/C1/C2/LIC)
    exists: bool | None = Field(default=None, description="registry_metadata.exists 의 요약 복사본")
    registry_metadata: PackageRegistryMetadata | None = None
    cooldown: CooldownCheck | None = None
    license_verdict: Literal["allowed", "review_required", "unknown"] | None = Field(
        default=None, description="VCPS 라이선스 허용목록 대조 결과. None=미확인",
    )
    # 취약점·악성 (VCPS C6)
    is_malicious_package: bool = False
    vulnerability_count: int = 0
    malicious_advisory_count: int = 0
    max_cve: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"] = Field(
        default="NONE",
        description="발견된 취약점의 최고 심각도. UNKNOWN=취약점은 있으나 심각도 미상(안전 아님)",
    )
    in_kev: bool = Field(default=False, description="CISA KEV(실제 악용 목록) 교차 일치 여부")
    kev_checked: bool = Field(
        default=False,
        description=(
            "KEV 대조가 실제로 성립했는가 — **``in_kev=False`` 를 '악용 목록에 없음'이라는 "
            "사실로 읽어도 되는지**를 정하는 값. False 면 '악용 없음'이 아니라 '대조 못 함'이다. "
            "``cache_sources_used`` 가 비었는지로 추론하면 안 된다: 악성 피드만 있고 KEV 캐시가 "
            "없는 경우 목록은 비어 있지 않은데 KEV 대조는 되지 않았다."
        ),
    )
    advisories: list[dict] = Field(
        default_factory=list,
        description=(
            "개별 취약점 목록 — {id, severity, summary, fixed_versions, modified}. "
            "``vulnerability_count`` 와 **같은 단위**이며 잘라내지 않는다. 예전에는 5건만 "
            "남겨, 26건이라고 적으면서 내역은 5건뿐인 조용한 절단이 있었다."
        ),
    )
    recommended_version: str | None = Field(
        default=None,
        description=(
            "나열된 취약점을 모두 넘어서는 최소 상한 — '이 버전 이상으로 올리세요'. "
            "advisory 중 하나라도 고쳐진 버전을 모르면 **None** 이다(올리면 다 해결된다는 "
            "잘못된 안심을 주지 않는다). 버전 비교가 불가능한 표기도 None."
        ),
    )
    kev_signals: list[dict] = Field(default_factory=list)
    heuristics: dict = Field(default_factory=dict)
    # 캐시·출처 증명
    cache_sources_used: list[str] = Field(default_factory=list)
    cache_freshness: dict = Field(default_factory=dict)
    cache_ecosystems: list[str] = Field(default_factory=list)
    cache_stale_sources: list[str] = Field(default_factory=list)
    source: str = ""
    # ── 기관 레지스트리 연동(선택) ────────────────────────────────────────
    # 연동은 GVSKB_REGISTRY_URL 환경변수 옵트인이며, 미설정 시 아래 값들은
    # 기본값 그대로 남는다(기존 동작과 100% 동일).
    registry_status: Literal[
        "ok", "unreachable", "rejected", "item_failed", "unauthorized", "disabled",
    ] = Field(
        default="disabled",
        description=(
            "레지스트리 조회 결과 상태. unreachable 은 '승인받았다'가 아니라 "
            "'물어보지 못했다' — 두 경우가 화면에서 구분돼야 한다. "
            "rejected 는 서버가 요청 형식을 거부한 것(재시도 무의미)이라 "
            "unreachable(재시도 유효)과 조치가 다르다. "
            "item_failed 는 배치는 성공했으나 **이 항목만** 판정되지 않은 것 — "
            "배치가 200 이라고 모든 항목이 답을 받은 것은 아니다."
        ),
    )
    registry_decision: dict | None = Field(
        default=None,
        description="레지스트리 원본 판정(status·max_env·approved_by·expires_at 등). 미조회 시 None",
    )
    registry_stale: bool = Field(
        default=False,
        description=(
            "이 판정이 보관 기한을 넘긴 로컬 캐시에서 나왔는가. True 여도 **차단은 "
            "그대로 유지된다**(조회 실패가 차단을 풀면 우회 수단이 된다) — 다르게 "
            "다뤄야 하는 것은 판정이 아니라 안내다."
        ),
    )
    engine_version: str | None = None
    checked_at: str | None = Field(default=None, description="검사 시각(UTC ISO)")
    error: str | None = None
    note: str | None = None
    disclaimer: str = ""
