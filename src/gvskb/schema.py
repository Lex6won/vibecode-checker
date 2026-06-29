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
        description="Regex patterns (Python re syntax). Empty list means rule is reference-only.",
    )
    flags: list[Literal["IGNORECASE", "MULTILINE", "DOTALL"]] = Field(default_factory=list)
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
    engine: str = Field(
        default="regex",
        description="Detection engine: regex | python-ast | semgrep | secret | ...",
    )


class ExternalConnection(BaseModel):
    """외부로 데이터를 보낼 수 있는 지점(외부 API 호출 · 설치된 외부 플러그인).

    이것은 *위반(Finding)이 아니라 검토용 인벤토리*입니다 — 사용 자체는 금지가
    아니며, 전송 데이터에 개인정보·행정정보가 포함되는지 보안팀이 확인하도록
    목록화합니다. ``review_level`` 은 우선순위 표시용(warn=⚠ 우선 검토)이며 위험
    건수(finding_count)·CI 게이팅에는 영향을 주지 않습니다.
    """

    kind: Literal["api", "package"]
    target: str = Field(..., description="외부 호스트(api 호출) 또는 패키지명(플러그인)")
    category: str = Field(
        default="other",
        description="ai | analytics | error | payment | messaging | library | other",
    )
    model: str | None = Field(default=None, description="AI 호출의 모델명(리터럴). 변수면 None")
    version: str | None = Field(default=None, description="패키지 버전 또는 API path 버전")
    location: str = Field(default="", description="file:line(api) 또는 매니페스트 파일(package)")
    data_summary: str = Field(default="", description="이용 정보 요약(카탈로그 + 인접 신호)")
    region: str | None = Field(default=None, description="국외 | 국내 | None(미상)")
    pii_adjacent: bool = Field(default=False, description="같은 줄/근접에 개인정보 신호")
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

    event_type: Literal["scan", "block", "warn", "approve_bypass", "reload_rules", "update_intel"]
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
    disclaimer: str = (
        "이 결과는 자동 보안 보조 검토입니다. 공공기관 운영 반영 전에는 기관 보안 담당자의 "
        "정책과 최신 법령·지침을 함께 확인해야 합니다."
    )
