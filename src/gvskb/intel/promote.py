"""Promote intel cache items into ``proposed`` rule MD files.

Auto-generated rules must never be ``approved``. They sit in
``rules/intel-proposed/`` (or a user-specified directory) until a maintainer
reviews and either promotes them by editing ``status:`` or deletes them.

This module is intentionally narrow: it converts CISA KEV items (CVE-level
intelligence) into rule files that the search layer can surface. Detection
patterns are left empty — these are *advisory* rules, not regex scanners.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable

from .cache import CacheEntry

DEFAULT_PROPOSED_DIR = "rules/intel-proposed"

# IDs we write must be filesystem-safe and stable across runs.
_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_id(cve_id: str) -> str:
    return _SAFE_ID_RE.sub("-", cve_id.strip())


def _severity_from_kev(item: dict) -> str:
    """KEV doesn't expose a numeric CVSS, but every entry is by definition
    actively exploited. We map ransomware-linked to critical, otherwise high.
    """
    if item.get("knownRansomwareCampaignUse", "").lower() == "known":
        return "critical"
    return "high"


def _today_iso() -> str:
    return date.today().isoformat()


def _review_due_iso(days: int = 90) -> str:
    return (datetime.now(timezone.utc).date()).isoformat()  # placeholder, overwritten below


def _due_in_days(days: int) -> str:
    from datetime import timedelta
    return (date.today() + timedelta(days=days)).isoformat()


def render_kev_rule(item: dict) -> tuple[str, str]:
    """Return (rule_id, markdown_text) for a single KEV item.

    Raises ValueError if the item lacks a CVE ID (skipped upstream).
    """
    cve = item.get("cveID", "")
    if not cve:
        raise ValueError("KEV item missing cveID")

    rule_id = f"INTEL-KEV-{_safe_id(cve)}"
    severity = _severity_from_kev(item)
    vendor = item.get("vendorProject", "")
    product = item.get("product", "")
    name = item.get("vulnerabilityName", "")
    short = (item.get("shortDescription") or "").replace("\n", " ").strip()
    action = (item.get("requiredAction") or "").replace("\n", " ").strip()
    date_added = item.get("dateAdded", "")
    due_date = item.get("dueDate", "")
    ransomware = item.get("knownRansomwareCampaignUse", "Unknown")
    cwes = item.get("cwes") or []

    # YAML body — keep escaping simple; descriptions can contain double quotes,
    # so we use single-quoted YAML scalars and escape any embedded single quotes.
    def q(value: str) -> str:
        return value.replace("'", "''")

    frontmatter = (
        "---\n"
        f"id: {rule_id}\n"
        f"title_ko: '{q(f'CISA KEV 등재: {cve} — {vendor} {product}'.strip())}'\n"
        f"title_en: '{q(f'CISA KEV: {cve} — {name}'.strip())}'\n"
        "status: proposed\n"
        "source_layer: realtime\n"
        "sources:\n"
        "  - publisher: CISA\n"
        "    document: Known Exploited Vulnerabilities Catalog\n"
        f"    item: '{q(cve)}'\n"
        "    url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n"
        f"cwe: {list(cwes) if cwes else []}\n"
        f"severity: {severity}\n"
        "domains: [vulnerability-intel, supply-chain]\n"
        "scenarios: [dependency-scan, sbom-review]\n"
        f"verified_at: {_today_iso()}\n"
        f"review_due: {_due_in_days(90)}\n"
        "detection:\n"
        "  patterns: []\n"
        "  category: vulnerability-intel\n"
        f"  why_it_matters: 'CISA가 실제 악용을 확인한 취약점입니다. {q(vendor)} {q(product)} 사용 여부를 SBOM·의존성 매니페스트로 확인하고, 패치되지 않았다면 우선 차단/격리 대상입니다.'\n"
        "  public_sector_impact:\n"
        "    - 행정 시스템 침해 가능성\n"
        "    - 공공 서비스 중단 위험\n"
    )
    if ransomware.lower() == "known":
        frontmatter += "    - 랜섬웨어 캠페인 악용 사례 확인됨\n"

    frontmatter += (
        f"  safe_fix: |\n"
        f"    CISA 권고 조치: {q(action) if action else '벤더 공지 패치 적용 + 영향 자산 격리'}\n"
        f"    공공기관 권고 만료일(미국 기준): {due_date or '미지정'}\n"
        f"  references:\n"
        f"    - {cve}\n"
        f"    - CISA KEV ({date_added})\n"
        f"  can_auto_fix: false\n"
        "---\n"
    )

    body = (
        f"\n## 무엇이 위험한가\n\n"
        f"- **CVE**: {cve}\n"
        f"- **벤더 / 제품**: {vendor} {product}\n"
        f"- **취약점 이름**: {name}\n"
        f"- **KEV 등재일**: {date_added}\n"
        f"- **랜섬웨어 악용**: {ransomware}\n"
        f"\n{short}\n"
        f"\n## 권고 조치\n\n"
        f"- CISA 요구 조치: {action or '벤더 공지에 따른 패치 또는 격리'}\n"
        f"- 미국 기관 기준 조치 마감: {due_date or '미지정'}\n"
        f"\n## 본 룰의 상태\n\n"
        f"이 룰은 `gvskb update-intel --promote`로 자동 생성된 *proposed* 상태입니다.\n"
        f"공공기관 정책에 따라 운영 반영 전 보안 담당자가 다음을 확인해야 합니다.\n\n"
        f"1. 본 CVE가 영향을 미치는 자산이 있는지 SBOM·의존성 매니페스트로 점검\n"
        f"2. 벤더 패치 공지 또는 대체 통제(WAF·격리)\n"
        f"3. 룰 본문 보완 후 `status: approved`로 승격\n"
    )
    return rule_id, frontmatter + body


@dataclass
class PromoteResult:
    created: list[str]
    skipped_existing: list[str]
    skipped_no_cve: int
    rules_dir: str

    def to_dict(self) -> dict:
        return {
            "created_count": len(self.created),
            "skipped_existing_count": len(self.skipped_existing),
            "skipped_no_cve": self.skipped_no_cve,
            "rules_dir": self.rules_dir,
            "created": self.created[:20],  # cap for compact output
        }


def promote_kev_to_rules(
    entry: CacheEntry,
    rules_dir: Path,
    *,
    overwrite: bool = False,
    limit: int | None = None,
) -> PromoteResult:
    """Write one proposed MD per KEV item. Existing files are skipped by default."""
    if entry.source_id != "cisa-kev":
        raise ValueError(f"promote_kev_to_rules expects cisa-kev cache, got {entry.source_id}")

    rules_dir.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    skipped_existing: list[str] = []
    skipped_no_cve = 0

    items: Iterable[dict] = entry.items
    if limit is not None:
        items = list(items)[:limit]

    for item in items:
        cve = item.get("cveID", "")
        if not cve:
            skipped_no_cve += 1
            continue
        try:
            rule_id, md = render_kev_rule(item)
        except ValueError:
            skipped_no_cve += 1
            continue
        target = rules_dir / f"{rule_id}.md"
        if target.exists() and not overwrite:
            skipped_existing.append(rule_id)
            continue
        target.write_text(md, encoding="utf-8")
        created.append(rule_id)

    return PromoteResult(
        created=created,
        skipped_existing=skipped_existing,
        skipped_no_cve=skipped_no_cve,
        rules_dir=str(rules_dir),
    )
