---
id: NIS-AI-M17
title_ko: AI시스템 경계보안 강화
title_en: AI System Perimeter Security
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M17
severity: high
decision_default: warn
domains: [llm-appsec, public-sector-internal]
languages: [yaml]
scenarios: [llm-integration]
related_baseline: [GOV-INTERNAL-NET-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
정보보호제품을 활용하여 *접근통제*. AI시스템 전용 네트워크 구성, 방화벽·망연계장치 등으로 *접근통제*. DMZ·중계서버 활용하여 *직접 접근* 차단. **내부망 전용 AI시스템은 인터넷과 물리적·논리적 분리**. 외부 데이터 반입 시 망연계시스템 + 악성코드 검사.

## 안전한 패턴
- AI 시스템 전용 VLAN
- DMZ 경유 외에 직접 접근 차단
- 내부망/외부망 분리 (망분리 정책)
- 외부 데이터 반입은 *망연계 시스템*만

## 공공 환경 적용
- 본 리포 [policies/public_default_strict.yaml](../../policies/public_default_strict.yaml) `network_policy.default_mode: online-restricted`

## 매핑
- 본 리포 [GOV-INTERNAL-NET-001](../scanner-builtin/GOV-INTERNAL-NET-001.md) — 실시간 검사 가능
- 「국가 정보보안 기본지침」 망분리 규정
