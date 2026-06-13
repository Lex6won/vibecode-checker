---
id: GOV-INTERNAL-NET-001
title_ko: 내부망 IP 또는 사설망 주소가 코드에 포함되어 있습니다
title_en: Internal network address detected
status: approved
source_layer: baseline
sources:
  - publisher: CISA
    document: Secure by Design
  - publisher: 행정안전부
    document: 전자정부 보안 운영 관행
severity: high
decision_default: block
domains: [public-sector-internal]
languages: [python, javascript, java, yaml, toml, shell]
scenarios: [data-pipeline, web-app, agent, llm-integration]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'
  category: public-sector-internal
  why_it_matters: 내부망 주소가 외부 저장소나 AI 도구로 나가면 공격자가 내부 구조를 추정할 수 있습니다.
  public_sector_impact:
    - 내부망 구조 노출
    - 침투 경로 단서 제공
  safe_fix: 내부 주소는 설정 파일 또는 기관 내부 secret/config 관리 체계로 분리하고 외부 전송을 막으세요.
  references:
    - 전자정부 보안 운영 관행
    - CISA Secure by Design
  can_auto_fix: false
---

## 무엇이 위험한가
RFC1918 사설 IP(10/8, 172.16/12, 192.168/16)가 코드·LLM 프롬프트·외부 로그로 흘러가면 행정망 구조에 대한 단서가 됩니다. 공격자는 이를 *내부 정찰의 출발점*으로 활용합니다.

## 안전한 패턴
- IP는 환경별 설정 파일로 분리 (`.env`, `config/local.yaml`)
- 설정 파일은 `.gitignore` 처리
- LLM 호출 전 IP·도메인 제거 미들웨어 통과
