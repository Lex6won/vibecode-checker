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
# 언어를 제한하지 않는다. 노출 위험은 **언어를 가리지 않는다** — 주민등록번호는
# Go 로 적으나 Rust 로 적으나 주민등록번호다. 예전에는 여기에 목록이 있었고,
# 그 목록에 typescript 가 없어 `.ts`/`.tsx` 에서 이 룰이 **한 번도 돌지 않았다**
# (실측 2026-08-09). 공공 웹앱의 주력이 TypeScript 다. GOV-PII-PHONE-001 에서
# 같은 구멍을 고쳤는데 형제 룰 셋에 그대로 남아 있었다.
languages: []
scenarios: [data-pipeline, web-app, agent, llm-integration]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'
  # 맥락 제외 — 실제 내부 주소가 아니라 **사용자 안내용 예시**인 줄은 취소한다.
  # 실측 오탐: `set /p ip="Enter server IP (e.g. 192.168.1.100): "` (설치 스크립트의 입력 안내)
  exclude_patterns:
    - '(?i)\b(?:e\.?g\.?|예시|예\)|보기|for example|sample|샘플|placeholder|형식|format)\b'
    - '(?i)(?:입력\s*(?:하세요|해주세요|예)|enter\s+.*\bip\b|type\s+.*\bip\b|usage\s*:)'
    - '(?i)0\.0\.0\.0|<[^>]*ip[^>]*>|\{\{?\s*ip\s*\}?\}|xxx\.xxx'
    # IPv4-mapped IPv6 표기(`::ffff:10.0.0.1`). 실제 설정에는 맨몸 IPv4 로 적지
    # 이 표기를 쓰지 않는다 — 소스에 이 모양으로 나오면 주소가 아니라 **표기법을
    # 설명하는 문장**이다. 실측 오탐: `// IPv4-mapped IPv6 (::ffff:10.0.0.1) → …`
    - '::ffff:'
  flags: [IGNORECASE]
  category: public-sector-internal
  why_it_matters: >-
    내부망 주소가 외부 저장소나 AI 도구로 나가면 공격자가 내부 구조를 추정할 수
    있습니다. 다만 **안내 문구의 예시 IP**(예: "Enter server IP (e.g. 192.168.1.100)")
    는 실제 주소가 아니므로 제외합니다 — 이 구분이 없으면 설치 스크립트가
    전부 차단 대상으로 잡힙니다.
  public_sector_impact:
    - 내부망 구조 노출
    - 침투 경로 단서 제공
  safe_fix: 내부 주소는 설정 파일 또는 기관 내부 secret/config 관리 체계로 분리하고 외부 전송을 막으세요.
  references:
    - 전자정부 보안 운영 관행
    - CISA Secure by Design
  can_auto_fix: false
examples:
  language: python
  positive:
    - "DB_HOST = \"10.0.15.22\""
    - "PROXY = \"http://192.168.0.100:8080\""
    - "BACKEND = \"172.16.4.9\""
  negative:
    - "PARTNER = \"172.15.1.1\""
    - "DNS = \"8.8.8.8\""
    - "NETMASK = \"255.255.255.0\""
---

## 무엇이 위험한가
RFC1918 사설 IP(10/8, 172.16/12, 192.168/16)가 코드·LLM 프롬프트·외부 로그로 흘러가면 행정망 구조에 대한 단서가 됩니다. 공격자는 이를 *내부 정찰의 출발점*으로 활용합니다.

## 안전한 패턴
- IP는 환경별 설정 파일로 분리 (`.env`, `config/local.yaml`)
- 설정 파일은 `.gitignore` 처리
- LLM 호출 전 IP·도메인 제거 미들웨어 통과
