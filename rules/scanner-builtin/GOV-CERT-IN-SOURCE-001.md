---
id: GOV-CERT-IN-SOURCE-001
title_ko: 인증서 파일이 소스에 함께 들어 있습니다 - 만료·교체 관리를 확인하세요
title_en: Certificate material bundled with source
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 전자정부 보안 운영 관행
  - publisher: OWASP
    document: ASVS 5.0
    item: V6 Stored Cryptography
cwe: [CWE-312]
severity: low
decision_default: warn
domains: [secret-scanning, public-sector-internal]
languages: []
scenarios: [web-app, data-pipeline]
related_baseline: [GOV-SECRET-PRIVATEKEY-001]
verified_at: 2026-07-31
review_due: 2027-01-31
detection:
  patterns:
    - '-----BEGIN CERTIFICATE-----'
    - '-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----'
  # 인증서 헤더도 패턴 자체가 확증 — 다만 심각도가 낮음(공개 자재)이다.
  confidence: confirmed
  category: secret-scanning
  why_it_matters: >-
    인증서 본문(공개키 부분)은 비밀이 아니므로 **유출 위험은 낮습니다**.
    다만 소스에 함께 두면 두 가지 문제가 생깁니다. 첫째, 만료·교체 시점을
    형상관리가 아닌 배포본이 쥐게 되어 **갱신 누락**이 발생합니다. 둘째,
    같은 폴더에 개인키(.key/.pem)가 함께 있는 경우가 많아 **실수로 개인키까지
    배포·커밋**되기 쉽습니다. 이 발견을 보면 같은 디렉터리에 개인키가 있는지
    반드시 함께 확인하세요.
  public_sector_impact:
    - 인증서 만료 시 서비스 중단(갱신 누락)
    - 같은 경로의 개인키 동반 유출 위험
  safe_fix: |
    인증서·키는 소스가 아니라 **서버의 인증서 저장 경로**에서 관리하세요.

    # 서버 설정에서 경로만 참조
    ssl_certificate     /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;   # 권한 600, root 소유

    - 만료일을 운영 일정에 등록하고 갱신 담당자를 지정하세요.
    - 같은 폴더에 개인키가 있으면 GOV-SECRET-PRIVATEKEY-001 조치를 우선하세요.
  references:
    - CWE-312 Cleartext Storage of Sensitive Information
    - OWASP ASVS V6
  can_auto_fix: false
examples:
  positive:
    - '-----BEGIN CERTIFICATE-----'
  negative:
    - 'ssl_certificate /etc/ssl/certs/server.crt;'
---

## 무엇이 위험한가
인증서 본문은 **공개 자재**라 그 자체로 비밀 유출은 아닙니다. 그래서 개인키(critical)와 달리 이 룰은 **낮음(검토 권고)** 입니다.

실제로 문제가 되는 지점:

| 상황 | 결과 |
|---|---|
| 만료일 관리 주체가 불분명 | 갱신 누락 → 서비스 중단 |
| 개인키가 같은 폴더에 동봉 | 배포·커밋 시 **개인키까지 함께 유출** |
| 배포본마다 인증서 사본 존재 | 교체 시 누락 지점 발생 |

## 확인 순서
1. **같은 디렉터리에 개인키(.key/.pem)가 있는지 먼저 확인** — 있으면 그쪽이 우선 조치 대상입니다
2. 인증서 만료일 확인 및 갱신 일정 등록
3. 소스에서 분리해 서버 인증서 경로로 이전
