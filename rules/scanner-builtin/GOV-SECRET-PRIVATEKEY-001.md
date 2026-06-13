---
id: GOV-SECRET-PRIVATEKEY-001
title_ko: 개인키 또는 인증서 비밀값이 코드에 포함되어 있습니다
title_en: Private key material detected
status: approved
source_layer: baseline
sources:
  - publisher: NIST
    document: SP 800-218 SSDF
  - publisher: Sigstore
    document: Sigstore overview
severity: critical
decision_default: block
domains: [secret-scanning]
languages: [python, javascript, java, shell, yaml]
scenarios: [llm-integration, web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
  category: secret-scanning
  why_it_matters: 개인키가 유출되면 인증서 기반 접속, 배포, 내부 시스템 인증이 바로 침해될 수 있습니다.
  public_sector_impact:
    - 인증 우회
    - 서버 접속 탈취
    - 배포 무결성 훼손
  safe_fix: 개인키를 즉시 폐기·재발급하고, 코드에는 secret manager 참조만 남기세요.
  references:
    - NIST SSDF
    - Sigstore
  can_auto_fix: false
---

## 무엇이 위험한가
PEM 형식의 개인키가 저장소에 들어가면 즉시 폐기·재발급이 필요한 *공급망 사고*입니다. Git history에서 강제 제거(`git filter-repo`)와 함께 인증서 발급기관 통보가 필요할 수 있습니다.

## 안전한 패턴
- 개인키는 HSM·기관 vault·OS keychain에만 보관
- 컨테이너는 mounted secret 또는 환경변수로 주입
- 코드에는 키 파일 *경로*만 두기 (`/etc/ssl/private/...`)
