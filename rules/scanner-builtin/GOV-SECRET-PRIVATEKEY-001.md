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
# languages 를 비워 **모든 파일 형식**에 적용한다 — 개인키는 대개 코드가 아니라
# `.pem`·`.key` 파일 자체로 존재하며, 언어 필터가 있으면 그 파일을 놓친다.
languages: []
scenarios: [llm-integration, web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    # 알고리즘·암호화 여부·PGP 를 모두 포괄한다(실측: 소스에 동봉된 SSL 개인키).
    - '-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----'
    - 'PuTTY-User-Key-File-\d'
  # PEM 개인키 헤더는 **패턴 자체가 확증**이다(값의 출처를 따질 필요가 없음).
  # 기본값(regex=pattern-only)으로 두면 "직접 확인하세요"가 붙어 과소 표기된다.
  confidence: confirmed
  category: secret-scanning
  why_it_matters: >-
    개인키가 유출되면 인증서 기반 접속·배포·내부 시스템 인증이 바로 침해됩니다.
    특히 기관 도메인 인증서의 개인키가 노출되면 **기관 사칭·중간자 공격**이
    가능해지고, Git 에 한 번이라도 커밋되면 이력에서 지워도 복구할 수 있으므로
    **파일 삭제가 아니라 키 폐기·재발급**이 필요합니다.
  public_sector_impact:
    - 인증 우회
    - 서버 접속 탈취
    - 기관 도메인 사칭·중간자 공격
    - 배포 무결성 훼손
  safe_fix: |
    1) **즉시 조치**: 노출된 키는 이미 신뢰할 수 없습니다 — 인증서 폐기·재발급.
       (파일만 지우는 것으로는 해결되지 않습니다)
    2) 키는 소스 밖 보호된 경로에 두고 권한을 제한하세요
       (Linux: /etc/ssl/private, chmod 600 · Windows: 인증서 저장소).
    3) `.gitignore` 에 `*.pem`, `*.key`, `*.p12`, `*.pfx` 추가.
    4) 이미 커밋됐다면 이력 정리(git filter-repo) + 키 재발급을 함께 하세요.
  references:
    - NIST SSDF
    - Sigstore
  can_auto_fix: false
examples:
  language: python
  positive:
    - "KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----\"\"\""
    - "PUTTY = \"PuTTY-User-Key-File-2: ssh-rsa\""
  negative:
    - "CERT = \"\"\"-----BEGIN CERTIFICATE-----\"\"\""
    - "PUB = \"\"\"-----BEGIN PUBLIC KEY-----\"\"\""
---

## 무엇이 위험한가
PEM 형식의 개인키가 저장소에 들어가면 즉시 폐기·재발급이 필요한 *공급망 사고*입니다. Git history에서 강제 제거(`git filter-repo`)와 함께 인증서 발급기관 통보가 필요할 수 있습니다.

## 안전한 패턴
- 개인키는 HSM·기관 vault·OS keychain에만 보관
- 컨테이너는 mounted secret 또는 환경변수로 주입
- 코드에는 키 파일 *경로*만 두기 (`/etc/ssl/private/...`)
