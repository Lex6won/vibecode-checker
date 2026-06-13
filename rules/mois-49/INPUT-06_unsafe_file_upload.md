---
id: MOIS-49-INPUT-06
title_ko: 위험한 형식 파일 업로드
title_en: Unsafe File Upload
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-6
cwe: [CWE-434]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
업로드된 파일이 *실행 가능한 형식*(`.jsp`, `.php`, `.exe`)이거나 *내용 검증* 없이 저장되어 웹쉘 업로드·임의 코드 실행.

## 안전한 패턴
- 파일 확장자 화이트리스트
- MIME 검증 + 매직 넘버 확인
- 업로드 디렉토리에 실행 권한 제거
- 파일명 *재명명* (UUID)
- 안티바이러스 스캔

## 매핑
- OWASP ASVS V12 (File Upload), CWE-434
