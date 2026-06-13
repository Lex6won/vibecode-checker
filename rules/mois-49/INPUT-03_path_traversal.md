---
id: MOIS-49-INPUT-03
title_ko: 경로 조작 및 자원 삽입
title_en: Path Traversal and Resource Injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-3
cwe: [CWE-22, CWE-99]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부 입력으로 *파일 경로·자원 식별자*가 조작되어 비인가 파일에 접근 또는 시스템 자원 노출. `../` 등 path traversal 패턴.

## 안전한 패턴
- 경로 화이트리스트 + `os.path.realpath` 정규화
- 사용자 입력은 *파일명*만 허용 (확장자·경로 분리)
- chroot 또는 컨테이너 격리

## 매핑
- OWASP ASVS V12 (Files and Resources), CWE-22
