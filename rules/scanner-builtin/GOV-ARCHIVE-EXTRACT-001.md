---
id: GOV-ARCHIVE-EXTRACT-001
title_ko: tar 압축을 검사 없이 전체 풀기 - 압축 속 경로로 임의 위치에 파일 쓰기
title_en: tar archive extracted without a member filter (path traversal on extraction)
status: approved
source_layer: baseline
sources:
  - publisher: Python Software Foundation
    document: tarfile — Extraction filters
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: 경로 조작 및 자원 삽입
cwe: [CWE-22]
severity: medium
decision_default: warn
domains: [web-appsec]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [CWE-22]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    # tarfile 로 연 것을 filter 없이 전체 풀기 (열기와 풀기가 몇 줄 떨어져 있어도)
    # 열기 뒤 **처음 나오는** extractall 만 본다 — 안전하게 푼 tar 뒤의 zip 풀기까지 건너가 잡지 않게.
    - 'tarfile\.open\s*\((?:(?!\.extractall\s*\()[\s\S]){0,400}?\.extractall\s*\((?![^)\n]*\bfilter\s*=)'
    # 형식을 가리지 않는 풀기 — tar 가 들어오면 같은 문제
    - 'shutil\.unpack_archive\s*\((?![^)\n]*\bfilter\s*=)'
  confidence: likely
  category: path-traversal
  why_it_matters: >-
    tar 안의 파일 이름에는 `../` 나 절대 경로, 심볼릭 링크가 들어갈 수 있습니다. `extractall()` 을 필터 없이 부르면
    파이썬 3.11 이하는 그대로 따라가 압축을 푸는 폴더 밖의 파일을 덮어씁니다(3.12·3.13 은 경고만 내고 같은 동작,
    3.14 부터 기본 차단). 올린 압축이나 내려받은 모델·데이터 묶음을 풀 때 서버 파일이 바뀔 수 있습니다.
    zip 은 표준 `zipfile` 이 경로를 정리하므로 이 룰의 대상이 아닙니다.
  public_sector_impact:
    - 업로드한 압축으로 서버의 설정·코드 파일 덮어쓰기
    - 내려받은 모델·데이터 묶음을 통한 침해
  safe_fix: |
    필터를 명시하세요(파이썬 3.12 이상, 3.8~3.11 은 보안 패치 판).
        with tarfile.open(path) as tar:
            tar.extractall(dest, filter="data")
    필터를 쓸 수 없으면 멤버마다 풀릴 경로가 대상 폴더 안인지 확인한 뒤 푸세요.
  references:
    - CWE-22 Path Traversal
    - CVE-2007-4559
    - PEP 706 Filter for tarfile.extractall
  can_auto_fix: false
examples:
  language: python
  positive:
    - "with tarfile.open(uploaded_path) as tar:\n    tar.extractall(\"/srv/app/models\")"
    - "tar = tarfile.open(fileobj=upload.stream)\ntar.extractall(dest)"
    - "shutil.unpack_archive(saved_path, \"/srv/app/data\")"
  negative:
    - "with tarfile.open(path) as tar:\n    tar.extractall(dest, filter=\"data\")"
    - "with zipfile.ZipFile(upload) as zf:\n    zf.extractall(dest)"
    - "with tarfile.open(path) as tar:\n    tar.extractall(dest, filter=\"data\")\nwith zipfile.ZipFile(upload) as zf:\n    zf.extractall(dest)"
    - "shutil.unpack_archive(saved_path, dest, filter=\"data\")"
---

## 무엇이 위험한가
압축 파일 안의 경로를 믿고 그대로 풀면, 만든 사람이 정한 위치에 파일이 써집니다.

## 안전한 패턴
```python
with tarfile.open(path) as tar:
    tar.extractall(dest, filter="data")
```
