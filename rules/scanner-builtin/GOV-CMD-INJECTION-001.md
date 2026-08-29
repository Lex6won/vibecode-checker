---
id: GOV-CMD-INJECTION-001
title_ko: 외부 입력이 운영체제 명령으로 실행될 수 있습니다
title_en: Possible command injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-17
  - publisher: OWASP
    document: ASVS 5.0
    item: V5
cwe: [CWE-78]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python, data]
scenarios: [web-app, data-pipeline, agent]
related_baseline: [MOIS-49-SW-17]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '\bos\.system\s*\(|subprocess\.(run|Popen|call)\s*\([^)]*shell\s*=\s*True'
  category: gov-secure-coding
  why_it_matters: 파일명이나 요청값이 명령어로 실행되면 서버 파일 삭제, 정보 탈취, 원격 명령 실행으로 이어질 수 있습니다.
  public_sector_impact:
    - 서버 침해
    - 자료 삭제
    - 내부 시스템 장악
  safe_fix: |
    shell=True와 os.system을 피하고 인자를 분리하세요.
    subprocess.run(["cat", "--", filename], shell=False, check=True)
  references:
    - MOIS-49-SW-17
    - CWE-78
    - OWASP ASVS V5
  can_auto_fix: true
examples:
  language: python
  positive:
    - "import os\nos.system(cmd)"
    - "import subprocess\nsubprocess.run(cmd, shell=True)"
  negative:
    - "import subprocess\nsubprocess.run(['ls', '--', path], shell=False)"
    - "x = 42"
---

## 무엇이 위험한가
사용자 입력이 `os.system()` 또는 `shell=True` 호출에 들어가면 임의 명령 실행이 가능합니다. 행정 서버 점유 → 자료 삭제·내부 정찰 → 사고 확산까지 한 번에 이어집니다.

## 안전한 패턴
```python
import subprocess
subprocess.run(["cat", "--", filename], shell=False, check=True)
# 또는 라이브러리 사용 (pathlib, shutil 등)
```
