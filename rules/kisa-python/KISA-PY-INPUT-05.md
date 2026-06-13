---
id: KISA-PY-INPUT-05
title_ko: Python에서 운영체제 명령어 삽입 위험 - os.system/os.popen/shell=True
title_en: OS command injection in Python (os.system, os.popen, subprocess shell=True)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 5. 운영체제 명령어 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-12
cwe: [CWE-78]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, agent, batch-job]
related_baseline: [MOIS-49-INPUT-05, GOV-CMD-INJECTION-001]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - 'os\.system\s*\('
    - 'os\.popen\s*\('
    - 'subprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True'
    - 'commands\.(?:getoutput|getstatusoutput)\s*\('
  category: kisa-secure-coding
  why_it_matters: >-
    os.system / os.popen / subprocess의 shell=True는 *셸을 통과해 명령을 실행*하므로
    문자열 안의 ;, &, |, $() 같은 메타문자가 추가 명령으로 해석됩니다. 사용자
    입력이 명령에 결합되면 즉시 RCE입니다. 공공기관에서는 민원 처리 자동화,
    파일 변환 배치, AI 에이전트의 도구 호출에서 자주 발견됩니다.
  public_sector_impact:
    - 서버 원격 명령 실행
    - 행정 시스템 침해
    - 자동화 배치 작업의 권한 탈취
  safe_fix: |
    shell을 거치지 않는 형태로 작성하세요.
    subprocess.run(["convert", "--", filename], shell=False, check=True)
    파일 경로/이름에 사용자 입력이 섞이면 pathlib + base dir 검증을 추가하세요.
  references:
    - KISA Python 가이드 제2절 5
    - MOIS-49-INPUT-05
    - CWE-78
  can_auto_fix: false
examples:
  language: python
  positive:
    - "import os\nos.system(cmd)"
    - "import subprocess\nsubprocess.run(cmd, shell=True)"
    - "subprocess.Popen(['sh', '-c', x], shell=True)"
  negative:
    - "import subprocess\nsubprocess.run(['ls', '--', path], shell=False, check=True)"
    - "import subprocess\nsubprocess.run(['cat', filename])"
---

## 무엇이 위험한가
`os.system(f"cp {filename} /tmp/")` 패턴은 *filename*에 `a; rm -rf /tmp/*` 같은 문자열이 들어가면 두 번째 명령으로 해석됩니다. `shell=True`는 같은 위험을 가집니다.

## 안전한 패턴 (가이드 원문 인용)
- `subprocess.run(["program", "arg1", arg2], shell=False)` — 인자 배열 사용
- 외부 입력은 별도 검증 후 사용
- 가능하면 표준 라이브러리(shutil, pathlib) 대체

## 관련
[GOV-CMD-INJECTION-001](../scanner-builtin/GOV-CMD-INJECTION-001.md)이 이미 일부 패턴을 잡습니다. 본 룰은 *commands 모듈, subprocess shell=True 변형* 등을 추가로 보강합니다.
