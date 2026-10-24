---
id: GOV-AUTOEXEC-PYTHON-STARTUP-001
title_ko: 파이썬 인터프리터가 기동할 때마다 실행되는 파일(.pth import · sitecustomize.py)이 있습니다
title_en: Python interpreter-startup execution surface (.pth import line, sitecustomize/usercustomize)
status: approved
source_layer: baseline
sources:
  - publisher: Python Software Foundation
    document: Python 표준 라이브러리 — site 모듈
    url: https://docs.python.org/3/library/site.html
  - publisher: Python Packaging Authority
    document: pip — Secure installs
    url: https://pip.pypa.io/en/stable/topics/secure-installs/
cwe: [CWE-829, CWE-506]
severity: critical
decision_default: block
domains: [agent-supply-chain]
languages: [python]
scenarios: [data-pipeline, web-app, agent, llm-integration, package-install]
related_baseline: [KISA-PY-CODE-03, KISA-PY-SEC-15]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # 파일 이름(.pth · sitecustomize.py · usercustomize.py)과 내용을 함께 봐야 한다 — autoexec-surface 엔진.
  # 저장소 트리와 가상환경의 site-packages 를 둘 다 본다. 허용 목록: _virtualenv.pth · distutils-precedence.pth
  # · easy-install.pth · setuptools.pth · *-nspkg.pth · __editable__*.pth (정상 도구가 두는 import 줄).
  patterns: []
  confidence: confirmed
  category: agent-supply-chain
  why_it_matters: >-
    `site` 모듈은 `site-packages` 의 `*.pth` 파일에서 `import` 로 시작하는 줄을 **인터프리터 기동마다
    실행**하고, `sitecustomize.py`·`usercustomize.py` 가 있으면 import 합니다. 어떤 모듈을 import 하지
    않아도, 어떤 스크립트를 돌리든 실행됩니다. 2026-10 PyPI 사고(litellm 1.107.0)는 정확히 이 경로로
    자격증명 수집기와 원격 코드 로더를 심었습니다 — 패키지의 `__init__.py` 를 아무리 봐도 보이지 않습니다.
  public_sector_impact:
    - 가상환경 하나가 감염되면 그 환경의 모든 스크립트·서비스가 감염 상태로 기동
    - 패키지를 지워도 .pth 가 남아 재감염 (pip uninstall 이 지우지 않을 수 있음)
  safe_fix: |
    1. 해당 `.pth`·`sitecustomize.py` 를 **열어 보되 파이썬을 실행하지 마세요**(파이썬을 켜는 순간 그 파일이 돕니다).
       `type`/`cat` 으로 내용을 확인합니다.
    2. 어느 패키지가 설치했는지 확인하세요: `pip show -f <패키지>` 의 파일 목록에 그 .pth 가 있는지.
       패키지 메타데이터(`pyproject.toml` 의 `data-files`)가 `site-packages` 에 직접 쓰는 것은 정상 관행이 아닙니다.
    3. 의심스러우면 **가상환경을 새로 만들고** 고정 버전으로 재설치하세요. 그 환경에서 쓰던 자격증명은 재발급합니다.
    4. 저장소 안에 `.pth`·`sitecustomize.py` 가 커밋돼 있으면 왜 있는지 작성자에게 확인하세요 — 대개 필요 없습니다.
  references:
    - Python site 모듈 문서
    - CWE-506 Embedded Malicious Code
  can_auto_fix: false
examples:
  # 실제 사고의 모듈 이름을 예시에 그대로 쓰지 않는다 — 보안 소프트웨어가 그 문구가 든 파일의 읽기를 막아
  # 룰 파일 자체가 로드되지 않을 수 있다(2026-10-24 이 PC 실측: EINVAL). 모양만 같은 중립 이름을 쓴다.
  positive:
    - "import zz_startup_hook"
  negative:
    - "/home/user/project/src"
---

## 무엇이 위험한가

파이썬은 "코드를 실행하기 전에" 이 파일들을 먼저 실행한다. `python --version` 만 쳐도 돈다.
패키지 소스 검사(`__init__.py`)로는 보이지 않는 자리다.

## 이 발견을 보면 확인할 것

| 확인 | 왜 |
|---|---|
| `.pth` 의 `import` 줄이 가리키는 모듈 | 그 모듈 파일(`cook.py` 등)을 열어 네트워크·파일 수집 여부 확인 |
| `sitecustomize.py` 의 내용 | 백그라운드 스레드·fork·주기적 다운로드가 있으면 격리 |
| 어느 패키지가 설치했나 | `pip show -f` — 패키지 메타데이터 자체가 공격 매개체 |

## 오해하지 마세요

가상환경 도구와 setuptools 가 두는 `_virtualenv.pth`·`distutils-precedence.pth`·`*-nspkg.pth`·
`__editable__*.pth` 는 정상이며 허용 목록에 있다. 경로만 적힌 `.pth`(import 줄 없음)는 잡지 않는다.
