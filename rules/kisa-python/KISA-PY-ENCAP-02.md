---
id: KISA-PY-ENCAP-02
title_ko: Python 제거되지 않은 디버그 코드 - pdb/breakpoint/IPython.embed 및 app.debug=True
title_en: Active debug code left in Python (pdb/breakpoint/IPython.embed and app.debug=True)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제7절 2. 제거되지 않고 남은 디버그 코드
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-39
cwe: [CWE-489, CWE-215]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, batch-job, data-pipeline]
related_baseline: [MOIS-49-ENCAP-02]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?<![A-Za-z0-9_])pdb\\.set_trace\\s*\\("
    - "(?<![A-Za-z0-9_])ipdb\\.set_trace\\s*\\("
    - "(?<![A-Za-z0-9_])pdb\\.post_mortem\\s*\\("
    - "(?<![A-Za-z0-9_])breakpoint\\s*\\("
    - "(?<![A-Za-z0-9_])IPython\\.embed\\s*\\("
    - "(?<![A-Za-z0-9_])IPython\\.start_ipython\\s*\\("
    - "(?<![A-Za-z0-9_])app\\.debug\\s*=\\s*True\\b"
  category: kisa-secure-coding
  why_it_matters: >-
    `pdb.set_trace()`·`breakpoint()`·`IPython.embed()`가 운영 코드에 남아
    실행되면 *실행 흐름이 멈추고 stdin 입력을 기다립니다*. WSGI/ASGI
    프로세스라면 응답을 영원히 못 주는 좀비 워커가 되고, 컨테이너 환경에서는
    헬스 체크에 걸려 *전체 서비스 재기동 루프*에 빠질 수 있습니다.
    `app.debug = True`(Flask)·`DEBUG=True`(Django)는 임의 파이썬 코드 실행이
    가능한 *대화형 디버거 페이지*를 외부에 노출시킵니다. KISA 가이드 본문은
    "어플리케이션을 배포 전에 반드시 DEBUG 모드를 비활성화 해야 한다"고
    명시합니다.
  public_sector_impact:
    - 운영 워커 정지 (stdin 대기)
    - Flask Werkzeug 디버거를 통한 RCE
    - Django DEBUG 페이지를 통한 settings/SECRET_KEY 노출
  safe_fix: |
    *모든 디버그 트레이스 함수는 배포 전 제거*하세요. CI에서 grep으로 차단
    하는 것이 가장 확실합니다.
        # 운영 코드에서 금지:
        # pdb.set_trace(), breakpoint(), IPython.embed()
    프레임워크 디버그 모드:
        # Flask
        app.debug = False
        app.run(debug=False)
        # Django settings.py
        DEBUG = False
        ALLOWED_HOSTS = ["..."]
    환경 변수 기반 토글로 *운영 환경에서 절대 켜질 수 없도록* 하세요.
        app.debug = os.environ.get("ENV") == "dev"
  references:
    - KISA Python 가이드 제7절 2
    - MOIS-49-ENCAP-02
    - CWE-489, CWE-215
    - https://flask.palletsprojects.com/en/stable/debugging/
    - https://docs.djangoproject.com/en/stable/ref/settings/#debug
  can_auto_fix: false
examples:
  language: python
  positive:
    - "import pdb; pdb.set_trace()"
    - "breakpoint()  # FIXME remove"
    - "app.debug = True"
  negative:
    - "logger.debug('processing %s', item)"
    - "app.debug = False"
    - "if env == 'dev':\n    pass  # debugging hooks disabled in prod"
---

## 무엇이 위험한가
파이썬에는 *최소 4가지* 디버그 트레이스 함수가 있고, 이 중 어느 하나라도 운영 코드에 남아 있으면 *프로세스가 stdin을 기다리며 멈춥니다*.

- `pdb.set_trace()` / `ipdb.set_trace()` — 표준 디버거 진입
- `breakpoint()` (Python 3.7+) — `PYTHONBREAKPOINT` 환경변수로 어떤 디버거든 호출
- `IPython.embed()` — 대화형 IPython 셸 진입
- `pdb.post_mortem()` — 예외 발생 직후 디버거 진입

Flask의 `app.debug = True`(또는 `app.run(debug=True)`)는 *Werkzeug interactive debugger*를 외부에 공개합니다. 이는 단순 정보 노출이 아니라 *원격 임의 Python 코드 실행*을 허용하는 백도어입니다. 2023~2024년 실제 공공기관 침해 사례 중에서도 보고된 패턴입니다.

(주: `DEBUG=True`/`app.run(debug=True)` 자체는 [`KISA-PY-ERR-01`](./KISA-PY-ERR-01.md)에서도 잡습니다 — 본 룰은 디버그 *트레이스 함수*와 Flask의 *속성 할당*(`app.debug = True`)에 집중합니다.)

## 안전한 패턴 (가이드 원문 인용)
```python
# Flask
from flask import Flask
app = Flask(__name__)
app.debug = False                 # 명시적으로 False
# app.run(debug=False)            # 또는 환경 변수 기반
app.debug = os.environ.get("ENV") == "dev"

# Django settings.py
DEBUG = False
ALLOWED_HOSTS = ["service.example.go.kr"]
```

CI 단계 차단 권장:
```bash
# pre-commit 또는 GitHub Action
grep -rnE '\b(pdb\.set_trace|breakpoint|IPython\.embed)\s*\(' src/ && exit 1
```

## False positive 주의
- `logger.debug(...)` 같은 *정상 로깅*은 본 룰이 잡지 않습니다(패턴은 `pdb.set_trace`·`breakpoint`·`IPython.embed` 등 *디버거 진입 함수*만).
- 라이브러리 이름 충돌(예: 사내 `breakpoint` 함수)을 정의했다면 함수 정의 라인은 `(?<![A-Za-z0-9_])breakpoint\(` 패턴에 매칭될 수 있습니다. 의도적이면 `# gvskb: ignore KISA-PY-ENCAP-02`로 억제하세요.
- 본 룰은 운영 차단을 위해 `decision_default: block`입니다. 개발 환경 스캔에서는 `gvskb evaluate --profile public-default-warn`처럼 완화 프로파일로 돌리세요.
- *Django settings*의 `DEBUG = True`는 [`KISA-PY-ERR-01`](./KISA-PY-ERR-01.md)이 잡고 있으므로 본 룰에서는 `app.debug = True`(Flask)만 잡아 중복을 줄였습니다.
