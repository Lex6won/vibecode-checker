---
id: KISA-PY-ENCAP-01
title_ko: Python 잘못된 세션에 의한 데이터 노출 - 클래스 변수에 request 데이터 대입
title_en: Wrong-session data exposure in Python (class variable assigned from request data)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제6절 1. 잘못된 세션에 의한 데이터 정보 노출
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-38
cwe: [CWE-488, CWE-543]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app]
related_baseline: [MOIS-49-ENCAP-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) 클래스 변수에 request.* 대입 — `ClassName.attr = request.POST.get(...)`
    #    self. 시작이 아닌 점이 핵심 신호. 첫 토큰이 대문자로 시작하는 식별자.
    - "^\\s*[A-Z][A-Za-z0-9_]*\\.[a-z_][A-Za-z0-9_]*\\s*=\\s*request\\."
    # 2) 클래스 변수에 사용자 입력 컨테이너 대입 (Flask: session/request.args 등)
    - "^\\s*[A-Z][A-Za-z0-9_]*\\.[a-z_][A-Za-z0-9_]*\\s*=\\s*session\\["
    # 3) 클래스 본문에서 mutable 컨테이너 = 공유 가능한 default 위험 신호 (ClassName.attr = [] / {} 직후 request 대입)
    - "^\\s*[A-Z][A-Za-z0-9_]*\\.[a-z_][A-Za-z0-9_]*\\s*=\\s*request\\.(?:POST|GET|args|form|json|values)\\.get\\s*\\("
  category: kisa-secure-coding
  why_it_matters: >-
    파이썬 *클래스 변수*는 인스턴스가 아니라 *클래스 객체 자체*에 붙어 있어
    *모든 인스턴스·모든 스레드가 공유*합니다. WSGI/ASGI 서버는 같은 워커
    안에서 여러 요청을 다중 스레드로 처리하므로, 다음 코드 한 줄이 *세션
    교차 누출* 을 만듭니다.
        class UserDescription:
            user_name = ''
            def show(self, request):
                UserDescription.user_name = request.POST.get('name', '')
                # 다른 스레드에서 같은 시점에 self.user_name 읽으면 *남의 이름*
    KISA 가이드는 *공유가 금지된 변수는 인스턴스 변수(self.x)* 로 선언하라고
    명시합니다. 동시에 싱글톤 패턴에서도 동일 위험이 있어 CWE-543(Use of
    Singleton Without Synchronization) 이 함께 적용됩니다.
  public_sector_impact:
    - 행정 포털에서 *민원인 A가 B의 이름·주민번호* 를 화면에서 봄
    - 결재 시스템에서 *같은 워커의 다른 사용자 세션 데이터* 가 응답에 섞임
    - 감사 로그상으로 "정상 응답" 으로 기록되어 *원인 추적이 매우 어려움*
  safe_fix: |
    KISA 가이드 안전 예시: 공유 금지 데이터는 *인스턴스 변수(`self.x`)* 로
    선언합니다.
        class UserDescription:
            def show_user_profile(self, request):
                # 인스턴스 변수 -> 스레드/세션 간 공유되지 않음
                self.user_name = request.POST.get('name', '')
                self.user_profile = self.get_user_profile()
                return render(request, 'profile.html',
                              {'profile': self.user_profile})

            def get_user_profile(self):
                return self.get_user_description(self.user_name)

    싱글톤·전역 캐시가 *반드시 필요*하다면:
    1) `threading.local()` 로 스레드 단위 격리,
    2) 또는 `asyncio.Lock` / `threading.RLock` 으로 *명시적 동기화*,
    3) 진짜 세션 데이터는 *Django session framework* / Flask `session` /
       FastAPI `Request.state` 로 *프레임워크 세션 저장소* 사용.
    `ClassName.attr = ...` 같은 클래스 변수 대입은 *상수* 외에는 금지하세요.
  references:
    - KISA Python 가이드 제6절 1
    - MOIS-49-ENCAP-01
    - CWE-488, CWE-543
    - https://docs.python.org/3/library/threading.html#thread-local-data
    - https://docs.djangoproject.com/en/stable/topics/http/sessions/
  can_auto_fix: false
examples:
  language: python
  positive:
    - "UserDescription.user_name = request.POST.get('name', '')"
    - "SessionStore.token = request.GET['token']"
    - "Cache.last_user = request.form['user_id']"
  negative:
    - "self.user_name = request.POST.get('name', '')"
    - "request.session['user_name'] = request.POST.get('name', '')"
    - "user_name = request.POST.get('name', '')  # local var, no class-level binding"
---

## 무엇이 위험한가
파이썬 클래스 변수는 *인스턴스가 아니라 클래스 객체 자체*에 붙어 있어, **같은 워커의 모든 스레드·모든 요청이 한 슬롯을 공유**합니다. Django/Flask 의 WSGI 멀티스레드 모드, FastAPI 의 ASGI worker 에서 동시에 두 요청이 들어오면 *한 사용자가 다른 사용자의 데이터를 본다*는 치명적 버그가 발생합니다.

KISA 가이드 본문 예시(취약):
```python
class UserDescription:
    user_name = ''                            # 클래스 변수 (공유)

    def show_user_profile(self, request):
        UserDescription.user_name = request.POST.get('name', '')  # 공유 슬롯에 쓰기
        self.user_profile = self.get_user_profile()
        return render(request, 'profile.html', {'profile': self.user_profile})
```

위 코드의 위험 시나리오:
1. 시민 A가 자기 이름 "홍길동" 으로 요청 -> `UserDescription.user_name = "홍길동"`
2. *동시에* 시민 B가 요청 -> 같은 슬롯이 "김영희" 로 덮어 쓰임
3. A의 `self.get_user_profile()` 이 *김영희* 의 프로필을 읽어 A에게 응답

CWE-488(Exposure of Data Element to Wrong Session) + CWE-543(Singleton Without Synchronization) 이 결합된 *클래식 공공 포털 버그* 입니다. 행정 시스템에서 발생 시 *주민등록번호·결재 내용 교차 노출* 로 직결됩니다.

## 안전한 패턴 (가이드 원문 인용)
```python
from django.shortcuts import render

class UserDescription:

    def get_user_profile(self):
        # 인스턴스 변수만 사용 -> 스레드 간 공유 없음
        result = self.get_user_description(self.user_name)
        return result

    def show_user_profile(self, request):
        # 인스턴스 변수로 선언해 세션 간 공유되지 않도록 한다
        self.user_name = request.POST.get('name', '')
        self.user_profile = self.get_user_profile()
        return render(request, 'profile.html',
                      {'profile': self.user_profile})
```

세션 컨텍스트가 필요한 경우 *프레임워크 세션 저장소* 를 쓰세요:
```python
# Django
request.session['user_name'] = request.POST.get('name', '')

# Flask
from flask import session
session['user_name'] = request.form['name']

# FastAPI
request.state.user_name = body.name
```

전역 공유가 *불가피한* 자원(연결 풀, 캐시)은 `threading.local()` 또는 명시적 락:
```python
import threading
_local = threading.local()

def set_request_user(name):
    _local.user_name = name  # 스레드별 슬롯
```

## False positive 주의
- 본 룰은 *대문자로 시작하는 식별자.소문자속성* 패턴을 잡습니다. 모듈 레벨 전역(`settings.SECRET = request.GET[...]`)은 동일 위험이지만, 일반적인 *모듈명은 소문자* 이므로 일부 케이스를 놓칠 수 있습니다.
- `self.` 로 시작하는 *인스턴스 변수* 대입은 매칭되지 않습니다 (negative #1).
- 라우트 데코레이터가 *클래스 메서드* 인 클래스 기반 뷰(Django CBV, Flask-Classful)는 *클래스 본문 안에서 self 가 아닌 클래스명을 쓰는 실수* 가 자주 일어납니다. 본 룰의 주 타깃입니다.
- 진짜 상수(`Config.DEFAULT_TIMEOUT = 30`) 는 `request.` 가 등장하지 않으므로 매칭되지 않습니다.
- 사내 명명 규약상 *클래스명에 가까운 PascalCase 모듈* 을 쓴다면 false positive 가능. `# gvskb: ignore KISA-PY-ENCAP-01` 로 억제하세요.
