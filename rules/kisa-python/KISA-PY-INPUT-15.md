---
id: KISA-PY-INPUT-15
title_ko: Python 보안 결정에 사용되는 부적절한 입력값 - 쿠키·히든필드·환경변수로 권한 판단
title_en: Reliance on untrusted inputs in a security decision (Python)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 15. 보안기능 결정에 사용되는 부적절한 입력값
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-15
cwe: [CWE-807, CWE-602]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, auth]
related_baseline: [MOIS-49-INPUT-15]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) 쿠키에서 권한/역할/관리자 플래그를 읽음 (Django: request.COOKIES, Flask: request.cookies)
    - "(?i)request\\.COOKIES?\\s*(?:\\[|\\.get\\s*\\()\\s*['\"](?:role|is_admin|admin|grade|level|priv|privilege|auth|permission|isadmin|user_type|user_role)['\"]"
    - "(?i)request\\.cookies\\s*(?:\\[|\\.get\\s*\\()\\s*['\"](?:role|is_admin|admin|grade|level|priv|privilege|auth|permission|isadmin|user_type|user_role)['\"]"
    # 2) request.POST / GET / form / args 에서 권한 플래그를 직접 읽음
    - "(?i)request\\.(?:POST|GET|form|args|values|json)\\s*(?:\\[|\\.get\\s*\\()\\s*['\"](?:is_admin|admin|role|grade|level|privilege|permission|user_type|user_role)['\"]"
    # 3) 히든필드/숨김필드 - hidden 이름으로 받아 권한 결정
    - "(?i)request\\.(?:POST|GET|form|args|values)\\s*(?:\\[|\\.get\\s*\\()\\s*['\"]hidden[_-]?(?:role|admin|grade|priv|permission)"
    # 4) 환경변수로 인증 우회 (os.environ['BYPASS_AUTH'] / DEBUG_USER 등) 후 같은 라인 분기
    - "(?i)os\\.environ\\s*(?:\\[|\\.get\\s*\\()\\s*['\"](?:BYPASS_AUTH|SKIP_AUTH|DEBUG_USER|ADMIN_OVERRIDE|FORCE_ADMIN)"
  category: kisa-secure-coding
  why_it_matters: >-
    쿠키, 히든필드, 환경변수, 클라이언트가 보낸 헤더는 모두 *공격자가 자유롭게 조작*
    할 수 있는 입력값입니다. KISA 가이드 안전하지 않은 예시
    `role = request.COOKIE['role']; if role == 'admin': ...` 한 줄은
    브라우저 개발자도구에서 쿠키 값을 `admin` 으로 바꾸기만 하면 그대로 *관리자 권한*
    이 부여되는 즉시 우회입니다. 가이드 안전 예시는 동일 로직을
    `request.session['role']` 로 *서버 측 세션*에서 가져오도록 바꿉니다.
  public_sector_impact:
    - 쿠키 조작만으로 일반 시민이 *관리자 화면* 접근
    - 히든필드 `is_admin=1` 전송으로 결재 권한 우회
    - 운영 서버에 남은 `BYPASS_AUTH=1` 환경변수로 인증 전면 무력화
  safe_fix: |
    *중요 보안 결정에 사용되는 값은 반드시 서버 측 세션·DB 에서 조회*하세요.
        # Django
        role = request.session['role']        # 클라이언트가 조작 불가
        if role == 'admin':
            password_init_and_sendmail(...)
        # 또는 user 객체에서 직접
        if request.user.is_authenticated and request.user.is_staff:
            ...
    Flask 는 `flask_login.current_user.role`, FastAPI 는
    `Depends(get_current_active_user)` + DB 조회를 사용하고, 쿠키/히든필드/
    환경변수에서 권한 플래그를 *직접* 읽어 분기하지 마세요. JWT 사용 시에도
    서명 검증을 거친 claim 만 신뢰하세요.
  references:
    - KISA Python 가이드 제1절 15
    - MOIS-49-INPUT-15
    - CWE-807, CWE-602
    - OWASP ASVS V4.1 Access Control
    - https://docs.djangoproject.com/en/stable/topics/http/sessions/
  can_auto_fix: false
examples:
  language: python
  positive:
    - "role = request.COOKIES['role']"
    - "if request.POST.get('is_admin') == '1': grant_admin()"
    - "user_role = request.cookies.get('user_role', 'user')"
    - "if os.environ.get('BYPASS_AUTH') == '1': return True"
  negative:
    - "role = request.session['role']"
    - "if request.user.is_authenticated and request.user.is_staff: grant_admin()"
    - "role = User.objects.get(pk=request.user.pk).role"
---

## 무엇이 위험한가
보안 결정(인증·인가·관리자 여부·잔액 한도 등)에 사용되는 값이 *클라이언트가 보낸 입력값* 이면 그 보안 메커니즘은 즉시 무력화됩니다. 쿠키, GET/POST 파라미터, 히든필드, HTTP 헤더, 그리고 운영 중에 남겨진 환경변수는 *모두* 외부에서 조작 가능합니다.

KISA 가이드 안전하지 않은 예시는 매우 흔한 패턴입니다:
```python
role = request.COOKIE['role']
if role == 'admin':
    password_init_and_sendmail(request_id, request_mail)
```
브라우저 개발자도구의 Application 탭에서 `role` 쿠키 값을 `admin` 으로 편집하기만 하면 일반 사용자가 *남의 패스워드를 초기화* 하고 메일까지 발송할 수 있습니다.

공공기관 사례:
- 시민 포털에서 쿠키 `grade=1` 을 `grade=9` 로 바꿔 *관리자 전용 통계* 다운로드
- 결재 시스템 히든필드 `is_approver=1` 을 위조해 권한 없는 부서원이 *결재 승인*
- 운영 점검 후 남은 `BYPASS_AUTH=1` 환경변수가 컨테이너 이미지에 그대로 baked 되어 *프로덕션에서도 인증 우회*

핵심 원칙은 KISA 가이드 그대로입니다 — *상태 정보나 민감한 데이터, 특히 사용자 세션 정보와 같은 중요 정보는 서버에 저장하고 보안 확인 절차도 서버에서 실행* 해야 합니다.

## 안전한 패턴 (가이드 원문 인용)
```python
from django.shortcuts import render

def init_password(request):
    # 세션에서 권한 정보를 가져옴 (서버 측 저장소 — 위변조 불가)
    role = request.session['role']
    request_id = request.POST.get('user_id', '')
    request_mail = request.POST.get('user_email', '')
    # 세션에서 가져온 권한이 관리자인지 비교
    if role == 'admin':
        # 사용자의 패스워드 초기화 및 메일 발송 처리
        password_init_and_sendmail(request_id, request_mail)
        return render(request, '/success.html')
    else:
        return render(request, '/failed.html')
```

더 안전한 방식 — Django `request.user` 직접 활용:
```python
from django.contrib.auth.decorators import login_required, permission_required

@login_required
@permission_required('auth.change_user_password', raise_exception=True)
def init_password(request):
    # 인증/권한은 모두 서버 측 user 객체 + 데코레이터로 강제
    password_init_and_sendmail(
        request.POST.get('user_id', ''),
        request.POST.get('user_email', ''),
    )
    return render(request, '/success.html')
```

## False positive 주의
- 본 룰은 *쿠키/POST/GET/히든필드에서 권한·역할 키워드를 읽는 라인* 을 잡습니다. 같은 값을 단순히 *로깅* 하거나 *UI 표시* 만 하는 경우에도 매칭될 수 있으나, 운영상 권한 판단으로 이어지기 쉬우므로 보수적으로 block 으로 둡니다. 명백히 표시 전용이라면 `# gvskb: ignore KISA-PY-INPUT-15` 로 억제하세요.
- `request.session['role']` 처럼 *세션* 에서 가져오는 경우는 negative 예시 #1 처럼 매칭되지 않습니다.
- `os.environ['BYPASS_AUTH']` 패턴은 CI 테스트 코드에서도 등장할 수 있습니다. 테스트 파일(`tests/`)은 정책에서 제외하거나 명시적으로 ignore 주석을 추가하세요.
- JWT 토큰을 신뢰하기 *전에 서명 검증을 거친 후* claim 을 읽는 경우는 본 룰 대상이 아닙니다 — 단, 서명 검증 없이 `jwt.decode(..., verify=False)` 한 결과를 분기하는 패턴은 별도 룰(JWT 미검증)에 해당합니다.
