---
id: KISA-PY-SEC-02
title_ko: Python 부적절한 인가 - 권한 확인 없이 .objects.delete()/update() 수행
title_en: Improper authorization in Python (delete/update without permission check)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 2. 부적절한 인가
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-22-AUTHZ
cwe: [CWE-285, CWE-862, CWE-863]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app]
related_baseline: [MOIS-49-SEC-02]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) Django: .objects.filter(...).delete() / .update() — 권한 검사 없이 사용자 입력으로 식별
    - "\\.objects\\.(?:filter|get)\\s*\\([^)]*(?:id|pk|user_id|owner|owner_id)\\s*=\\s*request\\.(?:GET|POST|args|form|values|params|json)"
    # 2) request.POST 로 식별자 받은 직후 .delete()/.update() (request.* 와 같은 라인)
    - "\\.objects\\.[A-Za-z_]+\\([^)]*\\)\\.(?:delete|update)\\s*\\([^)]*request\\."
    # 3) Flask: 권한 검사 없이 db.session.delete / commit on request.* 식별자
    - "db\\.session\\.delete\\s*\\([^)]*request\\.(?:args|form|values|json)"
    # 4) FastAPI/Flask 라우트가 user_id를 path/query로 받고 즉시 query (decorator 부재 신호는 라인 단위로 어렵지만 같은 라인 패턴은 잡음)
    - "(?<![A-Za-z0-9_])User\\.objects\\.get\\s*\\(\\s*(?:id|pk|username)\\s*=\\s*request\\.(?:GET|POST|args|form|values|params|json)"
  category: kisa-secure-coding
  why_it_matters: >-
    `Content.objects.filter(id=request.POST['content_id']).delete()` 한 줄은
    *누구나 어떤 컨텐츠든 삭제*할 수 있게 만듭니다. KISA 가이드 안전 예시는
    `@login_required` + `@permission_required('content.delete',
    raise_exception=True)` 데코레이터로 *역할 기반* 인가를 강제합니다.
    공공 민원·결재 시스템은 *같은 인증 사용자라도 자기 자원만 다룰 수 있어야*
    하므로, 권한 데코레이터 부재는 곧 IDOR(Insecure Direct Object Reference)
    로 직결됩니다.
  public_sector_impact:
    - IDOR로 타 부서/타 시민 민원·결재 변조·삭제
    - 권한 상승 (일반 사용자가 관리자 액션 호출)
    - 감사 로그 무결성 훼손 (권한 검사 없으면 행위자 식별도 부정확)
  safe_fix: |
    Django: 함수 뷰에는 `@login_required` + `@permission_required(...,
    raise_exception=True)`, 클래스 뷰에는 `PermissionRequiredMixin`을
    적용하세요. *권한 + 소유권*을 둘 다 검사해야 합니다.
        from django.contrib.auth.decorators import login_required, permission_required
        @login_required
        @permission_required('content.delete', raise_exception=True)
        def delete_content(request):
            obj = get_object_or_404(Content, id=request.POST['content_id'])
            if obj.owner != request.user:        # 소유권 추가 검사
                raise PermissionDenied
            obj.delete()
            return render(request, '/success.html')
    Flask: `@login_required` + 명시적 `if g.user.id != obj.owner_id: abort(403)`.
    FastAPI: `Depends(get_current_active_user)` + Pydantic 모델로 권한 명세.
  references:
    - KISA Python 가이드 제2절 2
    - MOIS-49-SEC-02
    - CWE-285, CWE-862, CWE-863
    - OWASP API Top 10 - BOLA (Broken Object Level Authorization)
    - https://docs.djangoproject.com/en/stable/topics/auth/default/#permissions-and-authorization
  can_auto_fix: false
examples:
  language: python
  positive:
    - "Content.objects.filter(id=request.POST.get('content_id', '')).delete()"
    - "User.objects.get(id=request.GET['uid']).delete()"
    - "Content.objects.filter(pk=cid).update(title=request.POST['title'])"
  negative:
    - "obj = get_object_or_404(Content, id=cid, owner=request.user)\nobj.delete()"
    - "if obj.owner == request.user: obj.delete()"
    - "Content.objects.filter(owner=request.user).delete()"
---

## 무엇이 위험한가
부적절한 인가(Improper Authorization)는 *로그인은 되어 있지만, 그 사용자가 해당 자원에 대한 권한이 있는지를 검사하지 않는* 약점입니다. 대표 패턴 두 가지:

1. *권한 데코레이터 부재* — `@permission_required` 없이 `delete_content` 뷰가 노출
2. *소유권 검사 부재* — `Content.objects.filter(id=cid).delete()` 가 사용자 = 소유자인지 검사하지 않음

공격은 단순합니다. 공격자가 자신의 권한으로 로그인한 뒤 `content_id`만 다른 사람 것으로 바꿔 POST 하면 *남의 데이터*를 삭제·수정합니다. 이를 IDOR(Insecure Direct Object Reference) 또는 BOLA(Broken Object Level Authorization)라 부르며 OWASP API Top 10 1위입니다.

공공기관 민원 시스템 사례:
- 시민 A가 자기 민원 상태 조회 페이지에서 `complaint_id=12345`를 `complaint_id=12346`으로 바꾸면 시민 B의 민원 내용을 본다
- 부서장 결재 페이지에서 `doc_id`만 바꿔 다른 부서 결재를 *승인 처리* 한다

## 안전한 패턴 (가이드 원문 인용)
```python
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, render

@login_required
# 가이드 안전 예시: 권한 데코레이터로 RBAC 강제
@permission_required('content.delete', raise_exception=True)
def delete_content(request):
    cid = request.POST.get('content_id', '')
    obj = get_object_or_404(Content, id=cid)
    # 권한이 있어도 소유권은 별도 검사 (IDOR 방지)
    if obj.owner != request.user:
        raise PermissionDenied
    obj.delete()
    return render(request, '/success.html')
```

Flask:
```python
from flask_login import login_required, current_user
from flask import abort

@app.post('/content/delete')
@login_required
def delete():
    obj = Content.query.get_or_404(request.form['cid'])
    if obj.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    db.session.delete(obj); db.session.commit()
```

## False positive 주의
- 본 룰은 *`request.*` 와 `.delete()`/`.update()`/`.get()` 이 같은 라인*에 등장하는 IDOR 신호를 잡습니다. 권한·소유권 검사가 별도 라인에 있다면 본 룰은 *여전히* 매칭될 수 있습니다 — 의도된 보수적 detection입니다. 명백히 안전한 코드라면 `# gvskb: ignore KISA-PY-SEC-02`로 억제하세요.
- `.objects.filter(owner=request.user)` 처럼 *현재 사용자로 필터*하는 패턴은 소유권 검사가 쿼리에 포함되어 있으므로 매칭되지 않습니다 (negative 예시 #3).
- 권한 데코레이터가 *함수 시그니처 위에 별도 라인*으로 붙은 코드는 단일 라인 regex 검출 한계로 본 룰이 인지하지 못합니다. 보수적으로 warn 결정만 내리고 차단(block)으로 올리지 않은 이유입니다.
- 관리 명령 스크립트(`manage.py` 안의 일회성 cleanup)는 HTTP request 컨텍스트가 없으므로 매칭되지 않습니다.
