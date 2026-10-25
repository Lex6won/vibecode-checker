---
id: GOV-AUTHZ-ADMIN-POSTURE-001
title_ko: 관리자·민감 경로에 서버측 인증·인가 검사 근거가 없습니다 (미확인)
title_en: Admin or sensitive route has no server-side authentication/authorization evidence (unverified)
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-1·2 (적절한 인증 없는 중요기능 허용 · 부적절한 인가)
  - publisher: OWASP
    document: ASVS V4 Access Control
cwe: [CWE-306, CWE-285]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, javascript, typescript]
scenarios: [web-app]
related_baseline: [MOIS-49-SEC-01, MOIS-49-SEC-02, KISA-PY-SEC-02, KISA-JS-SEC-02]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # authz-posture 수집기(프로젝트 단위). 관리자·민감 경로(/admin·/manage·/internal·설정·사용자 삭제/역할 변경)의 라우트 핸들러에
  # 거부 분기가 있는 검사(데코레이터·미들웨어·본문 401/403·전역 before_request/use/middleware/dependencies)가 없을 때.
  # 전역 보호 근거가 프로젝트 어디든 있으면 내지 않는다. 쓰기 메서드는 likely, 조회만이면 pattern-only.
  patterns: []
  confidence: likely
  category: access-control
  why_it_matters: >-
    개발보안 가이드는 관리자 동작 등 중요 기능에 인증과 별도 권한 검증을 서버에서 요구합니다. 화면 진입 조건만으로는
    URL 직접 호출을 막지 못하므로, 서버 라우트에 검사 근거가 보이지 않으면 사람이 확인해야 합니다.
  public_sector_impact:
    - 관리자 API 가 토큰 발급·사용자 삭제·설정 변경을 무인증으로 노출
  safe_fix: |
    1. 관리자 라우트에 인증·역할 데코레이터/미들웨어를 붙이거나, 전역 훅(before_request · app.use · middleware)에서
       세션·토큰을 검사하고 실패 시 401/403 으로 거부하세요.
    2. 외부 SSO·리버스 프록시가 보호한다면 그 설정을 제출물에 포함하거나 검토 의견에 적으세요 — 이 발견은 "미확인"입니다.
  references:
    - MOIS-49 SEC-01 · SEC-02
    - CWE-306 Missing Authentication for Critical Function
  can_auto_fix: false
examples:
  positive:
    - "from flask import Blueprint\nbp = Blueprint('admin', __name__)\n@bp.route('/api/admin/users', methods=['POST'])\ndef create_user():\n    return issue()"
  negative:
    - "from flask import Blueprint\nbp = Blueprint('admin', __name__)\n@bp.route('/api/admin/users', methods=['POST'])\n@admin_required\ndef create_user():\n    return issue()"
---

전역 보호(거부 분기가 있는 `before_request` · `app.use(인증 미들웨어)` · Next.js `middleware` · FastAPI `dependencies`)가 있으면 잡지 않는다.
