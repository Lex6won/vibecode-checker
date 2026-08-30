---
id: KISA-PY-ERR-01
title_ko: Python 오류 메시지 정보 노출 - 예외/traceback을 응답으로 반환
title_en: Detailed exception/traceback returned to user in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제5절 1. 오류 메시지 정보노출
cwe: [CWE-209, CWE-497]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app]
related_baseline: [MOIS-49-ERR-01]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "(?:return|render|jsonify|HttpResponse)\\s*\\([^)]*(?:traceback\\.format_exc|str\\s*\\(\\s*e\\s*\\)|repr\\s*\\(\\s*e\\s*\\))"
    - "(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG)\\s*=\\s*True"
    # (삭제 2026-08-29) `app.run(debug=True)` 는 GOV-FLASK-DEBUG-001(차단·RCE 설명)이
    # 글자 단위로 같은 패턴을 갖는다. 같은 줄 2건을 피한다. Django `DEBUG = True` 는 남긴다.
  category: kisa-secure-coding
  why_it_matters: >-
    `return str(e)` 또는 `jsonify({"error": traceback.format_exc()})`처럼 예외
    상세를 응답으로 돌려주면 DB 구조·파일 경로·서버 버전·라이브러리 버전 등
    내부 정보가 공격자에게 노출됩니다. 운영의 `DEBUG=True`도 같은 위험.
  public_sector_impact:
    - 행정 시스템 내부 구조 노출
    - 후속 공격 정찰 정보 제공
    - 개인정보가 stack frame에 남아있을 위험
  safe_fix: |
    사용자에게는 일반화된 메시지만 보내고, 상세는 *서버 로그*로 분리.
    try:
        ...
    except Exception:
        logger.exception("complaint_save_failed")  # 서버 로그
        return jsonify({"error": "서비스 처리 중 오류가 발생했습니다"}), 500
    운영 환경의 DEBUG/FLASK_DEBUG/DJANGO_DEBUG는 반드시 False.
  references:
    - KISA Python 가이드 제5절 1
    - MOIS-49-ERR-01
    - CWE-209, CWE-497
  can_auto_fix: false
examples:
  language: python
  positive:
    - "return jsonify({\"error\": str(e)}), 500"
    - "DEBUG = True"
  negative:
    - "return jsonify({\"error\": \"처리 중 오류가 발생했습니다\"}), 500"
    - "app.run(host=\"127.0.0.1\")"
---

## 무엇이 위험한가
LLM이 만든 에러 핸들러는 종종 `return str(e)`로 끝납니다. 운영에 그대로 들어가면 SQL 에러로 컬럼 이름이 새고, 파일 에러로 절대 경로가 새고, ImportError로 의존성 버전이 샙니다.

## 안전한 패턴
```python
import logging
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def on_error(e):
    logger.exception("unhandled")
    return jsonify({"error": "서비스 처리 중 오류가 발생했습니다"}), 500

# 운영
if os.environ.get("ENV") != "prod":
    app.debug = False  # 운영은 절대 True 금지
```
