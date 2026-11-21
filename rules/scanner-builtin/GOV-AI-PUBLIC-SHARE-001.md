---
id: GOV-AI-PUBLIC-SHARE-001
title_ko: AI 데모 화면을 인증 없이 외부에 공개 (Gradio share·전체 바인드)
title_en: AI demo UI exposed publicly without authentication (Gradio share / 0.0.0.0)
status: approved
source_layer: baseline
sources:
  - publisher: 국가정보원
    document: 국가·공공기관 AI보안 가이드북 v2.0
    item: M17 AI시스템 경계보안 강화
  - publisher: Gradio
    document: Sharing Your App — Security and File Access
cwe: [CWE-306, CWE-668]
severity: high
decision_default: block
domains: [ai-security]
languages: [python]
scenarios: [llm-integration, web-app]
related_baseline: [NIS-AI-M17]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    # 공개 터널 — 인증을 걸어도 내부 서비스가 외부 주소로 나간다
    - '\.launch\s*\([^)\n]*\bshare\s*=\s*True'
    # 모든 주소에 바인드하면서 auth 없음
    - '\.launch\s*\((?![^)\n]*\bauth\s*=)[^)\n]*\bserver_name\s*=\s*["'']0\.0\.0\.0["''](?![^)\n]*\bauth\s*=)'
  string_arguments: true
  confidence: likely
  category: misconfig
  why_it_matters: >-
    Gradio 의 `share=True` 는 PC 나 서버에서 도는 화면을 외부 중계 서버를 거친 공개 주소로 내보냅니다. 주소를 아는
    사람은 누구나 로그인 없이 그 화면의 기능(내부 문서 검색, 모델 호출, 파일 업로드)을 쓸 수 있고, 내부망에서 돌리던
    도구가 방화벽을 우회해 밖으로 열립니다. `0.0.0.0` 바인드에 인증이 없으면 같은 망의 누구나 접속합니다.
  public_sector_impact:
    - 내부 자료를 다루는 AI 화면이 인터넷에 공개
    - 방화벽·망분리 통제를 우회하는 외부 터널
    - 인증 없는 모델 호출로 비용·자료 유출
  safe_fix: |
    공개 공유를 끄고, 접속 주소를 제한하고, 인증을 거세요.
        demo.launch(server_name="127.0.0.1", auth=(os.environ["UI_USER"], os.environ["UI_PASSWORD"]))
    여러 사람이 써야 하면 기관 인증을 거치는 프록시 뒤에 두세요.
  references:
    - CWE-306 Missing Authentication for Critical Function
    - 국가·공공기관 AI보안 가이드북 M17
  can_auto_fix: false
examples:
  language: python
  positive:
    - "demo.launch(server_name=\"0.0.0.0\", share=True)"
    - "demo.queue().launch(share=True)"
    - "iface.launch(server_name=\"0.0.0.0\", server_port=7860)"
  negative:
    - "demo.launch(server_name=\"127.0.0.1\", auth=(os.environ[\"UI_USER\"], os.environ[\"UI_PASSWORD\"]))"
    - "demo.launch()"
    - "demo.launch(server_name=\"0.0.0.0\", auth=check_login)"
    - "demo.launch(share=False)"
---

## 무엇이 위험한가
개발 편의를 위한 공유 옵션이 내부 도구를 인터넷에 그대로 노출합니다.

## 안전한 패턴
```python
demo.launch(server_name="127.0.0.1", auth=(os.environ["UI_USER"], os.environ["UI_PASSWORD"]))
```
