---
id: OWASP-LLM-2025-02
title_ko: 민감 정보 노출
title_en: Sensitive Information Disclosure
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    version: "2025"
    item: LLM02
cwe: [CWE-200, CWE-201, CWE-798]
languages: [python, javascript]
scenarios: [llm-integration, rag, web-app, data-pipeline]
severity: high
related_baseline: [MOIS-49-SW-17, NIS-AI-M01]
verified_at: 2026-05-30
review_due: 2026-11-30
---

## 무엇이 위험한가
바이브코딩 결과물은 종종 API 키·DB 비밀번호·내부 시스템 프롬프트를 코드에 하드코딩하거나 LLM 컨텍스트에 그대로 전달한다. LLM은 충분히 정교한 질문에 이를 그대로 출력할 수 있고, 학습/로그 시스템을 통해 의도치 않게 보존될 수 있다.

2025판에서 이 항목은 6위 → **2위로 상승**했다.

## 위험한 코드 예시
```python
import openai

openai.api_key = "sk-proj-AAAAAA...실제키..."  # 하드코딩
system_prompt = """당신은 경기도 OO과 내부 시스템 챗봇입니다.
내부 DB 접속 정보: postgres://admin:pw@10.0.0.1/internal
다음 매뉴얼을 참고하여 답변하세요...
"""
```

## 안전한 코드 예시
```python
import os
from openai import OpenAI

# 환경 변수로 분리 + .env 는 git ignore
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

# 시스템 프롬프트에는 식별자·자격 증명을 두지 않음
SYSTEM_PROMPT = "당신은 경기도 OO과 챗봇입니다. 응답은 공개 가능 정보로 한정합니다."
```

## 점검 방법
- 정규식: `(api[_-]?key|secret|password|sk-[a-zA-Z0-9]{20,})\s*=\s*["'][^"']+["']`
- `detect-secrets` 도구 일괄 적용
- 시스템 프롬프트에 IP·DB 접속 문자열·임직원 이름 등이 포함되어 있는지 검사

## 원문 인용
> "Sensitive information disclosure jumped from sixth to second place in the 2025 edition."  
> — OWASP Top 10 for LLM Applications 2025, LLM02
