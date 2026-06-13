# OWASP AI Testing Guide v1 (AITG)

본 디렉토리는 **OWASP AI Testing Guide v1 (2025-11 출시)** 의 4-layer 테스트 프레임워크를 룰화한 것입니다.

> **공식 출처**: [OWASP AI Testing Guide](https://owasp.org/www-project-ai-testing-guide/)
>
> **철학**: "Security is not sufficient; AI Trustworthiness is the real objective." (보안만으로는 부족하다; AI 신뢰성이 진정한 목표이다.)
>
> **정렬**: Google SAIF (Secure AI Framework)와 정렬되어 AI 시스템을 4 layer로 분해, OWASP LLM Top 10의 위협을 *아키텍처 컴포넌트*에 매핑하여 *구체적이고 검증 가능한 시나리오*로 변환.
>
> ⚠️ AITG v1은 *프로세스 가이드*이며 공식 PDF가 우선합니다. 본 디렉토리는 4 layer의 *핵심 테스트 카테고리*만 룰로 표현했습니다. 세부 테스트 케이스는 GitHub 원문 참조.

---

## 4 Layer 구조

OWASP AITG v1은 AI 시스템을 다음 4 계층으로 분해하여 *각 계층의 위험을 독립 테스트*합니다.

| Layer | 한국어 | 본 디렉토리 룰 | 핵심 시험 영역 |
|---|---|---|---|
| `AITG-APP` | AI Application Layer (응용 계층) | [APP_application_layer.md](APP_application_layer.md) | 프롬프트 인젝션, 출력 처리, 사용자 인터페이스 안전성 |
| `AITG-MODEL` | AI Model Layer (모델 계층) | [MODEL_model_layer.md](MODEL_model_layer.md) | 모델 회피, 환각, 편향, 드리프트 |
| `AITG-INFRA` | AI Infrastructure Layer (인프라 계층) | [INFRA_infrastructure_layer.md](INFRA_infrastructure_layer.md) | 공급망, 배포, 비밀 관리, 운영 통제 |
| `AITG-DATA` | AI Data Layer (데이터 계층) | [DATA_data_layer.md](DATA_data_layer.md) | 데이터 오염, 개인정보, 무결성, RAG 인덱스 |

---

## AITG에서 명시하는 일반 실패 유형

> AITG는 *AI 시스템이 실패하는 9가지 일반 유형*을 식별합니다. 이를 위 4 layer에 매핑하여 테스트 케이스를 구성합니다.

1. **적대적 조작** (prompt injection, jailbreak, model evasion) — APP/MODEL
2. **편향성 및 공정성 실패** — MODEL/DATA
3. **민감 정보 유출** — APP/DATA
4. **환각 및 허위 정보 (Misinformation)** — MODEL
5. **데이터/모델 중독 (Poisoning)** — DATA/MODEL
6. **과도한 자율성 또는 안전하지 않은 기능** — APP
7. **사용자 의도 또는 조직 정책과의 미정렬** — APP/MODEL
8. **투명하지 않거나 설명 불가능한 출력** — APP
9. **모델 드리프트 및 시간 경과에 따른 성능 저하** — MODEL/INFRA

---

## OWASP LLM Top 10 2025와의 매핑

AITG는 LLM Top 10의 위협을 *어느 layer*에서 테스트해야 하는지 안내합니다.

| LLM Top 10 항목 | 테스트 Layer |
|---|---|
| LLM01 Prompt Injection | APP |
| LLM02 Sensitive Information Disclosure | APP / DATA |
| LLM03 Supply Chain | INFRA |
| LLM04 Data and Model Poisoning | DATA / MODEL |
| LLM05 Improper Output Handling | APP |
| LLM06 Excessive Agency | APP |
| LLM07 System Prompt Leakage | APP |
| LLM08 Vector and Embedding Weaknesses | DATA |
| LLM09 Misinformation | MODEL |
| LLM10 Unbounded Consumption | INFRA |

---

## 공공 환경 테스트 우선순위

본 PoC의 정책([`policies/public_default_strict.yaml`](../../policies/public_default_strict.yaml))과 가장 강하게 연결되는 layer:

| 우선순위 | Layer | 사유 |
|---|---|---|
| 1 | DATA | 개인정보·민원자료 보호 |
| 2 | APP | 프롬프트 인젝션·출력 처리 |
| 3 | INFRA | 외부 LLM 데이터 전송 통제 |
| 4 | MODEL | 환각·편향 (장기 모니터링) |

---

## 갱신 주기

- **AITG**: 부정기 (v1이 2025-11 첫 출시)
- **본 디렉토리**: AITG 갱신 시 즉시 반영
- 출처 메타: [config/security_sources.yaml](../../config/security_sources.yaml) `OWASP-AI-TESTING-GUIDE`
