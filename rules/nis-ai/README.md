# 국정원 AI 보안 가이드북 룰셋

본 디렉토리는 **국정원 국가·공공기관 AI 보안 가이드북 (2025-12-16 final판, v2.0)** 의 위협·대책 *전체*를 기계 가독 룰로 옮긴 것입니다.

> **공식 출처**: [국정원 / 디지털플랫폼정부위원회 AI 보안 가이드북](https://www.aikorea.go.kr/web/board/brdDetail.do?menu_cd=000011&num=144)
>
> **버전 이력**:
> - v1.0 (2023-06): 챗GPT 등 생성형 AI 활용 보안 가이드라인
> - **v2.0 (2025-12-16)**: 국가·공공기관 AI 보안 가이드북 (현재 적용)
>
> ⚠️ 본 디렉토리의 룰은 가이드북의 *재구조화*이며, **공식 가이드북 원문이 우선**합니다. 운영 반영 전에 가이드북 원문 + 기관 보안담당자 검토가 필요합니다.

---

## 가이드북 구성

| 구성 | 항목 수 | 본 디렉토리 prefix | 본 디렉토리 작성 상태 |
|---|---|---|---|
| 위협 (Threats) | **15개** | `NIS-AI-T01` ~ `NIS-AI-T15` | ✅ **15/15 완료** |
| 보안 대책 (Controls) | **30개** | `NIS-AI-M01` ~ `NIS-AI-M30` | ✅ **30/30 완료** |
| 체크리스트 | 57개 (부록 1) | (룰별 분산) | 📝 별도 작업 예정 |

가이드북은 **생성형 AI · 에이전틱 AI · 피지컬 AI** 3 유형을 다룹니다.

> **가이드북에서 다루지 않는 내용** (PDF 직접 인용): "본 가이드북은 AI시스템의 보안성·안전성을 중심으로 다루므로 답변의 *편향, 환각 등에 대해서는 생략*하였다." → 환각·misinformation은 [OWASP-LLM-2025-09](../owasp-llm-2025/LLM09_misinformation.md)로 보완

---

## 위협 (T01~T15) — 전체 15개 작성 완료

| ID | 명칭 | 룰 파일 |
|---|---|---|
| `NIS-AI-T01` | 학습데이터 오염 | [T01_data_poisoning.md](T01_data_poisoning.md) |
| `NIS-AI-T02` | 비인가 민감정보 학습 | [T02_unauthorized_sensitive_data_learning.md](T02_unauthorized_sensitive_data_learning.md) |
| `NIS-AI-T03` | AI 백도어 삽입 | [T03_ai_backdoor_insertion.md](T03_ai_backdoor_insertion.md) |
| `NIS-AI-T04` | 학습데이터 추출 | [T04_training_data_extraction.md](T04_training_data_extraction.md) |
| `NIS-AI-T05` | 학습데이터 비인가자 접근 | [T05_unauthorized_training_data_access.md](T05_unauthorized_training_data_access.md) |
| `NIS-AI-T06` | AI모델 추출 | [T06_ai_model_extraction.md](T06_ai_model_extraction.md) |
| `NIS-AI-T07` | 민감정보 입력·유출 | [T07_sensitive_data_input_and_leakage.md](T07_sensitive_data_input_and_leakage.md) |
| `NIS-AI-T08` | 프롬프트 인젝션 | [T08_prompt_injection.md](T08_prompt_injection.md) |
| `NIS-AI-T09` | 회피 공격 | [T09_evasion_attack.md](T09_evasion_attack.md) |
| `NIS-AI-T10` | 통신구간 공격 | [T10_communication_channel_attack.md](T10_communication_channel_attack.md) |
| `NIS-AI-T11` | 서비스 거부 공격 | [T11_denial_of_service.md](T11_denial_of_service.md) |
| `NIS-AI-T12` | 사고·이상행위 모니터링 체계 부재 | [T12_monitoring_absence.md](T12_monitoring_absence.md) |
| `NIS-AI-T13` | AI시스템 권한관리 부실 | [T13_ai_privilege_mismanagement.md](T13_ai_privilege_mismanagement.md) |
| `NIS-AI-T14` | 공급망 공격 | [T14_supply_chain_attack.md](T14_supply_chain_attack.md) |
| `NIS-AI-T15` | 용역업체 보안관리 부실 | [T15_vendor_security_mismanagement.md](T15_vendor_security_mismanagement.md) |

---

## 대책 (M01~M30) — 전체 30개 작성 완료

| ID | 명칭 | 룰 파일 |
|---|---|---|
| `NIS-AI-M01` | 신뢰할 수 있는 출처의 데이터 활용 | [M01_trusted_data_source.md](M01_trusted_data_source.md) |
| `NIS-AI-M02` | 신뢰할 수 있는 출처의 AI모델·라이브러리 활용 | [M02_trusted_model_and_library.md](M02_trusted_model_and_library.md) |
| `NIS-AI-M03` | 데이터 검사 | [M03_data_inspection.md](M03_data_inspection.md) |
| `NIS-AI-M04` | 데이터 암호화 | [M04_data_encryption.md](M04_data_encryption.md) |
| `NIS-AI-M05` | 데이터 접근통제 | [M05_data_access_control.md](M05_data_access_control.md) |
| `NIS-AI-M06` | 민감정보 사용 사전 승인 | [M06_sensitive_data_prior_approval.md](M06_sensitive_data_prior_approval.md) |
| `NIS-AI-M07` | 보안등급에 맞는 학습데이터 구성·활용 | [M07_classified_training_data_structure.md](M07_classified_training_data_structure.md) |
| `NIS-AI-M08` | 데이터 로깅·모니터링 | [M08_data_logging_and_monitoring.md](M08_data_logging_and_monitoring.md) |
| `NIS-AI-M09` | AI시스템 로깅·모니터링 | [M09_logging_and_monitoring.md](M09_logging_and_monitoring.md) |
| `NIS-AI-M10` | 데이터 수집 명세서 관리 | [M10_data_collection_manifest.md](M10_data_collection_manifest.md) |
| `NIS-AI-M11` | AI시스템 구성요소 명세서 관리 (AIBOM) | [M11_ai_components_manifest.md](M11_ai_components_manifest.md) |
| `NIS-AI-M12` | AI시스템 구성요소 무결성 검증 | [M12_components_integrity_verification.md](M12_components_integrity_verification.md) |
| `NIS-AI-M13` | 입·출력 필터링 | [M13_input_output_filtering.md](M13_input_output_filtering.md) |
| `NIS-AI-M14` | 입력 길이·형식 제한 | [M14_input_length_format_limit.md](M14_input_length_format_limit.md) |
| `NIS-AI-M15` | 가드레일 다중화 | [M15_guardrail_multiplication.md](M15_guardrail_multiplication.md) |
| `NIS-AI-M16` | AI모델 구조·가중치 유출 방지 | [M16_model_structure_protection.md](M16_model_structure_protection.md) |
| `NIS-AI-M17` | AI시스템 경계보안 강화 | [M17_perimeter_security.md](M17_perimeter_security.md) |
| `NIS-AI-M18` | AI시스템 통신구간 보호 | [M18_communication_protection.md](M18_communication_protection.md) |
| `NIS-AI-M19` | 과도한 권한 부여 제한 | [M19_excessive_privilege_restriction.md](M19_excessive_privilege_restriction.md) |
| `NIS-AI-M20` | 민감 명령 승인 절차 마련 | [M20_sensitive_command_approval.md](M20_sensitive_command_approval.md) |
| `NIS-AI-M21` | 비상대응 체계 마련 | [M21_emergency_response.md](M21_emergency_response.md) |
| `NIS-AI-M22` | 설명 가능한 AI 구성 | [M22_explainable_ai.md](M22_explainable_ai.md) |
| `NIS-AI-M23` | AI모델 대상 적대적 모의공격 수행 | [M23_adversarial_simulation.md](M23_adversarial_simulation.md) |
| `NIS-AI-M24` | AI모델에 적대적 공격유형 학습 | [M24_adversarial_training.md](M24_adversarial_training.md) |
| `NIS-AI-M25` | AI시스템 구성요소 취약점 점검·보안업데이트 | [M25_vulnerability_patching.md](M25_vulnerability_patching.md) |
| `NIS-AI-M26` | AI모델 복구 | [M26_model_recovery.md](M26_model_recovery.md) |
| `NIS-AI-M27` | 요청 속도 제한 | [M27_rate_limit.md](M27_rate_limit.md) |
| `NIS-AI-M28` | AI시스템 구성요소 완전 삭제 | [M28_complete_deletion.md](M28_complete_deletion.md) |
| `NIS-AI-M29` | 용역업체 보안관리 | [M29_vendor_management.md](M29_vendor_management.md) |
| `NIS-AI-M30` | 사용자 교육 및 보안정책 수립 | [M30_user_education_and_policy.md](M30_user_education_and_policy.md) |

---

## 위협 ↔ 대책 매트릭스 (가이드북 표 4 인용)

각 룰의 `related_baseline` 필드로 *crosswalk 그래프*가 자동 구성됩니다. 핵심 매핑 예시:

| 위협 | 주요 대책 |
|---|---|
| T01 학습데이터 오염 | M01, M03 |
| T03 AI 백도어 삽입 | M02, M11, M12 |
| T07 민감정보 입력·유출 | M13, M30 |
| T08 프롬프트 인젝션 | M13, M14, M15, M23, M24 |
| T11 서비스 거부 공격 | M14, M27 |
| T13 AI시스템 권한관리 부실 | M19, M20, M21 |
| T14 공급망 공격 | M02, M11, M12, M25 |

전체 매트릭스는 각 룰 파일의 `related_baseline` 합집합으로 자동 계산됩니다.

---

## AI 시스템 수명주기별 적용

가이드북은 5단계 수명주기에서 각 위협·대책의 적용 시점을 명시합니다:

| 단계 | 핵심 대책 |
|---|---|
| ① 데이터 수집 | M01, M03, M06, M10 |
| ② AI 학습 | M02, M04, M05, M07 |
| ③ AI시스템 구축 | M11, M12, M17 |
| ④ AI시스템 운영 | M08, M09, M13~M21, M25, M27 |
| ⑤ AI시스템 폐기 | M28 |
| (전 수명주기) | M22, M23, M24, M26, M29, M30 |

---

## 구축 유형별 중점 대책 (가이드북 제2장 제2절)

| 구축 유형 | 중점 대책 |
|---|---|
| **내부망 전용 AI시스템** | M07, M09, M17, M19, M20, M21 |
| **내부업무용 AI시스템 + 외부망 연계** | M01, M03, M07, M12, M17 |
| **대민서비스용 AI시스템 + 내부망 연계** | (별도 작업) |

세부 구축 유형별 대책은 가이드북 원문 + 본 디렉토리 향후 보완 작업으로 추가됩니다.

---

## 갱신 주기

- **가이드북**: 추정 1~2년 (2023-06 v1.0 → 2025-12 v2.0 → 차기 미정)
- **본 디렉토리**: 가이드북 갱신 시 즉시 반영
- 출처 메타: [config/security_sources.yaml](../../config/security_sources.yaml) `KR-NIS-AI-SECURITY-GUIDE`
