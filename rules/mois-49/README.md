# 행정안전부 소프트웨어 개발보안 가이드 룰셋 (49개 보안약점)

본 디렉토리는 **행정안전부 소프트웨어 개발보안 가이드 (2021-12-29, 5차 개정)** 의 *구현단계 49개 보안약점* 전체를 기계 가독 룰로 옮긴 것입니다.

> **공식 출처**: [행정안전부 SW 개발보안 가이드 (2021-12-29)](https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956)
> **공공데이터포털**: https://www.data.go.kr/data/15049187/fileData.do
>
> **관련 자료**: 행정안전부 SW 보안약점 진단가이드 (2021-11-30), KISA Python 시큐어코딩 가이드 (2023 개정), KISA JavaScript 시큐어코딩 가이드 (2022)

---

## 7개 카테고리 — 49개 항목 전체 작성 완료

| 절 | 카테고리 | prefix | 항목 수 | 작성 상태 |
|---|---|---|---|---|
| 제1절 | 입력데이터 검증 및 표현 | `INPUT-` | **17** | ✅ 17/17 |
| 제2절 | 보안기능 | `SEC-` | **16** | ✅ 16/16 |
| 제3절 | 시간 및 상태 | `TIME-` | 2 | ✅ 2/2 |
| 제4절 | 에러처리 | `ERR-` | 3 | ✅ 3/3 |
| 제5절 | 코드오류 | `CODE-` | 5 | ✅ 5/5 |
| 제6절 | 캡슐화 | `ENCAP-` | 4 | ✅ 4/4 |
| 제7절 | API 오용 | `API-` | 2 | ✅ 2/2 |
| **합계** | | | **49** | ✅ **49/49** |

---

## 제1절. 입력데이터 검증 및 표현 (17)

| ID | 명칭 |
|---|---|
| [INPUT-01](INPUT-01_sql_injection.md) | SQL 삽입 |
| [INPUT-02](INPUT-02_code_injection.md) | 코드 삽입 |
| [INPUT-03](INPUT-03_path_traversal.md) | 경로 조작 및 자원 삽입 |
| [INPUT-04](INPUT-04_xss.md) | 크로스사이트 스크립트 (XSS) |
| [INPUT-05](INPUT-05_os_command_injection.md) | 운영체제 명령어 삽입 |
| [INPUT-06](INPUT-06_unsafe_file_upload.md) | 위험한 형식 파일 업로드 |
| [INPUT-07](INPUT-07_open_redirect.md) | 신뢰되지 않는 URL 주소로 자동접속 연결 |
| [INPUT-08](INPUT-08_xxe.md) | 부적절한 XML 외부 개체 참조 (XXE) |
| [INPUT-09](INPUT-09_xml_injection.md) | XML 삽입 |
| [INPUT-10](INPUT-10_ldap_injection.md) | LDAP 삽입 |
| [INPUT-11](INPUT-11_csrf.md) | 크로스사이트 요청 위조 (CSRF) |
| [INPUT-12](INPUT-12_ssrf.md) | 서버사이드 요청 위조 (SSRF) |
| [INPUT-13](INPUT-13_http_response_splitting.md) | HTTP 응답분할 |
| [INPUT-14](INPUT-14_integer_overflow.md) | 정수형 오버플로우 |
| [INPUT-15](INPUT-15_security_decision_input.md) | 보안기능 결정에 사용되는 부적절한 입력값 |
| [INPUT-16](INPUT-16_buffer_overflow.md) | 메모리 버퍼 오버플로우 |
| [INPUT-17](INPUT-17_format_string.md) | 포맷 스트링 삽입 |

## 제2절. 보안기능 (16)

| ID | 명칭 |
|---|---|
| [SEC-01](SEC-01_missing_authentication.md) | 적절한 인증 없는 중요기능 허용 |
| [SEC-02](SEC-02_improper_authorization.md) | 부적절한 인가 |
| [SEC-03](SEC-03_incorrect_permission.md) | 중요한 자원에 대한 잘못된 권한 설정 |
| [SEC-04](SEC-04_weak_crypto.md) | 취약한 암호화 알고리즘 사용 |
| [SEC-05](SEC-05_unencrypted_sensitive_data.md) | 암호화되지 않은 중요정보 |
| [SEC-06](SEC-06_hardcoded_secrets.md) | 하드코드된 중요정보 |
| [SEC-07](SEC-07_insufficient_key_length.md) | 충분하지 않은 키 길이 사용 |
| [SEC-08](SEC-08_weak_random.md) | 적절하지 않은 난수값 사용 |
| [SEC-09](SEC-09_weak_password.md) | 취약한 비밀번호 허용 |
| [SEC-10](SEC-10_improper_signature_verification.md) | 부적절한 전자서명 확인 |
| [SEC-11](SEC-11_improper_cert_validation.md) | 부적절한 인증서 유효성 검증 |
| [SEC-12](SEC-12_cookie_info_leak.md) | 사용자 하드디스크에 저장되는 쿠키를 통한 정보노출 |
| [SEC-13](SEC-13_comment_with_info.md) | 주석문 안에 포함된 시스템 주요정보 |
| [SEC-14](SEC-14_unsalted_hash.md) | 솔트 없이 일방향 해쉬함수 사용 |
| [SEC-15](SEC-15_no_integrity_check_download.md) | 무결성 검사 없는 코드 다운로드 |
| [SEC-16](SEC-16_no_brute_force_protection.md) | 반복된 인증시도 제한 기능 부재 |

## 제3절. 시간 및 상태 (2)

| ID | 명칭 |
|---|---|
| [TIME-01](TIME-01_toctou_race_condition.md) | 경쟁조건 : 검사시점과 사용시점 (TOCTOU) |
| [TIME-02](TIME-02_infinite_loop.md) | 종료되지 않는 반복문 또는 재귀함수 |

## 제4절. 에러처리 (3)

| ID | 명칭 |
|---|---|
| [ERR-01](ERR-01_error_message_exposure.md) | 오류 메시지 정보노출 |
| [ERR-02](ERR-02_no_error_handling.md) | 오류 상황 대응 부재 |
| [ERR-03](ERR-03_improper_exception.md) | 부적절한 예외 처리 |

## 제5절. 코드오류 (5)

| ID | 명칭 |
|---|---|
| [CODE-01](CODE-01_null_pointer.md) | Null Pointer 역참조 |
| [CODE-02](CODE-02_improper_resource_release.md) | 부적절한 자원 해제 |
| [CODE-03](CODE-03_use_after_free.md) | 해제된 자원 사용 |
| [CODE-04](CODE-04_uninitialized_variable.md) | 초기화되지 않은 변수 사용 |
| [CODE-05](CODE-05_unsafe_deserialization.md) | 신뢰할 수 없는 데이터의 역직렬화 (2021 신규) |

## 제6절. 캡슐화 (4)

| ID | 명칭 |
|---|---|
| [ENCAP-01](ENCAP-01_session_data_leak.md) | 잘못된 세션에 의한 데이터 정보노출 |
| [ENCAP-02](ENCAP-02_leftover_debug.md) | 제거되지 않고 남은 디버그 코드 |
| [ENCAP-03](ENCAP-03_private_array_returned.md) | Public 메소드부터 반환된 Private 배열 |
| [ENCAP-04](ENCAP-04_public_assigned_to_private.md) | Private 배열에 Public 데이터 할당 |

## 제7절. API 오용 (2)

| ID | 명칭 |
|---|---|
| [API-01](API-01_dns_lookup_security.md) | DNS lookup에 의존한 보안결정 |
| [API-02](API-02_vulnerable_api.md) | 취약한 API 사용 |

---

## scanner-builtin 실시간 검사와의 매핑

행안부 49 보안약점 중 *실시간 코드 검사 가능* 항목:

| MOIS-49 항목 | 본 리포 detection 룰 |
|---|---|
| INPUT-01 SQL 삽입 | [GOV-SQL-INJECTION-001](../scanner-builtin/GOV-SQL-INJECTION-001.md) |
| INPUT-02 코드 삽입 | [GOV-CODE-EXEC-001](../scanner-builtin/GOV-CODE-EXEC-001.md) |
| INPUT-04 XSS | [GOV-LLM-OUTPUT-HANDLING-001](../scanner-builtin/GOV-LLM-OUTPUT-HANDLING-001.md) (일부) |
| INPUT-05 OS 명령 삽입 | [GOV-CMD-INJECTION-001](../scanner-builtin/GOV-CMD-INJECTION-001.md) |
| INPUT-12 SSRF | [GOV-INTERNAL-NET-001](../scanner-builtin/GOV-INTERNAL-NET-001.md) (간접) |
| SEC-05 미암호화 중요정보 | [GOV-PII-RRN-001](../scanner-builtin/GOV-PII-RRN-001.md), [GOV-PII-PHONE-001](../scanner-builtin/GOV-PII-PHONE-001.md) |
| SEC-06 하드코드된 중요정보 | [GOV-SECRET-APIKEY-001](../scanner-builtin/GOV-SECRET-APIKEY-001.md), [GOV-SECRET-PRIVATEKEY-001](../scanner-builtin/GOV-SECRET-PRIVATEKEY-001.md) |
| SEC-13 주석 내 주요정보 | (부분) GOV-SECRET-* |

---

## 기존 룰

- [`MOIS-49-SW-17`](SW-17_external_input_validation.md) — 외부 입력값 검증 (INPUT-01, INPUT-05 등의 종합 참조)

향후 SW-17 → 카테고리 룰들로 자연 흡수 또는 별명 유지.

---

## 갱신 주기

- **가이드 본체**: 2021-12-29 5차 개정 이후 **미갱신** (2026-05-31 기준 약 5년)
- **본 디렉토리**: 가이드 개정 시 즉시 반영
- 신규 위협(LLM 공급망·슬롭스쿼팅 등)은 [실시간 인텔리전스](../intel/)와 [국정원 AI 가이드북](../nis-ai/)이 보완
- 출처 메타: [config/security_sources.yaml](../../config/security_sources.yaml) `KR-MOIS-SW-SECURE-CODING`
