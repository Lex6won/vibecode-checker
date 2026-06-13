# eval_corpus — gvskb 독립 벤치마크 코퍼스

> ⚠️ **경고: 이 폴더의 모든 코드는 의도적으로 취약하게 작성된 테스트 샘플입니다.**
> - 모든 API 키·토큰·비밀번호·주민등록번호·전화번호는 **가짜(FAKE) 테스트 값**입니다 (실제 자격증명·개인정보 아님).
> - 주민등록번호는 형식만 맞춘 임의 값이며 유효 검증번호가 아닙니다.
> - **이 코드를 설치·실행·배포하지 마십시오.** 오직 gvskb 탐지 성능 측정 용도입니다.

## 목적

협의자료의 "자체 평가 P/R/F1 100%"는 각 룰에 내장된 예제를 룰 자신에게 되먹인 **자기참조 평가**입니다.
이 코퍼스는 그와 **독립적인** ground truth를 제공하여, 실제 바이브코딩 산출물에 대한 탐지율·오탐율을 정량 측정합니다.

## 구성

| 디렉터리 | 언어 | 시나리오 | 시드 |
|---|---|---|---|
| `projects/a_minwon_flask/` | Python | Flask 민원 조회 앱 | SQLi·시크릿·RRN·MD5·경로조작·debug |
| `projects/b_express_api/` | JavaScript | Express API | eval·XSS·시크릿·명령주입·new Function |
| `projects/c_static_page/` | HTML+JS | 정적 안내 페이지 | DOM XSS·innerHTML·RRN |
| `projects/d_llm_chatbot/` | Python | LLM 챗봇/RAG | 프롬프트 인젝션·시크릿·exec(LLM출력)·pickle·RRN·verify=False |
| `projects/e_data_pipeline/` | Python | pandas 파이프라인 | read_pickle·RRN/전화·os.system |
| `projects/f_dependencies/` | manifest | 취약 의존성 | 취약버전·typosquat |
| `projects/g_clean_twins/` | Py/JS | **음성 대조군**(안전 코드) | 오탐 측정 |
| `projects/h_hard_variants/` | Py/JS/Java | **경계 프로브** | alias/난독화/JWT/Java — 미탐 한계 측정 |

`manifest.yaml` = ground truth 라벨. `scripts/run_benchmark.py` 로 실행하면 `results/` 에 결과 생성.

## 재현

```bash
# 저장소 루트에서
GVSKB_MODE=offline PYTHONPATH=src python scripts/run_benchmark.py
```

`results/` 는 .gitignore 처리(매 실행 산출물). 코퍼스·manifest·README 만 버전관리됩니다.
