# Changelog

이 프로젝트의 주요 변경 사항을 기록합니다. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전(SemVer)](https://semver.org/lang/ko/)을 따릅니다.

## [0.2.1] - 2026-07-05

### 실시간 인텔 활용 구조 (Added)
- **일일 인텔 번들 자동 게시** — `update-intel` 워크플로가 매일 캐시를 수집한 뒤
  `intel-bundle export`로 검증 가능한 zip을 만들어 **`intel-latest` 릴리스에
  고정 URL로 게시**(+sha256 사이드카, 30일 아티팩트). 이전에는 CI가 받은 캐시가
  러너에서 휘발되어 "매일 갱신"의 산출물이 proposed 룰 PR뿐이었음 — 이제 망분리
  기관은 매일 아침 검증된 반입 번들을 내려받기만 하면 됨.
- **리포트 인텔 기준일 자동 표기** — 오프라인 스캔 시 캐시의 `fetched_at`을 읽어
  `intel_freshness`(피드별 날짜)를 채움. 보안팀이 "며칠 캐시 기준 판정인지"를
  리포트만으로 확인 가능(기존에는 필드·배너만 있고 채우는 코드가 없었음).
- **EPSS·NVD 점수 병기** — 매일 수집만 되고 판정에 쓰이지 않던 epss-recent·
  nvd-recent 캐시를 활용: KEV 등재 취약점 신호에 **EPSS 악용확률(0~1)·백분위**와
  **CVSS 3.1 점수·심각도**를 병기해 보안팀 우선순위 판단 근거 제공.
  테스트 467 → 471.

### 탐지 (Added)
- **LLM 프롬프트 인젝션 탐지**(`GOV-LLM-PROMPT-INJECTION-001`, OWASP LLM01 · 국정원
  AI 가이드 T08) — Python AST taint를 확장해, 문자열 결합(`+`)·f-string으로 **동적
  조립된 프롬프트 변수가 실제 LLM SDK 호출**(OpenAI `chat.completions.create`·
  Anthropic `messages.create`·Gemini `generate_content` 등)에 도달하면 발화합니다.
  SQL taint와 같은 스코프 추적을 재사용하며, **입력을 데이터로만 전달**하거나(역할
  분리 `messages`) 상수 프롬프트·비-LLM `.create()`(ORM)는 발화하지 않아 오탐 0을
  유지합니다. 독립 벤치마크 LLM 카테고리 **0/1 → 1/1**, 종합 recall **96.7% → 100%**
  (30/30), 오탐 0. 테스트 455 → 467.

## [0.2.0] - 2026-07-04

공공기관 실사용 워크플로("공무원 검사 → 보안팀 붙임 제출 → 보안성 검토 → 운영 배포")를
기준으로 탐지·리포트·오프라인 운영·감사를 전면 보강한 릴리스입니다.

### 탐지 (Added)
- **다줄 SQL 삽입 탐지** — Python AST 변수추적(mini-taint): "윗줄에서 쿼리 조립,
  아랫줄에서 `execute()`" 형태(AI 생성 코드의 지배적 패턴)를 탐지. 파라미터 바인딩은
  발화하지 않음(오탐 0 유지).
- **JS/TS 다줄 taint 스캐너**(`js-taint` 엔진) — 의존성 없이 동작. 다줄 조립 후
  `.query()/.execute()`·`eval()/Function()`·`innerHTML` 도달 탐지.
  `DOMPurify.sanitize` 정화·상수 재할당은 발화하지 않음.
- **런타임 룰 status 게이트** — `proposed`(자동 생성) 룰은 `GVSKB_ALLOW_PROPOSED=1`
  없이는 집행되지 않고, `deprecated`는 절대 집행되지 않음. 검색·조회에는 영향 없음.

### 리포트 (Added / Changed)
- **두 독자용 2층 재설계 (두괄식)** — ① 요약층(공무원, 항상 펼침): 문서 헤더 표 →
  **결론 박스(배포 승인=초록 / 미승인=빨강)** → 핵심 숫자 → 조치 가이드(3단계) →
  가장 먼저 할 일 → 검토 범위·한계. ② 상세층(보안팀, 기본 접힘): 발견을 **보안
  분야별**(개인정보·비밀값·주입·웹·암호화·설정·AI·코드안정성)로 묶어 펼치면 위치·
  왜 위험한지·대응 방법·근거를 표시. 모든 상세는 접힘 → **인쇄 시 자동 펼침**.
- **수정 프롬프트 복사 버튼**(인라인 스크립트, 외부 로딩 없음). 공문서 톤을 위해
  장식 이모지를 줄이고 승인/미승인은 색·굵은 글씨로만 구분.
- **검토 범위·한계 고지** 섹션 — "발견 0건 ≠ 안전"을 문서가 스스로 밝힘.
- **배포 판정**(배포 승인/미승인/보류) + 잔여 위험 문구 — 보안팀 승인 근거.
- **개인정보·비밀값 전용 요약** + 같은 줄 다중 룰 묶음("발견 N건 · 고유 위치 M곳").
- **의존성(패키지) 취약점 섹션** — `scan_dependencies`/`--check-deps` 결과 병합.
  판정 불가·파싱 불가는 '안전 아님'으로 명시.
- **외부 연결 인벤토리 보강** — 운영주체·국가(예: `OpenAI(미국)`), 호출 지점 수
  ("외 N곳"), AI 학습·보존 정책 확인 체크리스트. 국외이전 검토는 "누구에게,
  어느 나라로"가 특정되어야 하기 때문.
- **오프라인(망분리) 모드 배너** — 캐시 기준 검사임을 리포트에 정직하게 표기.
- **SARIF 2.1.0 출력**(`--format sarif`, MCP `render_report format="sarif"`) —
  GitHub code scanning·기관 보안도구 연동. 억제된 발견은 표준 `suppressions`로 표기.
- 리포트는 공문의 **'붙임' 문서** 전제 — 결재 헤더·서명란을 넣지 않음(결재는 상위 공문).

### 오프라인(망분리) 운영 (Added / Fixed)
- **인텔 캐시 무결성** — 로드 시 sha256 재검증, 변조·손상 캐시는 자동 무시.
- **신선도 정책** — 기본 30일(`GVSKB_INTEL_MAX_AGE_DAYS`) 초과 캐시의 '이상 없음'은
  `checked_stale`(검토 필요)로 승격. 악성 발견(양성)은 오래돼도 유효.
- **생태계 커버리지** — 캐시가 담은 생태계를 기록. PyPI 전용 캐시로 npm 패키지를
  '깨끗함' 판정하지 않음. KEV 단독 캐시는 '깨끗함'의 근거가 아님.
- **`gvskb intel-bundle export|import`** — 망분리 반입을 sha256 전수 검증되는
  단일 zip 절차로 공식화(검증 실패 시 전체 거부).
- `doctor`·MCP `server_status`에 인텔 캐시 존재·건수·경과일 진단 추가.
- `update-intel --from-cache`가 캐시 나이를 표시하고 신선도 초과 시 WARN.

### 게이트 정확성 (Fixed)
- `scan_dependencies`가 락파일(yarn.lock·poetry.lock 등)에 `verdict:"ok"`를 반환하던
  거짓 통과 제거 — 파싱 전에 감지해 `unparsed`(검토 필요)로 거절.
- 알려진 CVE가 있는 패키지가 `ok`로 통과하던 문제 — `review_required`로 승격.
- `gvskb check-package`가 판정 불가(오프라인 캐시 없음·API 실패)에 exit 0을 내던
  문제 — CI가 "검사 못 함"을 통과로 처리할 수 없도록 비-0 종료.
- 리포트 HTML `class="pill ..."` 속성 미이스케이프(신뢰 불가 리포트 JSON 렌더 시
  저장형 XSS) 봉쇄.
- **인쇄(PDF) 시 접힌 상세 누락** — 최신 Chromium/Edge의 `::details-content` 클리핑
  대응. 발견 상세·수정 프롬프트가 인쇄물에 온전히 포함됨.

### 감사·예외 (Added)
- **JSONL 감사로그**(`GVSKB_AUDIT_DIR` 옵트인) — scan/block/warn/approve_bypass/
  update_intel 이벤트를 월별 파일에 append. 원본 코드·개인정보는 저장하지 않고
  해시·마스킹 증거만 기록.
- **승인된 예외 파일**(`.gvskb-exceptions.yaml`) — 사유·승인자·만료일이 모두 있어야
  유효. 발견을 숨기지 않고 게이트만 통과시키며, 만료 시 자동으로 다시 차단.
  적용 내역은 리포트 '승인된 예외 내역'과 감사로그 `approve_bypass`로 남음.

### CI / 공급망 (Fixed)
- `update-intel` 워크플로 — 신규(untracked) proposed 룰을 감지하지 못해 PR이
  생성되지 않던 버그 수정(`git status --porcelain`), 외부 액션 커밋 SHA 핀.
- `gvskb scan --check-deps` — 코드+패키지 위험을 한 번에 검사해 리포트에 병합.
- pre-commit 예시 수정(`pass_filenames: false`), exit code 문서화(64 포함).

## [0.1.0] - 2026-06-13

- 최초 공개: 215개 룰(KISA·행안부·국정원·OWASP), regex+AST+semgrep 3엔진,
  FastMCP 서버 + `gvskb` CLI, 한국어 md/HTML 리포트, 망분리 오프라인 모드,
  독립 벤치마크(recall 96.7% / 오탐 0).
