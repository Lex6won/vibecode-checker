# Changelog

이 프로젝트의 주요 변경 사항을 기록합니다. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고,
버전은 [유의적 버전(SemVer)](https://semver.org/lang/ko/)을 따릅니다.

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
- **검토 범위·한계 고지** 섹션 — "발견 0건 ≠ 안전"을 문서가 스스로 밝힘.
- **배포 판정**(배포 불가/조건부/미발견) + 잔여 위험 문구 — 보안팀 승인 근거.
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
