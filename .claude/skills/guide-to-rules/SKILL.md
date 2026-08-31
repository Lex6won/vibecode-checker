---
name: guide-to-rules
description: 새 국가·기관 보안 가이드(MD 변환본)를 받아 기존 룰과 격차 분석 후 status:proposed 초안 룰을 작성·검증한다. 사용자가 가이드 MD 경로를 주면 실행.
---

# 가이드 → 룰 반영 절차

사용자가 변환된 보안 가이드 MD 파일 경로를 넘긴다(`$ARGUMENTS`). 결과물은
`rules/guide-proposed/` 아래의 **status: proposed 초안 룰**과 사람이 검토할
**격차 분석 표**다. 초안은 사람이 `approved` 로 승격하기 전까지 검사에 영향을
주지 않는다(스캐너가 proposed 를 건너뜀 — `regex_scanner.py` 의 status 게이트).

## 0. 원칙 (건너뛰지 말 것)

- **원문을 복제하지 않는다.** 요약·인용·구조화만 한다(README 정책). `sources:`
  frontmatter 에 발행처·문서명·조항 번호를 정확히 적는다. **존재하지 않는 조항을
  지어내는 것은 이 도구 최악의 결함이다** — 확실하지 않으면 조항 번호를 비운다.
- **모든 판단은 초안으로만.** 이 스킬은 룰을 `approved` 로 만들지 않는다.
  집행(검사 반영)은 사람의 결정이다.
- **커밋 전 적대적 검증**: 새 패턴이 만들 오탐을 반대 방향으로 직접 쳐 본다
  (negative 예시·기존 코퍼스). 탐지만 확인하고 끝내지 않는다.

## 1. 가이드 읽기·항목화

1. 가이드 MD 전체를 읽는다(부분 읽기 금지 — 뒤쪽 부록에 점검 항목표가 흔함).
2. 보안 요구사항을 개별 항목으로 쪼갠다: `항목번호 · 요구 내용 요약 · 대상
   (코드 패턴/설정/프로세스) · 탐지 가능성`.
3. 탐지 가능성 분류:
   - **A 정적 탐지 가능** — 정규식/AST 로 코드에서 잡을 수 있음 → 탐지 룰 후보
   - **B 지식 룰** — 코드에서 못 잡지만 인용 가치 있음(프로세스·정책 요구) →
     detection 없는 참조 룰 후보
   - **C 범위 밖** — 런타임·인프라 전용 등. 표에 사유와 함께 기록만 한다.

## 2. 격차 분석 (기존 룰 대조)

항목마다 기존 룰 328+개와 대조한다:

```bash
# 키워드로 기존 룰 검색 (여러 키워드로 반복)
grep -rli "<키워드>" rules/ --include=*.md
# 로드된 룰 검색 (서버 없이)
PYTHONPATH=src python -m gvskb.cli search "<키워드>"
```

판정 4갈래: **이미 커버**(기존 룰 ID 기록) / **부분 커버**(기존 룰 보강 제안 —
기존 룰을 직접 고치지 말고 보강 내용을 표에 적는다) / **신규 필요** / **범위 밖**.
"이미 커버"를 후하게 판정하지 않는다 — 패턴이 실제로 그 형태를 잡는지
`scan_code` 로 1건 확인한다.

## 3. 신규 룰 초안 작성

`rules/guide-proposed/<ID>.md` 로 작성한다. **최근 승인 룰을 템플릿으로 삼는다**
(예: `rules/scanner-builtin/GOV-PATH-BOUNDARY-001.md` — frontmatter 필드 전부,
title_ko/en·sources·cwe·severity·decision_default·domains·languages·scenarios·
related_baseline·verified_at·review_due·detection·examples).

- `status: proposed` (필수 — 이것이 안전장치다)
- `source_layer: baseline`
- `sources:` 에 이 가이드의 발행처·문서명·조항
- ID 는 대상 카테고리 관례를 따른다(예: `GOV-<주제>-NNN`). 기존 ID 와 충돌 금지.
- `detection.patterns` + `exclude_patterns`, `confidence: pattern-only` 부터 시작
- **`examples.positive`(잡혀야 할 취약 코드) / `negative`(잡히면 안 되는 안전
  코드) 각 3개 이상 — 없으면 머지 불가.** negative 에는 흔한 안전 관용구·주석·
  설명 문장을 반드시 포함한다(마크업 속 설명문 오탐이 반복된 결함 유형).
- 본문: 무엇이 위험한가 / 안전한 패턴 / 이 룰의 한계

## 4. 검증 (전부 통과해야 초안 완성)

```bash
PYTHONPATH=src python -m gvskb.cli validate-rules --fail-on error
PYTHONPATH=src python -m gvskb.cli evaluate          # 예시 기반 정밀도 — 새 룰 P/R 확인
python -m pytest -q                                   # 회귀 0 확인
```

- `status: proposed` 초안은 집행되지 않으므로 **룰셋 지문을 움직이지 않는다**
  — `validate-rules` 에 드리프트가 뜨면 안 된다(뜨면 status 오타를 의심하라).
  `ruleset --bump` 는 이 단계가 아니라 **승격(6단계)에서** 한다.
- 적대적 검증: positive 를 살짝 비튼 변형(공백·대소문자·따옴표)이 잡히는지,
  negative 의 흔한 변형이 잡히지 않는지 `scan_code` 로 추가 확인.

## 5. 산출물 보고

사용자에게 표로 보고한다:

| 가이드 항목 | 판정 | 룰 ID / 기존 룰 | 비고 |
|---|---|---|---|

+ 신규 초안 파일 목록(전체 경로), evaluate 수치, 남은 판단(승격 여부)은
사람 몫임을 명시. CHANGELOG(Unreleased)에 한 줄 추가. 커밋·PR 은 사용자
확인 후 진행한다.

## 6. 승격 (사람이 결정한 뒤에만)

검토자가 승인하면: `status: proposed → approved` 로 바꾸고 파일을 주제에 맞는
카테고리 디렉터리(예: `rules/scanner-builtin/`)로 옮긴다. **이 순간 룰이 지문에
들어와 드리프트 ERROR 가 나는 것이 정상이다** — `ruleset --bump <새 버전>`
(관례: `2026.08.30f` → `2026.09.01a`)으로 버전을 올리고 검증 3종을 다시
돌린다. guide-proposed 에는 초안만 남는다.
