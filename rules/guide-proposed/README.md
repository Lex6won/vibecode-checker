# guide-proposed — 새 보안 가이드에서 나온 초안 룰

새로 발간된 국가·기관 보안 가이드(PDF→MD 변환본)를 분석해 만든 **초안 룰**이
여기 놓입니다. 절차는 `.claude/skills/guide-to-rules/SKILL.md` 와
`CONTRIBUTING.md` 의 「새 보안 가이드를 룰로 반영하기」를 따릅니다.

## 수명주기

1. 가이드 MD → 격차 분석 → 신규 항목만 여기 `status: proposed` 로 작성
2. `proposed` 인 동안 **검사에 영향 없음** — 스캐너가 건너뜁니다
   (`--allow-proposed` 를 명시해야만 실험적으로 켜짐)
3. 사람이 검토·승인하면 `status: approved` 로 바꾸고 주제에 맞는 카테고리
   디렉터리(`rules/scanner-builtin/` 등)로 **이동**합니다
4. 채택하지 않기로 한 초안은 사유를 커밋 메시지에 남기고 삭제합니다

`rules/intel-proposed/`(CISA KEV 자동 초안, 90일 미승격 시 자동 폐기)와 달리
이 디렉터리는 **자동 폐기가 없습니다** — 사람이 만든 초안은 사람이 정리합니다.

## 요건

- `status: proposed` · `source_layer: baseline` · `sources:` 에 가이드
  발행처·문서명·조항 필수 (원문 복제 금지 — 요약·인용·구조화만)
- `examples.positive`/`negative` 필수 — 없으면 `validate-rules` 가 막습니다
- 룰 파일 추가·수정 후 `gvskb ruleset --bump <버전>` 으로 룰셋 버전 갱신
