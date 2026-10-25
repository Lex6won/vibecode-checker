# k_ts_2026 — 타입스크립트 말뭉치 (46차)

타입스크립트 코드에 대해 체커(특히 선택 설치 엔진 `ts-structure`)의 탐지·오탐을 숫자로 재는 채점표다.
합성 코드이며 페이로드·실제 도메인은 없다.

- `t*` = 탐지 대상(TS 캐스트·제네릭·계산된 속성·별칭·Next.js 라우트·React JSX·관리자 경로),
  `n*` = 같은 생태계의 정상 관용구(파라미터 바인딩·zod 검증·`.d.ts`·이름만 eval 인 함수·보호된 관리자 경로).
- `requires_engine: ts-structure` 케이스는 `pip install vibecode-checker[ts]` 가 있을 때만 채점한다.
- 실행: `GVSKB_MODE=offline PYTHONPATH=src python scripts/run_holdout.py --corpus k_ts_2026`
  → `eval_corpus/results/k_ts_2026_results.md`
- 알려진 공백(`kind: known_gap`): 파일 간 흐름의 출처 확인. 잡히기 시작하면 드라이버가 알린다.
