# j_agentic_2026 — 홀드아웃 말뭉치 (41차)

2026년 공급망·개발환경 사고의 **구조만** 재현한 검증용 말뭉치다. 실행 코드(페이로드)는 없고,
빈 스크립트를 가리키는 설정, `import x` 한 줄짜리 `.pth`, 라벨 분기 없는 `pull_request_target`
처럼 **모양**만 있다. 도메인은 전부 `.example` 합성이다.

- **검증 전용**: 룰을 만들 때 쓴 개발용 fixture 는 `tests/test_round37~40*.py` 에 있다. 이 말뭉치는
  룰 작성에 쓰지 않았고, 신규 룰의 미탐·오탐을 숫자로 말하기 위한 홀드아웃이다.
- **별도 표**: 기존 벤치마크(`scripts/run_benchmark.py`, 42 케이스)의 수치와 섞지 않는다.
- 실행: `GVSKB_MODE=offline PYTHONPATH=src python scripts/run_holdout.py` → `eval_corpus/results/holdout_results.md`
- `t*` 는 탐지 대상, `n*` 는 같은 생태계의 정상 모양(음성 대조군). 각 폴더를 **독립 루트**로 검사한다.
