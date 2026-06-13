# 경계 프로브: 패턴에 없는 시크릿 형식 — 미탐 예상 (가짜 값. 탐지 한계 측정용)
JWT_SAMPLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIn0.FAKEFAKEFAKEFAKEFAKEFAKEFAKE"  # H-04 jwt token

GITHUB_TOKEN = "ghp_FAKE0000000000000000000000000000TEST"  # H-05 github pat

DATABASE_URL = "postgres://admin:p4ssFAKE@db.internal.example:5432/minwon"  # H-06 db connection string
