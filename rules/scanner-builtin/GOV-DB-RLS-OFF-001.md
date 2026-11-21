---
id: GOV-DB-RLS-OFF-001
title_ko: 행 단위 보안(RLS) 해제 또는 전부 허용 정책 - 공개 키로 테이블 전체 접근
title_en: Row level security disabled or policy that allows everything
status: approved
source_layer: baseline
sources:
  - publisher: Supabase
    document: Row Level Security
  - publisher: OWASP
    document: OWASP API Security Top 10 2023
    item: API1 Broken Object Level Authorization
cwe: [CWE-862, CWE-284]
severity: high
decision_default: block
domains: [web-appsec]
languages: [sql]
scenarios: [web-app]
related_baseline: [CWE-862]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    - '(?i)\balter\s+table\s+[\w."]+\s+disable\s+row\s+level\s+security'
    - '(?i)\bcreate\s+policy\b[^;]{0,300}?\bfor\s+(?:all|insert|update|delete)\b[^;]{0,200}?\b(?:using|with\s+check)\s*\(\s*true\s*\)'
  confidence: likely
  category: authorization
  why_it_matters: >-
    Supabase 처럼 브라우저가 공개 키로 DB 에 직접 닿는 구조에서는 행 단위 보안(RLS) 정책이 유일한 접근 통제입니다.
    RLS 를 끄거나 변경 작업에 `using (true)` 정책을 걸면, 공개 키를 가진 누구나(=웹 화면을 연 누구나) 로그인 없이
    테이블 전체를 읽고 고칠 수 있습니다. 개발 중 오류를 피하려고 넣은 설정이 그대로 남는 경우가 많습니다.
  public_sector_impact:
    - 로그인 없이 테이블 전체 조회·수정·삭제
    - 개인정보 대량 유출
  safe_fix: |
    RLS 를 켜고, 로그인한 사용자와 행의 소유자를 대조하는 정책을 쓰세요.
        alter table public.documents enable row level security;
        create policy "own rows" on public.documents for all using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
  references:
    - CWE-862 Missing Authorization
    - OWASP API1:2023 Broken Object Level Authorization
  can_auto_fix: false
examples:
  language: sql
  positive:
    - "alter table public.documents disable row level security;"
    - "create policy \"allow all\" on public.profiles for all using (true) with check (true);"
    - "CREATE POLICY p ON items FOR UPDATE USING (true);"
  negative:
    - "alter table public.documents enable row level security;"
    - "create policy \"own rows\" on public.documents for all using (auth.uid() = owner_id);"
    - "create policy \"public read\" on public.notices for select using (true);"
---

## 무엇이 위험한가
브라우저가 DB 에 직접 닿는 구조에서 RLS 는 서버의 권한 검사를 대신합니다. 끄면 검사가 없는 것입니다.
공지처럼 누구나 읽어도 되는 표의 `for select using (true)` 는 이 룰의 대상이 아닙니다.

## 안전한 패턴
```sql
alter table public.documents enable row level security;
create policy "own rows" on public.documents for all using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
```
