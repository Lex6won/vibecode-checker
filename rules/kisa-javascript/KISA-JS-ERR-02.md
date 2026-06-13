---
id: KISA-JS-ERR-02
title_ko: JavaScript 오류상황 대응 부재 - 비어있거나 무의미한 catch 블록으로 예외 삼킴
title_en: Detection of error condition without action in JavaScript (empty/swallowed catch)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제4절 2. 오류상황 대응 부재
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-36
cwe: [CWE-390, CWE-391, CWE-755]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, frontend]
related_baseline: [MOIS-49-ERR-02]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "catch\\s*\\([^)]*\\)\\s*\\{\\s*\\}"
    - "catch\\s*\\([^)]*\\)\\s*\\{\\s*(?://[^\\n]*\\n\\s*)+\\}"
    - "catch\\s*\\(\\s*(\\w+)\\s*\\)\\s*\\{\\s*console\\.log\\s*\\(\\s*\\1\\s*\\)\\s*;?\\s*\\}"
    - "\\.catch\\s*\\(\\s*\\(\\s*\\w*\\s*\\)\\s*=>\\s*\\{\\s*\\}\\s*\\)"
    - "\\.catch\\s*\\(\\s*\\(\\s*\\)\\s*=>\\s*\\{\\s*\\}\\s*\\)"
  category: kisa-secure-coding
  why_it_matters: >-
    `try { ... } catch (e) {}` 또는 `.catch(() => {})`처럼 *예외를 잡고도 아무
    조치를 하지 않는* 코드는 가이드 §제4절 2의 핵심 사례입니다. 예외가 발생한 시점에
    이미 *비정상 상태*가 되었는데도 프로그램이 그대로 진행되면, 가이드의 예제처럼
    *기본 암호화 키*(`0000...`)로 데이터가 암호화되거나, 권한 검사가 실패했는데도
    요청이 통과되거나, 결제 실패가 성공으로 기록되는 *논리 결함*이 발생합니다.
    `console.log(err)`만 찍는 것도 *복구 조치가 없으므로* 같은 종류의 부적절한
    대응입니다.
  public_sector_impact:
    - 암호화 실패가 무시되어 평문/약한 키로 민원 데이터 저장
    - 권한 검증 예외가 삼켜져 비인가 요청이 정상 처리
    - 결제·신청 트랜잭션 실패가 성공으로 기록되어 회계 불일치
  safe_fix: |
    예외를 잡았다면 *반드시* (1) 복구 조치, (2) 안전한 기본값 설정, (3) 상위로 재던지기,
    (4) 사용자에게 실패 응답 중 하나를 수행하세요. 단순 `console.log`는 *대응*이 아닙니다.
    try {
      staticKey.key = staticKeys[keyId].key;
    } catch (err) {
      logger.error({ err, keyId }, 'key selection failed');
      // 안전한 기본값: 매 요청 랜덤 키
      staticKey.key = crypto.randomBytes(16).toString('hex');
      staticKey.iv  = crypto.randomBytes(8).toString('hex');
    }
    Promise는 `.catch(err => { logger.error(err); throw err; })` 또는 명시적 실패
    응답으로 처리하세요.
  references:
    - KISA JavaScript 가이드 제4절 2
    - MOIS-49-ERR-02
    - CWE-390
    - CWE-755
    - OWASP Improper Error Handling
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "try { staticKey.key = staticKeys[keyId].key; } catch (err) {}"
    - "try { JSON.parse(req.body.payload); } catch (e) { console.log(e); }"
    - "fetch('/api/x').then(r => r.json()).catch(() => {});"
  negative:
    - "try { staticKey.key = staticKeys[keyId].key; } catch (err) { logger.error({ err }, 'key fail'); staticKey.key = crypto.randomBytes(16).toString('hex'); }"
    - "try { JSON.parse(req.body.payload); } catch (e) { return res.status(400).send('invalid payload'); }"
    - "fetch('/api/x').then(r => r.json()).catch(err => { logger.error(err); throw err; });"
---

## 무엇이 위험한가
예외를 잡고 아무 조치를 하지 않으면 *프로그램은 비정상 상태를 정상으로 가정한 채 계속 실행*됩니다. 가이드 §제4절 2의 안전하지 않은 예제는 사용자가 `keyId`로 잘못된 인덱스를 보내 `staticKeys[keyId]`가 undefined가 되어도 catch가 `console.log(err)`만 하고 끝납니다. 그 결과 `statickKey.key`는 초기값인 `'00000000000000000000000000000000'`을 그대로 사용해 *고정된 영(0) 키로 모든 민원 데이터가 암호화*됩니다. 권한 체크 예외가 삼켜지면 비인가 요청이 정상 처리되고, 결제 예외가 삼켜지면 미결제가 결제 완료로 기록됩니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
try {
  staticKey.key = staticKeys[keyId].key;
  staticKey.iv  = staticKeys[keyId].iv;
} catch (err) {
  // 키 선택 중 오류 발생 시 랜덤으로 암호화 키를 생성하도록 설정
  staticKey.key = crypto.randomBytes(16).toString('hex');
  staticKey.iv  = crypto.randomBytes(8).toString('hex');
}
```

## False positive 주의
- catch 본문에 *어떤 실행문이라도* 있으면 첫 번째/두 번째 패턴은 매칭하지 않습니다(빈 블록과 주석-only 블록만 잡음). `throw err`, `logger.error(...)`, `res.status(...)`, 변수 할당, 사용자 정의 함수 호출은 정상 대응으로 간주합니다.
- 세 번째 패턴은 *오직* `console.log(err)` 단독 호출만 잡습니다. `console.log` 외에 다른 문장이 한 줄이라도 더 있으면 매칭하지 않습니다.
- `.catch(() => {})` / `.catch((e) => {})` Promise 무시는 명시적으로 매칭합니다. 의도된 *fire-and-forget* 호출이라면 주석으로 의도를 명시하고 별도 리뷰하세요.
- 테스트 코드에서 *예외 발생만 검증*하는 `try { fn() } catch {}` 패턴은 의도된 경우입니다. 테스트 파일은 스캔 제외 또는 별도 정책을 적용하세요.
- `try { ... } catch { /* intentionally ignored */ }`도 매칭됩니다. 정말 의도한 무시라면 코드 리뷰에서 근거를 남겨야 합니다.
