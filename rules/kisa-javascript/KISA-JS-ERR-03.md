---
id: KISA-JS-ERR-03
title_ko: Node.js 부적절한 예외 처리 - catch에서 swallowed exception / console.log만 수행
title_en: Improper exception handling in Node.js (swallowed catch with only console.log)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제4절 3. 부적절한 예외 처리
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-36
cwe: [CWE-754, CWE-390, CWE-755]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, agent]
related_baseline: [MOIS-49-ERR-03]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "catch\\s*\\(\\s*[A-Za-z_$][\\w$]*\\s*\\)\\s*\\{\\s*(?://[^\\n]*\\n\\s*)*(?:console\\.(?:log|error|warn|debug)\\s*\\([^)]*\\)\\s*;?\\s*)?\\}"
    - "\\.catch\\s*\\(\\s*\\(?\\s*[A-Za-z_$][\\w$]*\\s*\\)?\\s*=>\\s*\\{\\s*(?://[^\\n]*\\n\\s*)*(?:console\\.(?:log|error|warn|debug)\\s*\\([^)]*\\)\\s*;?\\s*)?\\}\\s*\\)"
    - "\\.catch\\s*\\(\\s*\\(?\\s*\\)?\\s*=>\\s*\\{\\s*\\}\\s*\\)"
    - "catch\\s*\\(\\s*[A-Za-z_$][\\w$]*\\s*\\)\\s*\\{\\s*/\\*[^*]*\\*/\\s*\\}"
  category: kisa-secure-coding
  why_it_matters: >-
    `catch` 블록을 비워두거나 `console.log(err)`만 적어두면, 예외가 *조용히
    삼켜져* 프로그램이 잘못된 상태로 계속 실행됩니다. 가이드 §제4절 3 예제처럼
    암호화 키 조회 실패 시 catch가 비어 있으면 *기본 키 `0000...`* 로 암호화가
    진행되어 평문 노출과 동등한 보안 사고가 발생합니다. 또한 동일한 catch가
    여러 종류의 예외(인증 실패/네트워크 오류/파싱 오류)에 같은 응답을 주면
    잘못된 흐름 제어가 발생합니다.
  public_sector_impact:
    - 키/세션 조회 실패가 무시되어 기본값/평문으로 처리
    - 인증·인가 실패가 catch에서 삼켜져 권한 우회
    - 결제·민원 처리 중 예외가 로그만 남기고 성공 응답
  safe_fix: |
    catch 블록에서는 *반드시 다음 중 하나*를 수행하세요.
    1) 예외를 다시 던지기: throw err; 또는 throw new DomainError('...', { cause: err });
    2) 안전한 폴백을 수행하고 *즉시 함수 종료* (return / res.status(...).send(...));
    3) 예외 종류별 분기 (err.code === 'ENOENT' vs 'EACCES').
    } catch (err) {
      logger.error({ err }, 'key lookup failed');
      return res.status(500).send({ message: '키 조회 실패' });
    }
  references:
    - KISA JavaScript 가이드 제4절 3
    - MOIS-49-ERR-03
    - CWE-754
    - CWE-390
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "try { staticKey.key = staticKeys[keyId].key; } catch (err) { console.log(err); }"
    - "doWork().catch(e => { console.error(e); });"
    - "doWork().catch(() => {});"
  negative:
    - "try { staticKey.key = staticKeys[keyId].key; } catch (err) { staticKey.key = crypto.randomBytes(16).toString('hex'); return res.status(500).send('fail'); }"
    - "doWork().catch(err => { logger.error(err); throw err; });"
    - "try { run(); } catch (err) { if (err.code === 'ENOENT') return res.status(404).send('not found'); throw err; }"
---

## 무엇이 위험한가
빈 `catch`와 `console.log(err)`만 있는 catch는 *예외 처리를 한 것처럼 보이지만 실제로는 아무 조치가 없는* 상태입니다. 가이드 §제4절 3의 안전하지 않은 예제는 `staticKeys[keyId]` 조회가 실패해도 catch가 단순 로그만 찍고 코드 흐름이 이어져, 결국 `key: "0000..."`이라는 기본값으로 AES-256 암호화가 수행됩니다. 사실상 평문 저장과 같은 효과로, 공공 시스템의 개인정보·인증정보 보호 의무를 정면으로 위반합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
try {
  staticKey.key = staticKeys[keyId].key;
  staticKey.iv = staticKeys[keyId].iv;
} catch (err) {
  // 키 선택 중 오류 발생 시 랜덤으로 암호화 키를 생성하도록 설정
  staticKey.key = crypto.randomBytes(16).toString('hex');
  staticKey.iv = crypto.randomBytes(8).toString('hex');
}
```

## False positive 주의
- catch 본문에 `throw`, `return`, `res.`, `next(`, `reject(`, 또는 일반 함수 호출이 있으면 *조치를 한 것*으로 보고 매칭하지 않습니다.
- 의도적으로 무시해야 하는 cleanup 시나리오(예: 임시 파일 unlink 실패 무시)는 한 줄 주석 `// ignore` 대신 별도의 `safeUnlink()` 헬퍼로 감싸 코드 리뷰에서 의도를 명확히 드러내세요.
- `console.error`만 있는 catch도 가이드 기준상 *부적절*하지만, 백그라운드 작업처럼 의도된 fire-and-forget이라면 코드 리뷰에서 예외 처리 정책을 명시하세요.
