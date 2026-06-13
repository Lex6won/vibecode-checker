---
id: KISA-JS-CODE-02
title_ko: Node.js 부적절한 자원 해제 - try 블록 내 close 호출 (finally 누락)
title_en: Improper resource shutdown in Node.js (close inside try, missing finally)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제5절 2. 부적절한 자원 해제
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-37
cwe: [CWE-404, CWE-772]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app]
related_baseline: [MOIS-49-CODE-02]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "try\\s*\\{(?:(?!\\}\\s*(?:catch|finally))[\\s\\S]){0,800}?\\b(?:fs\\.openSync|fs\\.open|fs\\.createReadStream|fs\\.createWriteStream)\\s*\\((?:(?!\\}\\s*(?:catch|finally))[\\s\\S]){0,800}?\\}\\s*catch\\s*\\([^)]*\\)\\s*\\{(?:(?!\\}\\s*finally)[\\s\\S])*?\\}(?!\\s*finally)"
    - "try\\s*\\{(?:(?!\\}\\s*(?:catch|finally))[\\s\\S]){0,800}?\\b(?:db|client|conn|connection|pool)\\.(?:connect|getConnection|createConnection)\\s*\\((?:(?!\\}\\s*(?:catch|finally))[\\s\\S]){0,800}?\\}\\s*catch\\s*\\([^)]*\\)\\s*\\{(?:(?!\\}\\s*finally)[\\s\\S])*?\\}(?!\\s*finally)"
    - "try\\s*\\{(?:(?!\\}\\s*(?:catch|finally))[\\s\\S]){0,600}?\\b(?:fs\\.close|\\.end\\s*\\(\\s*\\)|\\.release\\s*\\(\\s*\\)|\\.destroy\\s*\\(\\s*\\))(?:(?!\\}\\s*(?:catch|finally))[\\s\\S]){0,600}?\\}\\s*catch\\s*\\([^)]*\\)\\s*\\{(?:(?!\\}\\s*finally)[\\s\\S])*?\\}(?!\\s*finally)"
  category: kisa-secure-coding
  why_it_matters: >-
    `fs.openSync`로 연 파일 디스크립터나 DB 커넥션을 `try` 블록 안에서 닫고
    `finally`가 없으면, 중간에 예외가 던져진 순간 close가 실행되지 않아
    *파일 핸들/소켓 누수*가 누적됩니다. 장시간 운영되는 Node.js 행정 서버는
    `EMFILE: too many open files` 또는 DB 커넥션 풀 고갈로 서비스 중단에
    이릅니다. 가이드 §제5절 2는 *예외 발생 여부와 상관없이 항상 실행되는
    finally 블록에서 할당 받은 모든 자원을 반환*하라고 명시합니다.
  public_sector_impact:
    - 파일 디스크립터 누수로 인한 EMFILE 발생, 서비스 중단
    - DB 커넥션 풀 고갈로 행정 시스템 응답 불가
    - 누수 누적으로 인한 야간 무인 서비스 다운
  safe_fix: |
    자원 해제는 반드시 `finally` 블록에서 수행하거나, `try { ... } finally { ... }`
    패턴을 사용하세요. `fs.promises` + `async/await`도 같은 패턴이 필요합니다.
    let fid = null;
    try {
      fid = fs.openSync(path, 'r');
      return fs.readFileSync(fid, 'utf8');
    } catch (e) {
      logger.error(e);
      throw e;
    } finally {
      if (fid !== null) fs.close(fid, () => {});
    }
    DB 커넥션은 `pool.getConnection()` → `try/finally` 안에서 `conn.release()`.
  references:
    - KISA JavaScript 가이드 제5절 2
    - MOIS-49-CODE-02
    - CWE-404
    - OWASP Unreleased Resource
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "try { const fid = fs.openSync('./config.cfg', 'r'); const data = fs.readFileSync(fid, 'utf8'); fs.close(fid, () => {}); } catch (e) { console.log('error'); }"
    - "try { const conn = await pool.getConnection(); const rows = await conn.query('SELECT 1'); conn.release(); return rows; } catch (e) { console.error(e); }"
    - "try { const stream = fs.createReadStream(path); stream.pipe(res); stream.destroy(); } catch (e) { res.send('fail'); }"
  negative:
    - "let fid = null; try { fid = fs.openSync('./config.cfg', 'r'); return fs.readFileSync(fid, 'utf8'); } catch (e) { throw e; } finally { if (fid) fs.close(fid, () => {}); }"
    - "let conn; try { conn = await pool.getConnection(); return await conn.query('SELECT 1'); } finally { if (conn) conn.release(); }"
    - "const data = await fs.promises.readFile(path, 'utf8'); return data;"
---

## 무엇이 위험한가
파일 핸들·소켓·DB 커넥션은 유한한 OS 자원입니다. `try` 블록 안에서 `fs.close` / `conn.release()`를 호출하면, *그 직전 라인에서 예외가 발생하면 close가 실행되지 않습니다*. 가이드 §제5절 2의 안전하지 않은 예제는 `fs.readFileSync('100', 'utf8')`에서 예외가 던져진 후 `fs.close(fid, ...)`이 호출되지 않아 파일 디스크립터가 누수됩니다. Node.js 프로세스는 보통 1024개 정도의 fd만 허용하므로 누수 1024회 후 서버가 응답을 끊습니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
let fid = null;
let fdata = null;
try {
  fid = fs.openSync(configPath, 'r');
  fdata = fs.readFileSync(fid, 'utf8');
} catch (e) {
  console.log('error occured!', e);
  // try 절에서 할당된 자원은 finally 절에서 시스템에 반환을 해야 함
} finally {
  fs.close(fid, err => {
    if (err) console.log('error occured while file closing');
    else console.log('file closed');
  });
}
return res.send(fdata);
```

## False positive 주의
- `try { ... } catch { ... } finally { ... }` 형태로 `finally` 블록이 있으면 매칭하지 않습니다.
- `fs.promises.readFile` 같은 *자동 close* 헬퍼는 자원 해제를 라이브러리가 처리하므로 매칭 대상이 아닙니다.
- `using` 선언(Stage 3 explicit resource management)이나 라이브러리의 `withConnection(cb)` 콜백 패턴도 자동 해제로 보고 매칭하지 않습니다.
- 짧은 한 줄 함수에서는 catch 블록이 없을 수도 있는데, 그런 경우 별도 누수 위험이 있어도 패턴 범위를 벗어나니 코드 리뷰로 보완하세요.
