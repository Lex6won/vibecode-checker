---
id: KISA-JS-SEC-07
title_ko: Node.js 충분하지 않은 키 길이 - RSA<2048 / ECC<224 / 약한 DH 그룹
title_en: Insufficient key size in Node.js (RSA<2048, ECC<224, weak DH groups)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 7. 충분하지 않은 키 길이 사용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-38
cwe: [CWE-326, CWE-327]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, cryptography]
related_baseline: [MOIS-49-SEC-07]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "generateKeyPair(?:Sync)?\\s*\\(\\s*['\"]rsa['\"][^)]*modulusLength\\s*:\\s*(?:512|768|1024|1280|1536|2047)\\b"
    - "generateKeyPair(?:Sync)?\\s*\\(\\s*['\"](?:dsa|rsa-pss)['\"][^)]*modulusLength\\s*:\\s*(?:512|768|1024|1280|1536|2047)\\b"
    - "generateKeyPair(?:Sync)?\\s*\\(\\s*['\"]ec['\"][^)]*namedCurve\\s*:\\s*['\"](?:secp(?:112r[12]|128r[12]|160[kr][12]|192[kr]1)|prime192v[123]|secp224k1)['\"]"
    - "createDiffieHellman\\s*\\(\\s*(?:512|768|1024|1536|2047)\\s*[),]"
    - "modulusLength\\s*:\\s*(?:512|768|1024)\\b"
  category: kisa-secure-coding
  why_it_matters: >-
    KISA 보안강도별 암호 알고리즘 비교표는 *RSA·DSA는 최소 2048비트, ECC는 최소
    224비트*를 요구합니다(보안강도 112비트, 2030년까지). 1024비트 RSA는 학술적으로
    이미 인수분해가 시도되고 있으며, 192비트 이하 곡선(secp192k1 등)은 깨졌거나
    위험한 수준입니다. 1024비트 이하 Diffie-Hellman 그룹 역시 Logjam 공격으로
    대규모 도청이 가능합니다. 공공 시스템이 약한 키로 서명·암호화하면 *수년 후
    해독되어 과거 통신/문서가 모두 노출*되는 장기적 위험이 발생합니다.
  public_sector_impact:
    - 행정 전자서명·민원 토큰의 장기 위변조 위험
    - 과거 암호화 통신 기록의 사후 복호화(harvest-now-decrypt-later)
    - 평가·인증(CC, 망분리 진단) 미준수로 인한 운영 중단
  safe_fix: |
    KISA 가이드 §제2절 7 권고치 이상으로 설정하세요.
    // RSA: 2048비트 이상
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    // ECC: 224비트 이상 (secp256r1/secp384r1 권장)
    crypto.generateKeyPairSync('ec', { namedCurve: 'secp256r1', ... });
    // DH: 2048비트 이상 또는 모던 그룹(ffdhe2048+) 사용
    crypto.createDiffieHellman(2048);
  references:
    - KISA JavaScript 가이드 제2절 7
    - MOIS-49-SEC-07
    - CWE-326
    - NIST SP 800-131A Rev.2
    - KISA 암호 알고리즘 안전성 분석
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024, publicKeyEncoding: { type: 'spki', format: 'pem' } });"
    - "crypto.generateKeyPairSync('ec', { namedCurve: 'secp192k1', publicKeyEncoding: { type: 'spki', format: 'der' } });"
    - "const dh = crypto.createDiffieHellman(1024);"
  negative:
    - "const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' } });"
    - "crypto.generateKeyPairSync('ec', { namedCurve: 'secp256r1', publicKeyEncoding: { type: 'spki', format: 'der' } });"
    - "const dh = crypto.createDiffieHellman(2048);"
---

## 무엇이 위험한가
짧은 키는 *검증된 알고리즘*도 무력화시킵니다. (1) **RSA 1024비트**는 NIST가 이미 2014년에 사용 중지를 권고했고, 학술적으로 1024비트 RSA-FACTOR 시도가 진행 중입니다. (2) **ECC 192비트 이하 곡선**(`secp192k1`, `prime192v1`)은 일부가 깨졌거나 보안 마진이 매우 부족합니다. (3) **DH 1024비트 그룹**은 Logjam 공격으로 단일 그룹 사전 계산만으로 대규모 도청이 실증되었습니다. 가이드 §제2절 7은 KISA *보안강도별 암호 알고리즘 비교표*를 기준으로 **RSA/DSA ≥ 2048비트, ECC ≥ 224비트(권장 256+)**를 요구합니다. 약한 키로 만든 서명·암호문은 *수년 후 해독*되어 과거의 통신 전체가 노출될 수 있습니다(harvest-now-decrypt-later).

## 안전한 패턴 (가이드 원문 인용)
```javascript
const crypto = require("crypto");

function safeMakeRsaKeyPair() {
  // RSA: 2048비트 이상
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: 'pem' },
    privateKeyEncoding: { type: "pkcs8", format: 'pem' }
  });
  return { PUBLIC: publicKey, PRIVATE: privateKey };
}

function safeMakeEcc() {
  // ECC: 224비트 이상
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256r1',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  return { PUBLIC: publicKey.toString('hex'), PRIVATE: privateKey.toString('hex') };
}
```

## False positive 주의
- 정상값(`modulusLength: 2048`, `3072`, `4096`)은 패턴이 *512~2047 범위*만 매칭하므로 잡히지 않습니다.
- `secp256r1`, `secp384r1`, `secp521r1`, `ed25519`, `x25519` 등 안전한 곡선은 매칭에서 제외됩니다.
- DH 그룹의 경우 2048비트 이상은 매칭되지 않습니다.
- 시험용 키 생성 코드라도 운영 환경에 그대로 배포되면 동일 위험이 발생합니다. 테스트 키임을 명시하고 운영 빌드에서 제외하세요.
- 다섯 번째 패턴(`modulusLength: 512|768|1024`)은 RSA·DSA 외에 다른 알고리즘에서도 동일한 약한 길이를 잡는 보조 패턴입니다.
