---
id: KISA-PY-INPUT-08
title_ko: Python XXE - 외부 엔티티 해석이 켜진 XML 파서 사용 (lxml/sax/xml.dom)
title_en: XML External Entity (XXE) in Python XML parsers (lxml/sax/xml.dom)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 8. 부적절한 XML 외부 개체 참조
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-08
cwe: [CWE-611, CWE-827]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [MOIS-49-INPUT-08]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - 'etree\.XMLParser\s*\([^)]*resolve_entities\s*=\s*True'
    - 'lxml\.etree\.(?:parse|fromstring|XML)\s*\('
    - 'setFeature\s*\(\s*feature_external_ges\s*,\s*True\s*\)'
    - 'xml\.dom\.minidom\.parse(?:String)?\s*\('
    - 'xml\.sax\.parse(?:String)?\s*\('
  category: kisa-secure-coding
  why_it_matters: >-
    Python 기본 `xml.etree.ElementTree`는 외부 엔티티를 처리하지 않지만,
    *lxml*은 기본값으로 외부 엔티티 해석이 켜져 있고 `xml.sax`도
    `feature_external_ges=True`로 설정하면 즉시 취약해집니다. 공격자가
    `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 같은 DTD를 포함한 XML을
    업로드하면 *서버 파일 읽기, SSRF, DoS*가 발생합니다. 공공기관에서는
    HWPX/DOCX/ONNX 등 XML 기반 포맷을 다루는 파이프라인에서 자주 노출됩니다.
  public_sector_impact:
    - 서버 내 민감 파일 노출 (/etc/passwd, settings.py)
    - 내부 네트워크 SSRF (인트라넷 자원 탐지)
    - Billion Laughs 등 DoS
  safe_fix: |
    *defusedxml* 사용을 권장합니다.
        import defusedxml.ElementTree as ET
        ET.fromstring(xml_bytes)
    lxml을 써야 한다면 명시적으로 외부 엔티티/네트워크/DTD 비활성화:
        parser = etree.XMLParser(
            resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False
        )
        etree.parse(src, parser)
    xml.sax는 `setFeature(feature_external_ges, False)`로 설정.
  references:
    - KISA Python 가이드 제1절 8
    - MOIS-49-INPUT-08
    - CWE-611
    - OWASP XML External Entity Prevention Cheat Sheet
    - https://docs.python.org/3/library/xml.html#xml-vulnerabilities
  can_auto_fix: false
examples:
  language: python
  positive:
    - "from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)"
    - "from lxml import etree\ntree = lxml.etree.parse(src)"
    - "from xml.sax.handler import feature_external_ges\nparser.setFeature(feature_external_ges, True)"
  negative:
    - "import defusedxml.ElementTree as ET\nET.fromstring(data)"
    - "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)"
    - "parser.setFeature(feature_external_ges, False)"
---

## 무엇이 위험한가
XXE는 *공공기관에서 가장 과소평가된 취약점* 중 하나입니다. 결재·민원 첨부에서 받은 XML/HWPX 파일을 lxml 기본 설정으로 파싱하기만 해도 `<!ENTITY xxe SYSTEM "file:///etc/shadow">` 한 줄로 서버 파일이 외부에 유출됩니다. AI 코딩 도우미는 보통 `etree.parse(src)` 같이 옵션 없는 형태를 제안하기 때문에 더 위험합니다.

## 안전한 패턴 (가이드 원문 인용)
```python
# 권장: defusedxml — 모든 XML 공격 패턴을 한 번에 차단
import defusedxml.ElementTree as ET
root = ET.fromstring(xml_bytes)

# lxml이 필요하면 명시 비활성화
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,   # 외부 엔티티 차단
    no_network=True,          # 네트워크 액세스 차단
    load_dtd=False,           # DTD 로딩 차단
    dtd_validation=False,
)
tree = etree.parse(file_obj, parser)

# xml.sax
from xml.sax.handler import feature_external_ges
parser.setFeature(feature_external_ges, False)
```

## False positive 주의
- 패턴이 다소 넓어 `lxml.etree.parse/fromstring/XML(...)` 형태 자체를 잡습니다. 한 줄에서 안전한 옵션을 동시에 표현하기 어렵기 때문에, 명시적으로 안전한 파서를 한 변수에 분리해 만든 코드(`parser = etree.XMLParser(resolve_entities=False, no_network=True); etree.parse(src, parser)`)는 *parse 호출 라인*에서 본 룰이 매칭될 수 있습니다. 안전한 호출임을 코드 리뷰로 확인했다면 `# gvskb: ignore KISA-PY-INPUT-08`로 억제하세요.
- `defusedxml.*` 호출은 패턴 prefix가 다르므로 매칭되지 않습니다.
- `xml.etree.ElementTree`(표준 라이브러리)는 외부 엔티티를 처리하지 않아 패턴에 포함하지 않았습니다.
