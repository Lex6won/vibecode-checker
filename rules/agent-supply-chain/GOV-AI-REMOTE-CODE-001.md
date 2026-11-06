---
id: GOV-AI-REMOTE-CODE-001
title_ko: AI 모델을 불러올 때 모델 저장소의 코드가 실행됩니다 (trust_remote_code · torch.hub)
title_en: Loading an AI model executes code from the model repository
status: approved
source_layer: baseline
sources:
- publisher: 국정원
  document: 국가·공공기관 AI보안 가이드북
  version: '2025.12'
  item: M02
- publisher: 국정원
  document: 국가·공공기관 AI보안 가이드북
  version: '2025.12'
  item: M12
- publisher: 국정원
  document: 국가·공공기관 AI보안 가이드북
  version: '2025.12'
  item: T03
- publisher: 국정원
  document: 국가·공공기관 AI보안 가이드북
  version: '2025.12'
  item: T14
cwe:
- CWE-494
- CWE-94
severity: high
decision_default: warn
domains:
- llm-appsec
languages:
- python
- shell
- data
- config
scenarios:
- llm-integration
- rag
- agent
- data-pipeline
related_baseline:
- NIS-AI-M02
- NIS-AI-M12
- NIS-AI-T03
- NIS-AI-T14
- KISA-PY-SEC-15
verified_at: '2026-11-06'
review_due: '2027-05-06'
detection:
  patterns:
  - \btrust_remote_code\s*=\s*True\b
  - '[\"'']?\btrust_remote_code[\"'']?\s*:\s*[Tt]rue\b'
  - --trust-remote-code\b
  - \btorch\.hub\.load\s*\(
  - \btrust_repo\s*=\s*True\b
  exclude_patterns:
  - source\s*=\s*[\"']local[\"']
  - add_argument\s*\(
  - 금지|위험|쓰지 말|사용하지 말|do not|don't|avoid
  category: agent-supply-chain
  confidence: pattern-only
  why_it_matters: 모델 파일이 아니라 모델 저장소에 든 파이썬 코드가 이 PC 권한으로 실행됩니다. 저장소가 오염되거나 게시자가 바뀌면 불러오는 순간 임의 코드가 돕니다.
  public_sector_impact:
  - AI 모델 공급망 공격
  - 서버 권한 탈취
  - 학습데이터·자격증명 유출
  safe_fix: trust_remote_code 를 끄고 표준 아키텍처 모델을 쓰세요. 꼭 필요하면 검토한 커밋으로 revision 을 고정하고, 코드를 내부로 복사해 격리 환경에서 먼저 확인하세요.
  references:
  - 국정원 AI보안 가이드북 M02·M12·T14
  - CWE-494
  can_auto_fix: false
examples:
  language: python
  positive:
  - m = AutoModel.from_pretrained("acme/m", trust_remote_code=True)
  - p = pipeline("text-generation", model="acme/m", trust_remote_code = True)
  - d = load_dataset("acme/d", trust_remote_code=True)
  - m = torch.hub.load("acme/repo", "net")
  - m = torch.hub.load("acme/repo", "net", trust_repo=True)
  - vllm serve acme/m --trust-remote-code
  negative:
  - m = AutoModel.from_pretrained("acme/m", trust_remote_code=False)
  - 'def load(trust_remote_code: bool = False): ...'
  - m = torch.hub.load("./local_repo", "net", source="local")
  - parser.add_argument("--trust-remote-code", action="store_true")
  - '# trust_remote_code=True 는 쓰지 말 것'
  - msg = "trust_remote_code=True 는 금지입니다"
  - torch.hub.set_dir(cache_dir)
---

## 무엇이 위험한가
`trust_remote_code=True` 와 `torch.hub.load` 는 모델 가중치만 읽는 것이 아니라 저장소에 있는 파이썬 코드를 그대로 실행합니다. 공개 저장소에서 악성 모델이 발견된 사례를 가이드북도 T03 위협 사례로 듭니다.

## 안전한 패턴
표준 아키텍처 모델을 `trust_remote_code` 없이 불러오고, 부득이하면 커밋 해시로 `revision` 을 고정한 뒤 코드를 검토합니다. 가능하면 내부 미러에 받아 해시를 기록합니다.

## 이 룰의 한계
같은 줄만 봅니다. 값을 변수로 넘기면(`trust_remote_code=flag`) 잡지 않습니다. 코드를 검토했는지는 알 수 없어 차단이 아니라 경고입니다.
