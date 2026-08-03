"""외부 연결 인벤토리 추출 — 외부 API 호출 + 설치된 외부 플러그인/라이브러리.

위반(Finding) 탐지가 아니라 *검토용 목록*을 만든다. 목적: 공공 보안팀이 "이
서비스가 어디로 데이터를 보내는가"를 한눈에 보고, 특히 개인정보(PII)가 함께
나갈 수 있는 지점과 국외 전송을 우선 검토하도록 돕는다.

정직성: 정적 분석은 실제 전송 페이로드를 증명하지 못한다. 따라서
- 호스트가 변수로 조립되면 누락될 수 있고(= "최소 목록"),
- data_summary·region 은 카탈로그/인접 신호 기반의 *힌트*이며 판정이 아니다.
"""
from __future__ import annotations

import re

from ..schema import ExternalConnection

# ---------------------------------------------------------------------------
# 카탈로그 — 알려진 호스트/패키지의 종류·데이터 요약·국외/국내·운영주체.
# (category, data_summary, region, operator) — 부분 문자열 매칭.
#   region: "국외" | "국내" | None(미상)
#   operator: 운영주체·국가 — 개인정보 국외이전 검토는 "누구에게, 어느 나라로"가
#   특정돼야 하므로 "국외" 표시만으로는 부족하다. 미등록 호스트는 None(직접 확인).
# ---------------------------------------------------------------------------
_HOST_CATALOG: tuple[tuple[str, str, str, str | None, str | None], ...] = (
    # 외부 AI (대부분 국외)
    ("api.openai.com", "ai", "프롬프트·임베딩 등 입력 텍스트", "국외", "OpenAI(미국)"),
    ("openai.azure.com", "ai", "프롬프트 텍스트(Azure OpenAI)", "국외", "Microsoft(미국)"),
    ("api.anthropic.com", "ai", "메시지 프롬프트", "국외", "Anthropic(미국)"),
    ("generativelanguage.googleapis.com", "ai", "텍스트 입력(Google Gemini)", "국외", "Google(미국)"),
    ("aiplatform.googleapis.com", "ai", "텍스트/데이터 입력(Vertex AI)", "국외", "Google(미국)"),
    ("api.cohere.ai", "ai", "텍스트 입력(Cohere)", "국외", "Cohere(캐나다)"),
    ("api.mistral.ai", "ai", "프롬프트 텍스트(Mistral)", "국외", "Mistral AI(프랑스)"),
    ("api-inference.huggingface.co", "ai", "추론 입력(HuggingFace)", "국외", "Hugging Face(미국)"),
    # 국내 AI
    ("clovastudio.apigw.ntruss.com", "ai", "프롬프트 텍스트(네이버 HyperCLOVA)", "국내", "네이버클라우드(한국)"),
    ("clovastudio.stream.ntruss.com", "ai", "프롬프트 텍스트(네이버 HyperCLOVA)", "국내", "네이버클라우드(한국)"),
    # 분석/텔레메트리
    ("api.mixpanel.com", "analytics", "사용자ID·이벤트 속성", "국외", "Mixpanel(미국)"),
    ("google-analytics.com", "analytics", "사용자 행동·페이지뷰", "국외", "Google(미국)"),
    ("api.segment.io", "analytics", "사용자 이벤트", "국외", "Twilio Segment(미국)"),
    ("api.amplitude.com", "analytics", "사용자 행동 이벤트", "국외", "Amplitude(미국)"),
    # 에러 추적
    ("ingest.sentry.io", "error", "예외·스택·환경값(개인정보 섞일 수 있음)", "국외", "Sentry(미국)"),
    ("sentry.io", "error", "예외·스택·환경값", "국외", "Sentry(미국)"),
    # 결제 (국내외)
    ("api.stripe.com", "payment", "결제·카드 토큰", "국외", "Stripe(미국)"),
    ("api.iamport.kr", "payment", "결제 정보(포트원/아임포트)", "국내", "포트원(한국)"),
    ("api.tosspayments.com", "payment", "결제 정보(토스페이먼츠)", "국내", "토스페이먼츠(한국)"),
    ("kapi.kakao.com", "messaging", "카카오 API(메시지·프로필)", "국내", "카카오(한국)"),
    # 메시징
    ("slack.com", "messaging", "메시지 본문", "국외", "Slack/Salesforce(미국)"),
    ("discord.com", "messaging", "메시지 본문", "국외", "Discord(미국)"),
    # ── 인프라·운영 (데이터 전송이 거의 없어 '기타'로 뭉뚱그리면 노이즈가 된다) ──
    ("acme-v02.api.letsencrypt.org", "infra", "인증서 발급 요청(도메인명)", "국외", "Let's Encrypt/ISRG(미국)"),
    ("letsencrypt.org", "infra", "인증서 발급·검증", "국외", "Let's Encrypt/ISRG(미국)"),
    ("api.ipify.org", "infra", "**서버의 공인 IP가 외부로 노출됨**", "국외", "ipify(미국)"),
    ("ifconfig.me", "infra", "**서버의 공인 IP가 외부로 노출됨**", "국외", "ifconfig.me(미국)"),
    ("checkip.amazonaws.com", "infra", "서버 공인 IP 조회", "국외", "AWS(미국)"),
    ("ntp.org", "infra", "시각 동기화(전송 데이터 없음)", "국외", "NTP Pool(국제)"),
    ("registry.npmjs.org", "infra", "패키지 다운로드(설치 시)", "국외", "npm/GitHub(미국)"),
    ("pypi.org", "infra", "패키지 다운로드(설치 시)", "국외", "PyPI/PSF(미국)"),
    ("api.github.com", "infra", "저장소·릴리스 조회", "국외", "GitHub(미국)"),
    # ── 설치 자재 배포처 ──────────────────────────────────────────────
    # 공공기관 온프레미스 구축 스크립트에 반복해서 등장한다(실측: 공공 Flask 프로젝트).
    # 운영 중 데이터 전송이 아니라 **설치 시 다운로드**이므로 국외이전 검토
    # 대상이 아니다. 다만 폐쇄망에서는 이 주소들이 곧 '설치 불가' 지점이므로
    # 미분류로 흘려보내지 않고 무엇을 반입해야 하는지 드러낸다.
    ("nginx.org", "infra", "웹서버 설치본 다운로드(개인정보 전송 아님)", "국외", "F5/NGINX(미국)"),
    ("nginx.com", "infra", "웹서버 벤더 사이트(개인정보 전송 아님)", "국외", "F5/NGINX(미국)"),
    ("nssm.cc", "infra", "윈도우 서비스 등록 도구 다운로드(개인정보 전송 아님)", "국외", "NSSM(국제)"),
    ("slproweb.com", "infra", "Windows OpenSSL 빌드 다운로드(개인정보 전송 아님)", "국외", "Shining Light Productions(미국)"),
    ("python.org", "infra", "Python 설치본 다운로드(개인정보 전송 아님)", "국외", "Python Software Foundation(미국)"),
    ("github.com", "infra", "저장소·릴리스 다운로드(개인정보 전송 아님)", "국외", "GitHub(미국)"),
    # ── CDN·정적 리소스 (폐쇄망에서 화면이 깨지는 축) ──
    ("cdn.jsdelivr.net", "cdn", "정적 파일 로딩(JS·CSS)", "국외", "jsDelivr(국제)"),
    ("unpkg.com", "cdn", "정적 파일 로딩(npm 패키지)", "국외", "Cloudflare/unpkg(미국)"),
    ("cdnjs.cloudflare.com", "cdn", "정적 파일 로딩(라이브러리)", "국외", "Cloudflare(미국)"),
    ("fonts.googleapis.com", "cdn", "웹폰트 로딩(방문자 IP 전달)", "국외", "Google(미국)"),
    ("fonts.gstatic.com", "cdn", "웹폰트 파일 로딩", "국외", "Google(미국)"),
    ("ajax.googleapis.com", "cdn", "정적 파일 로딩(라이브러리)", "국외", "Google(미국)"),
    ("code.jquery.com", "cdn", "정적 파일 로딩(jQuery)", "국외", "jQuery Foundation(미국)"),
    ("cdn.tailwindcss.com", "cdn", "정적 파일 로딩(Tailwind)", "국외", "Tailwind Labs(미국)"),
    # ── 국내 공공·플랫폼 API (공공기관 프로젝트에 실제로 자주 등장) ──
    ("apis.data.go.kr", "gov-api", "공공데이터 조회(요청 파라미터)", "국내", "공공데이터포털(한국)"),
    ("api.odcloud.kr", "gov-api", "공공데이터 조회(요청 파라미터)", "국내", "공공데이터포털(한국)"),
    ("api.vworld.kr", "gov-api", "공간정보 조회(좌표·주소)", "국내", "국토교통부 브이월드(한국)"),
    ("business.juso.go.kr", "gov-api", "주소 검색(입력 주소)", "국내", "행정안전부 주소기반산업지원(한국)"),
    ("openapi.naver.com", "platform", "검색·번역 등 요청 텍스트", "국내", "네이버(한국)"),
    ("dapi.kakao.com", "platform", "지도·검색 요청(좌표·검색어)", "국내", "카카오(한국)"),
    ("maps.googleapis.com", "platform", "지도·좌표 요청", "국외", "Google(미국)"),
    # google.com 계열은 **경로마다 성격이 다르다**(/maps 는 좌표, /recaptcha 는
    # 방문자 IP·토큰). _lookup_host 는 호스트만 보므로 용도를 단정하지 않고
    # 확인 지점을 지목한다. 실측(공공 Flask 프로젝트): 신고 좌표가 `maps?q={lat},{lon}` 링크로
    # 엑셀·화면에 실려 나갔다 — 위치는 재난 업무에서 개인정보성이 있다.
    # 반드시 googleapis 계열 뒤에 둔다(부분 문자열 매칭이라 순서가 판정을 바꾼다).
    ("maps.google.com", "platform", "지도 링크(좌표가 URL 에 실릴 수 있음)", "국외", "Google(미국)"),
    ("www.google.com", "platform", "구글 서비스 요청·링크 — 경로 확인 필요(/maps=좌표, /recaptcha=방문자 IP)", "국외", "Google(미국)"),
    ("google.com", "platform", "구글 서비스 요청·링크 — 경로 확인 필요", "국외", "Google(미국)"),
)

# 카탈로그에 없을 때의 **접미사·형태 기반 추정** — 완전 미분류를 줄인다.
# (판정 근거가 약하므로 data_summary 에 '추정'을 명시한다.)
_HOST_HEURISTICS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"(^|\.)cdn\.|(^|\.)cdn[a-z0-9-]*\.|(^|\.)static\.|(^|\.)assets\."),
     "cdn", "정적 파일 로딩(추정) — 폐쇄망에서 로딩 실패 가능"),
    (re.compile(r"(^|\.)fonts?\."), "cdn", "웹폰트 로딩(추정)"),
    (re.compile(r"\.go\.kr$|\.go\.kr[:/]"), "gov-api", "국내 공공 API(추정) — 요청 파라미터 확인 필요"),
    (re.compile(r"(^|\.)api\.|(^|\.)apis?\."), "api", "외부 API 호출(추정) — 전송 데이터 확인 필요"),
)

# SDK 호출 패턴 → 매핑 호스트(코드에 URL 리터럴이 없어도 잡는다)
_SDK_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"openai\.(?:chat\.completions|completions|embeddings|ChatCompletion|Embedding|images|audio|moderations)|\.chat\.completions\.create"), "api.openai.com"),
    (re.compile(r"\bgenai\.|GenerativeModel|generate_content"), "generativelanguage.googleapis.com"),
    (re.compile(r"\banthropic\b|client\.messages\.create|Anthropic\("), "api.anthropic.com"),
    (re.compile(r"\bcohere\.|ClientV?2?\(\s*api_key"), "api.cohere.ai"),
    (re.compile(r"clova", re.IGNORECASE), "clovastudio.apigw.ntruss.com"),
    (re.compile(r"\bmixpanel\."), "api.mixpanel.com"),
    (re.compile(r"Sentry\.init|sentry_sdk\.init"), "ingest.sentry.io"),
    (re.compile(r"\bstripe\.", re.IGNORECASE), "api.stripe.com"),
)

# 패키지(플러그인) 카탈로그 — (category, data_summary, operator)
# operator: SDK가 데이터를 보내는 운영주체·국가(국외이전 검토용). None=로컬/미상.
_PACKAGE_CATALOG: dict[str, tuple[str, str, str | None]] = {
    "openai": ("ai", "AI: 프롬프트·임베딩을 OpenAI로 전송", "OpenAI(미국)"),
    "anthropic": ("ai", "AI: 메시지 프롬프트를 Anthropic으로 전송", "Anthropic(미국)"),
    "@anthropic-ai/sdk": ("ai", "AI: 메시지 프롬프트를 Anthropic으로 전송", "Anthropic(미국)"),
    "@google/generative-ai": ("ai", "AI: 텍스트를 Google Gemini로 전송", "Google(미국)"),
    "google-generativeai": ("ai", "AI: 텍스트를 Google Gemini로 전송", "Google(미국)"),
    "google-cloud-aiplatform": ("ai", "AI: 데이터를 Google Vertex AI로 전송", "Google(미국)"),
    "cohere": ("ai", "AI: 텍스트를 Cohere로 전송", "Cohere(캐나다)"),
    "mistralai": ("ai", "AI: 프롬프트를 Mistral로 전송", "Mistral AI(프랑스)"),
    "langchain": ("ai", "AI 프레임워크: 외부 LLM 호출 가능", None),
    "langchain-openai": ("ai", "AI 프레임워크: OpenAI 호출", "OpenAI(미국)"),
    "llama-index": ("ai", "AI 프레임워크: 외부 LLM 호출 가능", None),
    "llama_index": ("ai", "AI 프레임워크: 외부 LLM 호출 가능", None),
    "mixpanel": ("analytics", "분석: 사용자 행동 이벤트 전송", "Mixpanel(미국)"),
    "mixpanel-browser": ("analytics", "분석: 사용자 행동 이벤트 전송", "Mixpanel(미국)"),
    "@amplitude/analytics-browser": ("analytics", "분석: 사용자 이벤트 전송", "Amplitude(미국)"),
    "@segment/analytics-node": ("analytics", "분석: 사용자 이벤트 전송", "Twilio Segment(미국)"),
    "@sentry/node": ("error", "에러: 예외·스택을 Sentry로 전송", "Sentry(미국)"),
    "@sentry/browser": ("error", "에러: 예외·스택을 Sentry로 전송", "Sentry(미국)"),
    "@sentry/react": ("error", "에러: 예외·스택을 Sentry로 전송", "Sentry(미국)"),
    "sentry-sdk": ("error", "에러: 예외·스택을 Sentry로 전송", "Sentry(미국)"),
    "stripe": ("payment", "결제: 카드·결제 정보를 Stripe로 전송", "Stripe(미국)"),
}

# ---------------------------------------------------------------------------
# 외부 정적 리소스(CDN) — 폐쇄망(망분리) 배포 시 이 로딩은 반드시 실패한다.
# 화면·기능이 조용히 깨지거나, 통제되지 않은 회선에서는 외부 요청 자체가 정책
# 위반이 될 수 있으므로 인벤토리에 별도 종류(resource)로 표시한다.
# ---------------------------------------------------------------------------
_CDN_CATALOG: tuple[tuple[str, str, str | None], ...] = (
    # (host needle, 리소스 요약, 운영주체)
    ("cdn.jsdelivr.net", "JS/CSS 라이브러리(CDN)", "jsDelivr(국외)"),
    ("unpkg.com", "npm 패키지 번들(CDN)", "unpkg/Cloudflare(미국)"),
    ("cdnjs.cloudflare.com", "JS/CSS 라이브러리(CDN)", "Cloudflare(미국)"),
    ("fonts.googleapis.com", "웹폰트 CSS", "Google(미국)"),
    ("fonts.gstatic.com", "웹폰트 파일", "Google(미국)"),
    ("ajax.googleapis.com", "JS 라이브러리(CDN)", "Google(미국)"),
    ("code.jquery.com", "jQuery(CDN)", "jQuery/StackPath(미국)"),
    ("bootstrapcdn.com", "Bootstrap(CDN)", "jsDelivr/StackPath(국외)"),
    ("cdn.tailwindcss.com", "Tailwind 런타임(CDN)", "Tailwind Labs(미국)"),
    ("esm.sh", "ESM 모듈(CDN)", "esm.sh(국외)"),
    ("cdn.skypack.dev", "ESM 모듈(CDN)", "Skypack(미국)"),
    ("fontawesome.com", "아이콘 폰트(CDN)", "Fonticons(미국)"),
)

# 리소스 로딩 문맥 — 단순 URL 언급(주석·문서 링크)은 잡지 않도록, 실제 로딩
# 구문(src=/​<link href=/@import/url()/ESM import/importScripts)일 때만 매칭.
_RESOURCE_CTX = re.compile(
    r"""(?:\bsrc\s*=\s*["']?https?://
      |@import\s+(?:url\(\s*)?["']?https?://
      |\burl\(\s*["']?https?://
      |\bimport\s+[^;\n]{0,120}?\bfrom\s+["']https?://
      |\bimportScripts\(\s*["']https?://
    )""",
    re.IGNORECASE | re.VERBOSE,
)
# <link href="https://..."> — href는 <link>(스타일시트·폰트 로딩)일 때만.
# <a href>는 리소스 로딩이 아니라 이동 링크라 화면 파손 신호가 아니다.
_LINK_HREF_CTX = re.compile(r"<link\b[^>]*\bhref\s*=\s*[\"']?https?://", re.IGNORECASE)


def _lookup_cdn(host: str) -> tuple[str, str | None]:
    low = host.lower()
    for needle, summary, operator in _CDN_CATALOG:
        if needle in low:
            return summary, operator
    return "외부 정적 리소스(JS/CSS/폰트 등) — 내용 확인 필요", None


def extract_static_resources(code: str, filename: str = "<memory>") -> list[ExternalConnection]:
    """외부 정적 리소스 로딩(CDN 등) 지점을 인벤토리로 추출.

    폐쇄망 표시: 이 항목들은 인터넷 없이 **로딩 자체가 실패**하므로
    airgap_impact="breaks" 로 표시된다 — 내부 사본/사내 미러로 교체 대상.
    """
    lines = code.splitlines()
    agg: dict[str, dict] = {}
    for idx, line in enumerate(lines, start=1):
        if not (_RESOURCE_CTX.search(line) or _LINK_HREF_CTX.search(line)):
            continue
        for m in _URL_RE.finditer(line):
            host = m.group(1)
            if _INTERNAL_HOST.match(host):
                continue
            a = agg.setdefault(host, {"idx": idx, "count": 0})
            a["idx"] = min(a["idx"], idx)
            a["count"] += 1

    out: list[ExternalConnection] = []
    for host, a in agg.items():
        summary, operator = _lookup_cdn(host)
        out.append(ExternalConnection(
            kind="resource",
            target=host,
            category="cdn",
            location=f"{filename}:{a['idx']}",
            data_summary=summary,
            # 카탈로그 등재 CDN은 전부 국외 사업자 — 미등재 호스트는 미상(직접 확인).
            region="국외" if operator else None,
            operator=operator,
            call_count=a["count"],
            review_level="info",
            airgap_impact="breaks",
        ))
    return out


# PII 인접 신호 — 같은 줄에 이 토큰들이 보이면 개인정보 전송 가능으로 표시(warn).
_PII_SIGNAL = re.compile(
    r"주민|rrn|전화|휴대폰|phone|이메일|email|민원|카드|계좌|account|여권|passport"
    r"|password|비밀번호|secret|개인정보|생년월일|birth|주소",
    re.IGNORECASE,
)

# 내부망/로컬 호스트 — 외부 전송이 아니므로 인벤토리에서 제외.
_INTERNAL_HOST = re.compile(
    r"^(?:localhost|127\.|0\.0\.0\.0|::1"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
)

# userinfo(user@) 는 건너뛰고, 호스트는 점을 포함한 실제 도메인만(예: 'x' 같은
# 사용자명·로컬 토큰 오추출 방지).
_URL_RE = re.compile(
    r"https?://(?:[^@/\s]+@)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(/[A-Za-z0-9._/-]*)?",
    re.IGNORECASE,
)
_MODEL_RE = re.compile(r"""model\s*[=:]\s*["']([\w.\-:]+)["']""")
_GENMODEL_RE = re.compile(r"""GenerativeModel\s*\(\s*["']([\w.\-:]+)["']""")
_APIVER_RE = re.compile(r"/(v\d+\w*)")


# 설치 안내 문서·설치 스크립트 — 여기 등장하는 URL 은 **운영 중 데이터 전송이
# 아니라 다운로드 링크**다. 국외이전 검토 대상으로 올리면 실측처럼 노이즈가 된다
# (nginx.org·nssm.cc·python.org 등이 '미분류 외부 전송'으로 잡혔음).
_DOC_SUFFIXES = (".md", ".rst", ".txt", ".adoc")
_INSTALLER_SUFFIXES = (".bat", ".cmd", ".ps1", ".sh", ".bash")

# HTML 은 양쪽 다 가능하다 — Flask 템플릿은 **런타임에 브라우저가 부르는 코드**이고
# 설치 가이드는 문서다. 경로로 구분하되, 애매하면 **런타임으로 본다**:
# 런타임을 문서로 잘못 보면 폐쇄망에서 화면이 깨지는 실제 위험을 숨기게 되지만,
# 문서를 런타임으로 보면 목록에 한 줄 더 나올 뿐이다(과소 판정 방지 우선).
_RUNTIME_PATH_HINTS = ("/templates/", "/static/", "/views/", "/pages/",
                       "/components/", "/public/", "/src/")
_DOC_PATH_HINTS = ("/docs/", "/doc/", "/deploy/", "readme", "guide", "가이드",
                   "설치", "install", "manual", "매뉴얼", "안내")


def _file_context(filename: str) -> str:
    """이 파일이 '실행되는 코드'인가 '문서·설치 스크립트'인가."""
    low = filename.lower().replace("\\", "/")
    name = low.rsplit("/", 1)[-1]
    if any(name.endswith(sfx) for sfx in _DOC_SUFFIXES):
        return "doc-or-installer"
    if any(name.endswith(sfx) for sfx in _INSTALLER_SUFFIXES):
        return "doc-or-installer"
    if name.endswith((".html", ".htm")):
        if any(h in low for h in _RUNTIME_PATH_HINTS):
            return "runtime"        # 템플릿·정적 페이지 — 브라우저가 실제로 로딩
        if any(h in low for h in _DOC_PATH_HINTS):
            return "doc-or-installer"
        return "runtime"            # 애매하면 런타임(과소 판정 방지)
    return "runtime"


def _lookup_host(host: str) -> tuple[str, str, str | None, str | None]:
    """호스트 → (category, data_summary, region, operator).

    1) 카탈로그 정확 매칭 → 2) 접미사·형태 추정 → 3) 미분류.
    추정은 국가·운영주체를 단정하지 않는다(None = 직접 확인 필요).
    """
    low = host.lower()
    for needle, cat, summary, region, operator in _HOST_CATALOG:
        if needle in low:
            return cat, summary, region, operator
    for pattern, cat, summary in _HOST_HEURISTICS:
        if pattern.search(low):
            return cat, summary, None, None
    return "unclassified", "전송 데이터 확인 필요", None, None


def _model_on_line(line: str) -> str | None:
    m = _MODEL_RE.search(line) or _GENMODEL_RE.search(line)
    return m.group(1) if m else None


def extract_api_connections(code: str, filename: str = "<memory>") -> list[ExternalConnection]:
    """코드에서 외부 API 호출 지점을 인벤토리로 추출.

    1) https://host 리터럴, 2) 알려진 SDK 호출(URL 없이도) 둘 다 감지한다.
    내부망 호스트는 제외하고, PII 인접 줄은 review_level=warn 으로 표시한다.
    """
    lines = code.splitlines()
    agg: dict[str, dict] = {}  # 호스트(파일 단위) → 병합 누적값

    for idx, line in enumerate(lines, start=1):
        # 리소스 로딩 구문(src=/​<link href=/@import/ESM import)은 extract_static_resources
        # 가 kind="resource"로 담당한다 — 같은 호스트가 api로 중복 계상되지 않게 건너뜀.
        if _RESOURCE_CTX.search(line) or _LINK_HREF_CTX.search(line):
            continue
        hosts_on_line: list[tuple[str, str | None]] = []  # (host, api_version)
        for m in _URL_RE.finditer(line):
            host = m.group(1)
            if _INTERNAL_HOST.match(host):
                continue
            ver_m = _APIVER_RE.search(m.group(2) or "")
            hosts_on_line.append((host, ver_m.group(1) if ver_m else None))
        # URL 리터럴이 있으면 그게 더 구체적이므로 SDK 매핑은 URL이 없을 때만(중복 방지).
        if not hosts_on_line:
            for pat, mapped_host in _SDK_PATTERNS:
                if pat.search(line):
                    hosts_on_line.append((mapped_host, None))
        if not hosts_on_line:
            continue

        window = " ".join(lines[idx - 1: idx + 2])  # 현재 줄 + 다음 2줄(인자 다중행 대응)
        pii = bool(_PII_SIGNAL.search(window))
        model = _model_on_line(window)
        for host, apiver in hosts_on_line:
            a = agg.setdefault(host, {"idx": idx, "ver": None, "model": None, "pii": False, "count": 0})
            a["idx"] = min(a["idx"], idx)
            a["ver"] = a["ver"] or apiver
            a["model"] = a["model"] or model
            a["pii"] = a["pii"] or pii
            a["count"] += 1  # 호출 지점 수 — 보안팀이 검토 범위(규모)를 알 수 있게

    out: list[ExternalConnection] = []
    for host, a in agg.items():
        cat, summary, region, operator = _lookup_host(host)
        if a["pii"]:
            summary += " · ⚠ 개인정보 인접"
        ctx = _file_context(filename)
        if ctx == "doc-or-installer":
            # 설치 안내·스크립트에 등장하는 주소 — 운영 중 전송이 아니다.
            #
            # 단, **카탈로그가 아는 호스트의 구체적 경고를 지우면 안 된다.**
            # 실측(공공 Flask 프로젝트): 설치 가이드가 `Invoke-RestMethod https://api.ipify.org`
            # 실행을 안내하는데, 통짜 문구가 이를 "다운로드 주소"로 덮어써
            # '서버 공인 IP가 외부로 노출됨' 경고가 보고서에서 사라졌다.
            # 문맥은 덧붙이고, 아는 게 없을 때만 통짜 문구를 쓴다.
            if cat == "unclassified":
                summary = "설치·안내 문서의 다운로드 주소(운영 중 전송 아님)"
            else:
                summary = f"설치·안내 문서에 등장(운영 중 전송 아님) · {summary}"
        out.append(ExternalConnection(
            kind="api",
            target=host,
            category=cat,
            model=a["model"] if cat == "ai" else None,
            version=a["ver"],
            location=f"{filename}:{a['idx']}",
            data_summary=summary,
            region=region,
            operator=operator,
            call_count=a["count"],
            pii_adjacent=a["pii"],
            review_level="warn" if (a["pii"] and ctx == "runtime") else "info",
            context=ctx,
            # 폐쇄망 표시: 외부 API 호출은 데이터 전송 시도 — 차단되어 기능이
            # 멈추거나, 통제되지 않은 회선에서는 정책 위반 전송이 될 수 있다.
            # 문서·설치 링크는 폐쇄망에서 '설치가 안 된다'는 뜻이라 성격이 다르다.
            airgap_impact="egress" if ctx == "runtime" else None,
        ))
    return out


def inventory_packages(packages: list[dict], source: str = "manifest") -> list[ExternalConnection]:
    """매니페스트에서 파싱된 패키지 목록 → 플러그인 인벤토리.

    공급망 취약점 검사가 아니라 *목록화*다(취약점은 scan_dependencies가 별도로 봄).
    알려진 외부 전송 SDK는 종류·요약을 붙이고, 그 외는 '라이브러리(로컬)'로 둔다.
    """
    out: list[ExternalConnection] = []
    for pkg in packages:
        name = pkg.get("name")
        if not name:
            continue
        version = pkg.get("version")
        cat, summary, operator = _PACKAGE_CATALOG.get(
            name, ("library", "라이브러리 (로컬, 외부전송 없음/미상)", None)
        )
        out.append(ExternalConnection(
            kind="package",
            target=name,
            category=cat,
            version=version,
            location=source,
            data_summary=summary,
            region=None,
            operator=operator,
            pii_adjacent=False,
            review_level="info",
            # 외부 전송 SDK(운영주체 특정)만 egress — 로컬 라이브러리는 영향 없음.
            airgap_impact="egress" if operator else None,
        ))
    return out


def dedupe_connections(conns: list[ExternalConnection]) -> list[ExternalConnection]:
    """동일 (kind, target, location, model) 중복 제거 후 우선순위 정렬.

    정렬: warn(⚠) 먼저 → api 먼저 → 국외 먼저 → 종류 → 대상. (리포트 D 결정)
    """
    best: dict[tuple, ExternalConnection] = {}
    for c in conns:
        best.setdefault((c.kind, c.target, c.location, c.model), c)
    _kind_order = {"api": 0, "resource": 1, "package": 2}
    # 검토 우선순위 — 개인정보가 실제로 나갈 가능성이 높은 순.
    _cat_order = {
        "ai": 0, "payment": 1, "analytics": 2, "messaging": 3, "error": 4,
        "platform": 5, "gov-api": 6, "api": 7, "unclassified": 8, "other": 8,
        "cdn": 9, "infra": 10, "library": 11,
    }

    def key(c: ExternalConnection) -> tuple:
        return (
            0 if c.review_level == "warn" else 1,
            # 실제 실행되는 호출을 먼저 — 문서·설치 링크는 검토 대상이 아니다.
            0 if c.context == "runtime" else 1,
            _kind_order.get(c.kind, 9),
            0 if c.region == "국외" else 1,
            _cat_order.get(c.category, 9),
            c.target,
        )

    return sorted(best.values(), key=key)