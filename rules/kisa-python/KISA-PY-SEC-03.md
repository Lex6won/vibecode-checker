---
id: KISA-PY-SEC-03
title_ko: Python 중요한 자원에 대한 잘못된 권한 설정 - os.chmod 0o777/0o666 world-writable
title_en: Incorrect permission assignment for critical resource (os.chmod with world-writable mode)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 3. 중요한 자원에 대한 잘못된 권한 설정
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-23-PERM
cwe: [CWE-732, CWE-276]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [batch-job, data-pipeline, web-app]
related_baseline: [MOIS-49-SEC-03]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) os.chmod / os.fchmod / os.lchmod 에 world-writable 8진수 모드 (0o7??, 0o?7?, 0o??7 의 일부) — 핵심 패턴은 0o777, 0o776, 0o775, 0o774, 0o666, 0o667, 0o646, 0o646, 0o646
    - "os\\.(?:chmod|fchmod|lchmod)\\s*\\([^)]*,\\s*0o[0-7]?[0-7]?[67]\\s*\\)"
    # 2) 8진수가 0o777 / 0o666 / 0o755 가 아닌 *world write 비트* 가 켜진 경우 — 일반화 패턴
    - "os\\.(?:chmod|fchmod|lchmod)\\s*\\([^)]*,\\s*0o7{2,3}\\s*\\)"
    - "os\\.(?:chmod|fchmod|lchmod)\\s*\\([^)]*,\\s*0o6{2,3}\\s*\\)"
    # 3) stat 상수 합성으로 world write/exec 부여 (S_IWOTH, S_IXOTH, S_IRWXO 단독)
    - "os\\.(?:chmod|fchmod|lchmod)\\s*\\([^)]*stat\\.(?:S_IWOTH|S_IXOTH|S_IRWXO)"
    # 4) Pathlib chmod 도 동일하게 잡음
    - "\\.chmod\\s*\\(\\s*0o7{2,3}\\s*\\)"
    - "\\.chmod\\s*\\(\\s*0o6{2,3}\\s*\\)"
    # 5) shutil/umask 로 전체 시스템 umask 를 0 으로 — 모든 파일이 world-writable
    - "os\\.umask\\s*\\(\\s*(?:0|0o0+)\\s*\\)"
  category: kisa-secure-coding
  why_it_matters: >-
    KISA 가이드 안전하지 않은 예시 `os.chmod('/root/system_config', 0o777)` 한 줄은
    *시스템 설정 파일* 에 *모든 사용자가 읽기·쓰기·실행* 권한을 부여합니다.
    공격자가 *비특권 계정* 만 얻어도 설정 파일을 수정해 권한 상승, 백도어 삽입,
    크론 트리거가 가능합니다. 가이드 안전 예시는 동일 파일에 `0o700` (소유자
    전용 rwx) 을 부여합니다. 공유 PC·다중 사용자 서버·컨테이너 볼륨에서는
    *최소 권한 원칙* 을 코드로 강제해야 합니다.
  public_sector_impact:
    - 행정 서버 공용 디렉터리에 world-writable 설정 파일 → 권한 상승
    - 망분리 공용 PC 에서 다른 직원이 비밀번호·세션 파일 변조
    - 컨테이너 볼륨 마운트 시 호스트 측 root 가 아닌 사용자가 설정 변조
  safe_fix: |
    *최소 권한 원칙* 으로 모드를 조정하세요.
        # 설정 파일: 소유자만 읽기/쓰기 (0o600)
        os.chmod('/root/system_config', 0o600)
        # 실행 파일: 소유자만 rwx (0o700), 그룹에 한해 r-x 허용 시 (0o750)
        os.chmod('/usr/local/bin/job', 0o700)
        # umask 는 기본값 0o022 또는 더 엄격한 0o077 유지
        os.umask(0o077)
    Pathlib 도 동일:
        from pathlib import Path
        Path('config.yaml').chmod(0o600)
    민감 파일을 새로 만들 때는 `os.open(path, O_WRONLY|O_CREAT|O_EXCL, 0o600)`
    + tempfile.mkstemp() 처럼 *생성 시점부터* 엄격한 모드를 지정하세요.
  references:
    - KISA Python 가이드 제2절 3
    - MOIS-49-SEC-03
    - CWE-732, CWE-276
    - https://docs.python.org/3/library/os.html#os.chmod
    - OWASP File Permissions
  can_auto_fix: false
examples:
  language: python
  positive:
    - "os.chmod('/root/system_config', 0o777)"
    - "os.chmod(path, 0o666)"
    - "Path('config.yaml').chmod(0o777)"
    - "os.chmod(p, stat.S_IRWXO)"
    - "os.umask(0)"
  negative:
    - "os.chmod('/root/system_config', 0o700)"
    - "os.chmod(path, 0o600)"
    - "Path('config.yaml').chmod(0o640)"
    - "os.umask(0o077)"
---

## 무엇이 위험한가
유닉스 파일 권한 8진수의 마지막 자리(others)는 *시스템의 모든 비특권 사용자* 에게 해당 권한을 부여합니다. `0o777` (rwxrwxrwx) 와 `0o666` (rw-rw-rw-) 은 *world-writable* 상태로, 같은 호스트의 임의 사용자가 파일을 *수정* 할 수 있게 만듭니다.

KISA 가이드 안전하지 않은 예시는 *시스템 설정 파일* 에 `0o777` 을 부여합니다:
```python
os.chmod('/root/system_config', 0o777)
```
공격자가 *비특권 셸* 만 확보해도 (예: 웹쉘, 다른 취약 서비스, 인사이더) 이 파일을 수정해 *권한 상승* 으로 이어집니다. 시스템 초기화 스크립트가 이 설정을 읽어 명령을 실행한다면 백도어 삽입까지 가능합니다.

공공기관 사례:
- 행정 서버의 배치 작업 폴더가 `0o777` 로 생성되어 *어느 직원 계정으로도* 배치 스크립트 변조 가능
- 망분리 공용 PC 에서 한 직원이 만든 임시 파일이 `0o666` 으로 저장되어 다른 직원이 *주민 자료* 를 읽거나 변조
- Docker 볼륨 마운트 시 컨테이너 내부에서 `chmod 777` 했는데 호스트의 일반 사용자에게도 권한이 부여되어 호스트 측 권한 상승

가이드 안전 예시:
```python
os.chmod('/root/system_config', 0o700)   # 소유자 전용 rwx
```

## 안전한 패턴 (가이드 원문 인용)
```python
import os

def write_file():
    # 소유자 외에는 아무런 권한을 주지 않음.
    os.chmod('/root/system_config', 0o700)
    with open('/root/system_config', 'w') as f:
        f.write("your config")
```

민감 파일 생성 시 *처음부터* 엄격한 모드 지정 (race 방지):
```python
import os, tempfile
from pathlib import Path

# tempfile 은 기본 0o600 으로 생성
fd, path = tempfile.mkstemp(prefix='svc-', suffix='.conf')
os.write(fd, b'secret=...')
os.close(fd)

# 또는 os.open 으로 명시
fd = os.open('/etc/app/secret.conf',
             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

# Pathlib
Path('/etc/app/secret.conf').chmod(0o600)

# 프로세스 단위 umask 도 함께 강화
os.umask(0o077)   # 새로 만드는 파일은 기본 0o600 이 됨
```

권한 매핑 가이드:
- `0o600` (rw-------) : 시크릿, DB 패스워드 파일, 키 파일
- `0o640` (rw-r-----) : 그룹 공유 설정
- `0o700` (rwx------) : 개인 실행 파일, 캐시 디렉터리
- `0o750` (rwxr-x---) : 그룹 공유 실행 파일
- `0o755` (rwxr-xr-x) : 공개 실행 파일 (단, world-write 비트는 절대 켜지 말 것)

## False positive 주의
- 본 룰은 `os.chmod / os.fchmod / os.lchmod` 와 Pathlib `.chmod()` 에서 *world-write 비트(2)나 world-exec 비트(1)* 가 켜진 8진수 모드를 잡습니다. `0o755` 같이 world-read/exec 만 켜진 경우는 매칭되지 않습니다.
- 변수로 모드를 받는 경우(`os.chmod(p, mode)`) 는 정적 regex 로 위험성을 판별하기 어려워 매칭하지 않습니다. 모드 변수가 외부 입력에서 오면 별도 코드 리뷰가 필요합니다.
- `stat.S_IRWXO`, `stat.S_IWOTH`, `stat.S_IXOTH` 같이 상수 합성으로 권한을 부여하는 경우도 매칭됩니다 — 정당한 사유가 있다면 `# gvskb: ignore KISA-PY-SEC-03` 로 억제하세요.
- `os.umask(0)` 은 *전체 프로세스의 기본 마스크를 0으로* 만들어 이후 만들어지는 모든 파일이 world-writable 이 되므로 위험합니다 — 패턴 #5 에서 잡습니다.
- 컨테이너 진입 스크립트에서 일시적으로 `chmod 777` 후 즉시 더 좁은 권한으로 재설정하는 경우는 *첫 호출이 매칭* 됩니다. 의도된 보수적 detection 이며, 코드 리뷰 후 ignore 처리하세요.
