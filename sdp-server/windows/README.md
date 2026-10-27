# Windows PC에서 시작하기

현재 구성은 **이 PC 안에서만 사용하는 로컬 검증 환경**입니다. 인터넷·다른 PC에서 접근할 수 있는 운영 배포는 아직 아닙니다. PC가 꺼지거나 절전 상태이면 서버도 사용할 수 없습니다. 실제 Windows 실행은 미확인이며, 아래 도구의 공통 로직과 실제 인증서/HTTPS 연결은 macOS Node24.19.0에서 시험했습니다.

## 준비

- Node.js 24.19.0 이상 24.x와 Git.
- 이미 설치돼 있고 출처를 신뢰하는 OpenSSL 실행 파일의 절대 경로. 아래 Git 경로는 예시이며 파일 존재를 확인해야 합니다. 도구는 소프트웨어를 다운로드하거나 설치하지 않습니다.
- 최신 소스의 `feat/local-sdp-server` 브랜치. 기존 작업 폴더는 덮어쓰지 말고 새 폴더를 사용합니다.

CMD에서:

```bat
git clone --branch feat/local-sdp-server --single-branch https://github.com/jjeya-hannam/choi-bujang-secret-vault.git sdp-windows
cd sdp-windows
node --version
```

## 1. 개인 설정을 한 번 생성

다음은 OpenSSL이 예시 위치에 실제 설치돼 있을 때의 명령입니다. 개인 폴더 `C:\SDP-Private`는 **존재하지 않아야** 합니다. 실패해 일부 파일이 남았으면 지우거나 재사용하지 말고 원인을 확인한 뒤 다른 새 폴더를 지정합니다.

```bat
node sdp-server\tools\init-local.mjs --private-dir "C:\SDP-Private" --openssl "C:\Program Files\Git\usr\bin\openssl.exe"
```

성공 표시는 `SDP_LOCAL_INITIALIZED`입니다. CA·서버/기기 인증서·서로 다른 서명 키·등록부·server.json/client.json/response.json·짧은 접속 토큰을 해당 PC의 개인 폴더에 만듭니다. 생성 신원은 실제 사용자 로그인으로 확인한 신원이 아니라 로컬 예제용 가명입니다. 시스템 신뢰 저장소에는 인증서를 설치하지 않습니다.

다른 일반 계정의 접근과 상위 경로 교체 권한을 검사합니다. Windows 정책이 PowerShell 파일 실행을 막으면 안전하게 실패합니다. 실행 정책을 자동 변경하거나 우회하지 않습니다. 이런 오류에서는 비밀값을 제외한 상태 코드만 전달하세요.

## 2. 별도 CMD 창 세 개에서 실행

각 창에서 저장소 폴더로 이동합니다.

**첫 번째 창: SDP 서버**

```bat
sdp-server\windows\start-server.cmd
```

설정 경로 질문에는 따옴표 없이 `C:\SDP-Private\server.json`을 입력합니다. 이 실행기는 Node 버전·개인 파일·ACL을 읽기 전용으로 검사한 뒤 시작합니다. `SDP_LOCAL_READY`가 준비 표시입니다.

**두 번째 창: 보호 예제 원본**

```bat
node sdp-server\tools\demo-origin.mjs "C:\SDP-Private\server.json"
```

이 서버는 127.0.0.1:8080에서 고정 예제만 제공합니다. 실제 자료실·DB를 연결하거나 읽지 않습니다. 서명 없는 직접 접근은 403이어야 합니다.

**세 번째 창: 기존 접속 앱**

```bat
sdp-server\windows\start-client.cmd
```

설정 경로 질문에는 `C:\SDP-Private\client.json`을 입력합니다. 브라우저에서 http://127.0.0.1:5189 를 열고 신원·허용 앱·접근 판정을 확인합니다. 허용 판정은 실제 원본 자료 조회 결과와 구분합니다. 기록·기기·세션 중 지원하지 않는 조회가 확인 불가로 보이는 것은 연결 성공으로 계산하지 않습니다.

종료는 각 창의 Ctrl+C입니다. 시작 프로그램·작업 스케줄러·방화벽·공유기·전역 환경 변수는 바꾸지 않습니다.

## 토큰 만료와 실제 운영 전 남은 일

첫 토큰은 **5분 후 만료**됩니다. 초기 시연용이며 무인 장기 로그인·자동 갱신은 아직 구현하지 않았습니다. 만료는 정상적인 거부 결과이고 인증 검증을 꺼서 해결하지 않습니다.

수동 갱신 시 개인 등록부에서 로컬 기기 ID를 확인한 뒤 기존 `admin issue`로 **새 이름**의 토큰 파일을 발급하고, client.json의 tokenFile 경로를 새 파일로 바꾼 후 앱을 다시 시작합니다. 토큰 내용을 복사해 채팅에 보내거나 브라우저 저장소에 넣지 않습니다. 기존 파일을 덮어쓰거나 기기를 다시 등록하는 방식으로 우회하지 않습니다. 구체적인 명령과 XDR 승인 대응은 상위 `sdp-server/README.md`를 참고하세요.

Windows에서 실제 시작·허용/거부·종료를 확인한 뒤 실제 사용자 인증·갱신, 보호 대상 웹과 가명 신원 연결, 서버의 외부 접근 범위를 결정해야 합니다. 기존 공개 Vercel 자료실에는 아직 원본 검증기를 적용하지 않았습니다. 무료 AI 연결부는 계속 기본 비활성화이며 실제 모델 실행은 별도입니다.

ACL 읽기 규격: [Microsoft Get-Acl](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-5.1).
