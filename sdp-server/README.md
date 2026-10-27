# 자체 SDP 서버 — 로컬 통합 기반

별도 외부 패키지 없이 Node.js 24.19.0~24.x에서 실행합니다. 서버는 127.0.0.1에만 열립니다. 공개 운영 서버나 완성된 VPN 제품이 아닙니다.

Windows PC에서 시작하려면 [Windows 초기화·실행 안내](windows/README.md)를 따릅니다. Windows 자체 실행은 미확인이며 개인 키 생성과 실행 도구를 준비한 상태입니다.

## 구현과 확인 범위

- TLS 1.3 상호 인증 + 인증서 지문에 묶인 서명 JWT를 매 요청 검사합니다.
- 운영자가 등록한 가명 사용자·프로젝트·기기와 앱 허용 목록을 대조합니다. JWT 기본 수명은 5분, 최대 15분입니다.
- 기존 앱의 `/alekov/context`, `/alekov/apps`, `/alekov/decision` 계약과 연결합니다.
- `/protected/앱ID/경로`는 허용된 기기의 GET/HEAD만 고정된 로컬 원본 서버로 전달합니다. 임의 목적지, 리다이렉트, 인증 헤더·쿠키 전달을 허용하지 않습니다.
- 기기 회수는 등록부에 저장하며 재시작 후에도 유지합니다. 원본 응답 전달 직전에도 회수 여부를 검사합니다.
- 관리 작업은 로컬 명령으로만 수행합니다. HTTP 등록·토큰 발급·관리 API는 열지 않습니다.
- 원본 서버의 검증 미들웨어가 서명·정확한 경로/방법·신원·시간·일회용 nonce를 검사합니다. 원본 키가 없는 게이트웨이 요청도 거부합니다.
- 선택적인 XDR 연결은 기존 알려진 취약점 판정기를 재사용합니다. 완전한 JNDI 표기는 `alert / 0.72`와 수동 검토 제안을 남깁니다. Wazuh 수준·침해 성공을 만들어내거나 자동 회수하지 않습니다.

가상 신원으로 실제 HTTPS·mTLS·JWT·원본 HTTP·기존 앱 연결을 시험했습니다. 이는 실제 사용자 인증이나 운영 배포의 증거가 아닙니다. 시험 결과와 실행 증거는 작업 공간의 `outputs/agent-sdp-server-review/`에 보관합니다.

## 개인 설정 준비

서버 설정, CA, 서버/기기 인증서와 개인키, JWT 서명 키, 등록부, 발급 토큰은 **저장소 밖의 개인 폴더**에 둡니다. POSIX에서는 관련 파일 권한을 0600으로 제한합니다. Windows 운영에서는 별도 계정·ACL 점검이 필요합니다. 개인키나 토큰을 채팅·로그·Git에 넣지 않습니다.

아래는 설정 형식입니다. 경로와 가명 ID를 실제 운영자가 준비한 값으로 바꾸며, 예시 자체로 연결되지는 않습니다.

```json
{
  "schema": "student.sdp.server.v1",
  "host": "127.0.0.1",
  "port": 7443,
  "caFile": "/private-sdp/ca.pem",
  "certFile": "/private-sdp/server.pem",
  "keyFile": "/private-sdp/server.key",
  "jwtKeyFile": "/private-sdp/jwt.key",
  "issuer": "private-sdp",
  "audience": "private-sdp-client",
  "registryFile": "/private-sdp/registry.json",
  "originKeyFiles": {"vault": "/private-sdp/vault-origin.key"},
  "xdrEvidenceFile": "/private-sdp/xdr-proposals.json",
  "xdrEvidenceKeyFile": "/private-sdp/xdr-evidence.key",
  "apps": [{
    "id": "vault",
    "name": "보호 자료실",
    "upstream": "http://127.0.0.1:8080",
    "subjects": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
  }]
}
```

CA는 서버 인증서와 기기별 clientAuth 인증서를 발급해야 합니다. 서버 인증서의 SAN은 앱 설정의 servername과 일치해야 합니다. JWT 서명 키는 암호학적 난수 32~128바이트의 파일입니다. 테스트는 임시 CA를 생성·삭제하며 시스템 신뢰 저장소를 변경하지 않습니다. 운영 CA 자동 구축·사용자 로그인·인증서 갱신은 이번 구현에 포함하지 않습니다.

원본 서명 키와 XDR 증거 서명 키도 각각 별도의 암호학적 난수 32~128바이트 파일입니다. JWT 키와 재사용하지 않습니다. `originKeyFiles`에 키가 없으면 해당 앱의 게이트웨이 요청은 거부됩니다. XDR의 두 설정은 함께 넣거나 함께 생략합니다. 생략하면 XDR 검사·제안 저장은 실행되지 않습니다. 증거 파일은 첫 시작에만 신규 생성하며 최대 256개 제안/1MiB로 제한합니다.

원본 Node 웹 서버의 모든 보호 경로 앞에 `src/origin-proof.mjs`의 `createProtectedOriginHandler({key,appId}, handler)`를 설치합니다. key는 게이트웨이와 공유하는 해당 앱의 원본 서명 키입니다. handler의 세 번째 인자가 검증된 가명 신원이며, 요청 헤더의 신원 주장을 직접 신뢰하지 않습니다. 서명 없는 직접 접근은 403입니다. 기존 앱의 자료 소유권 검사는 그대로 유지해야 하며, 가명 ID를 DB 사용자 ID로 추측해서 연결하면 안 됩니다.

이 검증기는 원본 프로세스마다 최근 nonce를 메모리에 보관합니다. 재시작이나 여러 원본 프로세스 사이에는 nonce 기록이 공유되지 않습니다. 운영에서는 단일 프로세스 범위를 지키거나 공유 재전송 방지 저장소를 구현하고, 별도로 네트워크 격리도 적용해야 합니다.

## 실행 순서

프로젝트 루트에서 실행합니다. 아래 경로는 준비한 외부 설정 경로로 바꿉니다. init은 신규 등록부만 만들고 기존 파일을 덮어쓰지 않습니다.

```sh
npm --prefix sdp-server run admin -- /private-sdp/server.json init
npm --prefix sdp-server run admin -- /private-sdp/server.json enroll aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa sample-project 1111111111111111 /private-sdp/device.pem vault
npm --prefix sdp-server run admin -- /private-sdp/server.json issue 1111111111111111 /private-sdp/access-token.txt
npm --prefix sdp-server start -- /private-sdp/server.json
```

enroll은 운영자가 인증서 소유자와 승인 사실을 확인한 뒤 실행합니다. 가명 문자열을 넣는 행위 자체가 실제 사용자 신원 확인은 아닙니다. issue는 토큰을 0600 신규 파일로 저장하며 출력하지 않습니다. 토큰 갱신은 별도 신규 파일을 발급한 뒤 앱 자격 교체 절차로 처리합니다.

기존 `on-client/docs/SDP_HOST_CONNECTION.md` 형식으로 앱 설정을 별도 준비합니다. 서버 CA, 등록한 기기의 인증서·개인키, 발급 토큰, 프로젝트와 서버 주소를 지정합니다. 학생 앱은 다음처럼 명시적으로 연결합니다.

```sh
npm --prefix on-client run student -- --sdp-host-config /private-sdp/client.json
```

앱은 신원·허용 앱·접근 판정을 조회합니다. 접근 판정 성공은 원본 자료를 실제로 읽었다는 뜻이 아닙니다. 브라우저에 기기 개인키나 JWT를 전달하지 않습니다. 이번 단계에는 브라우저에서 보호 앱을 자동으로 여는 자격 중계 기능이 없습니다. 미구현 기록·기기·세션 조회는 오류로 표시되며 가짜 성공 목록을 만들지 않습니다.

기기를 회수하려면 다음을 실행합니다. 기존 토큰도 이후 요청에서 거부됩니다.

```sh
npm --prefix sdp-server run admin -- /private-sdp/server.json revoke 1111111111111111
npm --prefix sdp-server test
```

## XDR 제안 검토와 명시적 회수

운영자 전용 외부 응답 설정은 서버 설정과 별도입니다.

```json
{
  "schema": "student.sdp.response.v1",
  "registryFile": "/private-sdp/registry.json",
  "evidenceFile": "/private-sdp/xdr-proposals.json",
  "evidenceKeyFile": "/private-sdp/xdr-evidence.key"
}
```

제안 목록을 검토한 뒤, 실제 목록의 eventId 하나를 지정해 승인합니다. 아래 `EVENT_UUID`는 목록에서 확인한 번호로 바꿉니다. 명령에 대상 기기를 직접 전달할 수 없으며 서명된 서버 기록으로만 결정합니다.

```sh
npm --prefix sdp-server run respond -- --config /private-sdp/response.json --list
npm --prefix sdp-server run respond -- --config /private-sdp/response.json --event EVENT_UUID --approve
```

정상 요청과 약한 점검 도구 흔적만으로는 회수 제안을 만들지 않습니다. 제안은 원문 경로·헤더·토큰을 저장하지 않습니다. 승인 전에는 권한이 유지되고, 승인 후 해당 기기의 기존 토큰이 거부됩니다. 15분이 지난 제안이나 등록부 세대/기기 결속이 바뀐 제안은 거부합니다. 재승인은 새 집행으로 계산하지 않으며, 회수 후 기록 저장 실패는 미확정 상태와 실패 종료 코드로 구분합니다.

현재 연결 범위는 알려진 취약점 모듈 하나입니다. 저장소의 다른 XDR 모듈과 운영 Wazuh 수집까지 연결됐다는 뜻은 아닙니다. 배포할 때 저장소의 `xdr/known-cve/decide.mjs`도 함께 보존해야 합니다.

## 무료 AI 사용 방향

`ai/local-advisor.mjs`는 기본 비활성화된 선택 기능입니다. 로컬 Ollama의 `/api/chat`에 명시적으로 선택한 모델과 짧은 규칙 코드·집계값만 보냅니다. 외부 API 키나 유료 공급자로 자동 전환하지 않습니다. 실제 모델 다운로드·설치·추론은 아직 하지 않았습니다. 로컬 모델도 메모리·연산·전력 비용과 모델별 이용 조건은 확인해야 합니다.

실행 환경에서 `createLocalAdvisor({enabled:true,model:'설치한-로컬-모델명'})`을 명시하고 검증된 사건 요약에만 `explain()`을 호출합니다. 현재 HTTP 접근 경로와 연결하지 않은 보조 모듈입니다. AI 실패는 접근 통제에 영향을 주지 않으며, 설명 결과는 권한 변경이나 명령으로 실행하지 않습니다. 로컬 런타임의 클라우드 전달을 끄는 것은 별도 운영 설정입니다.

공식 규격: https://docs.ollama.com/api/introduction · https://docs.ollama.com/api/chat

## 운영 전 남은 일

배포 환경 선정, 실제 사용자 로그인 및 기기 등록·발급·갱신, 원본 서버 전체 경로에 검증기 적용과 네트워크 격리, 요청 제한·감사 저장·다른 XDR 모듈/운영 사건 수집이 필요합니다. 로컬 원본 시험에서는 우회가 거부됐지만 기존 공개 Vercel 자료실에는 아직 이 검증기를 적용하지 않았습니다. 서버 중복 실행·다중 호스트 등록부 공유도 지원 범위 밖입니다.
