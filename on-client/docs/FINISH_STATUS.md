# 1~7일차 완성본 작업 현황 · Windows 실검증 대기

기준 원격 22단계와 첫 보완본을 보존하고 학생 소유 모듈을 추가했습니다. 제공 src/server.mjs, public 화면·CSS, 인증 어댑터는 수정하지 않았습니다.

| 과제 | 구현·검증 결과 |
|---|---|
| 1. 기존 앱 실행·핵심 3기능 | 기존 시험과 예제 브라우저 확인. 접속 현황·기록 근거·제안/실행 분리를 유지 |
| 2. CPU·메모리·디스크 | 일반 권한 수동 실측. CPU Δ샘플 %, 메모리 bytes, 디스크 일반 사용자 가용 bavail. Mac 실측 확인 |
| 3. 연결·방화벽·Windows 기록 | 주소 없이 네트워크 구성 개수. Windows 방화벽 ActiveStore 설정 및 System/Application 최근24시간 경고·오류 합계 읽기 구현. Windows 실검증 대기, Mac에서는 확인 불가 |
| 4. 화면·다시 조회·오류 | 실측 4카드·단위·시각·최근8회 메모리 이력·취소/시간초과·늦은 응답 폐기. 예제/SDP 미연결과 분리. 기존 CSS 재사용 |
| 5. 다른 환경 재현 | 독립 합성/HTTP 보안 시험 포함 전체87건 통과. 브라우저에서 실측·재조회 이력 확인. Windows 사람 직접 확인 대기 |
| 6. 포장·바로가기 | 학생용 package:portable와 .cmd/.sh 시작기, 현재 사용자 Windows 바로가기 생성기. 공식 승인 host 패키지와 구분. Windows .lnk 실행 미확인 |
| 7. 시연·한계·근거 | 실제 Mac 화면·독립 시험 기록·실행 안내 정리. 실제 Windows 캡처·운영 연동·공식 최종 제출은 미실행 |

## Windows 명령 프롬프트

Git과 Node.js24(수업 기준24.19.0)를 준비합니다. 기존 폴더를 지우지 말고 새 폴더로 받습니다.

```bat
git clone https://github.com/jjeya-hannam/choi-bujang-secret-vault.git gamst-finish-windows
cd gamst-finish-windows\on-client
node --version
npm run student:demo
```

오류가 나면 다음 명령으로 넘어가지 않습니다. gamst-finish-windows 폴더가 이미 있으면 덮어쓰거나 삭제하지 말고 다른 새 폴더 이름을 사용합니다. 외부 npm 의존성이 없으므로 이 앱 실행에 npm install은 필요하지 않습니다.

http://127.0.0.1:5189 를 엽니다. 보호 현황의 「내 PC 상태 조회」를 누릅니다. CPU·메모리·디스크·네트워크 값은 실제 로컬 관측이며 보안 기록은 demo입니다. 한 번 더 조회하여 이력을 확인합니다. Windows 방화벽과 기록의 숫자 또는 확인 불가 사유를 확인하세요. 경고·오류 건수는 공격 탐지 결과가 아닙니다. SDP 실제 연결은 준비되지 않았습니다. 종료는 Ctrl+C입니다.

예제 보안 기록도 원하지 않으면 `npm run student`를 실행합니다. 기존 제공 실행기 `npm start`와 `npm run demo`도 유지하며, 이 실행기에는 PC 경로가 없어 확인 불가 안내가 표시됩니다.

선택적 검사: `npm test`, `npm run check`. 선택적 Windows 바탕화면 바로가기는 앱 폴더에서 `powershell -NoProfile -File tools\create-shortcut.ps1`입니다. 기존 바로가기는 덮어쓰지 않습니다. 실행 정책이 막으면 정책을 낮추거나 관리자 권한으로 우회하지 말고 오류만 알려주세요. .cmd를 직접 실행할 수도 있습니다.

포장: `npm run package:portable -- --out "..\..\gamst-portable-output"`. 출력 상위 폴더가 존재하고 마지막 폴더는 아직 없어야 합니다. source-app.tar.gz, PORTABLE_SOURCE_MANIFEST.json, SOURCE_RUN.md는 학생용이며 공식 완성본4파일을 대신하지 않습니다. 비밀·자격·DB·로그·Git·테스트는 묶음에서 제외합니다.

## 시연과 보안 한계

1. 앱 첫 화면의 SDP 연결 없음과 예제 여부 확인.
2. PC 조회 → 실측4카드·단위·시각 확인 → 수동 재조회 이력 확인.
3. Windows 항목의 성공/권한 실패를 확인. 실패·미지원에 예시 값을 채우지 않음.
4. 예제 업무 앱에서 허용·거부·추가 확인 구분. AI/조치가 실행됐다고 주장하지 않음.
5. Ctrl+C 종료, 시작기로 재실행. 서버는127.0.0.1만 사용.

로컬 HTTP는 정확한 Host·Origin·사용자 정의 헤더·GET·고정 경로, 동일 출처, no-store, 1개 점검·시간 제한을 적용합니다. 다른 사이트의 단순 요청을 거부하지만 이미 PC에서 실행되는 악성 프로그램을 인증으로 차단하는 수단은 아닙니다. 관리자 권한·보안 설정 변경·외부 전송·실제 AI 자격 읽기를 추가하지 않았습니다. 방화벽·이벤트는Windows 고정 읽기 명령만 사용하고 개인 정보·IP·MAC·로그 내용은 반환하지 않습니다.

검증 환경은 macOS/Node22.22.2입니다. Windows/Node24 실제 실행, 회사 SDP·계정·유료 AI·조치 집행·OSV 실조회·공식 포장·최종 제출은 미확인입니다. 실제 Windows 결과를 확인한 뒤 기록을 갱신합니다.
