# gamst 학생 설명서 — 21단계

문서 상태: 검증 중. 2026-10-25 포털에서 19·20단계 통과와 21단계 공개를 확인했습니다. 이후 21단계 공식 통과와 22단계 공개도 확인했습니다. 실제 실행 지원 범위는 아래와 같고 22단계 기록은 GAMST_FINAL_HANDOVER.md를 참조합니다. 19단계 실제 집행 연결과 22단계 동일 최종 소스의 누적 재현·공식 접수까지 완료·수용되기 전에는 v1.0으로 표시하지 않습니다.

## 작업 폴더와 실행

현재 작업 폴더는 `C:\Users\pc\Documents\Codex\2026-10-19\qk\outputs\gamst\on-client`입니다. 새 PowerShell 창에서 이 폴더를 작업 위치로 연 뒤 아래 명령을 한 줄씩 실행합니다. 다른 위치에 복구했다면 해당 `on-client` 폴더를 사용합니다.

이번 작업에서는 이미 설치된 Node.js v24.22.1을 사용했습니다. 제공 `package.json`의 검수 기준은 24.19.0이며 두 버전은 같지 않습니다. 24.19.0에서의 실행은 미확인입니다. Workbench를 새로 설치할 필요가 없고 앱 실행 중 상시 실행할 필요도 없습니다. 이번 작업에서 외부 npm 패키지를 설치하지 않았습니다.

검증한 환경은 Windows의 PowerShell 7.6.5, Node.js v24.22.1입니다. Git은 저장소 복구·커밋에 사용하며 이 앱 실행 자체에 외부 npm 의존성은 없습니다. 다른 OS·브라우저·Node 버전의 동작은 미확인입니다.

아래 네 명령은 에이전트가 실행한 명령입니다. 사용자가 직접 재현한 결과는 별도 기록합니다.

```powershell
node --version
node --check student/extension.mjs
node --test test/*.test.mjs
node src/server.mjs --demo
```

20단계 최종 소스의 문법 검사는 정상이며 모의DOM 검사 40개가 통과했습니다. 별도 빈 폴더에서 같은 소스의 66개 파일 일치와 예제→연결 없음→예제 서버 재시작을 확인했습니다. 브라우저 실제 조작은 내장 브라우저 연결 시간 초과로 미확인입니다. 마지막 명령은 `http://127.0.0.1:5189`에서 예제 서버 시작을 확인했습니다. 실행 창을 유지하고 브라우저로 주소를 엽니다. 종료는 실행 창에서 Ctrl+C를 누릅니다. 예제 시작 확인은 실제 계정·AI 인증·조치 실행·OSV 연결 확인이 아닙니다.

설치 명령이나 실제 연결용 설정 명령은 이번에 실행하지 않아 기재하지 않았습니다. 다른 PC에서 Node.js가 없거나 지정 버전 준비가 필요하면 설치 절차는 확인 필요입니다. 제공 실행·연결 안내는 `STUDENT_LAUNCH_GUIDE.md`, `AI_SETUP_GUIDE.md`, `CONNECTION_TROUBLESHOOT.md`를 참고합니다. 비밀값은 채팅·문서·코드에 넣지 않습니다.

## 폴더 구조와 정상 시작·종료·재실행

```text
저장소 최상위/             Git 커밋·제출 위치, 기존 1~12단계 보존
  README.md                이 저장소의 학생 앱 안내
  on-client/               앱 실행용 PowerShell 작업 위치
    package.json           start/demo/check/test와 기준 버전
    public/                제공 화면
    src/                   제공 앱 서버·접근 제어/XDR·AI·조치·OSV 연결
    student/extension.mjs  학생 표시 함수 8개
    student/engine-adapter.mjs  제공 호스트 연결 자리
    test/                  합성 DOM 회귀 검사
    docs/GAMST_*.md        학생 설명서·확인 기록
```

1. 파일 탐색기에서 `on-client` 폴더를 열고 주소 표시줄에 PowerShell을 입력해 실행하거나, PowerShell의 작업 위치가 이 폴더인지 확인합니다. Git 커밋은 한 단계 위 저장소 최상위를 기준으로 합니다.
2. 위의 버전·문법·모의 검사 명령을 순서대로 실행합니다. Node가 없거나 기준 버전 설치가 필요하면 제공 `STUDENT_LAUNCH_GUIDE.md`의 설치 안내를 따르되 이번 기록에 새 설치 성공을 추가하지 않습니다.
3. `node src/server.mjs --demo` 실행 후 기본 정상 시작 신호는 `케셰브 예제: http://127.0.0.1:5189`입니다. 프로젝트 별칭은 gamst이지만 제공 서버의 제목은 케셰브로 유지했습니다. ON_PORT를 설정한 환경은 시작 신호의 포트가 다를 수 있습니다.
4. 그 PowerShell 창을 유지하고 PC 브라우저로 표시된 주소를 엽니다. 예제 자료 표시와 세 메뉴를 확인합니다. 실제 계정 연결 성공을 의미하지 않습니다.
5. 종료는 서버를 실행한 창에서 Ctrl+C입니다. 재실행은 같은 폴더에서 같은 demo 명령을 다시 실행합니다. 포트 사용 중 오류가 나면 기존 창·프로세스의 소유자를 먼저 확인하고 임의의 다른 서버를 종료하지 않습니다.

에이전트는 첫 예제 서버를 Ctrl+C로 종료했으며, 새 폴더 검증에서는 직접 시작한 Node 프로세스만 종료한 뒤 재실행했습니다. 현재 실행 명령은 설치·관리자 권한·Windows 보안 보호 해제를 요구하지 않습니다. 제공 start-alekov.ps1 기본 실행은 개인 연결 준비를 할 수 있으므로 이번 오프라인 검사에서는 사용하지 않았습니다.

## 구성도

```text
[브라우저]
  public/index.html, public/app.js
  student/extension.mjs
  http://127.0.0.1:5189
       │ 제공 UI가 요청, 학생 함수는 표시
       ▼
[앱 서버]
  src/server.mjs
  http://127.0.0.1:5189
       ├── [기존 접속·XDR 서버]
       │     연결 파일: src/engine/sdp-host.mjs
       │     학생 연결 자리: student/engine-adapter.mjs
       │     실제 외부 주소: 미설정·연결 미확인
       │
       └── [CLCO 수업용 AI]
             연결 파일: src/ai/service.mjs, vendor/clco-http.mjs
             실제 외부 주소·앱 권한: 미설정·연결 미확인
```

표시한 파일은 `on-client` 기준 실제 파일 경로입니다. 외부 서버가 구성도에 있다는 사실만으로 연결됐다고 판단하지 않습니다. 현재 학생 어댑터 기본값은 disconnected입니다. 예제 모드는 합성 자료를 보여 줍니다. OSV 취약점 조회는 별도 `src/vulnerabilities/osv.mjs`와 `src/vulnerabilities/project-scan.mjs`가 담당하며 실제 조회는 미확인입니다. 승인된 공개 패키지 목록 없이 비공개 패키지를 외부로 보내지 않습니다.

## 제공 코드와 학생 구현 경계

제공 파일의 기준 목록과 원본 해시는 `.on-starter-manifest.json`의 `sourceHashes`입니다. 이 목록은 출처 비교 기준이며 학생 성취 목록이 아닙니다. `student/extension.mjs`와 `student/engine-adapter.mjs`도 제공 시작 틀에 포함됩니다. 이번 작업의 학생 구현은 그중 `student/extension.mjs`의 표시 함수입니다.

| 영역 | 파일 | 역할·이번 작업 범위 |
|---|---|---|
| 제공 UI | `public/app.js`, `public/index.html`, `public/style.css`, `public/ai-connect.mjs`, `public/vulnerabilities-view.mjs` | 메뉴, 새로고침, 네트워크 요청, AI 연결·취소, 조치 확인 및 결과 조회. 학생 구현 성취로 세지 않으며 수정 대상이 아님 |
| 제공 서버 | `src/server.mjs`, `src/engine.mjs`, `src/engine/`, `src/ai/`, `src/actions/`, `src/vulnerabilities/`, `vendor/` | 인증·원천 연결·서버 검증·조치·OSV 처리. 수정 대상이 아님 |
| 제공 설정·문서 | `package.json`, `.env.example`, 기존 `docs/`, `.on-starter-manifest.json` | 계약·실행 기준. 기존 문서와 인증 설정을 변경하지 않음 |
| 학생 표시 | `student/extension.mjs` | 아래 여덟 함수를 구현. DOM 생성과 textContent로 현재 입력을 표시 |
| 학생 자체 검사 | `test/*.test.mjs` | 모의DOM·합성 입력 기반 검사. 공식 판정이나 실제 원천 실행 인증이 아님 |
| 학생 문서 | `docs/GAMST_STUDENT_GUIDE.md`, `docs/GAMST_REPRODUCTION.md` | 준비 설명서와 사용자 재현 기록 |

## 여덟 함수의 역할

| 함수 | 표시와 동작 |
|---|---|
| `renderIdentity` | 현재 사용자·기기·세션과 각 목록을 구분합니다. 보안 기준 충족/미충족/확인 불가, 활성/만료/철회됨을 글자로 표시하고 오류·새 입력에서 이전 표시를 교체합니다. |
| `renderDecision` | 접속 허용·거부·추가 확인·확인 불가를 원래 코드, 이유, 확인 시각과 함께 표시합니다. 요청 실패는 거부 판정과 구분합니다. |
| `renderEvents` | 기록을 최신순으로 표시하고 기록 종류·업무 앱·접속 상태 필터와 사건 상세를 제공합니다. 상세에는 근거·규칙·세 상태를 표시하며 실제 조치 요청은 보내지 않습니다. |
| `renderStatus` | 기기·세션 목록, 알림, 실패·빈 목록·불러오는 중을 구분합니다. 허용한 비밀 없는 진단 값만 보여 주고 「도움정보 복사」를 제공합니다. |
| `renderAiConnection` | 전송 연결 점검과 모델 목록 응답, test/verified, 모델 수·시각을 표시합니다. 이 결과를 사건 설명 모델 호출·설명 수용 완료로 표현하지 않습니다. |
| `renderExplanation` | 선택 사건의 근거·규칙·확인 불가 상태와 검증된 설명을 연결합니다. 잘못된 참조나 이미 실행했다고 주장하는 설명은 거부하고 조치 제안은 사람 확인 전 미실행으로 표시합니다. |
| `renderAction` | 미실행·준비·전달·ACK·결과 불명을 구분합니다. succeeded도 observation.effectApplied가 true일 때만 관측 효과로 표시하고 제공 UI의 확인 절차를 사용합니다. |
| `renderVulnerabilities` | 정확한 패키지 버전, lock 정보, OSV 출처·시각·취약점 ID·수정 시각을 표시합니다. 전체/부분/미조회/미설정/확인 불가와 패키지별 결과를 구분합니다. |

## 실패 문구와 다음 확인

실패 뒤 자동으로 다시 요청하지 않습니다. 재조회·집행 버튼은 제공 화면의 버튼입니다. 「도움정보 복사」는 학생 상태 칸의 버튼이며 별도 집행 버튼이나 비밀 입력란은 만들지 않습니다.

| 화면 문구·코드 | 의미 | 확인할 것 |
|---|---|---|
| 연결 없음 / disconnected | 실제 원천 연결이 준비되지 않았거나 연결되지 않음 | 담당자에게 현재 계정·앱 연결 준비 확인. 예제 자료를 실제 자료로 취급하지 않음 |
| 확인 불가 / CONTRACT_MISMATCH / ENGINE_RESULT_UNVERIFIED | 응답·범위·계약을 확인할 수 없음 | 연결 상태와 제공 계약 확인. 정상·빈 목록으로 단정하지 않음 |
| 연결 실패 / 기록을 불러오지 못했습니다 | 자료 요청 실패 | 연결 상태 확인 후 위쪽 다시 불러오기를 직접 누름. 이전 사용자를 현재 값으로 해석하지 않음 |
| 요청 실패 | 접속 판정을 받지 못함 | 업무 앱 요청과 연결 상태 확인. 거부 판정과 구분 |
| 시간 초과 / TIMEOUT / REQUEST_TIMEOUT / ENGINE_TIMEOUT | 정해진 시간 안에 응답 확인 못함 | 잠시 뒤 직접 다시 요청. 이전 결과를 현재 결과로 취급하지 않음 |
| ON_AI_PROVISIONING_PENDING | 학생 계정·앱 권한 준비 중 | 담당자에게 계정 연결·앱 권한 발급 확인. 학생 과제 실패로 기록하지 않음 |
| WB_CLCO_AUTH_REQUIRED / WB_CLCO_ACCESS_BLOCKED | 인증 확인 필요 또는 접근 제한 | 계정 연결 다시 확인 및 담당자 문의. 키를 복사하거나 채팅에 보내지 않음 |
| WB_CLCO_COHORT_BUDGET_EXHAUSTED / WB_CLCO_LIMIT_REACHED | 반 사용량 소진·이용 한도 | 담당자에게 사용량·한도 확인 |
| WB_CLCO_SESSION_CLOSED | 이용 시간 밖 | 허용 이용 시간 확인 |
| WB_CLCO_RATE_LIMITED | 요청 제한 | 잠시 뒤 「현재 API 연결 점검」을 직접 누름 |
| 취소 / CANCELLED / REQUEST_CANCELLED | 사용자가 취소함 | 이전 응답을 현재 결과로 취급하지 않음. 필요할 때 직접 다시 요청 |
| ON_AI_MODEL_LIST_EMPTY / MODEL_NOT_CONFIGURED | 사용 가능한 모델 없음·모델 미설정 | 담당자에게 모델 허용 설정 확인 |
| ON_AI_INVALID_INPUT / ON_AI_INVALID_OUTPUT | 사건 근거 부족 또는 설명 응답 검증 실패 | 사건 근거·규칙 확인. 원천 기록은 유지되며 설명을 사실·집행으로 사용하지 않음 |
| 결과 불명(unknown) | 조치 효과를 확인 못함 | 성공·효과 없음 둘 다 단정하지 말고 제공 UI에서 원천 결과만 재조회. 실제 집행은 현재 UNV |
| 확인 기한 지남(expired) | 사람 확인 기한 만료 | 실제 지원 조치가 있을 때만 제공 절차로 다시 준비 |
| not_configured / not_checked | 프로젝트 조회 준비 미완료·아직 조회 안 함 | 담당자의 프로젝트·공개 승인 패키지 설정 확인. 취약점 없음으로 해석하지 않음 |
| partial / unverifiable / 조회 실패 | 일부 조회 실패·조회 확인 불가·요청 실패 | 이미 받은 ID는 유지하고 확인 불가 범위를 구분. 승인 설정·연결 확인 뒤 직접 재조회 |
| 복사하지 못했습니다 | 클립보드 이용 불가 | 표시된 비밀 없는 도움정보를 직접 선택하여 복사 |

기기 보안 상태 표시는 악성코드 검사·치료 기능이 아닙니다. unknown은 안전·정상이라는 뜻이 아니며 noncompliant는 보안 기준 미충족입니다.

## 확인 범위와 기다림(UNV)

- 코드 확인: 입력 계약, 제공 UI 호출, 학생 표시 함수, 새 DOM 반환 및 오류 분기를 원문으로 대조했습니다.
- 모의 확인: `test/*.test.mjs`의 합성 입력과 모의DOM으로 상태·갱신·실패·안전한 출력 등을 검사합니다. 구체 결과는 최종 실행 기록을 봅니다.
- 실제 실행 확인: 위에 적은 Node 명령을 실행했고 예제 서버의 loopback 시작을 확인했습니다. 브라우저 조작 결과는 별도 관찰 기록이 있을 때만 추가합니다.
- 사용자 직접 확인: 사용자가 확인해 알려 준 결과가 아직 없어 13~21단계 재현표는 모두 미확인입니다.
- 기다림(UNV): 실제 계정·기기·세션의 원천 인증 연결, 17단계 실제 AI 인증과 사건 설명 모델 호출, 19단계 실제 집행·원천 효과 조회, 20단계 실제 OSV 조회. 21단계 원문 판정은 통과했으며 22단계 공식 접수는 준비 중입니다. 실제 연동 UNV와는 별개입니다.

다음 직접 확인은 한 번에 하나씩 진행합니다. 첫 확인은 1280px 이상 브라우저에서 보호 현황·업무 앱·보안 기록 메뉴를 마우스와 Tab·Enter로 이동하는 것입니다. 완료한 뒤 실제 결과를 재현 기록에 남깁니다. 새로운 사용자나 장애를 실제 환경에 임의로 만들지 않습니다.
