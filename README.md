# BYTE BACK 방어전 · 8단계 저장점

8단계는 메모 `student_notes`와 강사 공지 `instructor_announcements`를 서로 다른 자원 ID로 구분합니다. 기존 자료·주소·메뉴는 유지합니다. 판정기는 엔진 계약의 사용자·기기·서비스·method·정확 경로를 검사합니다. 메모 단일 자원은 UUID만 허용하고 `export` 같은 기능 이름은 같은 깊이의 ID로 통과하지 않습니다. 쿼리로 기능을 고르는 요청, 알 수 없는 경로, method/route 불일치는 거부합니다.

`/notes/demo` 가상 자원에는 학생이 정의한 서버측 소유 정책으로 `learner_fixture`만 허용합니다. 자원 인식과 소유 정책은 위험 신호의 `source`와 독립적입니다. 같은 GET 경로를 다른 `subjectId`로 요청하면 `deny/policy_denied`이며, 추가 본인 확인을 마쳐도 소유 권한은 생기지 않습니다. 이 정책은 `scripts/fixture-7.mjs`의 공개 가상 자원·주체를 대상으로 명시적으로 설정한 로컬 정책입니다. 두 값이 시작 틀에 함께 있다는 사실을 공식 운영 소유권 계약의 증거로 취급하지 않습니다. 현재 요청 계약에는 실제 UUID 자원의 DB 소유자와 가명 `subjectId`를 연결하는 신뢰된 mapping이 없습니다. 판정기는 `/notes` 엔진 경로와 `/api/notes` 배포 경로를 각자의 정확한 route로 검사해 최종 API까지 입장을 허용합니다. 이 allow는 메모 소유권 허용이 아닙니다. 최종 API는 검증된 JWT 사용자 ID와 DB `owner_id`를 대조해 본인 읽기·수정을 허용하고 타인 조회·수정을 거부합니다. 엔진만으로 실제 UUID의 주체별 소유권을 판정하는 기능은 현재 연결되지 않았습니다. 이전 UUID 전체 거부 변경은 본인 정상 요청까지 막아 철회했습니다.

서버 API는 검증 사용자와 저장된 `owner_id`를 다시 비교해 자기 메모 읽기·수정만 허용합니다. 요청 본문의 소유자·role·헤더 권한은 사용하지 않습니다. 별도 `/api/announcements/:id` 구역은 현재 강사 권한과 공지 저장소가 연결되지 않았으므로 수정을 403으로 거부하고 조회는 404로 응답합니다. 강사 정상 수정 기능이 연결됐다고 주장하지 않습니다. 판정 계약에 임의 역할을 추가하지 않습니다.

경로 거부의 `policy_denied` 이유 코드는 운영 등록부가 로컬에 없어 실제 심판에서 등록 여부를 확인해야 합니다. `resource_scope`는 실제 구현한 규칙 이름입니다. `node --test test/resource-r8.test.mjs test/decider-r6.test.mjs test/decider-r7.test.mjs test/login-binding-r8.test.mjs`로 가상 API/판정 회귀를 실행합니다. A의 자기 메모 읽기·수정은 200, B의 A 메모는 404, 학생의 공지 수정은 403이어야 합니다. 화면에서는 방어전 8단계의 심판 제출을 누릅니다. 로컬 시험은 실제 심판 점수나 실제 계정 접속 증거가 아닙니다.

6단계의 등록 기기 규칙을 유지하고, 7단계의 가상 복합 이상 사건에는 `step_up_required`로 추가 확인을 요청합니다. `judge_fixture` 출처의 평소와 다른 새벽 시각(0~5시), 처음 보는 네트워크(`unusual`), 최근 5분 내 자료 읽기 위험 사건 20건 이상이 함께 있어야 적용합니다. 지역 하나만으로 차단하지 않으며 정상 가상 사건은 허용합니다.

현재 실제 계약의 접속 신호는 `source: none`, 지역·네트워크는 `unknown`입니다. 이를 임의 정상값으로 만들거나 클라이언트 헤더를 신뢰 신호로 바꾸지 않습니다. `judge_fixture`는 실제 위치 증거가 아닙니다. 현재 계약에는 실제 재로그인 확인 호출이 없어 실제 재로그인 시험은 미실행입니다. 가상 사건의 `stepUp` 확인 상태와 유효한 나이(0~900초)는 로컬 재확인 연습에만 사용합니다.

`npm run fixture:7`로 정상 allow와 복합 이상 step_up을 비교합니다. `npm run decider:test` 및 `node --test test/decider-r6.test.mjs test/decider-r7.test.mjs`는 가상 요청 시험이며 실제 심판 점수가 아닙니다. `npm run bundle`은 실제 배포의 비로그인 API 거부와 로컬 기기·접속 판정을 구분해 기록하고 실제 재로그인은 미실행으로 남깁니다. 실제 심판 점수는 제출 뒤에 확인합니다.

화면에서는 방어전 7단계의 심판 제출을 눌러 결과를 확인합니다. 로컬 정상 결과는 등록 기기의 allow이며, 미등록 기기는 deny/device_not_registered, 복합 이상 사건은 step_up/step_up_required여야 합니다. 기존 1~6단계 및 XDR 기능을 보존합니다.

2단계의 서버 자료 분리 위에 Supabase Auth 로그인과 서버 토큰 검증을 연결했습니다. 브라우저는 로그인 전 자료를 요청하지 않으며, 서버는 유효하지 않은 토큰에 `401` JSON 오류를 돌려줍니다.

## 현재 동작

- 정적 `data.json`과 `public/data.json`에는 가상 메모 본문이 없습니다.
- 공개 화면은 이메일·비밀번호 로그인, 계정 만들기, 로그아웃을 제공합니다. 인증 요청도 `/api/auth` 서버 함수로 전달합니다.
- `/api/notes`는 검증된 계정의 가상 메모 목록 조회와 추가를 처리합니다.
- `/api/notes/:id`는 한 건 조회·수정·삭제를 처리합니다.
- 서버는 `src/verify-login.mjs`로 학생 토큰과 심판 토큰을 검증하고, 브라우저의 `owner_id` 값은 사용하지 않습니다.
- 모든 메모 CRUD는 서버에서 검증된 사용자 ID와 DB `owner_id`를 대조합니다. 다른 계정의 UUID로 요청하면 404입니다.
- 학습용 `public.notes` 테이블은 anon 및 authenticated의 직접 SELECT·INSERT·UPDATE·DELETE 권한을 모두 회수했습니다. 서버 전용 service_role만 CRUD 권한을 유지합니다. 4단계 소유자 RLS 정책도 유지합니다.
- 브라우저는 Supabase 공개 키를 담지 않고, 모든 메모 CRUD를 같은 출처의 서버 함수로 보냅니다. 세션 복원과 갱신도 서버 함수에서 처리합니다.
- Vercel 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`는 서버에서만 읽습니다. 브라우저 묶음에는 Supabase URL이나 공개 키가 없습니다.
- `vercel.json`은 첫 화면에 `X-Content-Type-Options: nosniff`를 붙입니다.
- `/bonus.html`은 두 수업용 XDR 경보 묶음의 재실행 결과를 읽기 전용으로 보여 줍니다. 무차별 로그인 28건과 웹 입력 조작 26건의 판정 코드, 패턴 근거, 시험 결과는 `xdr/`에 있습니다. 외부 Jev 서비스와 실제 운영 게이트웨이는 연결되지 않아 이 화면은 모의 방어 기록입니다.

## 다시 실행하고 확인

`npm install` 후 `npm run build -- --local`로 정적 화면을 만들 수 있습니다. 실제 서버 함수는 Vercel에 배포된 주소에서 확인합니다. 로그인 없이 `/api/notes`를 열면 401 JSON 오류여야 합니다. 계정 생성과 로그인은 Supabase Auth 설정과 사용자 확인이 완료되어야 동작합니다.

열린 보너스 작전은 `npm run xdr:run -- brute-force`, `npm run xdr:run -- web-injection`으로 다시 실행합니다. `result.json`의 차단·알림·기록 건수, `alerts.log`의 경보 한 줄, `deny-rules.json`의 만료 시각·근거 경보 ID를 확인합니다. 실제 소스 주소와 학생 로그인 자료는 로그에 넣지 않습니다.

학습용 DB의 기존 메모 네 건은 본문을 유지하며 UUID 식별자만 추가했습니다. 아직 소유자가 지정되지 않은 기존 행은 로그인한 계정의 목록에 나타나지 않습니다. 실제 학생 기록과 비밀 키를 넣지 않습니다.

2단계 이전의 공개 Git 커밋과 이전 배포 이력은 자동으로 사라지지 않습니다. 이번 단계의 배포·심판 판정은 실제 확인 뒤에만 통과로 기록합니다.

8단계 최신 완료 심판 커밋 b31a3f120fb2도 36/100, S08_OTHER_ZONE_ALLOWED입니다. 이번 저장점은 정상 UUID 전면 거부를 철회하고 정규화된 엔진 경로도 검사합니다. 엔진 입장→API의 A 정상 200/B 타인 조회·수정 404 및 타인 수정 때 자료 불변을 가상 신원·DB로 확인했습니다. 이 검사는 실제 운영 엔진의 소유권 연결이나 실제 계정 HTTP 시험 증거가 아닙니다.

심판 JWT의 대상 주소는 설정의 프로젝트 별칭과 서버 환경변수 VERCEL_URL의 현재 배포 호스트 두 정확값만 허용합니다. 요청 Host나 토큰에서 허용 주소를 만들지 않습니다. 다른 배포 주소·다른 발급자·잘못된 서명·만료·역할·배열 aud는 거부합니다. 실패 로그에는 고정 사유 코드만 남기며 토큰·사용자 ID·메모 본문은 남기지 않습니다. 기존 고유 배포 주소와 별칭의 불일치는 재현됐지만 실제 심판 실패 원인인지 아직 확인되지 않았습니다.

관련 가상 검사 20개 통과. 이 저장점의 배포·재제출과 실제 심판 결과는 확인 뒤 기록합니다. 100점을 받기 전에는 9단계로 진행하지 않습니다.

8단계 진단 저장점: 프로덕션에서 Vercel 시스템의 대표 호스트와 설정 공개 주소가 정확히 일치할 때만 manifest의 공개 접속 주소로 사용합니다. Git 저장소·커밋·고유 배포 정보 검증은 유지하며 preview는 고유 주소를 유지합니다. 기존 고유 주소의 익명 GET/PUT은 둘 다 Vercel SSO 302, 대표주소는 앱 401 JSON으로 확인했습니다. 대표주소 입력으로 b31 재제출해도 36점이며 확인한 로그 시간대에는 새 API 호출이 보이지 않았습니다. 로그 수집 범위만으로 심판 요청 부재를 단정하지 않습니다.

API 응답 진단은 종료 시 고정 메서드·자원 종류·HTTP 상태·검증 신원 종류와 서명이 확인된 심판 a/b 구분만 기록합니다. 토큰·사용자 ID·실행 ID·자원 UUID·경로·쿼리·메모 내용은 기록하지 않습니다. 새 배포에서 정상 소유자와 타인의 실제 판정은 심판 재제출 후 확인합니다. 아직 엔진의 실제 UUID 소유권 연결은 없으며, 이를 시험 계정 상수나 추측한 가명으로 대신하지 않습니다.

## Work 8단계 구역 규칙 검증

2026-10-13 심판 상세 화면의 안내는 메모 한 건의 소유자 비교를 API가 수행하고 판정기는 메모 전체 목록과 공지 쓰기를 거부하도록 명시합니다. `S08_OTHER_ZONE_ALLOWED`를 UUID 소유권 mapping 부족만으로 해석한 이전 진단을 수정합니다. 판정기는 `GET /notes`와 `GET /api/notes`를 거부하며, 단건 UUID와 POST 생성은 기존 API 소유권 검사를 유지합니다. 공지 쓰기는 누구에게나 거부합니다. 전체 목록을 엔진에서 닫는 것은 이번 단계의 의도된 정책 변경이며, 서버 API 자체의 소유자 필터는 유지합니다.

운영 DB 메모 4건의 owner_id는 모두 NULL, 학생 인증 계정은 0개로 확인했습니다. 기존 행은 수정하지 않았습니다. 로컬 서명 검증 및 API 시험과 실제 심판 A/B HTTP 증거는 구분합니다. 재실행: `node --test test/*.test.mjs`, `npm run decider:test`, `npm run bundle`. 실제 배포와 심판 결과는 확인 후 기록합니다.

## 9단계 저장점

8단계 저장점 `8f05d466af14`는 배포 후 심판에 재제출했으며 사용자가 통과를 확인했습니다. Work에서 심판 화면의 8단계 격파와 9단계 제출 가능 상태도 확인했습니다. 이전 문단의 결과 확인 예정 상태는 이 기록으로 갱신합니다.

탐지 함수는 공식 `docs/DETECT_EVENTS.md`와 공개 스타터의 동일한 연습 계약을 따릅니다. 시각·method·가명 subject만 추출하며 입력을 변경하지 않습니다. 주체별 GET이 임의의 연속 10분(양끝 포함)에 120건을 넘으면 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject }`만 반환합니다. 정상 사건·정확 120건·분산된 사건·다른 주체는 합산하지 않고 observe합니다. 회수 API와 기기 권한 변경은 구현하지 않습니다. 기존 decide 응답과 1~8단계 보호 규칙은 유지합니다.

심판 제작 안내의 네트워크 복합 조건과 특정 기기 대상은 공개 연습 계약에 필드가 없습니다. 임의 신호·기기 상수로 대신하지 않습니다. 로컬 연습 통과를 운영 회수나 측정된 경과 시간으로 주장하지 않으며 실제 결과는 심판에서 확인합니다.

재실행: `npm run detect:test` 및 `node --test test/detect-r9.test.mjs`. 정상 조회·정확 120건은 observe, 10분 내 121건은 propose_revocation/burst_read입니다. 제출 묶음: `npm run bundle`; 화면에서는 9단계의 「심판에게 제출하기」를 누릅니다. 운영 DB 기존 메모와 중단된 다른 과제는 변경하지 않습니다.

## 10단계 저장점

9단계 저장점 `225e24257380`의 실제 심판 점수는 100/100입니다(조건 4개·완결성 가점 3개). 화면에서 공격 4종 격파를 확인했습니다. 구체적인 회수 소요 시간 숫자는 표시되지 않았습니다.

시험 정책 사본은 `policy-backups/stage9`에 있는 9단계 안전 소스 4개이며 manifest와 고정 SHA256을 검증합니다. `node scripts/policy-recovery.mjs --target ../trial-policy/<시험폴더>`로 실행 전에 버전·변경 파일·해시·계획 digest를 표시합니다. 검토한 digest를 `--apply --confirm <digest>`로 전달해야 시험 폴더만 복원합니다. 사본 누락·해시 불일치·계획 후 변경·symlink·운영 경로는 중단합니다. 감사 파일과 다른 서비스 파일은 보존합니다. 실행 전 네 파일을 재검증하고 각 파일은 atomic rename으로 교체하나 여러 파일 전체의 crash transaction을 제공하지 않습니다.

메모 복구는 서비스 notes의 학생 정의 `POST /api/restore`, 본문 `{id: UUID}`입니다. `restoreRoute`는 `POST /api/restore`로 설정했고 공식 공개 스타터에 자료형·본문 예시가 없으므로 심판 호환성을 아직 주장하지 않습니다. 엔진은 정확한 POST 경로만 API까지 전달하며 최종 API는 서명 검증된 심판 B만 허용합니다. 동일 JWT 실행·소유자·대상 ID의 백업을 검증하고 한 건만 복구합니다. A·학생·익명·다른 실행은 거부됩니다. 본문에 owner/run/내용을 받지 않습니다.

`supabase/stage10.sql`은 새 private schema와 불변 백업, service_role만 호출 가능한 SECURITY INVOKER 생성/복구 RPC를 추가합니다. B의 POST 생성과 사전 백업은 같은 DB transaction이며 실패하면 둘 다 취소됩니다. SHA256은 ID·소유자·내용·원래 bigint ID·생성 시각을 포함한 원본 JSONB 전체에 적용합니다. 복구 직후 같은 해시를 재검증하고 실패·타인 UUID 충돌이면 transaction을 취소합니다. 원래 메모 4건은 변경하지 않습니다. 백업의 수정·삭제와 공개 역할 접근은 금지합니다.

운영 적용 순서: DB SQL 검토·승인 후 적용 → 기존 행·권한 검증 → 코드 저장점·배포 → 신규 심판 B 메모 생성/변조/삭제 복구 시험 → 기존 1~9 보호 재시험. 사용자의 명시적 승인 후 운영 DB SQL을 적용했습니다. 운영 DB에서도 변조/삭제 복구·타인/다른 실행/해시변조/불변백업/원자실패/기존행보존 assertions를 통과했습니다. 시험 transaction은 ROLLBACK했고 기존 메모 4건과 owner NULL 상태를 유지했습니다. 익명·학생의 복구 RPC 호출 권한은 없습니다. HTTP 심판 복구 시험과 10단계 점수는 확인 예정입니다. 로컬 PostgreSQL에서 변조/삭제 복구·타인/다른 실행/해시변조/불변백업/원자실패/기존행보존 assertions를 모두 통과했습니다.

로컬 재시험: `node --test test/restore-r10.test.mjs test/policy-recovery-r10.test.mjs`, `npm run detect:test`, `npm run decider:test`. 이전 보호 확인은 `node --test test/r5.test.mjs test/decider-r6.test.mjs test/decider-r7.test.mjs test/resource-r8.test.mjs test/login-binding-r8.test.mjs test/api-diagnostics-r8.test.mjs test/auth-boundary-r8.test.mjs test/detect-r9.test.mjs`입니다. 운영 계정의 전체 HTTP 회귀와 복구 후 심판 공격은 운영 적용 전 미실행 상태로 기록합니다.
