# BYTE BACK 방어전 · 8단계 저장점

8단계는 메모 `student_notes`와 강사 공지 `instructor_announcements`를 서로 다른 자원 ID로 구분합니다. 기존 자료·주소·메뉴는 유지합니다. 판정기는 엔진 계약의 사용자·기기·서비스·method·정확 경로를 검사합니다. 메모 단일 자원은 UUID만 허용하고 `export` 같은 기능 이름은 같은 깊이의 ID로 통과하지 않습니다. 쿼리로 기능을 고르는 요청, 알 수 없는 경로, method/route 불일치는 거부합니다.

서버 API는 검증 사용자와 저장된 `owner_id`를 다시 비교해 자기 메모 읽기·수정만 허용합니다. 요청 본문의 소유자·role·헤더 권한은 사용하지 않습니다. 별도 `/api/announcements/:id` 구역은 현재 검증 신원 계약에 강사 권한과 공지 저장소가 없으므로 수정을 403으로 거부하고 조회는 404로 응답합니다. 강사 정상 수정 기능이 연결됐다고 주장하지 않습니다. 판정 계약에 임의 역할을 추가하지 않습니다.

경로 거부의 `policy_denied` 이유 코드는 운영 등록부가 로컬에 없어 실제 심판에서 등록 여부를 확인해야 합니다. `resource_scope`는 실제 구현한 규칙 이름입니다. `node --test test/resource-r8.test.mjs test/decider-r6.test.mjs test/decider-r7.test.mjs`로 가상 API/판정 회귀를 실행합니다. A의 자기 메모 읽기·수정은 200, B의 A 메모는 404, 학생의 공지 수정은 403이어야 합니다. 화면에서는 방어전 8단계의 심판 제출을 누릅니다. 로컬 시험은 실제 심판 점수나 실제 계정 접속 증거가 아닙니다.

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

8단계 첫 심판 판정은 36/100이며 S08_OTHER_ZONE_ALLOWED 단건 조회 조건이 실패했습니다. DB 소유자 필터를 유지하고 반환된 행의 owner_id 및 note_id를 검증된 사용자와 요청 ID에 다시 대조합니다. 목록에서도 본인 행만 반환하고 owner_id는 응답에 포함하지 않습니다. 재판정 전 100점으로 기록하지 않습니다.
