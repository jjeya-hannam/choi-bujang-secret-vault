# BYTE BACK 방어전 · 3단계 저장점

2단계의 서버 자료 분리 위에 Supabase Auth 로그인과 서버 토큰 검증을 연결했습니다. 브라우저는 로그인 전 자료를 요청하지 않으며, 서버는 유효하지 않은 토큰에 `401` JSON 오류를 돌려줍니다.

## 현재 동작

- 정적 `data.json`과 `public/data.json`에는 가상 메모 본문이 없습니다.
- 공개 화면은 이메일·비밀번호 로그인, 계정 만들기, 로그아웃을 제공합니다.
- `/api/notes`는 검증된 계정의 가상 메모 목록 조회와 추가를 처리합니다.
- `/api/notes/:id`는 한 건 조회·수정·삭제를 처리합니다.
- 서버는 `src/verify-login.mjs`로 학생 토큰과 심판 토큰을 검증하고, 브라우저의 `owner_id` 값은 사용하지 않습니다.
- Vercel 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`는 서버에서만 읽습니다. 브라우저에는 공개용 Supabase Project URL과 publishable key만 있습니다.
- `vercel.json`은 첫 화면에 `X-Content-Type-Options: nosniff`를 붙입니다.

## 다시 실행하고 확인

`npm install` 후 `npm run build -- --local`로 정적 화면을 만들 수 있습니다. 실제 서버 함수는 Vercel에 배포된 주소에서 확인합니다. 로그인 없이 `/api/notes`를 열면 401 JSON 오류여야 합니다. 계정 생성과 로그인은 Supabase Auth 설정과 사용자 확인이 완료되어야 동작합니다.

학습용 DB의 기존 메모 네 건은 본문을 유지하며 UUID 식별자만 추가했습니다. 아직 소유자가 지정되지 않은 기존 행은 로그인한 계정의 목록에 나타나지 않습니다. 실제 학생 기록과 비밀 키를 넣지 않습니다.

2단계 이전의 공개 Git 커밋과 이전 배포 이력은 자동으로 사라지지 않습니다. 이번 단계의 배포·심판 판정은 실제 확인 뒤에만 통과로 기록합니다.
