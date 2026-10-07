# BYTE BACK 방어전 · 2단계

현재 자료실은 1단계의 공개 정적 메모를 제거하고, 학습용 Supabase DB를 Vercel 서버 함수가 읽도록 옮기는 단계입니다. 실제 학생 자료, 토큰, 비밀키는 넣지 않습니다.

## 현재 작동하는 기능

- `data.json`과 `public/data.json`의 `notes`는 빈 배열입니다.
- 첫 화면은 `/api/notes` 서버 함수를 호출해 학습용 DB의 가상 메모 네 건을 표시합니다.
- 서버 함수의 DB 접속 정보는 Vercel 서버 환경변수에서만 읽고 브라우저 파일·응답·로그에 넣지 않습니다.
- `/api/notes`는 아직 로그인 없이 호출할 수 있는 공개 API이며, 이것이 3단계에서 막을 다음 약점입니다.

## Supabase 자료 보호

`public.notes`에는 `owner_id uuid` 칸이 있지만 `auth.users` 외래키는 없습니다. RLS가 켜져 있고 `anon`과 `authenticated`에는 직접 테이블 읽기 권한이 없습니다. Vercel 서버 함수만 서버 전용 자격으로 읽습니다.

## 100점 확인

- `/data.json`: 메모 0건
- `/aleph.json`: Vercel 빌드가 자동 생성
- 첫 화면 응답: `X-Content-Type-Options: nosniff`

## 남아 있는 한계

최신 정적 파일에서 메모를 제거해도 1단계의 옛 공개 Git 커밋과 옛 Vercel 배포 이력이 자동으로 사라지는 것은 아닙니다. 따라서 과거 노출이 해소됐다고 주장하지 않습니다. 현재 `/api/notes`도 인증이 없어 누구나 호출할 수 있습니다.

## 배포 뒤 확인 절차

1. 첫 화면에서 가상 카드 네 건이 표시되는지 확인합니다.
2. `/data.json`의 `notes`가 빈 배열인지 확인합니다.
3. `/aleph.json`이 열리고 현재 저장소·커밋과 맞는지 확인합니다.
4. 첫 화면 응답에 `X-Content-Type-Options: nosniff`가 있는지 확인합니다.
5. 최신 GitHub 파일에서 가상 메모 본문 문장이 검색되지 않는지 확인합니다.

실제 배포 시험 전에는 완료됐다고 기록하지 않습니다. [AGENTS.md](AGENTS.md)의 공통 규칙을 계속 따릅니다.
