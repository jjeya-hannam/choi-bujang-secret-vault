# BYTE BACK 방어전 · 2단계

현재 자료실은 1단계의 공개 정적 메모를 제거하고
학습용 Supabase DB를 Vercel 서버 함수가 읽도록 옮기는 단계입니다.

실제 학생 자료, 비밀번호, 토큰, 서버 전용 키를
코드나 Git 저장소에 넣지 않습니다.

## 현재 작동하도록 만든 구조

- `data.json`에는 메모 본문이 없고 `notes`는 빈 배열입니다.
- `public/data.json`도 메모 0건을 유지합니다.
- 첫 화면은 `/api/notes` 서버 함수를 호출합니다.
- 서버 함수는 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를
  서버 환경변수에서만 읽습니다.
- 브라우저 파일·응답·로그에는 서버 전용 키를 넣지 않습니다.
- `/api/notes`는 아직 로그인 없이 호출할 수 있습니다.
  이것이 다음 단계에서 막을 공개 API 약점입니다.

## Supabase 보호 상태

학습용 `public.notes` 테이블에는 `owner_id uuid` 칸이 있으며
`auth.users` 외래키는 연결하지 않습니다.

RLS를 켜고 `anon`과 `authenticated`에는
직접 SELECT 권한을 주지 않습니다.

Vercel 서버 함수만 서버 전용 자격으로 DB를 읽습니다.

## Vercel 비밀 환경변수

실제 값은 GitHub에 기록하지 않고
Vercel 프로젝트의 Environment Variables 화면에만 저장합니다.

필요한 이름은 다음 두 개입니다.

`SUPABASE_URL`

`SUPABASE_SECRET_KEY`

## 100점 추가 조건

`/data.json`은 메모 0건을 유지합니다.

`/aleph.json`은 Vercel 빌드 중 자동으로 생성합니다.

`vercel.json`은 모든 경로에
`X-Content-Type-Options: nosniff`를 설정합니다.

## 현재 남아 있는 약점

정적 최신 파일에서 자료를 제거했다고 해서
1단계의 옛 공개 Git 커밋과 옛 Vercel 배포 이력이
자동으로 삭제되는 것은 아닙니다.

따라서 과거 노출이 해소됐다고 주장하지 않습니다.

현재 `/api/notes`에도 아직 로그인 보호가 없으므로,
비로그인 방문자도 서버 API를 호출할 수 있습니다.
