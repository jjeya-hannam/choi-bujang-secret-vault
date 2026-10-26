# 학생용 소스 실행 묶음

`package:portable`은 학생이 만든 소스 포장 도구입니다. 수업의 `package-app`, 승인된 host, 설치 프로그램, 공식 최종 제출 자료를 대체하지 않습니다. 공식 포장 자료를 사용할 수 없어서 별도의 검토용 실행 묶음으로 구분합니다.

## 만들기

Node.js가 설치된 환경에서 `on-client` 폴더를 열고, 프로젝트 밖에 아직 존재하지 않는 출력 폴더를 지정합니다. 그 출력 폴더의 부모는 미리 있어야 합니다.

```sh
npm run package:portable -- --out /absolute/path/new-source-bundle
```

Windows PowerShell 예:

```powershell
npm run package:portable -- --out "C:\MyWork\new-source-bundle"
```

결과는 `source-app.tar.gz`, `PORTABLE_SOURCE_MANIFEST.json`, `SOURCE_RUN.md`입니다. 원본 파일을 지우거나 옮기지 않습니다. manifest에는 파일별 SHA256과 보관한 파일 목록, 알 수 있는 경우 기준 Git 커밋과 작업 트리 변경 여부를 기록합니다. 변경 중인 소스의 묶음을 기준 커밋과 동일한 소스라고 해석하지 않습니다. 코드 변경이 끝난 저장점에서 새 출력 폴더로 다시 만드세요.

포함 범위는 `public`, `src`, `vendor`, `student`의 허용된 코드·그림 파일과 package.json, 학생용 시작 스크립트입니다. `.env`·`.env.example`·자격 데이터·DB·로그·Git·node_modules·시험·개발 문서는 제외합니다. 소스 symlink, 기존 출력, 출력과 소스의 겹침, 비밀값 의심 패턴, 지원하지 않는 보관 경로는 거부합니다. 임시 폴더에서 완성한 후 결과를 공개하며 실패 시 임시 자료만 제거합니다. 동시 실행은 출력 잠금 파일로 제한합니다. 포장 중 원본 파일이나 출력 부모를 다른 프로그램이 변경하지 않도록 하세요. 비밀값 패턴 검사는 모든 개인정보를 판별하는 기능이 아니므로 공개할 코드만 원본에 두세요.

manifest의 `includedCredentials: false`는 알려진 경로·패턴을 제외하는 포장 정책이며, 모든 비밀값이나 개인정보가 없음을 인증하는 표시는 아닙니다. `credentialPolicy`와 원본 코드 검토를 함께 확인하세요.

## 새 폴더에서 실행

1. 압축을 새 폴더에 풉니다. Windows 기본 압축 해제가 tar.gz를 지원하지 않으면 PowerShell의 `tar -xzf source-app.tar.gz`를 사용합니다.
2. Node.js 24.19.0을 별도로 설치하고 `node --version`을 확인합니다. Node 실행 파일은 묶음에 포함하지 않습니다.
3. `on-client/tools/start-portable.cmd`(Windows)를 두 번 누르거나, macOS에서 `sh tools/start-portable.sh`를 실행합니다. 이 파일은 예제 실행기이며 Windows `.lnk` 바로가기나 설치 프로그램이 아닙니다. 필요하면 Windows의 기존 바로가기 만들기 메뉴로 이 파일의 바로가기를 직접 만듭니다.
4. `http://127.0.0.1:5189`를 엽니다. 예제 값은 실측이나 실제 연결이 아닙니다. 종료는 실행 창에서 Ctrl+C입니다.
5. 연결 없음 화면은 `node src/server.mjs`로 실행합니다. 실제 연결은 별도의 승인된 어댑터·권한이 있어야 하며, 비밀 파일을 이 묶음에 복사하지 않습니다.

로컬 서버는 기존 코드의 loopback 바인딩을 유지합니다. 관리자 권한·방화벽 변경·자동 AI 요청·자동 보안 조치를 추가하지 않았습니다. Windows 실행, 승인된 host 실행, 실제 계정·PC 측정과 공식 접수는 별도로 확인해야 합니다.


현재 실행기는 학생 PC 호스트를 시작하며 Node24.19.0~24.x 실행 전 진단과 프로세스 한정 포트5189 고정을 적용합니다. 실제 Node24.19.0에서 93개 시험과 Mac 센서 읽기를 확인했으며 Windows 바로가기·방화벽·기록은 실검증 대기입니다. 과거 시험 결과는 당시 저장점 기준입니다.
