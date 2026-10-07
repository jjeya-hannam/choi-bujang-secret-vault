# XDR 보너스 경보

이 폴더는 보너스 여섯 개의 연습 경보입니다. 경보는 수업용으로 만든 Wazuh 모양이며, 실제 로그가 아닙니다. 정답은 이 저장소에 없습니다.

## 경보 묶음

`xdr/fixtures/<moduleKey>.json` 을 읽습니다. `moduleKey` 는 아래 여섯 개입니다.

| moduleKey | 보는 것 |
|---|---|
| `brute-force` | 짧은 시간에 몰린 로그인 실패 |
| `web-injection` | 웹 요청에 섞인 주입 형태 |
| `known-cve` | 이미 공개된 취약점을 노린 요청 형태 |
| `persistence` | 다시 켜도 남도록 심긴 서비스·예약 작업 |
| `privilege` | 평범한 계정의 갑작스러운 권한 상승 |
| `exfiltration` | 처음 보는 곳으로 빠지는 큰 전송 |

한 파일에는 명확한 공격, 애매한 시도, 정상 이벤트가 함께 들어 있습니다. 주소는 문서용 대역만 쓰고, 계정은 `user01` 같은 가상 이름입니다. `known-cve` 의 원격 조회 구문은 문서용 표기입니다. 그 문자열을 다른 시스템에 넣거나 변형하지 않습니다.

## 학생이 만드는 파일

항목마다 `xdr/<moduleKey>/decide.mjs` 를 만듭니다. `decide(alert)` 를 내보냅니다. 비동기 함수여도 됩니다. 반환은 아래 세 값입니다.

- `action`: `block`, `alert`, `record` 중 하나
- `confidence`: 0 이상 1 이하 숫자
- `reason`: 짧은 이유

명확한 공격은 `block`, 애매한 시도는 `alert`, 정상 이벤트는 `record` 입니다. 경보 원본은 고치지 않습니다.

## 실행

저장소 루트에서 항목 키 하나를 넣습니다.

```
node scripts/xdr-run.mjs brute-force
```

`npm run xdr:run -- brute-force` 도 같은 명령입니다. 실행기는 해당 경보마다 `decide` 를 부르고, 결과를 `xdr/<moduleKey>/result.json` 에 씁니다. 형식은 `aleph.xdr.result.v1` 이고, `decisions` 에는 경보 id·행동·확신도·이유가, `counts` 에는 `block`·`alert`·`record` 건수가 있습니다.

반환 형식이 틀린 경보는 `record` 로 남고, 오류 한 줄이 출력됩니다. 실행기 자체는 네트워크를 쓰지 않습니다. 판정자는 격리된 환경에서 같은 명령을 다시 실행해 결과를 봅니다. 이미 커밋된 `result.json` 만으로 판정이 끝나지 않습니다.

## 열린 보너스 작전 구현

`brute-force` 모듈은 28건을 읽고 block 10·alert 9·record 9로 나눕니다. `read-alerts.mjs`는 다섯 필드만 추출하며 설명의 비밀값 형태를 가립니다. 패턴 근거는 MITRE ATT&CK T1110입니다. 반복 시도가 명확한 문서용 주소만 만료 시각과 경보 ID가 붙은 `deny-rules.json`에 넣고, 검토할 건은 `alerts.log`에 남깁니다.

`web-injection` 모듈은 26건을 읽고 block 8·alert 9·record 9로 나눕니다. 패턴 근거는 MITRE ATT&CK T1190과 OWASP의 SQL 주입, XSS, 경로 순회, 명령 주입 자료입니다. 단일 검색어를 주입 공격으로 오인해 자동 차단하지 않습니다.

두 모듈의 `decide(alert)`는 외부 Jev 연결이 주어지지 않은 현재 수업 실행기에서 애매한 경보를 `alert`로 안전하게 돌려줍니다. 외부 Jev가 연결돼 실패해도 같은 방식입니다. `ztna-overlay.mjs`는 신뢰할 수 있는 게이트웨이가 전달한 출발 주소만 받아 만료된 거부 규칙을 무시합니다. 현재 시작 상태의 SDP 판정기(`src/decider.mjs`)에는 출발 주소 입력 계약이 없으므로 실제 운영 트래픽 차단이 연결됐다고 주장하지 않습니다.
