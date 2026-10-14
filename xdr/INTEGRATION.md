# 다른 웹에 ZTNA + XDR 연결하기

현재 재사용 대상은 Node.js 서버입니다. `known-cve/decide.mjs`는 단독으로 경보를 판단하고, `shared/request-guard.mjs`와 `ztna-overlay.mjs`는 호스트 서버의 신뢰된 주소와 규칙 스냅샷을 대조합니다. 기존 인증·등록 기기·재확인·자료 소유권 검사는 호스트가 계속 수행해야 합니다.

## 연결 계약

`createRequestGuard({ resolveTrustedSource, loadRules, clock })`가 비동기 `guard(serverContext)`를 반환합니다.

- `resolveTrustedSource`: 서버가 검증한 게이트웨이 연결에서 출발 IPv4/IPv6를 반환합니다. 클라이언트 본문이나 검증하지 않은 전달 헤더를 신뢰하지 않습니다. IP는 사용자·기기 신원이 아닙니다.
- `loadRules`: 해당 애플리케이션과 서비스에 고정된 서버 저장소에서 `aleph.xdr.deny-rules.v1` 스냅샷을 반환합니다. 요청 인자를 받지 않으므로 클라이언트가 규칙 저장소를 선택하게 하지 않습니다. 서로 다른 웹·테넌트의 규칙을 혼합하지 않습니다.
- `clock`: 서버의 현재 `Date` 또는 epoch 밀리초를 반환합니다. 비동기 읽기가 끝난 뒤 평가하므로 읽는 동안 만료된 규칙은 차단하지 않습니다. 클라이언트 시각은 사용하지 않습니다.

반환은 `{status, reason}`뿐이며 주소·계정·경보 본문을 내보내지 않습니다. `pass`는 XDR 추가 검사를 통과했다는 뜻으로, 자료 접근 권한을 부여하지 않습니다. `deny`는 활성 거부 규칙 일치, `unavailable`은 신뢰된 입력·저장소·시각을 확인하지 못한 상태입니다. `unavailable`을 허용으로 바꾸지 않습니다.

IPv6 표기와 IPv4-mapped IPv6는 정규화해 같은 주소의 우회를 막습니다. 손상된 규칙은 버리고 허용하는 대신 전체 스냅샷을 확인 불가로 처리합니다. 이 반환 코드를 기존 ALEPH SDP 응답이나 등록된 이유 코드 대신 사용하지 않습니다.

## 호스트가 구현할 연결 예시

아래 함수들은 호스트 서버가 제공해야 하는 인터페이스입니다. 특정 웹에 이미 배포된 코드가 아닙니다.

```js
import { createRequestGuard } from './xdr/shared/request-guard.mjs';

const guard = createRequestGuard({
  resolveTrustedSource: context => context.trustedGatewaySource,
  loadRules: () => policyStore.read(APP_SERVICE_NAMESPACE),
  clock: () => new Date(),
});

async function protectedRequest(request) {
  if (!(await authorizeIdentityDeviceAndOwner(request))) return forbidden();
  // 호스트가 연결의 실제 게이트웨이 출처를 검증한 뒤 생성한 문맥만 전달합니다.
  const risk = await guard(await verifiedGatewayContext(request));
  if (risk.status === 'deny') return forbidden();
  if (risk.status === 'unavailable') return temporarilyUnavailable();
  return serveAuthorizedResource(request);
}
```

## 시험 경보와 운영 수집의 구분

`known-cve/respond.mjs`는 수업 fixture와 문서용 주소만 처리합니다. 실제 IP를 쓰려고 이 제한만 제거해서 운영에 적용하지 않습니다. 운영 이벤트 변환·수집자 인증·서비스 범위·영속 저장의 동시성 제어는 대상 웹에서 별도로 연결해야 합니다. 운영 저장소에는 원자적 갱신 또는 버전 비교·단일 작성자와 장애 복구가 필요합니다. 현재 로컬 두 파일 교체가 운영 트랜잭션을 제공하는 것은 아닙니다.

판단 파일은 순수하게 유지하고, 생산 규칙은 검증된 수집 경계에서만 생성합니다. 테스트 fixture가 운영 사용자나 기기 권한을 변경하게 하지 않습니다. 정상 사용자와 공유되는 주소를 단순히 전체 차단하는 정책은 운영 환경의 NAT·프록시와 서비스 범위까지 검토해야 합니다.

확인: `node --test test/xdr-request-guard.test.mjs`. 다른 웹에서의 실제 연결·운영 집행과 심판 완성도 재판정은 아직 실행하지 않았습니다.

## 남은 세 탐지 모듈

`persistence`, `privilege`, `exfiltration`도 각각 `decide(alert)` 한 파일만으로 판단합니다. 각 모듈의 `patterns.json`은 검토 근거이고, `read-alerts.mjs`는 확인용 다섯 필드만 출력합니다. 원문 설명이나 계정·주소를 판단 이유에 복사하지 않습니다. confidence는 로컬 정책의 신호 강도이며 통계적으로 검증된 공격 확률이 아닙니다.

이 모듈들은 Wazuh 모양의 수업 경보에 있는 기술 태그, 수준, 변경·전송 의미를 분석합니다. 경보 설명에 적힌 승인·정기 작업 문구는 운영 서버의 승인 검증을 대신하지 않습니다. 다른 웹에서는 검증된 수집기가 만든 경보만 입력하고 승인 내역·평소 경로·전송 기준선을 신뢰할 수 있는 서버 자료와 대조해야 합니다.

각 `respond.mjs`는 `shared/respond-fixture.mjs`를 사용해 문서용 주소에만 만료 규칙과 근거 ID를 기록합니다. 실제 주소를 받는 운영 규칙 생성기가 아닙니다. 공통 JSON/로그 갱신은 순차 실행 전용이며 동시 쓰기 락과 두 파일을 아우르는 트랜잭션은 제공하지 않습니다. 실제 배포에는 호스트의 서비스별 저장소, 동시성 제어와 복구 처리가 필요합니다. 계정·기기 단위 회수 권한을 IP 차단으로 대신하지 않습니다.
