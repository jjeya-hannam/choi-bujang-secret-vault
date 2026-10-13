// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
import { decide } from './decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

export async function runAttackChecks(config) {
  if (config.step >= 3) {
    const base = new URL(config.publicAppUrl);
    const response = await fetch(new URL('/api/notes', base), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const type = response.headers.get('content-type') ?? '';
    let error = null;
    if (type.includes('application/json')) {
      try { error = (await response.json()).error; } catch { /* recorded below */ }
    }
    const attempts = [{ attackId: 'anonymous_note_read', expected: '비로그인 API 401 또는 403 JSON 거부',
      observed: `HTTP ${response.status}, JSON 오류 ${typeof error === 'string' ? error : '없음'}` }];
    if (config.step >= 6) {
      const { normal } = fixtureRequests();
      for (const [attackId, deviceRegistered, expected] of [
        ['local_registered_device', true, '로컬 가상 요청: 등록 기기 allow'],
        ['local_unregistered_device', false, '로컬 가상 요청: 미등록 기기 deny/device_not_registered'],
        ['local_unconfirmed_device', null, '로컬 가상 요청: 미확인 기기 deny/device_not_registered'],
      ]) {
        const result = await decide({ ...normal, deviceRegistered });
        attempts.push({ attackId, expected,
          observed: `로컬 판정기 직접 실행: ${result.decision}/${result.reasonCode}; 운영 엔진 및 심판 판정 아님` });
      }
    }
    if (config.step >= 7) {
      const { normal, suspicious } = fixtureRequests();
      for (const [attackId, request, expected] of [
        ['local_normal_signals', normal, '로컬 가상 정상 사건 allow'],
        ['local_composite_risk', suspicious, '로컬 가상 복합 사건 step_up/step_up_required'],
        ['local_verified_risk', { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, '로컬 가상 재확인 사건 allow'],
      ]) {
        const result = await decide(request);
        attempts.push({ attackId, expected,
          observed: `로컬 판정기 직접 실행: ${result.decision}/${result.reasonCode}; 실제 접속·재로그인·심판 판정 아님` });
      }
      attempts.push({ attackId: 'live_step_up_verification', expected: '실제 계약이 제공될 때 재로그인 확인 요청·응답 검증',
        observed: '미실행: 현재 계약에 실제 재로그인 확인 호출이 없음. 가상 요청 시험만 실행함' });
    }
    if (config.step >= 8) {
      const { normal } = fixtureRequests();
      const id = '11111111-1111-4111-8111-111111111111';
      for (const [attackId, request, expected] of [
        ['local_collection_read', { ...normal, path: '/api/notes', route: 'GET /api/notes' }, '판정기 메모 전체 목록 GET deny'],
        ['local_engine_collection_read', { ...normal, path: '/notes', route: 'GET /notes' }, '판정기 정규화 목록 GET deny'],
        ['local_note_api_admission', { ...normal, path: `/api/notes/${id}`, route: 'GET /api/notes/:id' }, '정확 UUID 경로의 API 진입 allow; 최종 소유 권한은 API에서 검증'],
        ['local_note_engine_admission', { ...normal, path: `/notes/${id}`, route: 'GET /notes/:id' }, '정규화된 엔진 UUID 경로의 API 진입 allow; 최종 소유 권한은 API에서 검증'],
        ['local_other_subject', { ...normal, subjectId: 'other_fixture' }, '가상 본인 메모를 다른 주체가 요청하면 deny'],
        ['local_owner_no_risk_source', { ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 } }, '등록된 가상 소유자의 자원은 위험 신호 출처와 관계없이 allow'],
        ['local_export_alias', { ...normal, path: '/api/notes/export', route: 'GET /api/notes/:id' }, '로컬 가상 export 별칭 deny'],
        ['local_announcement_edit', { ...normal, method: 'PUT', path: `/api/announcements/${id}`, route: 'PUT /api/announcements/:id' }, '로컬 가상 강사 권한 없는 공지 수정 deny'],
      ]) {
        const result = await decide(request);
        attempts.push({ attackId, expected, observed: `로컬 판정기 직접 실행: ${result.decision}/${result.reasonCode}; 실제 API 계정·심판 판정 아님` });
      }
      attempts.push({ attackId: 'live_resource_accounts', expected: '실제 A 자기 메모 허용·B 타인 메모 거부·학생 공지 수정 거부',
        observed: '미실행: 실제 계정 요청은 보내지 않음. 별도 가상 API 시험으로 소유자·권한 거부를 검증함' });
    }
    return attempts;
  }
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
