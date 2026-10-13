// Distinct logical resources; paths remain compatible with the existing notes API.
const RESOURCE_IDS = Object.freeze({ notes: 'student_notes', announcements: 'instructor_announcements' });
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function resourceRoute(method, path, { fixture = false } = {}) {
  if (typeof path !== 'string' || path.includes('?') || path.includes('#') || path.includes('%')) return null;
  if (path === '/api/notes' && ['GET', 'POST'].includes(method)) {
    return { resourceId: RESOURCE_IDS.notes, route: `${method} /api/notes`, id: null };
  }
  const note = /^\/api\/notes\/([^/]+)$/u.exec(path);
  if (note && UUID_PATTERN.test(note[1]) && ['GET', 'PUT', 'DELETE'].includes(method)) {
    return { resourceId: RESOURCE_IDS.notes, route: `${method} /api/notes/:id`, id: note[1] };
  }
  const announcement = /^\/api\/announcements\/([^/]+)$/u.exec(path);
  if (announcement && UUID_PATTERN.test(announcement[1]) && ['GET', 'PUT'].includes(method)) {
    return { resourceId: RESOURCE_IDS.announcements, route: `${method} /api/announcements/:id`, id: announcement[1] };
  }
  // Existing public local fixture contract uses /notes/demo rather than the deployed UUID URL.
  if (fixture && method === 'GET' && path === '/notes/demo') {
    return { resourceId: RESOURCE_IDS.notes, route: 'GET /notes/:id', id: 'demo' };
  }
  return null;
}

// ALEPH SDP 엔진이 신원·기기·경로를 확인한 계약 요청만 받습니다.
// 브라우저 헤더나 출처 없는 신호를 신뢰 상태로 승격하지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_scope']);

export async function decide(request) {
  let decision = 'allow';
  let reasonCode = 'approved';
  let ruleIds = ['device_registered'];
  const resource = resourceRoute(request.method, request.path, { fixture: request.signals?.source === 'judge_fixture' });
  if (request.deviceRegistered !== true) {
    decision = 'deny';
    reasonCode = 'device_not_registered';
  } else if (!request.subjectId || typeof request.subjectId !== 'string'
      || !/^[0-9a-f]{16}$/u.test(request.deviceId ?? '')
      || request.service !== 'notes' || request.queryLength !== 0
      || !resource
      || resource.route !== request.route
      || (resource.resourceId === RESOURCE_IDS.announcements && request.method !== 'GET')) {
    decision = 'deny';
    reasonCode = 'policy_denied';
    ruleIds = ['device_registered', 'resource_scope'];
  } else {
    const signals = request.signals;
    // 현재 실제 계약의 source=none/unknown은 정상 위치·네트워크 증거가 아닙니다.
    // judge_fixture는 가상 사건 연습에만 쓰며 실제 위치 이력으로 저장하지 않습니다.
    const unusualHour = Number.isInteger(signals?.hour)
      && signals.hour >= 0 && signals.hour < 6;
    const burst = Array.isArray(request.recentEvents) && request.recentEvents.some(event =>
      event.kind === 'risk_signal' && Number.isFinite(event.ageSeconds)
      && event.ageSeconds >= 0 && event.ageSeconds <= 300
      && Number.isInteger(event.count) && event.count >= 20);
    const fixtureRisk = signals?.source === 'judge_fixture'
      && signals.network === 'unusual' && unusualHour && burst;
    // 실제 재로그인 확인 호출 계약이 없습니다. 아래 값은 가상 요청 재확인 연습에만 적용합니다.
    const fixtureVerified = request.stepUp?.verified === true
      && Number.isFinite(request.stepUp.authAgeSeconds)
      && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= 900;
    if (fixtureRisk && !fixtureVerified) {
      decision = 'step_up';
      reasonCode = 'step_up_required';
      ruleIds = ['device_registered', 'step_up_required'];
    }
  }
  return { schema: 'aleph.decision.v1', requestId: request.requestId,
    decision, reasonCode, ruleIds };
}
