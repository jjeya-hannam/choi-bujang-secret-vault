// ALEPH SDP 엔진이 신원·기기·경로를 확인한 계약 요청만 받습니다.
// 브라우저 헤더나 출처 없는 신호를 신뢰 상태로 승격하지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

export async function decide(request) {
  let decision = 'allow';
  let reasonCode = 'approved';
  let ruleIds = ['device_registered'];
  if (request.deviceRegistered !== true) {
    decision = 'deny';
    reasonCode = 'device_not_registered';
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
