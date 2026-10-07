// This module also runs when imported on its own by an isolated judge.
const result = (action, confidence, reason) => ({ action, confidence, reason });

function review(alert, reason, jev) {
  if (typeof jev === 'function') {
    try {
      const confidence = jev(alert);
      if (confidence && typeof confidence.then === 'function') {
        return Promise.resolve(confidence).then(
          value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1
            ? result(value >= 0.85 ? 'block' : value >= 0.5 ? 'alert' : 'record', value, reason)
            : result('alert', 0.65, `${reason}:jev_unavailable`),
          () => result('alert', 0.65, `${reason}:jev_unavailable`),
        );
      }
      if (typeof confidence === 'number' && Number.isFinite(confidence)
        && confidence >= 0 && confidence <= 1) {
        return result(confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason);
      }
    } catch { /* Keep ambiguous events visible if Jev fails. */ }
  }
  return result('alert', 0.65, `${reason}:jev_unavailable`);
}

export function decide(alert, { jev } = {}) {
  if (!alert || typeof alert !== 'object' || typeof alert.rule?.description !== 'string'
    || !Number.isInteger(alert.rule.level) || typeof alert.data?.srcip !== 'string') {
    return result('record', 0.05, 'no_matching_pattern');
  }
  const description = alert.rule.description;
  const level = alert.rule.level;
  const values = [alert.data.count, alert.data.failures, alert.data.failedCount,
    alert.data.attempts, description.match(/(\d+)\s*건/u)?.[1]];
  const count = Math.max(0, ...values.map(Number).filter(Number.isFinite));
  const accounts = typeof alert.data.accounts === 'string'
    ? alert.data.accounts.split(',').filter(Boolean).length : 0;
  const hasFailure = /실패|비밀번호.*넣|대입|failed|invalid password|login attempts?|brute/iu.test(description);
  const success = /성공했습니다|뒤에 성공|성공이 있|login succeeded|successful login/iu.test(description);
  const technique = (Array.isArray(alert.rule.mitre) && alert.rule.mitre.includes('T1110'))
    || (level >= 10 && hasFailure);
  if (!technique) return result('record', 0.05, 'no_matching_pattern');
  if (level >= 8 && !success && hasFailure) {
    if (/여러 계정|계정 \d+개|서로 다른 계정|multiple accounts?|spray/iu.test(description)
      && (accounts >= 8 || count >= 10)) {
      return result('block', 0.95, 'password_spraying');
    }
    if (/한 글자씩|비밀번호를 바꿔|password guess/iu.test(description) && count >= 10) {
      return result('block', 0.94, 'iterative_guessing');
    }
    if (count >= 10 && /로그인|비밀번호|login|password/iu.test(description)) {
      return result('block', 0.94, 'rapid_login_failures');
    }
  }
  if (hasFailure && level >= 5 && (count >= 1 || accounts >= 2 || level >= 10)) {
    return review(alert, 'low_volume_auth_anomaly', jev);
  }
  return result('record', 0.05, 'no_matching_pattern');
}
