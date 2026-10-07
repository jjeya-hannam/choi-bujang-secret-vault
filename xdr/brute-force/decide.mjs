import { readFile } from 'node:fs/promises';
import { decision, reviewAmbiguous, validAlert } from '../shared/decision.mjs';

const catalogue = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
const names = new Set(catalogue.patterns.map(pattern => pattern.name));
const named = name => names.has(name) ? name : 'no_matching_pattern';

export async function decide(alert, { jev } = {}) {
  if (!alert || typeof alert !== 'object' || typeof alert.rule?.description !== 'string'
    || !Number.isInteger(alert.rule.level) || typeof alert.data?.srcip !== 'string') {
    return decision('record', 0.05, 'no_matching_pattern');
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
  const technique = validAlert(alert, 'T1110') || (level >= 10 && hasFailure);
  if (!technique) return decision('record', 0.05, 'no_matching_pattern');
  if (level >= 8 && !success && hasFailure) {
    if (/여러 계정|계정 \d+개|서로 다른 계정|multiple accounts?|spray/iu.test(description)
      && (accounts >= 8 || count >= 10)) {
      return decision('block', 0.95, named('password_spraying'));
    }
    if (/한 글자씩|비밀번호를 바꿔|password guess/iu.test(description) && count >= 10) {
      return decision('block', 0.94, named('iterative_guessing'));
    }
    if (count >= 10 && /로그인|비밀번호|login|password/iu.test(description)) {
      return decision('block', 0.94, named('rapid_login_failures'));
    }
  }
  if (hasFailure && level >= 5 && (count >= 1 || accounts >= 2 || level >= 10)) {
    return reviewAmbiguous(alert, named('low_volume_auth_anomaly'), jev);
  }
  return decision('record', 0.05, 'no_matching_pattern');
}
