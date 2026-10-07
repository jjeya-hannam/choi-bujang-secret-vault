import { readFile } from 'node:fs/promises';
import { decision, reviewAmbiguous, validAlert } from '../shared/decision.mjs';

const catalogue = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
const names = new Set(catalogue.patterns.map(pattern => pattern.name));
const named = name => names.has(name) ? name : 'no_matching_pattern';

export async function decide(alert, { jev } = {}) {
  if (!validAlert(alert, 'T1110')) return decision('record', 0.05, 'no_matching_pattern');
  const description = alert.rule.description;
  const level = alert.rule.level;
  const count = Number(alert.data.count);
  const accounts = typeof alert.data.accounts === 'string'
    ? alert.data.accounts.split(',').filter(Boolean).length : 0;
  const hasFailure = /실패|비밀번호.*넣|대입/u.test(description);
  const success = /성공했습니다|뒤에 성공|성공이 있/u.test(description);
  if (level >= 10 && !success && hasFailure) {
    if (/여러 계정|계정 \d+개|서로 다른 계정/u.test(description)
      && (accounts >= 8 || count >= 15)) {
      return decision('block', 0.95, named('password_spraying'));
    }
    if (/한 글자씩|바꿔 넣|바꿔 가며/u.test(description) && count >= 15) {
      return decision('block', 0.94, named('iterative_guessing'));
    }
    if (count >= 15 && /로그인|비밀번호/u.test(description)) {
      return decision('block', 0.94, named('rapid_login_failures'));
    }
  }
  if (hasFailure && level >= 5 && (count >= 1 || accounts >= 2)) {
    return reviewAmbiguous(alert, named('low_volume_auth_anomaly'), jev);
  }
  return decision('record', 0.05, 'no_matching_pattern');
}
