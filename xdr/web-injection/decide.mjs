import { readFile } from 'node:fs/promises';
import { decision, reviewAmbiguous, validAlert } from '../shared/decision.mjs';

const catalogue = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
const names = new Set(catalogue.patterns.map(pattern => pattern.name));
const named = name => names.has(name) ? name : 'no_matching_pattern';

function injectionPattern(description, url) {
  if (/SQL|데이터베이스 조회|union\s+select/iu.test(description)
    || /union(?:%20|\+|\s)+select|['"]\s+or\s+['"]?1/iu.test(url)) return 'repeated_sql_injection';
  if (/스크립트|script injection|XSS/iu.test(description)
    || /<script|%3cscript/iu.test(url)) return 'repeated_script_injection';
  if (/경로.*거슬러|경로 이탈|path traversal/iu.test(description)
    || /\.\.\/|%2e%2e%2f/iu.test(url)) return 'repeated_path_traversal';
  if (/명령 구분자|command separator|command injection/iu.test(description)) return 'repeated_command_separator';
  return null;
}

export async function decide(alert, { jev } = {}) {
  if (!alert || typeof alert !== 'object' || typeof alert.rule?.description !== 'string'
    || !Number.isInteger(alert.rule.level) || typeof alert.data?.srcip !== 'string') {
    return decision('record', 0.05, 'no_matching_pattern');
  }
  const description = alert.rule.description;
  const url = typeof alert.data.url === 'string' ? alert.data.url : '';
  const count = Math.max(0, ...[alert.data.count, alert.data.attempts,
    description.match(/(\d+)\s*번/u)?.[1]].map(Number).filter(Number.isFinite));
  const pattern = injectionPattern(description, url);
  const technique = validAlert(alert, 'T1190') || (alert.rule.level >= 10 && Boolean(pattern));
  if (!technique) return decision('record', 0.05, 'no_matching_pattern');
  if (pattern && alert.rule.level >= 8 && count >= 8) {
    return decision('block', 0.94, named(pattern));
  }
  if (alert.rule.level >= 5) return reviewAmbiguous(alert, named('single_input_anomaly'), jev);
  return decision('record', 0.05, 'no_matching_pattern');
}
