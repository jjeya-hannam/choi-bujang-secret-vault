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

export function decide(alert, { jev } = {}) {
  if (!alert || typeof alert !== 'object' || typeof alert.rule?.description !== 'string'
    || !Number.isInteger(alert.rule.level) || typeof alert.data?.srcip !== 'string') {
    return result('record', 0.05, 'no_matching_pattern');
  }
  const description = alert.rule.description;
  const url = typeof alert.data.url === 'string' ? alert.data.url : '';
  const count = Math.max(0, ...[alert.data.count, alert.data.attempts,
    description.match(/(\d+)\s*번/u)?.[1]].map(Number).filter(Number.isFinite));
  const pattern = injectionPattern(description, url);
  const technique = (Array.isArray(alert.rule.mitre) && alert.rule.mitre.includes('T1190'))
    || (alert.rule.level >= 10 && Boolean(pattern));
  if (!technique) return result('record', 0.05, 'no_matching_pattern');
  if (pattern && alert.rule.level >= 8 && count >= 8) {
    return result('block', 0.94, pattern);
  }
  if (alert.rule.level >= 5) return review(alert, 'single_input_anomaly', jev);
  return result('record', 0.05, 'no_matching_pattern');
}
