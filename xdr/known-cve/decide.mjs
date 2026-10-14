const PATTERNS = [
  {
    "name": "header_jndi_lookup",
    "condition": "로그에 반영되는 요청 헤더에서 jndi:ldap 같은 JNDI 원격 조회 식별 표기가 확인된 경우. 로그 처리 경로와 취약 버전을 별도로 확인하며, 표기만으로 실제 원격 조회나 악용 성공을 단정하지 않음.",
    "evidence": "Apache는 CVE-2021-44228의 로그 메시지·매개변수와 공격자가 제어하는 LDAP endpoint를 통한 JNDI 조회 위험을 설명한다. log4j-scan은 헤더 점검을 지원하며, 공개 앱 입력 악용은 MITRE T1190의 검토 범주다. https://logging.apache.org/security.html https://github.com/fullhunt/log4j-scan https://attack.mitre.org/techniques/T1190/"
  },
  {
    "name": "parameter_jndi_lookup",
    "condition": "로그에 반영되는 GET 또는 POST 인자에서 jndi:ldap 같은 JNDI 원격 조회 식별 표기가 확인된 경우. 인자가 실제 로그 처리에 전달되는지 별도로 확인하며, 표기만으로 취약성이나 악용 성공을 단정하지 않음.",
    "evidence": "Apache는 CVE-2021-44228에서 제어 가능한 로그 메시지·매개변수의 JNDI 조회 위험을 설명한다. log4j-scan은 GET·POST 인자 점검을 지원하며, MITRE T1190은 공개 앱 취약점 악용을 다룬다. https://logging.apache.org/security.html https://github.com/fullhunt/log4j-scan https://attack.mitre.org/techniques/T1190/"
  },
  {
    "name": "known_log4shell_scanner_trace",
    "condition": "확인된 경보에 log4j-scan 등 CVE-2021-44228 점검 도구 사용이 확인 가능한 도구명이나 검증된 표식으로 명시된 경우의 약한 검토 신호. 일반 scan·curl·브라우저 User-Agent·CVE 단어만으로 충족하지 않으며, 권한 있는 진단 가능성을 구분하고 악성이나 성공을 단정하지 않음. 모든 요청에 동일한 도구 식별자가 있다는 가정은 하지 않음.",
    "evidence": "log4j-scan 유지관리자는 CVE-2021-44228 점검과 헤더·GET·POST 인자 지원을 설명하지만 도구 사용 자체는 악용 성공 증거가 아니다. Apache의 취약점 조건과 MITRE T1190의 공개 앱 악용 맥락을 함께 검토한다. https://github.com/fullhunt/log4j-scan https://logging.apache.org/security.html https://attack.mitre.org/techniques/T1190/"
  }
];

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const string = value => typeof value === 'string' ? value : '';
const values = value => typeof value === 'string' ? [value]
  : object(value) ? Object.values(value).filter(item => typeof item === 'string') : [];
const REMOTE_LOOKUP = /\$\{\s*jndi\s*:\s*ldap\s*:\/\/[a-z0-9][a-z0-9.-]*(?::\d{1,5})?(?:\/[^\s{}]*)?\}/iu;
const RELATED = /jndi|log4j|log4shell|CVE-2021-44228/iu;
const WEAK_CONTEXT = /취약점.*(?:목록|문서|검색|이름)|라이브러리|중괄호|조회.*잘린|잘린.*조회|점검\s*도구/iu;

function result(confidence, pattern = null) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: pattern ? pattern.name : 'no_matching_pattern' };
}

export function decide(alert) {
  if (!object(alert) || !object(alert.rule) || !object(alert.data)
      || !Number.isSafeInteger(alert.rule.level) || alert.rule.level < 0) return result(0.05);
  const headers = [string(alert.data.useragent), ...values(alert.data.headers), ...values(alert.data.header)];
  const parameters = [string(alert.data.url), string(alert.data.query), string(alert.data.body)];
  const description = string(alert.rule.description);
  const technique = Array.isArray(alert.rule.mitre) && alert.rule.mitre.includes('T1190');
  const strongContext = technique && alert.rule.level >= 10;
  // Complete structure is a request signal, not evidence that a lookup succeeded.
  if (headers.some(value => REMOTE_LOOKUP.test(value))) return result(strongContext ? 0.92 : 0.72, PATTERNS[0]);
  if (parameters.some(value => REMOTE_LOOKUP.test(value))) return result(strongContext ? 0.92 : 0.72, PATTERNS[1]);
  // A known tool marker stays review-only, even with a high severity or technique.
  if (headers.some(value => /\blog4j-scan\b/iu.test(value))
      || /log4j-scan.{0,80}(?:사용|도구|scanner)|(?:사용|도구|scanner).{0,80}log4j-scan/iu.test(description)) {
    return result(0.65, PATTERNS[2]);
  }
  // Partial candidates require request fields plus a relevant alert context.
  // Technique/level alone never select a pattern or cause a block.
  const hasRequest = [...headers, ...parameters].some(value => value.length > 0);
  if (technique && alert.rule.level >= 5 && hasRequest
      && ([...headers, ...parameters].some(value => RELATED.test(value)) || WEAK_CONTEXT.test(description))) {
    if (/점검\s*도구/iu.test(description)) return result(0.55, PATTERNS[2]);
    if (headers.some(value => RELATED.test(value)) || /머리글|헤더/iu.test(description)) return result(0.55, PATTERNS[0]);
    return result(0.55, PATTERNS[1]);
  }
  return result(0.05);
}
