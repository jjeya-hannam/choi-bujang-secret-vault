const PATTERNS = [
  {
    "name": "unsigned_service_change",
    "condition": "새 서비스 등록 또는 서비스 실행 파일 변경이 명시되고 서명 없음이나 평소 목록에 없는 임시 실행 파일의 자동 지속 실행이 함께 확인되는 경우. 서비스 단어, 임시 파일, 서명 확인 불가만으로 차단하지 않음.",
    "evidence": "MITRE T1543은 서비스 등 시스템 프로세스의 생성·변경을 통한 지속 실행을 설명한다. 서명과 실행 파일·승인 이력의 결합은 이 모듈의 검토 기준이며 MITRE의 차단 점수가 아니다. https://attack.mitre.org/techniques/T1543/"
  },
  {
    "name": "suspicious_scheduled_task",
    "condition": "예약 작업이 임시 실행 파일을 가리키며 신규·알 수 없는 작업, 비정상 실행 시각, 임의 작업 이름 또는 시작 항목과의 동일 실행 파일 연결이 함께 확인되는 경우. 정상 유지보수 예약과 구분함.",
    "evidence": "MITRE T1053은 작업 예약을 이용한 반복 실행과 지속성을 설명하며 작업 생성·수정과 비정상 프로세스 실행의 상관분석을 제시한다. https://attack.mitre.org/techniques/T1053/"
  },
  {
    "name": "unexpected_startup_entry",
    "condition": "실제 시작 폴더 또는 시작 항목에 평소 목록에 없는 실행 프로그램이 추가된 경우. 목록 읽기, 기존 서명 도구, 실행 근거 없는 단일 변경은 별도 검토함.",
    "evidence": "MITRE T1547.001은 Startup Folder의 프로그램 추가를 통한 로그인 시 자동 실행을 설명한다. fixture의 T1543 태그를 그대로 Startup Folder의 공식 분류라고 취급하지 않는다. https://attack.mitre.org/techniques/T1547/001/"
  },
  {
    "name": "persistence_review",
    "condition": "예약 작업·서비스·시작 항목의 관련 변경 경보가 있지만 서명·승인·실행 경로·실행 이력이 부족해 명확한 지속성 악용으로 판단하지 못하는 경우. 높은 경보 수준이나 technique 태그만으로 차단하지 않음.",
    "evidence": "MITRE T1053과 T1543은 예약과 서비스의 악용을 다루지만 정상 운영 작업도 같은 기능을 사용하므로 실제 변경·실행·승인 맥락을 함께 검토한다. https://attack.mitre.org/techniques/T1053/ https://attack.mitre.org/techniques/T1543/"
  }
];

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = value => typeof value === 'string' ? value : '';
function result(confidence, pattern = null) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: pattern ? pattern.name : 'no_matching_pattern' };
}

export function decide(alert) {
  if (!object(alert) || !object(alert.rule) || !object(alert.data)
      || !Number.isSafeInteger(alert.rule.level) || alert.rule.level < 0 || alert.rule.level > 15
      || typeof alert.rule.description !== 'string') return result(0.05);
  const description = alert.rule.description;
  const path = text(alert.data.path).replace(/\\/gu, '/');
  const techniques = Array.isArray(alert.rule.mitre) ? alert.rule.mitre : [];
  const context = techniques.some(value => ['T1053', 'T1543', 'T1547', 'T1547.001'].includes(value));
  const strong = context && alert.rule.level >= 10;
  const service = /서비스|\bservice\b/iu.test(description);
  const task = /예약\s*작업|scheduled\s+task|cron\s+job/iu.test(description);
  const startup = /시작\s*(?:폴더|항목|프로그램)|\bstartup\b/iu.test(description) || /\/startup\//iu.test(path);
  const temporary = /(?:^|\/)(?:temp|tmp)\//iu.test(path) || /임시\s*(?:폴더|파일)|temporary\s+(?:file|folder)/iu.test(description);
  const unsigned = /서명(?:이|은)?\s*(?:없는|없(?:음|습니다))|\bunsigned\b|signature\s+(?:missing|absent)/iu.test(description);
  const novel = /새\s*서비스|처음\s*보는|평소\s*목록에\s*없|\bnew\b|\bunapproved\b|\bunrecognized\b/iu.test(description);
  const changed = /실행\s*파일이?\s*바뀌|(?:binary|executable).{0,25}(?:changed|modified)/iu.test(description);
  const registered = /등록|registered|registration|created/iu.test(description);
  const noRegistration = /등록은?\s*없|등록\s*없|등록하지\s*않|no\s+(?:new\s+)?service|no\s+(?:service\s+)?registration|not\s+registered|(?:registered|created|added)\s+not|not\s+(?:created|added)|(?:등록|추가|변경)(?:하지|되지|은|이)?\s*(?:않|없)|바뀌지\s*않|no\s+(?:change|addition)/iu.test(description);
  const unapproved = /\bunapproved\b|\bunauthorized\b|승인되지\s*않|미승인/iu.test(description);
  const unusual = /시간\s*밖|outside.{0,20}(?:hours|schedule)|처음\s*보는|평소\s*목록에\s*없|\bunrecognized\b/iu.test(description);
  const signedExisting = /서명된|\bsigned\b|verified\s+signature/iu.test(description)
    && /기존|\bexisting\b|\bapproved\b/iu.test(description) && !unsigned;
  if (signedExisting && !changed && !novel && !unapproved && !unusual) return result(0.05);
  if (noRegistration && context && alert.rule.level >= 5 && (service || task || startup)) {
    return result(0.60, PATTERNS[3]);
  }
  if (service && !noRegistration
      && ((unsigned && (novel || changed || registered))
        || (novel && temporary && /다시\s*켜도\s*남|재부팅|\bpersist|\bautostart|\breboot/iu.test(description)))) {
    return result(strong ? 0.93 : 0.72, PATTERNS[0]);
  }
  const offHours = /시간\s*밖|outside.{0,20}(?:hours|schedule)/iu.test(description);
  const randomName = /임의\s*문자열|random\s*(?:name|string)/iu.test(description);
  const approvedRoutine = !unapproved && /승인된|승인받은|\bauthorized\b|\bapproved\b/iu.test(description)
    && /정기|유지보수|\broutine\b|\bmaintenance\b/iu.test(description);
  if (task && temporary && (novel || offHours || randomName || startup)) {
    return result(strong && !approvedRoutine ? 0.93 : 0.72, PATTERNS[1]);
  }
  if (startup && novel && (/\/startup\//iu.test(path) || /추가|added/iu.test(description))) {
    return result(strong ? 0.93 : 0.72, PATTERNS[2]);
  }
  if (context && alert.rule.level >= 5 && (service || task || startup || temporary)
      && ((service && ((unsigned && temporary) || novel || unapproved))
        || /등록|변경|바뀌|만들|생겼|시작|멈|예약|create|change|modify|scheduled|startup/iu.test(description))) {
    return result(0.60, PATTERNS[3]);
  }
  return result(0.05);
}
