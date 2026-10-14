const PATTERNS = [
  {
    "name": "whole_collection_external_transfer",
    "condition": "외부 전송 완료·양수 전송량·목적지가 확인되고 높은 경보 수준에서 자료 전체 복사와 대용량이 함께 나타남",
    "evidence": "T1041은 명령 제어 통로로 자료를 내보내는 행위를 설명한다. 전체 자료 전송과 외부 통로는 별도 상관 신호다."
  },
  {
    "name": "novel_destination_bulk_transfer",
    "condition": "처음 보는 목적지로 다수 파일과 큰 전송량이 함께 완료되고 경보 수준이 높음",
    "evidence": "T1048은 기존 명령 통로와 다른 프로토콜을 이용한 자료 유출을 설명한다. 목적지 변화만으로는 자동차단하지 않는다."
  },
  {
    "name": "unusual_protocol_bulk_transfer",
    "condition": "평소와 다른 포트/프로토콜과 다수 파일·큰 전송량·완료 증거가 함께 있음",
    "evidence": "T1048의 대체 프로토콜과 유출 행위를 근거로 통로 변화와 전송 규모를 함께 본다."
  },
  {
    "name": "repeated_command_channel_transfer",
    "condition": "명령 제어 통로에서 대용량 전송이 반복되며 완료 증거와 높은 경보 수준이 있음",
    "evidence": "T1041은 기존 C2 통로에 실린 자료 유출을 설명한다. 반복과 전송량을 함께 확인한다."
  },
  {
    "name": "novel_destination_archive_transfer",
    "condition": "새 목적지의 압축 자료 대용량 전송에 비업무 시각·복수 파일·반복 중 하나가 추가됨",
    "evidence": "T1041/T1048은 통로를 통한 자료 이동을 설명한다. 단일 압축 생성 또는 전송 준비를 완료된 유출로 취급하지 않는다."
  },
  {
    "name": "off_hours_repeated_transfer",
    "condition": "업무/수업 시간 밖의 반복 대용량 전송이 완료됐고 경보 수준이 높음",
    "evidence": "T1048을 참고해 전송 통로와 반복 활동을 대조한다. 시각 하나만으로 차단하지 않는다."
  },
  {
    "name": "repeated_high_volume_transfer",
    "condition": "T1041/T1048 태그가 있는 반복 대용량 전송의 완료 증거와 높은 경보 수준이 있음",
    "evidence": "T1041의 유출 통로 신호와 반복·규모를 상관분석한다. 태그와 bytes 어느 하나만으로 차단하지 않는다."
  },
  {
    "name": "transfer_anomaly_review",
    "condition": "새 주소·작은 전송·기준선 변화·명령 통로 등 의심 신호가 있으나 복합 차단 증거가 부족함",
    "evidence": "T1041/T1048 분류는 조사 근거이며 정답 표식이 아니다. 완료된 유출의 복합 증거가 부족하면 0.65 alert로 검토를 유지한다."
  },
  {
    "name": "incomplete_transfer_review",
    "condition": "압축 준비만 있거나 전송 실패·외부 전송 없음으로 완료 증거가 부족함",
    "evidence": "MITRE 유출 기법은 자료가 통로로 전달되는 행위를 다룬다. 미완료 사건을 성공한 유출로 단정하지 않는다."
  }
];

// Standalone synthetic-alert classifier. No imports, storage, network or response side effects.
const decision = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence,
  reason,
});

function metric(value) {
  if (typeof value === 'string' && !/^\d{1,16}$/u.test(value)) return null;
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : null;
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)
      || typeof alert.rule?.description !== 'string' || alert.rule.description.length > 4096
      || !Number.isSafeInteger(alert.rule.level) || alert.rule.level < 0 || alert.rule.level > 15
      || !alert.data || typeof alert.data !== 'object' || Array.isArray(alert.data)) {
    return decision(0.05, 'no_matching_pattern');
  }
  const description = alert.rule.description;
  const bytes = metric(alert.data.bytes);
  const files = metric(alert.data.files);
  const count = metric(alert.data.count);
  const tagged = Array.isArray(alert.rule.mitre)
    && alert.rule.mitre.some(value => value === 'T1041' || value === 'T1048');
  const novelDestination = /처음\s*보는|처음\s*봅니다|평소와\s*다른\s*(?:주소|목적지)|낯선\s*(?:주소|목적지)|unfamiliar|unknown\s+destination|new\s+destination/iu.test(description);
  const unusualPort = /(?:평소에\s*)?쓰지\s*않던\s*포트|비정상\s*포트|unusual\s+port|alternative\s+protocol/iu.test(description);
  const offHours = /(?:수업|업무)\s*시간\s*밖|비업무\s*시간|outside\s+(?:business|class)\s+hours|off[ -]?hours/iu.test(description);
  const archive = /압축\s*파일|archive|compressed\s+file/iu.test(description);
  const repeated = /반복|연속|전송이\s*\d+\s*번|repeated|consecutive/iu.test(description) && (count !== null && count >= 5);
  const commandChannel = /명령\s*통로|명령.{0,6}제어|command\s+(?:channel|and\s+control)|\bC2\b/iu.test(description);
  const wholeCollection = /자료실\s*전체|전체\s*자료|entire\s+(?:vault|dataset)|whole\s+collection/iu.test(description);
  const external = /외부\s*주소|외부.{0,10}(?:전송|복사)|external\s+(?:address|destination)|outside\s+network/iu.test(description);
  const completed = /나갔|올라갔|전송됐|전송이|복사됐|uploaded|transferred|sent/iu.test(description);
  const failure = /실패|전송은\s*아직\s*없|외부\s*전송은\s*아직\s*없|전송.*없습니다|failed|no\s+(?:external\s+)?transfer|\bnot\s+(?:been\s+)?(?:transferred|sent|uploaded|copied)\b/iu.test(description);
  const baselineAnomaly = /평소보다|평소와\s*다른|늘었|높습니다|일부만\s*다른|처럼\s*보이는|자료\s*\d+\s*건.{0,12}읽힌|baseline|unusual|anomal/iu.test(description);
  const normal = /승인된.{0,24}(?:백업|업무|전송|동기화)|(?:정기|정상|허용된|예정된).{0,24}(?:백업|업무\s*전송|동기화)|authorized.{0,24}(?:backup|business|transfer)|scheduled\s+backup|routine\s+(?:backup|business\s+transfer)/iu.test(description);
  const explicitCompromise = /탈취|유출|악성|침해|stolen|unauthorized|malicious/iu.test(description);
  // Volume and ATT&CK tags alone cannot turn an approved backup into an attack.
  if (normal && !explicitCompromise && !commandChannel && !unusualPort) {
    return novelDestination || offHours || baselineAnomaly
      ? decision(0.65, 'transfer_anomaly_review') : decision(0.1, 'no_matching_pattern');
  }
  const destinationPresent = typeof alert.data.dstip === 'string' && alert.data.dstip.trim().length > 0;
  const transferred = bytes !== null && bytes > 0 && destinationPresent && completed && !failure;
  // Local practice thresholds, not MITRE definitions or verified production baselines.
  const large = bytes !== null && bytes >= 50000000;
  const bulkFiles = files !== null && files >= 50;
  const highSeverity = alert.rule.level >= 9;
  if (transferred && highSeverity && (tagged || commandChannel || unusualPort || novelDestination || external)) {
    if (wholeCollection && external && large) return decision(0.96, 'whole_collection_external_transfer');
    if (novelDestination && bulkFiles && large) return decision(0.95, 'novel_destination_bulk_transfer');
    if (unusualPort && bulkFiles && large) return decision(0.94, 'unusual_protocol_bulk_transfer');
    if (commandChannel && repeated && large) return decision(0.95, 'repeated_command_channel_transfer');
    if (novelDestination && archive && large && (offHours || (files !== null && files >= 2) || repeated)) {
      return decision(0.94, 'novel_destination_archive_transfer');
    }
    if (offHours && repeated && large) return decision(0.93, 'off_hours_repeated_transfer');
    if (tagged && repeated && large) return decision(0.91, 'repeated_high_volume_transfer');
  }
  const suspiciousContext = novelDestination || unusualPort || commandChannel || baselineAnomaly || offHours
    || (tagged && (archive || failure || alert.rule.level >= 5));
  if (suspiciousContext) return decision(0.65, failure ? 'incomplete_transfer_review' : 'transfer_anomaly_review');
  return decision(0.1, 'no_matching_pattern');
}
