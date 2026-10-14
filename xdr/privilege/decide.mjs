const PATTERNS = [
  { "name": "privileged_group_change", "condition": "관리자 그룹 추가·재가입 등 실제 권한 변경 의미와 T1078 또는 T1068 맥락 및 높은 규칙 수준이 함께 있을 때 검토한다. 승인된 정기 관리와 읽기·비관리자 그룹 변경은 구분하며 그룹 이름이나 반복 횟수만으로 차단하지 않는다.", "evidence": "유효 계정 악용은 권한 상승에 이용될 수 있으나 계정 사용 자체가 공격 증거는 아니다. 이 규칙의 이벤트 의미와 수준 조합은 로컬 검토 정책이다. https://attack.mitre.org/techniques/T1078/" },
  { "name": "new_privileged_session_execution", "condition": "새 관리자 권한으로 명령을 실행하거나 다른 계정 권한·처음 보는 출처·업무 밖 시각과 관리자 명령 또는 세션 권한 변경이 함께 나타나고 T1068/T1078 및 높은 수준이 뒷받침할 때 검토한다. 태그나 관리자 명령 하나만으로 차단하지 않는다.", "evidence": "T1068은 취약점 악용을 통한 높은 권한 획득을 설명한다. 명령·세션 기록만으로 취약점 악용 성공을 입증하지 않으며 여기서는 권한 변경의 복합 경보 맥락을 검토한다. https://attack.mitre.org/techniques/T1068/ https://attack.mitre.org/techniques/T1078/" },
  { "name": "privilege_review_candidate", "condition": "T1068/T1078 맥락과 권한 요청·실패·취소·그룹 또는 계정 권한 조회 의미는 있으나 강한 권한 변경 조건이 충분하지 않으면 alert로 검토한다. 정상 로그인·조회·정기 관리와 태그 단독은 record로 남긴다.", "evidence": "유효 계정 및 권한 상승 기술 분류는 조사 맥락이며 정상 관리 행위도 같은 용어를 포함할 수 있다. 미완료·모호한 이벤트는 자동 차단 대신 검토한다. https://attack.mitre.org/techniques/T1068/ https://attack.mitre.org/techniques/T1078/" }
];
const text = value => typeof value === 'string' ? value.toLowerCase() : '';
const output = (confidence, reason) => ({ action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason });

// Pure local event classifier. IDs, addresses, account names and counts do not
// select outcomes. Technique tags are context, not proof of compromise.
export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return output(0.05, 'no_matching_pattern');
  const description = text(alert.rule?.description), group = text(alert.data?.group);
  const mitre = Array.isArray(alert.rule?.mitre) ? alert.rule.mitre : [];
  const technique = mitre.some(value => value === 'T1068' || value === 'T1078');
  const level = Number.isSafeInteger(alert.rule?.level) && alert.rule.level >= 0 && alert.rule.level <= 15 ? alert.rule.level : 0;
  if (!technique) return output(0.05, 'no_matching_pattern');
  const administrative = /관리자|권한|privileg|administrator|\badmin\b|\broot\b/iu.test(description);
  const changed = /추가|들어가|들어왔|재가입|권한으로 바뀌|권한.*변경|added|rejoin|elevat|privilege.*chang/iu.test(description);
  const administratorGroup = ['administrators', 'administrator', 'admins', 'sudo', 'wheel', 'root'].includes(group)
    || /관리자 그룹|administrators? group/iu.test(description);
  const command = /명령.*실행|권한 명령|command.*execut|execut.*command/iu.test(description);
  const newAdmin = /방금.*관리자|새.*관리자|new(?:ly)?.*admin|recent.*elevat/iu.test(description);
  const unusual = /처음 보는|처음 봅니다|시간 밖|업무.*않|다른 계정.*권한|원격 주소|unfamiliar|unexpected|outside.*hours|another account/iu.test(description);
  const incomplete = /취소|실패|변경은 없|명령은 없|추가.{0,8}(?:않|없)|변경.{0,8}않|실행.{0,8}(?:않|없)|cancel|failed|no (?:change|command)|(?:not|never)\s+(?:added|changed|executed|elevated)/iu.test(description);
  const unapproved = /미승인|승인.{0,8}(?:않|없)|\b(?:unauthorized|unapproved)\b|\bnot\s+(?:authorized|approved)\b/iu.test(description);
  const approvedRoutine = !unapproved && /승인된|승인받은|\bauthorized\b|\bapproved\b/iu.test(description)
    && /정기|평소|예약|routine|scheduled|usual/iu.test(description) && !unusual && !newAdmin;
  if (approvedRoutine) return output(0.05, 'no_matching_pattern');
  if (level >= 10 && !incomplete) {
    if (administratorGroup && changed) return output(0.92, PATTERNS[0].name);
    if ((command && (newAdmin || unusual || changed)) || (administrative && changed && unusual)) return output(0.92, PATTERNS[1].name);
  }
  const relevant = administrative || /그룹|계정.*(?:조회|종류)|group|account.*(?:query|type)/iu.test(description) || administratorGroup;
  return relevant ? output(0.6, PATTERNS[2].name) : output(0.05, 'no_matching_pattern');
}
