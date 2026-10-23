// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity() { return '학생 구현 대기: 실제 로그인·기기·세션 정보를 연결하세요.'; },
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation({ event = null, explanation = {}, checkedAt = null } = {}) {
      // Every render owns a fresh tree. The host discards late requests on record changes.
      const root = document.createElement('section');
      const add = (tag, text, parent = root) => {
        const node = document.createElement(tag);
        node.textContent = text;
        parent.appendChild(node);
        return node;
      };
      const secret = /(?:Bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+)/i;
      const text = (value, max) => typeof value === 'string' && value.trim().length > 0
        && value.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value) && !secret.test(value);
      const messages = {
        ON_AI_PROVISIONING_PENDING: '학생 앱 이용 권한의 발급·연결을 준비 중입니다. 담당자에게 확인하세요.',
        WB_CLCO_AUTH_REQUIRED: '학생 앱 AI 인증을 확인하세요. 담당자에게 문의하세요.',
        WB_CLCO_ACCESS_BLOCKED: '학생 앱 AI 이용이 제한됐습니다. 담당자에게 확인하세요.',
        WB_CLCO_COHORT_BUDGET_EXHAUSTED: '반의 AI 사용량이 소진됐습니다.',
        WB_CLCO_RATE_LIMITED: 'AI 요청이 잠시 제한됐습니다. 잠시 후 직접 다시 요청하세요.',
        WB_CLCO_LIMIT_REACHED: 'AI 이용 한도에 도달했습니다.',
        WB_CLCO_SESSION_CLOSED: '현재 AI 이용 시간이 아닙니다.',
        WB_CLCO_TIMEOUT: 'AI 응답 시간이 초과됐습니다.',
        REQUEST_TIMEOUT: '서버의 AI 응답 시간이 초과됐습니다.',
        ENGINE_TIMEOUT: '서버의 확인 시간이 초과됐습니다.',
        TIMEOUT: 'AI 응답 시간이 초과됐습니다.',
        WB_CLCO_CANCELLED: 'AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
        CANCELLED: 'AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
        REQUEST_CANCELLED: 'AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
        MODEL_NOT_CONFIGURED: '서버에 사용할 AI 모델이 설정되지 않았습니다.',
        ON_AI_AUTHORIZATION_CHANGED: 'AI 이용 권한이 바뀌었습니다. 현재 권한을 담당자에게 확인하세요.',
        ON_AI_MODEL_LIST_EMPTY: '현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다.',
        SUBJECT_SCOPE_UNVERIFIED: '현재 로그인과 사건·프로젝트의 연결을 확인할 수 없습니다.',
        ON_AI_INVALID_INPUT: '설명에 필요한 사건 근거·규칙을 확인할 수 없습니다.',
        ON_AI_INVALID_OUTPUT: 'AI 설명의 근거·조치·응답 형식을 확인할 수 없습니다.',
        AI_REQUEST_UNVERIFIED: 'AI 연결 또는 응답을 확인할 수 없습니다.',
      };
      const fail = (message, code = 'ON_AI_INVALID_OUTPUT') => {
        add('h4', 'AI 설명 실패');
        add('p', `${code}: ${message}`);
        add('p', '기록은 그대로입니다. AI 설명 실패는 과제 실패가 아닙니다.');
        return root;
      };
      // Preserve useful failure details only after checking their display safety.
      if (explanation?.status === 'error') {
        const code = Object.hasOwn(messages, explanation.error?.code)
          ? explanation.error.code : 'AI_REQUEST_UNVERIFIED';
        const message = explanation.error?.message;
        const sensitiveMessage = /(?:\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,})/;
        const safeMessage = text(message, 500) && !/[\u0000-\u001f\u007f]/.test(message) && !sensitiveMessage.test(message);
        return fail(safeMessage ? message : messages[code], code);
      }
      if (!event) {
        add('p', '보안 기록에서 기록을 먼저 고르세요.');
        return root;
      }
      if (explanation?.status === 'loading') {
        add('p', 'AI 설명 요청 중입니다. 이전 설명은 현재 결과가 아닙니다.');
        return root;
      }
      if (explanation?.status === 'idle' || explanation?.status == null) {
        add('p', '이 기록의 AI 설명을 아직 요청하지 않았습니다.');
        return root;
      }
      if (explanation.status !== 'ok') return fail(messages.AI_REQUEST_UNVERIFIED, 'AI_REQUEST_UNVERIFIED');
      const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
      const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(value) && !secret.test(value);
      const rows = (value, max) => Array.isArray(value) && value.length > 0 && value.length <= 20
        && value.every(row => isRecord(row) && id(row.id) && text(row.text, max))
        && new Set(value.map(row => row.id)).size === value.length;
      const stateValues = {
        access: ['allowed', 'denied', 'unknown'],
        session: ['active', 'revoked', 'expired', 'unknown'],
        device: ['compliant', 'noncompliant', 'unknown'],
      };
      if (!id(event.id) || !rows(event.evidence, 500) || !rows(event.rules, 300)
        || !Array.isArray(event.supportedActions) || event.supportedActions.length > 20
        || !event.supportedActions.every(id) || new Set(event.supportedActions).size !== event.supportedActions.length
        || !isRecord(event.state) || Object.entries(stateValues).some(([key, values]) => !values.includes(event.state[key]))) {
        return fail('현재 사건의 근거·규칙·상태가 부족하거나 형식이 맞지 않아 설명을 쓸 수 없습니다.');
      }
      const data = explanation.data;
      if (!isRecord(data)) return fail(messages.ON_AI_INVALID_OUTPUT);
      if (data.executed !== false || data.requiresHumanConfirmation !== true) {
        return fail('AI가 이미 실행했다고 답했거나 사람 확인 조건을 확인할 수 없어 이 설명을 쓸 수 없습니다.');
      }
      // The public contract has no independent event ID: bind every reference to this event.
      const fields = ['summary', 'evidenceIds', 'proposals', 'requiresHumanConfirmation', 'executed'];
      if (Object.keys(data).length !== fields.length || !fields.every(key => Object.hasOwn(data, key))
        || !text(data.summary, 1500)) return fail(messages.ON_AI_INVALID_OUTPUT);
      const evidence = new Map(event.evidence.map(row => [row.id, row.text]));
      const refs = value => Array.isArray(value) && value.length > 0 && value.length <= 20
        && new Set(value).size === value.length && value.every(ref => id(ref) && evidence.has(ref));
      if (!refs(data.evidenceIds) || data.evidenceIds.length !== evidence.size) {
        return fail('근거가 맞지 않음: 현재 사건에 없는 근거 또는 누락·중복 근거가 있어 이 설명을 쓸 수 없습니다.');
      }
      if (!Array.isArray(data.proposals) || data.proposals.length > 3 || data.proposals.some(proposal =>
        !isRecord(proposal) || Object.keys(proposal).length !== 3
        || !['action', 'evidenceIds', 'reason'].every(key => Object.hasOwn(proposal, key))
        || !id(proposal.action) || !event.supportedActions.includes(proposal.action)
        || !refs(proposal.evidenceIds) || !text(proposal.reason, 500))) {
        return fail('조치 제안의 대상·근거·이유를 현재 사건과 연결할 수 없어 이 설명을 쓸 수 없습니다.');
      }
      root.setAttribute('data-student-explanation-event', event.id);
      add('h4', 'AI 설명(참고용)');
      add('p', `사건 ID: ${event.id}`);
      add('p', 'AI 설명은 해석입니다. 사실 판단은 인용한 근거와 원천이 알려 준 현재 상태를 기준으로 하세요.');
      add('p', data.summary);
      add('h5', '인용한 근거');
      const evidenceList = add('ul', '');
      for (const ref of data.evidenceIds) add('li', `${ref} — ${evidence.get(ref)}`, evidenceList);
      add('h5', '현재 규칙');
      const ruleList = add('ul', '');
      for (const rule of event.rules) add('li', `${rule.id} — ${rule.text}`, ruleList);
      add('h5', '확인되지 않은 현재 상태');
      const names = { access: '접속', session: '세션', device: '기기' };
      const unknown = Object.keys(names).filter(key => event.state[key] === 'unknown');
      if (unknown.length === 0) add('p', '없음');
      else {
        const states = add('ul', '');
        for (const key of unknown) add('li', `${names[key]}: 확인 불가(unknown)`, states);
      }
      add('h5', '조치 제안');
      if (data.proposals.length === 0) {
        add('p', event.supportedActions.length === 0
          ? '원천이 지원하는 조치가 없어 제안이 없습니다(정상).'
          : 'AI가 이 기록에 제안한 조치가 없습니다.');
      } else {
        const proposals = add('ul', '');
        for (const proposal of data.proposals) add('li', `${proposal.action} — ${proposal.reason} (근거 ${proposal.evidenceIds.join(', ')})`, proposals);
      }
      add('p', '사람 확인이 필요하며 실행되지 않았습니다. AI는 아무것도 실행하지 않았습니다.');
      if (typeof checkedAt === 'string' && checkedAt.length <= 40
        && /^\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})$/.test(checkedAt) && Number.isFinite(Date.parse(checkedAt))) {
        add('p', `확인 시각: ${checkedAt}`);
      }
      return root;
    },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
