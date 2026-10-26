// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView({ api, onChange } = {}) {
  let viewGeneration = 0;
  let pcCancel = null;
  const pcHistory = [];
  const views = {
    renderIdentity({ me = {}, devices = {}, sessions = {} } = {}) {
      const root = document.createElement('section');
      const add = text => { const n = document.createElement('p'); n.textContent = text; root.append(n); };
      const ds = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const ss = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      const device = d => add(`기기: ${d.label} / ID: ${d.id} / ${ds[d.status] ?? '확인 불가'}(${d.status ?? 'unknown'})`);
      const session = s => add(`세션 ID: ${s.id} / ${ss[s.status] ?? '확인 불가'}(${s.status ?? 'unknown'})`);
      for (const [name, r] of [['현재 계정', me], ['등록 기기', devices], ['현재 세션', sessions]]) {
        add(name);
        if (r.mode === 'demo') add('예제 자료');
        if (r.mode === 'disconnected') add('연결 없음');
        if (r.mode === 'unknown') add('확인 불가');
        if (r.status === 'loading') { add('불러오는 중'); continue; }
        if (r.status === 'error') { add(`연결 실패: ${r.error?.message ?? '확인 불가'}`); continue; }
        if (r.status !== 'ok') { add('확인 불가'); continue; }
        if (r === me) {
          if (!r.data?.user || !r.data?.device || !r.data?.session) { add('현재 계정 확인 불가'); continue; }
          add(`사용자: ${r.data.user.label} / ID: ${r.data.user.id}`); device(r.data.device); session(r.data.session);
        } else if (!Array.isArray(r.data)) add('목록 확인 불가');
        else if (!r.data.length) add(r === devices ? '등록된 기기가 없습니다' : '현재 연결이 없습니다');
        else for (const row of r.data) r === devices ? device(row) : session(row);
      }
      return root;
    },
    renderDecision({ status, mode, data, error, appId } = {}) {
      const root = document.createElement('section');
      const add = text => { const n = document.createElement('p'); n.textContent = text; root.append(n); };
      if (mode === 'demo') add('예제 자료');
      if (mode === 'disconnected') add('연결 없음');
      if (mode === 'unknown') add('확인 불가');
      if (appId) add(`요청 앱: ${appId}`);
      if (status === 'idle' || status == null) add('앱을 골라 접속을 요청하세요.');
      else if (status === 'loading') add('판정 확인 중');
      else if (status === 'error') { add(`요청 실패: ${error?.message ?? '확인 불가'}`); add('요청 실패는 거부 판정이 아닙니다. 접속 허용 여부를 확인할 수 없습니다.'); }
      else if (status === 'ok' && data) {
        const values = { allow: '허용', deny: '거부', challenge: '추가 확인 필요', unknown: '확인 불가' };
        const decision = Object.hasOwn(values, data.decision) ? data.decision : 'unknown';
        add(`${values[decision]}(${decision})`); add(`앱: ${data.appId ?? appId ?? '확인 불가'}`);
        add(`이유: ${data.reason ?? '확인 불가'}`); add(`판정 시각: ${data.checkedAt ?? '확인 불가'}`);
        if (decision === 'challenge') add('추가 확인 절차가 필요합니다. 이 앱은 확인 절차를 대신 수행하지 않습니다.');
      } else add('확인 불가(unknown)');
      return root;
    },
    renderEvents({ status, mode, data, error } = {}) {
      const root = document.createElement('section');
      const add = (tag, text, parent = root) => { const n = document.createElement(tag); n.textContent = text; parent.append(n); return n; };
      add('p', '본인의 접속 기록과 저장된 XDR 경보입니다. 전체 로그나 다른 사용자의 기록이 아닙니다.');
      if (mode === 'demo') add('p', '예제 자료');
      if (mode === 'disconnected') add('p', '연결 없음');
      if (mode === 'unknown') add('p', '확인 불가');
      if (status === 'loading') { add('p', '기록을 불러오는 중'); return root; }
      if (status === 'error') { add('p', `기록을 불러오지 못했습니다: ${error?.message ?? '확인 불가'}`); return root; }
      if (status !== 'ok' || !Array.isArray(data)) { add('p', '기록 확인 불가'); return root; }
      if (!data.length) { add('p', '표시할 기록이 없습니다'); return root; }
      const states = { access: { allowed: '허용', denied: '거부', unknown: '확인 불가' }, session: { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' }, device: { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' } };
      const kinds = { access: '접속 기록', xdr: 'XDR 경보' }, filters = {};
      const select = (key, title, values, labels = {}) => {
        const label = add('label', title), box = add('select', '', label); box.setAttribute('aria-label', title);
        for (const value of ['all', ...values]) { const option = add('option', value === 'all' ? '전체' : labels[value] ?? value, box); option.value = value; }
        box.value = 'all'; filters[key] = box; box.addEventListener('change', draw);
      };
      select('kind', '기록 종류', [...new Set(data.map(e => e.kind))], kinds);
      select('app', '업무 앱', [...new Set(data.map(e => e.appId).filter(Boolean))]);
      select('access', '접속 상태', [...new Set(data.map(e => e.state?.access ?? 'unknown'))], states.access);
      const list = add('div', ''), detail = add('div', '');
      const stateText = (key, value) => `${states[key][value] ?? '확인 불가'}(${Object.hasOwn(states[key], value) ? value : 'unknown'})`;
      function showDetail(event) {
        detail.replaceChildren(); const box = add('section', '', detail); box.setAttribute('data-student-event-detail', event.id);
        add('h4', `사건 ID: ${event.id}`, box); add('p', `업무 앱: ${event.appId || '확인 불가'}`, box);
        add('h5', '근거', box); for (const row of event.evidence ?? []) add('p', `${row.id}: ${row.text}`, box);
        add('h5', '규칙', box); for (const row of event.rules ?? []) add('p', `${row.id}: ${row.text}`, box);
        for (const [key, name] of [['access', '접속'], ['session', '세션'], ['device', '기기']]) add('p', `${name}: ${stateText(key, event.state?.[key])}`, box);
        for (const action of event.supportedActions ?? []) { const button = add('button', `${action} 미지원`, box); button.type = 'button'; button.disabled = true; }
        if (event.supportedActions?.length) add('p', '아직 지원하지 않는 조치입니다. 조치 실행 연결은 준비 중입니다. 요청을 보내지 않습니다.', box);
      }
      function draw() {
        list.replaceChildren(); detail.replaceChildren();
        const rows = [...data].filter(e => (filters.kind.value === 'all' || e.kind === filters.kind.value) && (filters.app.value === 'all' || e.appId === filters.app.value) && (filters.access.value === 'all' || (e.state?.access ?? 'unknown') === filters.access.value)).sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
        if (!rows.length) add('p', '선택한 조건에 맞는 기록이 없습니다', list);
        for (const event of rows) {
          const row = add('article', '', list); row.setAttribute('data-student-event-id', event.id);
          add('p', `사건 ID: ${event.id} / 시각: ${event.at} / 종류: ${kinds[event.kind] ?? '확인 불가'}(${event.kind}) / 업무 앱: ${event.appId || '확인 불가'}`, row);
          add('p', event.summary, row); const button = add('button', `${event.id} 상세`, row); button.type = 'button'; button.addEventListener('click', () => showDetail(event));
        }
      }
      draw(); return root;
    },
    renderStatus({ devices = {}, sessions = {}, notifications = [], diagnostics = {}, mode } = {}) {
      const root = document.createElement('section');
      root.setAttribute('aria-label', '보호 현황 관제');
      const add = (tag, text, parent = root) => { const n = document.createElement(tag); n.textContent = text; parent.append(n); return n; };
      const safe = value => typeof value === 'string' && value.length > 0 && value.length <= 2000
        && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]|Bearer\s+\S+|sk-(?:proj-|on-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|-----BEGIN|(?:password|secret|token|api[_ -]?key|authorization|비밀번호|토큰)\s*[:=]|eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i.test(value)
        ? value : '비밀 없는 값을 확인할 수 없습니다';
      const showMode = (value, parent) => {
        const labels = { demo: '예제 자료 · 실제 운영 관측이 아닙니다', connected: '원천 서버 연결 자료', disconnected: '연결 없음', unknown: '확인 불가' };
        add('p', labels[value] ?? '자료 출처 확인 불가', parent);
      };
      const timestamp = (value, parent) => {
        if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value))) add('p', `원천 확인 시각: ${value}`, parent);
      };
      const names = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가', active: '활성', expired: '만료', revoked: '철회됨' };
      const pcSlot = add('section', ''); pcSlot.setAttribute('aria-label', '학생 PC 실측 · 별도 조회');
      add('h3', '내 PC 상태 · 읽기 전용', pcSlot);
      add('p', '수동 조회를 누르면 이 앱 실행 PC의 값만 읽습니다. 예제 보안 기록·SDP 연결 여부와 별개입니다.', pcSlot);
      const pcButton = add('button', '내 PC 상태 조회', pcSlot); pcButton.type = 'button'; pcButton.setAttribute('class', 'btn');
      const pcMessage = add('p', '아직 PC 상태를 조회하지 않았습니다. 기존 제공 서버에서는 이 기능을 확인할 수 없습니다.', pcSlot); pcMessage.setAttribute('role', 'status');
      let pcOpening = false;
      pcButton.addEventListener('click', async () => {
        if (pcOpening || !root.isConnected) return;
        const generation = viewGeneration; pcOpening = true; pcButton.disabled = true; pcMessage.textContent = '학생 PC 조회 도구를 불러오는 중입니다.';
        try {
          const { createPcPanel } = await import('./pc-view.mjs');
          if (!root.isConnected || generation !== viewGeneration) return;
          const panel = createPcPanel({ history: pcHistory, isCurrent: () => root.isConnected && generation === viewGeneration });
          pcCancel = panel.cancel; pcSlot.replaceChildren(panel.element); await panel.refresh();
        } catch {
          if (root.isConnected && generation === viewGeneration) pcMessage.textContent = '확인 불가: 학생 PC 조회 도구가 없습니다. 학생 PC 실행기를 사용하거나 기존 기능을 계속 사용하세요.';
        } finally { pcOpening = false; if (root.isConnected) pcButton.disabled = false; }
      });
      add('h3', '보호 현황');
      showMode(mode, root);
      add('p', '아래는 원천이 제공한 기기·세션·보안 기록입니다. 위의 별도 PC 조회가 성공해도 전체 보안 상태나 SDP 연결 성공을 뜻하지 않습니다.');
      const grid = add('div', '');
      grid.setAttribute('class', 'grid-2');
      const card = (key, title) => {
        const box = add('section', '', grid); box.setAttribute('data-student-status-card', key);
        box.setAttribute('class', 'card');
        add('h4', title, box); return box;
      };
      const drawResource = (title, resource, box) => {
        showMode(resource.mode, box);
        if (resource.status === 'loading') add('p', `${title === '기기' ? '기기를' : '세션을'} 불러오는 중`, box);
        else if (resource.status === 'error') {
          add('p', `${title === '기기' ? '기기를' : '세션을'} 불러오지 못했습니다${/TIMEOUT/.test(resource.error?.code ?? '') ? ' (시간 초과)' : ''}: ${safe(resource.error?.message)}`, box);
          add('p', '위쪽 다시 불러오기 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.', box);
        } else if (resource.status !== 'ok' || !Array.isArray(resource.data)) add('p', `${title} 확인 불가 · 아직 조회하지 않았거나 결과를 확인할 수 없습니다.`, box);
        else {
          add('p', `현재 입력에 포함된 ${title}: ${resource.data.length}개`, box);
          if (!resource.data.length) add('p', title === '기기' ? '등록된 기기가 없습니다' : '현재 연결이 없습니다', box);
          for (const row of resource.data) add('p', `${title === '기기' ? safe(row?.label) + ' / ' : ''}ID: ${safe(row?.id)} / ${names[row?.status] ?? '확인 불가'}(${safe(row?.status)})`, box);
        }
      };
      drawResource('기기', devices, card('device', '등록 기기'));
      const sessionCard = card('session', '현재 세션');
      drawResource('세션', sessions, sessionCard);
      add('p', '세션은 지금 검증된 연결 하나만 표시합니다. 전체 접속 이력이 아닙니다.', sessionCard);
      const notificationCard = card('notifications', '주의할 알림');
      const notes = Array.isArray(notifications) ? notifications : [];
      if (!Array.isArray(notifications)) add('p', '알림 자료의 형식을 확인할 수 없습니다.', notificationCard);
      else {
        add('p', `현재 입력에 포함된 알림: ${notes.length}건`, notificationCard);
        if (!notes.length) add('p', '현재 입력에 주의할 알림이 없습니다. 미조회·실패한 자료의 안전을 뜻하지 않습니다.', notificationCard);
      }
      for (const note of notes) add('p', `${safe(note?.resource)} / ${safe(note?.code)}: ${safe(note?.message)}`, notificationCard);
      if (devices.status !== 'ok' || sessions.status !== 'ok') add('p', '기기 또는 세션 조회가 끝나지 않아 현재 알림만으로 전체 상태를 판단할 수 없습니다.', notificationCard);
      const sdp = card('sdp', 'SDP 연결 · 도움정보');
      showMode(diagnostics.mode, sdp); let copyText = '';
      if (diagnostics.status === 'ok' && diagnostics.data) {
        const d = diagnostics.data;
        const safeData = { requestId: safe(d.requestId), component: safe(d.component), version: safe(d.version), checkedAt: safe(d.checkedAt), engine: { mode: safe(d.engine?.mode), code: safe(d.engine?.code) } };
        add('p', `원천 엔진 상태: ${safeData.engine.mode} / ${safeData.engine.code}`, sdp);
        timestamp(d.checkedAt, sdp);
        copyText = JSON.stringify(safeData, null, 2); add('pre', copyText, sdp);
      } else if (diagnostics.status === 'loading') add('p', '도움정보를 불러오는 중', sdp);
      else if (diagnostics.status === 'error') add('p', `도움정보를 불러오지 못했습니다: ${safe(diagnostics.error?.message)}. 위쪽 도움정보 불러오기 버튼을 직접 누르세요.`, sdp);
      else add('p', '아직 도움정보를 조회하지 않았습니다. 제공 화면에서 도움정보 불러오기를 누르세요.', sdp);
      add('p', '이 값은 원천의 점검 응답입니다. 실제 터널 연결이나 모든 네트워크 보호를 확인한 결과가 아닙니다.', sdp);
      add('p', '도움 요청에 쓸 비밀 없는 점검 값만 복사합니다.', sdp);
      const copy = add('button', '도움정보 복사', sdp); copy.type = 'button'; copy.setAttribute('class', 'btn'); copy.disabled = !copyText;
      const copyResult = add('p', '', sdp); copyResult.setAttribute('role', 'status');
      copy.addEventListener('click', async () => {
        if (!copyText) return;
        try { if (!globalThis.navigator?.clipboard?.writeText) throw Error('unavailable'); await globalThis.navigator.clipboard.writeText(copyText); if (root.isConnected) copyResult.textContent = '도움정보를 복사했습니다.'; }
        catch { if (root.isConnected) copyResult.textContent = '복사하지 못했습니다. 표시된 도움정보를 직접 선택해 복사하세요.'; }
      });
      const supplement = add('section', ''); supplement.setAttribute('data-student-status-supplement', '');
      add('h4', '수동 읽기 전용 점검', supplement);
      add('p', '기기·세션 보조 조회는 이 영역에만 표시합니다. 중앙 기록·알림·도움정보를 갱신하지 않습니다. 전체 상태는 위쪽 다시 불러오기와 도움정보 불러오기를 사용하세요.', supplement);
      const refresh = add('button', '기기·세션 보조 조회', supplement); refresh.type = 'button'; refresh.setAttribute('class', 'btn');
      refresh.disabled = typeof api?.get !== 'function';
      const readStatus = add('p', refresh.disabled ? '보조 조회 연결을 사용할 수 없습니다.' : '아직 보조 조회를 실행하지 않았습니다.', supplement);
      readStatus.setAttribute('role', 'status');
      const readResult = add('div', '', supplement);
      let pending = false;
      const validResult = (value, kind) => value?.ok === true && Array.isArray(value.data) && value.data.length <= 1000
        && value.data.every(row => row && typeof row.id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(row.id)
          && safe(row.id) === row.id && (kind === 'device' ? ['compliant', 'noncompliant', 'unknown'] : ['active', 'revoked', 'expired', 'unknown']).includes(row.status)
          && (kind !== 'device' || typeof row.label === 'string' && safe(row.label) === row.label))
        && ['connected', 'demo', 'disconnected', 'unknown'].includes(value.meta?.mode);
      const readFailure = value => {
        const codes = { TIMEOUT: '조회 시간이 초과됐습니다.', CANCELLED: '조회가 취소됐습니다.', NETWORK_ERROR: '서버에 연결할 수 없습니다.', NOT_ALLOWED: '허용되지 않은 조회입니다.', AUTH_REQUIRED: '현재 인증을 확인할 수 없습니다.', UNAUTHORIZED: '현재 인증을 확인할 수 없습니다.' };
        const code = Object.hasOwn(codes, value?.error?.code) ? value.error.code : 'UNVERIFIED';
        return `${code}: ${codes[code] ?? '응답 형식 또는 조회 결과를 확인할 수 없습니다.'}`;
      };
      refresh.addEventListener('click', async () => {
        if (pending || typeof api?.get !== 'function' || !root.isConnected) return;
        pending = true; refresh.disabled = true; readResult.replaceChildren();
        readStatus.textContent = '기기·세션 보조 조회 중입니다. 이전 보조 결과는 현재 결과가 아닙니다.';
        const requestGeneration = viewGeneration;
        const current = () => root.isConnected && requestGeneration === viewGeneration;
        try {
          const results = await Promise.allSettled([Promise.resolve().then(() => api.get('/api/devices')), Promise.resolve().then(() => api.get('/api/sessions'))]);
          if (!current()) return;
          for (const [index, title, kind] of [[0, '기기', 'device'], [1, '세션', 'session']]) {
            const result = results[index].status === 'fulfilled' ? results[index].value : null;
            const box = add('section', '', readResult); add('h5', `${title} 보조 조회 결과`, box);
            if (!validResult(result, kind)) { add('p', readFailure(result), box); continue; }
            drawResource(title, { status: 'ok', mode: result.meta.mode, data: result.data }, box);
            timestamp(result.meta.checkedAt, box);
          }
          readStatus.textContent = '보조 조회가 끝났습니다. 각 결과의 출처와 실패 여부를 확인하세요. 중앙 화면은 갱신하지 않았습니다.';
        } finally {
          pending = false;
          if (root.isConnected) {
            refresh.disabled = false;
            if (requestGeneration !== viewGeneration) {
              readResult.replaceChildren();
              readStatus.textContent = '화면 상태가 바뀌어 보조 결과를 버렸습니다. 필요하면 직접 다시 조회하세요.';
            }
          }
        }
      });
      add('p', '핵심 흐름: 1. 실제 접속 판정 확인 2. 보안 기록의 근거 확인 3. 사람 확인이 필요한 제안과 실제 처리 결과 구분.');
      return root;
    },
    renderVulnerabilities({ status = 'idle', mode = 'unknown', data, error } = {}) {
      const root = document.createElement('section');
      const add = (tag, value, parent = root) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.appendChild(node);
        return node;
      };
      const text = value => typeof value === 'string' || typeof value === 'number' ? String(value) : '확인 불가';
      add('h4', '설치 패키지 취약점 조회');
      const modes = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      if (Object.hasOwn(modes, mode)) add('p', modes[mode]);
      if (status === 'idle') { add('p', '조회 전(idle). 제공 화면에서 설치 패키지 조회를 누르세요.'); return root; }
      if (status === 'loading') { add('p', '조회 중(loading). 이전 결과는 현재 조회 결과가 아닙니다.'); return root; }
      if (status === 'error') {
        const message = typeof error?.message === 'string' && error.message.length <= 1000
          && !/[\u0000-\u001f\u007f]|Bearer\s+\S+|sk-[\w-]{8,}|-----BEGIN|(?:password|api[_ -]?key|authorization)\s*[:=]/i.test(error.message)
          ? error.message : '오류 내용을 안전하게 확인할 수 없습니다.';
        add('p', `조회 실패: ${message}`);
        add('p', '조회 실패로 취약점 유무를 판단할 수 없습니다. 제공 화면에서 직접 다시 조회하세요.');
        return root;
      }
      const scans = { complete: '모두 조회(complete)', partial: '일부 조회 실패(partial)', not_checked: '아직 조회 안 함(not_checked)', not_configured: '조회 준비 미완료(not_configured)', unverifiable: 'lock 파일 확인 불가(unverifiable)' };
      if (status !== 'ok' || !data || !Object.hasOwn(scans, data.status)) {
        add('p', '조회 결과 확인 불가. 제공 화면에서 직접 다시 조회하세요.'); return root;
      }
      add('p', scans[data.status]);
      if (data.lockfileVersion != null) add('p', `lockfileVersion: ${text(data.lockfileVersion)}`);
      if (data.lockfileHash != null) add('p', `lockfileHash: ${text(data.lockfileHash)}`);
      if (data.checkedAt != null) add('p', `조회 시각: ${text(data.checkedAt)}`);
      if (!Array.isArray(data.packages) || data.packages.length === 0) {
        add('p', '표시할 패키지 조회 결과가 없습니다. 미조회·설정 없음·확인 불가는 취약점 없음의 근거가 아닙니다.');
        return root;
      }
      const states = { known_vulnerabilities: '알려진 항목 있음', none_found: '조회 범위에서 알려진 항목 없음', unverifiable: '조회 확인 불가' };
      const list = add('ul', '');
      for (const item of data.packages) {
        const row = add('li', '', list);
        row.setAttribute('data-student-package-name', text(item.name));
        row.setAttribute('data-student-package-version', text(item.version));
        add('p', `패키지: ${text(item.name)} · 설치 버전: ${text(item.version)}`, row);
        const findings = Array.isArray(item.vulnerabilities) ? item.vulnerabilities : [];
        const inconsistent = item.status === 'none_found' && findings.length > 0;
        const label = inconsistent ? '상태와 조회 항목 불일치·확인 불가' : Object.hasOwn(states, item.status) ? states[item.status] : '조회 확인 불가';
        add('p', `상태: ${label} (${text(item.status)})`, row);
        if (item.source != null) add('p', `출처: ${text(item.source)}`, row);
        if (item.checkedAt != null) add('p', `조회 시각: ${text(item.checkedAt)}`, row);
        if (item.status === 'unverifiable' && findings.length > 0) add('p', '일부 확인·전체 조회 확인 불가', row);
        for (const finding of findings) add('p', `취약점 ID: ${text(finding.id)} · 수정 시각(modified): ${text(finding.modified)}`, row);
      }
      add('p', '조회된 공개 취약점 정보이며 패키지의 전반적인 안전성 판정이나 치료 결과가 아닙니다.');
      return root;
    },
    renderAiConnection({ status = 'idle', mode = 'unknown', data, error, checkedAt, explanationAccepted = false } = {}) {
      const root = document.createElement('section');
      const add = (tag, text) => { const node = document.createElement(tag); node.textContent = text; root.appendChild(node); };
      add('h4', 'AI 연결 점검');
      const modes = { connected: '연결된 자료(connected)', demo: '예제 자료(demo) · 실제 게이트 수용 아님', disconnected: '연결 없음(disconnected)', unknown: '연결 상태 확인 불가(unknown)' };
      add('p', modes[mode] || modes.unknown);
      const manual = () => add('p', '다시 점검하려면 제공 화면의 「현재 API 연결 점검」 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.');
      const messages = {
        ON_AI_PROVISIONING_PENDING: '학생 계정 연결과 앱 권한 발급을 준비 중입니다. 담당자에게 확인하세요.',
        WB_CLCO_AUTH_REQUIRED: '인증을 확인할 수 없습니다. 계정 연결을 다시 확인하고 담당자에게 문의하세요.',
        WB_CLCO_ACCESS_BLOCKED: 'AI 접근이 제한됐습니다. 이용 권한을 담당자에게 확인하세요.',
        WB_CLCO_COHORT_BUDGET_EXHAUSTED: '반의 AI 사용량이 소진됐습니다. 담당자에게 확인하세요.',
        WB_CLCO_RATE_LIMITED: 'AI 요청이 제한됐습니다. 잠시 뒤 직접 다시 점검하세요.',
        WB_CLCO_LIMIT_REACHED: 'AI 이용 한도에 도달했습니다. 담당자에게 확인하세요.',
        WB_CLCO_SESSION_CLOSED: '현재 AI 이용 시간이 아닙니다. 이용 시간을 확인하세요.',
        WB_CLCO_TIMEOUT: 'AI 응답 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.',
        REQUEST_TIMEOUT: '서버의 AI 응답 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.',
        ENGINE_TIMEOUT: '서버의 확인 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.',
        TIMEOUT: 'AI 응답 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.',
        WB_CLCO_CANCELLED: 'AI 연결 점검을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
        CANCELLED: 'AI 연결 점검을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
        REQUEST_CANCELLED: 'AI 연결 점검을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.',
        MODEL_NOT_CONFIGURED: '사용할 AI 모델이 설정되지 않았습니다. 담당자에게 모델 허용 설정을 확인하세요.',
        ON_AI_AUTHORIZATION_CHANGED: 'AI 이용 권한이 바뀌었습니다. 계정 연결과 현재 앱 권한을 담당자에게 확인하세요.',
        ON_AI_MODEL_LIST_EMPTY: '현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.',
        SUBJECT_SCOPE_UNVERIFIED: '현재 로그인과 프로젝트의 연결을 확인할 수 없습니다. 담당자에게 계정 연결을 확인하세요.',
        ON_AI_INVALID_INPUT: 'AI 요청 입력을 확인할 수 없습니다. 담당자에게 확인하세요.',
        ON_AI_INVALID_OUTPUT: 'AI 응답 형식을 확인할 수 없습니다. 담당자에게 확인하세요.',
        AI_REQUEST_UNVERIFIED: 'AI 연결 또는 응답을 확인할 수 없습니다. 연결 상태를 확인하고 잠시 뒤 직접 다시 점검하세요.',
      };
      const safeMessage = value => typeof value === 'string' && value.trim().length > 0 && value.length <= 500
        && !/[\u0000-\u001f\u007f]/.test(value)
        && !/(?:Bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+|\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,})/i.test(value);
      const fail = (code, message) => {
        add('p', `AI 연결 점검 실패: ${code}: ${message}`); add('p', messages[code]);
        add('p', '이전 점검 결과는 현재 결과가 아닙니다. 사건 설명의 모델 호출과 결과는 확인되지 않았습니다.');
        manual(); return root;
      };
      if (status === 'idle') { add('p', 'AI 연결 점검 전(idle)입니다. 이전 점검 결과는 현재 결과가 아닙니다.'); manual(); return root; }
      if (status === 'loading') {
        add('p', 'AI 연결 점검 중(loading)입니다. 이전 모델 수와 오류는 현재 결과가 아닙니다.');
        add('p', '필요하면 제공 화면의 「취소」 버튼을 누르세요. 사건 설명은 아직 실행하지 않았습니다.'); return root;
      }
      if (status === 'error') {
        const code = Object.hasOwn(messages, error?.code) ? error.code : 'AI_REQUEST_UNVERIFIED';
        return fail(code, safeMessage(error?.message) ? error.message : messages[code]);
      }
      const validTime = typeof checkedAt === 'string' && checkedAt.length <= 40
        && /^\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})$/.test(checkedAt) && Number.isFinite(Date.parse(checkedAt));
      if (status !== 'ok' || data?.transportChecked !== true || !['test', 'verified'].includes(data.audienceAuthorization)
        || !Number.isInteger(data.modelCount) || data.modelCount < 0 || data.modelCount > 10000 || !validTime) return fail('AI_REQUEST_UNVERIFIED', messages.AI_REQUEST_UNVERIFIED);
      add('p', data.audienceAuthorization === 'test' ? '시험 연결 점검(test) · 실제 게이트 수용 아님' : '앱 권한 확인 후 점검(verified) · 해당 점검 시각 기준');
      add('p', '전송 연결 점검 확인: transportChecked: true');
      add('p', `응답 모델 수: ${data.modelCount}`); add('p', `점검 시각: ${checkedAt}`);
      add('p', '연결과 모델 목록 응답만 점검했습니다. 사건 설명은 아직 실행하지 않았습니다. 실제 사건 설명의 모델 호출과 검증된 결과는 보안 기록에서 별도로 확인하세요.');
      if (data.modelCount === 0) add('p', '현재 응답에 쓸 수 있는 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.');
      manual(); return root;
    },
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
    renderAction({ status = 'idle', event, actionId, target, receipt, observation, message, confirmationExpiresAt, error } = {}) {
      const root = document.createElement('section');
      const add = (tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        root.appendChild(node);
        return node;
      };
      const safe = value => (typeof value === 'string' || typeof value === 'number')
        && String(value).trim().length > 0 && String(value).length <= 1000
        && !/[\u0000-\u001f\u007f]|Bearer\s+\S+|sk-(?:proj-)?[\w-]{8,}|-----BEGIN|(?:password|api[_ -]?key|authorization)\s*[:=]/i.test(String(value));
      const field = (label, value) => { if (safe(value)) add('p', `${label}: ${value}`); };
      const labels = {
        idle: '아직 미실행(idle)',
        loading: '조치 준비 또는 결과 조회 중(loading)',
        prepared: '준비됨·미실행(prepared). 제공 화면에서 실제 대상과 조치·확인 기한을 확인하세요.',
        executing: '서버에 전달 중(executing). 처리 결과는 아직 확인되지 않았습니다.',
        pending: '서버 접수·처리 중(pending). 접수 응답(ACK)은 효과 확인이 아닙니다.',
        denied: '거절(denied)', failed: '실패(failed)',
        expired: '확인 기한 지남(expired). 제공 화면에서 다시 준비하세요.',
        error: '요청 처리 안 됨(error)',
      };
      const confirmed = status === 'succeeded' && observation?.effectApplied === true;
      add('h4', '조치 요청 상태');
      if (confirmed) {
        add('p', '효과 확인(succeeded)');
        field('관측 시각', observation.observedAt);
        add('p', 'effectApplied: true');
      } else if (status === 'unknown' || status === 'succeeded' || !Object.hasOwn(labels, status)) {
        add('p', '결과 불명(unknown). 성공 또는 효과 없음으로 판단할 수 없습니다. 제공 화면에서 연동 시스템 결과만 재조회하세요.');
        if (status === 'succeeded') add('p', '수신 상태: succeeded. effectApplied: true가 확인되지 않았습니다.');
      } else add('p', labels[status]);
      field('사건 ID', event?.id);
      if (safe(event?.id)) root.setAttribute('data-student-action-event', String(event.id));
      if (Array.isArray(event?.evidence)) for (const proof of event.evidence) field('근거 ID', proof?.id);
      field('조치 ID', actionId); field('대상 ID', target?.id); field('대상 generation', target?.generation);
      field('확인 기한', confirmationExpiresAt); field('요청 ID', receipt?.requestId);
      field('접수 ID(receiptId)', receipt?.receiptId); field('접수 version', receipt?.version); field('접수 상태', receipt?.status);
      if (safe(receipt?.requestId)) root.setAttribute('data-student-action-request', String(receipt.requestId));
      if (receipt?.replayed === true) add('p', '같은 요청의 기존 접수 결과입니다(replayed: true). 새 실행으로 세지 않습니다.');
      if (['denied', 'failed', 'error', 'expired'].includes(status)) {
        field('안내', message); field('오류 코드', error?.code); field('오류 내용', error?.message);
        if (!safe(message) && !safe(error?.message)) add('p', '구체적인 사유는 확인할 수 없습니다.');
      }
      if (Array.isArray(event?.supportedActions) && event.supportedActions.length === 0) add('p', '연동 시스템이 지원하는 조치가 없어 조치 준비 버튼이 표시되지 않는 것이 정상입니다.');
      add('p', '조치 제안은 실행이 아닙니다. 집행에는 제공 화면의 사람 확인이 필요합니다. 학생 영역은 요청을 보내지 않습니다.');
      add('p', '조치 화면 취소는 서버에 전달된 조치 효과를 되돌리지 않습니다.');
      return root;
    },
  };
  // Any new host render invalidates pending auxiliary reads from an older view.
  return Object.fromEntries(Object.entries(views).map(([name, render]) => [name, function (...args) {
    pcCancel?.(); pcCancel = null;
    viewGeneration += 1;
    return render.apply(this, args);
  }]));
}
