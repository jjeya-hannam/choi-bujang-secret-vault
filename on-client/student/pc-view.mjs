// Manual, read-only local PC observations. No browser storage or background polling.
const labels = { cpu: 'CPU 사용률', memory: '메모리 사용량', disk: '디스크 남은 공간', network: '네트워크 구성' };
const units = { cpu: 'percent', memory: 'bytes', disk: 'bytes', network: 'count', firewall: 'profiles', eventLogs: 'count' };
const unknownReasons = { UNSUPPORTED_PLATFORM: '이 운영체제에서는 일반 권한 조회를 지원하지 않습니다.', OBSERVATION_FAILED: '일반 권한 조회에 실패했습니다.', OBSERVATION_TIMEOUT: '일반 권한 조회 시간이 초과됐습니다.', INVALID_OBSERVATION: '관측 값의 형식이나 범위를 확인할 수 없습니다.' };
const iso = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
const nonnegative = value => Number.isSafeInteger(value) && value >= 0;
const sizePair = value => value && nonnegative(value.total) && value.total > 0 && nonnegative(value.free) && value.free <= value.total;
const bytes = value => `${(value / 1024 ** 3).toFixed(2)} GiB`;
function safeMetric(key, value) {
  if (!value || !['observed', 'unknown'].includes(value.status) || value.unit !== units[key] || !iso(value.checkedAt)) return false;
  if (value.status === 'unknown') return value.observed === null && Object.hasOwn(unknownReasons, value.code);
  if (value.code !== 'OK') return false;
  const observation = value.observed;
  if (key === 'cpu') return typeof observation === 'number' && Number.isFinite(observation) && observation >= 0 && observation <= 100;
  if (key === 'memory' || key === 'disk') return sizePair(observation);
  if (key === 'network') return observation && nonnegative(observation.interfaces);
  if (key === 'firewall') return observation && nonnegative(observation.enabled) && nonnegative(observation.disabled);
  return observation && nonnegative(observation.system) && nonnegative(observation.application) && observation.windowHours === 24;
}
export function validatePcStatus(value) {
  if (value?.ok !== true || value.data?.schema !== 'student.pc-status.v1' || value.data.source !== 'local_pc'
    || !iso(value.data.checkedAt) || !['win32', 'darwin', 'linux', 'other'].includes(value.data.platform)) return null;
  const data = value.data;
  if (Object.keys(units).some(key => !safeMetric(key, data[key]))) return null;
  // Copy only allowlisted numeric observations. Unknown codes and extra strings never reach the DOM/history.
  return { checkedAt: data.checkedAt, platform: data.platform, ...Object.fromEntries(Object.keys(units).map(key => {
    const metric = data[key];
    const names = { memory: ['total', 'free'], disk: ['total', 'free'], network: ['interfaces'], firewall: ['enabled', 'disabled'], eventLogs: ['system', 'application', 'windowHours'] };
    const observed = metric.status === 'unknown' ? null : key === 'cpu' ? metric.observed
      : Object.fromEntries(names[key].map(name => [name, metric.observed[name]]));
    return [key, { status: metric.status, code: metric.code, checkedAt: metric.checkedAt, observed }];
  })) };
}
function observedText(key, metric) {
  if (metric.status !== 'observed') return `확인 불가 · ${unknownReasons[metric.code] ?? '일반 권한의 조회 결과를 확인하지 못했습니다.'}`;
  const value = metric.observed;
  if (key === 'cpu') return `${value.toFixed(1)} %`;
  if (key === 'memory') return `${bytes(value.total - value.free)} 사용 / ${bytes(value.total)} 전체`;
  if (key === 'disk') return `${bytes(value.free)} 남음 / ${bytes(value.total)} 전체`;
  if (key === 'network') return `${value.interfaces}개 네트워크 구성 항목`;
  if (key === 'firewall') return `켜짐 ${value.enabled}개 / 꺼짐 ${value.disabled}개 프로필`;
  return `System ${value.system}건 / Application ${value.application}건 · 최근 ${value.windowHours}시간 경고·오류 합계`;
}

export function createPcPanel({ fetcher = globalThis.fetch, history = [], isCurrent = () => true, timeoutMs = 12000 } = {}) {
  const root = document.createElement('section'); root.setAttribute('aria-label', '내 PC 상태 읽기 전용 관제');
  const add = (tag, text, parent = root) => { const node = document.createElement(tag); node.textContent = text; parent.appendChild(node); return node; };
  add('h3', '내 PC 상태 · 수동 실측');
  add('p', '이 앱을 실행한 PC의 일반 권한 읽기 전용 조회입니다. SDP·예제 보안 기록과 별개이며 보안 설정을 바꾸지 않습니다.');
  const refreshButton = add('button', '내 PC 상태 다시 조회'); refreshButton.type = 'button'; refreshButton.setAttribute('class', 'btn');
  const cancelButton = add('button', 'PC 조회 취소'); cancelButton.type = 'button'; cancelButton.setAttribute('class', 'btn'); cancelButton.disabled = true;
  const status = add('p', '아직 PC 상태를 조회하지 않았습니다. 예시 값은 표시하지 않습니다.'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  const current = add('div', ''); const previous = add('div', '');
  add('p', 'Windows 경고·오류 건수는 침해나 공격 탐지 결과가 아닙니다. 관리자 권한이 필요한 항목은 확인 불가로 남깁니다.');
  let generation = 0, busy = false, abort, rejectPending;
  const active = token => token === generation && root.isConnected && isCurrent();
  function drawHistory() {
    previous.replaceChildren(); if (!history.length) return;
    add('h4', '이 창에서 수동 조회한 최근 이력 · 현재 상태가 아님', previous);
    add('p', '최대 8회만 메모리에 보관하며 새로고침하면 사라집니다. 실패·미조회 값을 정상으로 채우지 않습니다.', previous);
    const table = add('table', '', previous); const header = add('tr', '', table);
    for (const title of ['관측 시각', 'CPU (%)', '사용 메모리 (GiB)', '디스크 남음 (GiB)']) { const th = add('th', title, header); th.setAttribute('scope', 'col'); }
    for (const entry of history) {
      const row = add('tr', '', table);
      add('td', entry.checkedAt, row);
      add('td', entry.cpu.status === 'observed' ? entry.cpu.observed.toFixed(1) : '확인 불가', row);
      add('td', entry.memory.status === 'observed' ? bytes(entry.memory.observed.total - entry.memory.observed.free) : '확인 불가', row);
      add('td', entry.disk.status === 'observed' ? bytes(entry.disk.observed.free) : '확인 불가', row);
    }
  }
  function cancel() {
    generation++; abort?.abort(); rejectPending?.reject(new Error('PC_CANCELLED')); rejectPending = null;
    busy = false;
    if (root.isConnected) { refreshButton.disabled = false; cancelButton.disabled = true; current.replaceChildren(); status.textContent = '조회가 취소되었거나 화면 상태가 바뀌었습니다. 결과는 현재 값으로 표시하지 않습니다.'; }
  }
  async function refresh() {
    if (busy || !root.isConnected || !isCurrent()) return;
    const token = ++generation; busy = true; refreshButton.disabled = true; cancelButton.disabled = false;
    current.replaceChildren(); status.textContent = 'PC 상태 조회 중입니다. 이전 값은 현재 결과가 아닙니다.'; drawHistory();
    const controller = new AbortController(); abort = controller; let timer;
    try {
      const interruption = new Promise((_, reject) => { rejectPending = { token, reject }; timer = setTimeout(() => { controller.abort(); reject(new Error('PC_TIMEOUT')); }, timeoutMs); });
      const response = await Promise.race([Promise.resolve().then(() => fetcher('/api/student/pc-status', { method: 'GET', headers: { 'x-student-pc-read': '1' }, credentials: 'same-origin', cache: 'no-store', signal: controller.signal })), interruption]);
      if (!active(token)) return;
      if (!response.ok) throw new Error(response.status === 404 ? 'PC_ROUTE_MISSING' : 'PC_UNAVAILABLE');
      const data = validatePcStatus(await Promise.race([response.json(), interruption]));
      if (!active(token)) return;
      if (!data) throw new Error('PC_INVALID_RESPONSE');
      add('p', `실제 로컬 관측 시각: ${data.checkedAt}`, current);
      const grid = add('div', '', current); grid.setAttribute('class', 'grid-2');
      for (const key of Object.keys(labels)) { const card = add('section', '', grid); card.setAttribute('class', 'card'); card.setAttribute('data-student-pc-card', key); add('h4', labels[key], card); add('p', observedText(key, data[key]), card); add('p', `관측 시각: ${data[key].checkedAt}`, card); }
      for (const [key, title] of [['firewall', '방화벽 설정 · 읽기 전용'], ['eventLogs', 'Windows 기록 · 경고·오류']]) { add('h4', title, current); add('p', observedText(key, data[key]), current); add('p', `관측 시각: ${data[key].checkedAt}`, current); }
      history.unshift(data); history.splice(8); drawHistory();
      status.textContent = '조회가 끝났습니다. 항목별 관측 값과 확인 불가를 구분해 확인하세요. SDP 연결이나 안전 판정의 증거가 아닙니다.';
    } catch (error) {
      if (!active(token)) return;
      current.replaceChildren();
      const messages = { PC_TIMEOUT: '조회 시간이 초과됐습니다.', PC_ROUTE_MISSING: '현재 실행 서버에는 학생 PC 조회 경로가 없습니다. 학생 PC 실행기를 사용하세요.', PC_INVALID_RESPONSE: '응답 형식이나 측정 단위를 확인할 수 없습니다.', PC_CANCELLED: '조회가 취소됐습니다.' };
      const code = Object.hasOwn(messages, error?.message) ? error.message : 'PC_UNAVAILABLE';
      status.textContent = `확인 불가: ${messages[code] ?? '로컬 PC 조회에 실패했습니다. 실행 상태를 확인하고 직접 다시 조회하세요.'}`;
    } finally {
      clearTimeout(timer); if (rejectPending?.token === token) rejectPending = null;
      if (token === generation) { busy = false; if (root.isConnected) { refreshButton.disabled = false; cancelButton.disabled = true; } }
    }
  }
  refreshButton.addEventListener('click', refresh); cancelButton.addEventListener('click', cancel);
  return { element: root, refresh, cancel };
}
