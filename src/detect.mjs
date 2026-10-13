// Consume only the verified synthetic event contract in docs/DETECT_EVENTS.md.
// No token, note content, client role, location or invented device mapping is read.
const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const reads = [];
  for (const event of events) {
    if (!event || event.method !== 'GET' || typeof event.at !== 'string'
        || typeof event.identity?.sub !== 'string' || !event.identity.sub.trim()) continue;
    const at = Date.parse(event.at);
    if (!Number.isFinite(at)) continue;
    reads.push({ at, subject: event.identity.sub });
  }
  reads.sort((a, b) => a.at - b.at || (a.subject < b.subject ? -1 : a.subject > b.subject ? 1 : 0));
  const subjects = new Map();
  for (const read of reads) {
    let window = subjects.get(read.subject);
    if (!window) {
      window = { times: [], start: 0 };
      subjects.set(read.subject, window);
    }
    window.times.push(read.at);
    while (read.at - window.times[window.start] > WINDOW_MS) window.start += 1;
    if (window.times.length - window.start > READ_LIMIT) {
      return { action: 'propose_revocation', reasonCode: 'burst_read', subject: read.subject };
    }
  }
  return { action: 'observe' };
}
