import { isIP } from 'node:net';
import { evaluateDenyRules } from '../ztna-overlay.mjs';

const MODULES = ['brute-force', 'web-injection', 'known-cve', 'persistence', 'privilege', 'exfiltration'];
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, names) => object(value) && Object.keys(value).length === names.length
  && Object.keys(value).every(key => names.includes(key));
const result = (status, reason) => Object.freeze({ status, reason });

function canonicalIp(value) {
  if (typeof value !== 'string' || value !== value.trim() || value.includes('%')) return null;
  const type = isIP(value);
  if (type === 4) return value;
  if (type !== 6) return null;
  const normalized = new URL('http://[' + value + ']/').hostname.slice(1, -1).toLowerCase();
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/u.exec(normalized);
  if (!mapped) return normalized;
  const high = Number.parseInt(mapped[1], 16), low = Number.parseInt(mapped[2], 16);
  return [high >>> 8, high & 255, low >>> 8, low & 255].join('.');
}

function clockTime(value) {
  const time = value instanceof Date ? value.getTime()
    : typeof value === 'number' && Number.isSafeInteger(value) ? value : NaN;
  return Number.isFinite(time) && Number.isFinite(new Date(time).getTime()) ? time : null;
}

function validExpiry(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString().replace('.000Z', 'Z') === value.replace('.000Z', 'Z');
}

function validatedRules(snapshot) {
  if (!keys(snapshot, ['schema', 'rules']) || snapshot.schema !== 'aleph.xdr.deny-rules.v1'
      || !Array.isArray(snapshot.rules)) return null;
  const rules = [];
  for (const rule of snapshot.rules) {
    if (!keys(rule, ['moduleKey', 'action', 'sourceAddress', 'expiresAt', 'evidenceAlertIds'])
        || !MODULES.includes(rule.moduleKey) || rule.action !== 'deny' || !validExpiry(rule.expiresAt)
        || !Array.isArray(rule.evidenceAlertIds) || rule.evidenceAlertIds.length === 0) return null;
    const sourceAddress = canonicalIp(rule.sourceAddress);
    if (sourceAddress === null) return null;
    for (const id of rule.evidenceAlertIds) {
      if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9_.-]{0,79}$/iu.test(id)) return null;
    }
    rules.push({ moduleKey: rule.moduleKey, action: 'deny', sourceAddress,
      expiresAt: rule.expiresAt, evidenceAlertIds: [...rule.evidenceAlertIds] });
  }
  return rules;
}

// Server providers are captured once. A pass only clears this overlay; the host
// must keep authentication, ownership and authorization checks in its handler.
// resolveTrustedSource must use a verified gateway boundary, never raw XFF/body.
export function createRequestGuard(options = {}) {
  if (!object(options)) throw new TypeError('INVALID_REQUEST_GUARD_CONFIGURATION');
  const { resolveTrustedSource, loadRules, clock } = options;
  if (typeof resolveTrustedSource !== 'function' || typeof loadRules !== 'function' || typeof clock !== 'function') {
    throw new TypeError('INVALID_REQUEST_GUARD_CONFIGURATION');
  }
  return async function guard(serverContext) {
    let source;
    try { source = canonicalIp(await resolveTrustedSource(serverContext)); }
    catch { return result('unavailable', 'source_unavailable'); }
    if (source === null) return result('unavailable', 'source_unavailable');
    let rules;
    // No request context is passed to the loader: app scope belongs to its
    // server-held closure, not a client-selected tenant or rules namespace.
    try { rules = validatedRules(await loadRules()); }
    catch { return result('unavailable', 'rules_unavailable'); }
    if (rules === null) return result('unavailable', 'rules_unavailable');
    // Sample after asynchronous reads: a rule may expire while providers wait.
    let at;
    try { at = clockTime(clock()); } catch { return result('unavailable', 'clock_unavailable'); }
    if (at === null) return result('unavailable', 'clock_unavailable');
    const evaluation = evaluateDenyRules(source, rules, new Date(at));
    return evaluation.blocked ? result('deny', 'active_deny_rule') : result('pass', 'no_active_deny_rule');
  };
}
