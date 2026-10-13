import { createHash, randomBytes } from 'node:crypto';
import { UUID_PATTERN } from './resource-policy.mjs';

export const SESSION_COOKIE = '__Host-vault_session';
export const DEVICE_COOKIE = '__Host-vault_device';
const CREDENTIAL = /^[A-Za-z0-9_-]{43}$/u;
export const DEVICE_STATUSES = Object.freeze(['unrequested', 'pending', 'approved', 'revoked']);
export const newCredential = () => randomBytes(32).toString('base64url');
export const hashCredential = value => `\\x${createHash('sha256').update(value).digest('hex')}`;

export function readCredential(req, name) {
  const cookie = req.headers?.cookie;
  if (typeof cookie !== 'string' || cookie.length > 8192) return null;
  const matches = cookie.split(';').map(part => part.trim()).filter(part => part.startsWith(`${name}=`));
  if (matches.length !== 1) return null;
  const value = matches[0].slice(name.length + 1);
  return CREDENTIAL.test(value) ? value : null;
}

export function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

export function trustedMutation(req, config, deploymentHostname) {
  const origins = [new URL(config.publicAppUrl).origin];
  if (typeof deploymentHostname === 'string'
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu.test(deploymentHostname)) {
    origins.push(`https://${deploymentHostname.toLowerCase()}`);
  }
  return origins.includes(req.headers?.origin)
    && /^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(req.headers?.['content-type'] ?? '')
    && (!req.headers?.['sec-fetch-site'] || req.headers['sec-fetch-site'] === 'same-origin');
}

export async function lookupSession(db, req) {
  const session = readCredential(req, SESSION_COOKIE), device = readCredential(req, DEVICE_COOKIE);
  if (!session || !device) return null;
  const { data, error } = await db.rpc('stage11_lookup_browser_session', {
    p_session_hash: hashCredential(session), p_device_hash: hashCredential(device),
  });
  if (error) throw new Error('session_lookup_unavailable');
  if (data?.signedIn !== true) return null;
  if (!UUID_PATTERN.test(data.userId ?? '') || !DEVICE_STATUSES.includes(data.deviceStatus)
      || data.deviceStatus === 'unrequested') throw new Error('invalid_session_result');
  return { kind: 'student', userId: data.userId, deviceRegistered: data.deviceStatus === 'approved', deviceStatus: data.deviceStatus };
}

export function createRequestLoginVerifier({ verifyBearer, db, config, deploymentHostname }) {
  return async function verify(authorization, req) {
    if (authorization !== undefined) {
      const identity = await verifyBearer(authorization);
      // A student JWT proves identity, but carries no trusted approved browser binding.
      if (identity?.kind === 'student') return Object.freeze({ ...identity, deviceRegistered: false });
      return identity;
    }
    if (!req) return null;
    const identity = await lookupSession(db, req);
    if (identity && !['GET', 'HEAD'].includes(req.method)
        && !trustedMutation(req, config, deploymentHostname)) return null;
    return identity ? Object.freeze(identity) : null;
  };
}

export const publicSessionStatus = identity => ({ signedIn: Boolean(identity),
  deviceStatus: identity?.deviceStatus ?? 'unrequested' });
