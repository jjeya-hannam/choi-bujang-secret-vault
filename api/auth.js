import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { UUID_PATTERN } from '../src/resource-policy.mjs';
import { SESSION_COOKIE, DEVICE_COOKIE, cookie, readCredential, newCredential, hashCredential,
  lookupSession, publicSessionStatus, trustedMutation, DEVICE_STATUSES } from '../src/browser-session.mjs';

function services() {
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('server_configuration_missing');
  const createAuthClient = () => createClient(url, key, { auth: {
    persistSession: false, autoRefreshToken: false, detectSessionInUrl: false,
  } });
  return { db: createAuthClient(), createAuthClient, config, deploymentHostname: process.env.VERCEL_URL };
}
const fail = (res, status, error) => res.status(status).json({ error });

export function createAuthHandler(getServices = services) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
      const bound = getServices();
      if (req.method === 'GET') return res.status(200).json(publicSessionStatus(await lookupSession(bound.db, req)));
      if (req.method !== 'POST') { res.setHeader('Allow', 'GET, POST'); return fail(res, 405, 'METHOD_NOT_ALLOWED'); }
      if (!trustedMutation(req, bound.config, bound.deploymentHostname)) return fail(res, 403, 'ORIGIN_FORBIDDEN');
      const { action, email, password } = req.body ?? {};
      if (!['signIn', 'signUp', 'signOut', 'requestDevice'].includes(action)) return fail(res, 400, 'INVALID_ACTION');
      if (action === 'requestDevice') {
        const identity = await lookupSession(bound.db, req);
        if (!identity) return fail(res, 401, 'AUTH_REQUIRED');
        // Sign-in submits pending enrollment. This action never approves it.
        return res.status(200).json(publicSessionStatus(identity));
      }
      if (action === 'signOut') {
        const session = readCredential(req, SESSION_COOKIE), device = readCredential(req, DEVICE_COOKIE);
        if (session && device) {
          const { error } = await bound.db.rpc('stage11_revoke_browser_session', {
            p_session_hash: hashCredential(session), p_device_hash: hashCredential(device),
          });
          if (error) return fail(res, 503, 'AUTH_UNAVAILABLE');
        }
        res.setHeader('Set-Cookie', cookie(SESSION_COOKIE, '', 0));
        return res.status(200).json({ signedIn: false, deviceStatus: 'unrequested' });
      }
      if (typeof email !== 'string' || email.length > 254 || !email.trim()
          || typeof password !== 'string' || !password || password.length > 1024) return fail(res, 400, 'INVALID_INPUT');
      // Isolated clients avoid cross-request auth state; tokens never reach JS.
      const auth = bound.createAuthClient().auth;
      const result = action === 'signIn' ? await auth.signInWithPassword({ email: email.trim(), password })
        : await auth.signUp({ email: email.trim(), password });
      if (result.error) return fail(res, 401, 'AUTH_FAILED');
      const session = result.data?.session, userId = result.data?.user?.id;
      if (!session) return res.status(200).json({ signedIn: false, deviceStatus: 'unrequested', confirmationRequired: action === 'signUp' });
      const now = Math.floor(Date.now() / 1000);
      if (!UUID_PATTERN.test(userId ?? '') || !Number.isSafeInteger(session.expires_at) || session.expires_at <= now + 60) return fail(res, 401, 'AUTH_FAILED');
      const opaqueSession = newCredential(), device = readCredential(req, DEVICE_COOKIE) ?? newCredential();
      const lifetime = Math.min(3600, session.expires_at - now);
      const { data, error } = await bound.db.rpc('stage11_create_browser_session', {
        p_user_id: userId, p_session_hash: hashCredential(opaqueSession), p_device_hash: hashCredential(device),
        p_expires_at: new Date((now + lifetime) * 1000).toISOString(),
      });
      if (error || !DEVICE_STATUSES.includes(data?.deviceStatus) || data.deviceStatus === 'unrequested') return fail(res, 503, 'AUTH_UNAVAILABLE');
      res.setHeader('Set-Cookie', [cookie(SESSION_COOKIE, opaqueSession, lifetime), cookie(DEVICE_COOKIE, device, 365 * 24 * 3600)]);
      return res.status(200).json({ signedIn: true, deviceStatus: data.deviceStatus });
    } catch { return fail(res, 503, 'AUTH_UNAVAILABLE'); }
  };
}
export default createAuthHandler();
