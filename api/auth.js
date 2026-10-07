import { createClient } from '@supabase/supabase-js';

function fail(res, status, code) {
  return res.status(status).json({ error: code });
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return fail(res, 405, 'METHOD_NOT_ALLOWED');
  }
  const { action, email, password, refreshToken } = req.body ?? {};
  if (!['signIn', 'signUp', 'refresh'].includes(action)) return fail(res, 400, 'INVALID_ACTION');
  if (action === 'refresh' ? typeof refreshToken !== 'string' || refreshToken.length > 4096
    : typeof email !== 'string' || email.length > 254 || typeof password !== 'string' || password.length > 1024 || !email || !password) {
    return fail(res, 400, 'INVALID_INPUT');
  }
  try {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SECRET_KEY;
    if (!url || !key) throw new Error('server_configuration_missing');
    const client = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } });
    let result;
    if (action === 'signIn') result = await client.auth.signInWithPassword({ email, password });
    else if (action === 'signUp') result = await client.auth.signUp({ email, password });
    else result = await client.auth.refreshSession({ refresh_token: refreshToken });
    if (result.error) return fail(res, 401, 'AUTH_FAILED');
    const session = result.data?.session;
    return res.status(200).json({ session: session ? {
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      expires_at: session.expires_at,
    } : null });
  } catch (error) {
    console.error('auth request failed', error?.name ?? 'unknown');
    return fail(res, 500, 'AUTH_UNAVAILABLE');
  }
}
