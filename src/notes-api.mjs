import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';
import { resourceRoute, RESOURCE_IDS, UUID_PATTERN } from './resource-policy.mjs';

const UUID = UUID_PATTERN;
let cached;

function services() {
  if (cached) return cached;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('server_configuration_missing');
  cached = {
    db: createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    }),
    verify: createLoginVerifier({ config, supabaseSecretKey: key,
      deploymentHostname: process.env.VERCEL_URL,
      onReject: code => console.warn('notes authorization rejected', code) }),
  };
  return cached;
}

// Fixed diagnostic enums only: never serialize requests, identities, or database rows.
function responseDiagnostic(req, res, log) {
  const method = ['GET', 'POST', 'PUT', 'DELETE'].includes(req.method) ? req.method : 'OTHER';
  let resource = 'unknown';
  let verifiedKind = 'none';
  let syntheticJudgeIdentity;
  try {
    const route = resourceRoute(req.method, new URL(req.url, 'https://api.invalid').pathname);
    if (route?.resourceId === RESOURCE_IDS.notes) resource = route.id === null ? 'notes_collection' : 'notes_item';
    else if (route?.resourceId === RESOURCE_IDS.announcements) resource = 'announcement_item';
    if (typeof res.once === 'function') {
      res.once('finish', () => {
        try {
          const status = Number.isInteger(res.statusCode) && res.statusCode >= 100 && res.statusCode <= 599
            ? res.statusCode : 0;
          const entry = { event: 'notes_response', method, resource, status, verifiedKind };
          if (syntheticJudgeIdentity !== undefined) entry.syntheticJudgeIdentity = syntheticJudgeIdentity;
          log(JSON.stringify(entry));
        } catch { /* Diagnostics must never change the authentication or response outcome. */ }
      });
    }
  } catch { /* Missing/mock response events or malformed diagnostic input are nonfatal. */ }
  return identity => {
    verifiedKind = ['student', 'judge'].includes(identity?.kind) ? identity.kind : 'none';
    if (verifiedKind === 'judge' && ['a', 'b'].includes(identity.identity)) {
      syntheticJudgeIdentity = identity.identity;
    }
  };
}

function json(res, status, error) {
  return res.status(status).json({ error });
}

function noteShape(row) {
  return { id: row.note_id, title: row.title, body: row.content };
}

function validFields(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && typeof value.title === 'string' && value.title.trim().length > 0
    && value.title.length <= 160 && typeof value.body === 'string'
    && value.body.length <= 10000;
}

export function createNotesHandler(getServices = services, logDiagnostic = line => console.info(line)) {
return async function handleNotes(req, res, rawId) {
  const recordIdentity = responseDiagnostic(req, res, logDiagnostic);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  try {
    const { db, verify } = getServices();
    const identity = await verify(req.headers.authorization);
    recordIdentity(identity);
    if (!identity) return json(res, 401, 'AUTH_REQUIRED');

    const url = new URL(req.url, 'https://api.invalid');
    const resource = resourceRoute(req.method, url.pathname);
    if (url.search || !resource || resource.resourceId !== RESOURCE_IDS.notes) return json(res, 403, 'RESOURCE_FORBIDDEN');
    const id = typeof rawId === 'string' ? rawId.toLowerCase() : null;
    if ((resource.id?.toLowerCase() ?? null) !== id) return json(res, 400, 'INVALID_ID');
    if (rawId !== undefined && (!id || !UUID.test(id))) return json(res, 400, 'INVALID_ID');
    const ownerId = identity.userId;
    if (!id && req.method === 'GET') {
      const { data, error } = await db.from('notes')
        .select('note_id,title,content,owner_id').eq('owner_id', ownerId)
        .order('created_at', { ascending: true });
      if (error) throw error;
      return res.status(200).json({ notes: (data ?? []).filter(row => row.owner_id === ownerId).map(noteShape) });
    }
    if (!id && req.method === 'POST') {
      const body = req.body;
      if (!validFields(body) || (body.id !== undefined && (typeof body.id !== 'string' || !UUID.test(body.id)))) {
        return json(res, 400, 'INVALID_NOTE');
      }
      const noteId = body.id ?? randomUUID();
      const { error } = await db.from('notes').insert({
        note_id: noteId, owner_id: ownerId,
        title: body.title.trim(), content: body.body,
      });
      if (error) {
        if (error.code === '23505') return json(res, 409, 'NOTE_EXISTS');
        throw error;
      }
      return res.status(201).json({ id: noteId });
    }
    if (id && req.method === 'GET') {
      const { data, error } = await db.from('notes')
        .select('note_id,title,content,owner_id').eq('note_id', id)
        .eq('owner_id', ownerId).maybeSingle();
      if (error) throw error;
      if (!data || data.owner_id !== ownerId || data.note_id !== id) return json(res, 404, 'NOTE_NOT_FOUND');
      return res.status(200).json(noteShape(data));
    }
    if (id && req.method === 'PUT') {
      if (!validFields(req.body)) return json(res, 400, 'INVALID_NOTE');
      const { data, error } = await db.from('notes')
        .update({ title: req.body.title.trim(), content: req.body.body })
        .eq('note_id', id).eq('owner_id', ownerId)
        .select('note_id,title,content,owner_id').maybeSingle();
      if (error) throw error;
      if (!data || data.owner_id !== ownerId || data.note_id !== id) return json(res, 404, 'NOTE_NOT_FOUND');
      return res.status(200).json(noteShape(data));
    }
    if (id && req.method === 'DELETE') {
      const { data, error } = await db.from('notes').delete()
        .eq('note_id', id).eq('owner_id', ownerId)
        .select('note_id').maybeSingle();
      if (error) throw error;
      if (!data) return json(res, 404, 'NOTE_NOT_FOUND');
      return res.status(204).end();
    }
    res.setHeader('Allow', id ? 'GET, PUT, DELETE' : 'GET, POST');
    return json(res, 405, 'METHOD_NOT_ALLOWED');
  } catch (error) {
    console.error('notes request failed', error?.code ?? error?.name ?? 'unknown');
    return json(res, 500, 'NOTES_UNAVAILABLE');
  }
};
}

export const handleNotes = createNotesHandler();

export function createAnnouncementHandler(getServices = services, logDiagnostic = line => console.info(line)) {
  return async function handleAnnouncement(req, res) {
    const recordIdentity = responseDiagnostic(req, res, logDiagnostic);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
      const { verify } = getServices();
      const identity = await verify(req.headers.authorization);
      recordIdentity(identity);
      if (!identity) return json(res, 401, 'AUTH_REQUIRED');
      const url = new URL(req.url, 'https://api.invalid');
      const resource = resourceRoute(req.method, url.pathname);
      if (url.search || !resource || resource.resourceId !== RESOURCE_IDS.announcements) return json(res, 403, 'RESOURCE_FORBIDDEN');
      // The verified identity contract provides no instructor authority or announcement storage.
      // Neither body.role nor a client header can supply the missing server authority.
      if (req.method !== 'GET') return json(res, 403, 'INSTRUCTOR_AUTHORITY_REQUIRED');
      return json(res, 404, 'ANNOUNCEMENT_NOT_FOUND');
    } catch { return json(res, 500, 'ANNOUNCEMENTS_UNAVAILABLE'); }
  };
}
export const handleAnnouncement = createAnnouncementHandler();
