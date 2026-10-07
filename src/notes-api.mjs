import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
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
    verify: createLoginVerifier({ config, supabaseSecretKey: key }),
  };
  return cached;
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

export async function handleNotes(req, res, rawId) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  try {
    const { db, verify } = services();
    const identity = await verify(req.headers.authorization);
    if (!identity) return json(res, 401, 'AUTH_REQUIRED');

    const id = typeof rawId === 'string' ? rawId : null;
    if (rawId !== undefined && (!id || !UUID.test(id))) return json(res, 400, 'INVALID_ID');
    const ownerId = identity.userId;
    if (!id && req.method === 'GET') {
      const { data, error } = await db.from('notes')
        .select('note_id,title,content').eq('owner_id', ownerId)
        .order('created_at', { ascending: true });
      if (error) throw error;
      return res.status(200).json({ notes: (data ?? []).map(noteShape) });
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
        .select('note_id,title,content').eq('note_id', id)
        .eq('owner_id', ownerId).maybeSingle();
      if (error) throw error;
      if (!data) return json(res, 404, 'NOTE_NOT_FOUND');
      return res.status(200).json(noteShape(data));
    }
    if (id && req.method === 'PUT') {
      if (!validFields(req.body)) return json(res, 400, 'INVALID_NOTE');
      const { data, error } = await db.from('notes')
        .update({ title: req.body.title.trim(), content: req.body.body })
        .eq('note_id', id).eq('owner_id', ownerId)
        .select('note_id,title,content').maybeSingle();
      if (error) throw error;
      if (!data) return json(res, 404, 'NOTE_NOT_FOUND');
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
}
