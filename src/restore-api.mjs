import { getNotesServices } from './notes-api.mjs';
import { UUID_PATTERN } from './resource-policy.mjs';

function reject(res, status, error) { return res.status(status).json({ error }); }

// Provisional HTTP contract: POST /api/restore { id: UUID }.
// The student-defined route must be checked against the judge after deployment.
export function createRestoreHandler(getServices = getNotesServices) {
  return async function handleRestore(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    try {
      const { db, verify } = getServices();
      const identity = await verify(req.headers?.authorization);
      if (!identity) return reject(res, 401, 'AUTH_REQUIRED');
      if (identity.kind !== 'judge' || identity.identity !== 'b'
          || !UUID_PATTERN.test(identity.userId ?? '') || !UUID_PATTERN.test(identity.runId ?? '')) {
        return reject(res, 403, 'RESTORE_FORBIDDEN');
      }
      const url = new URL(req.url, 'https://api.invalid');
      if (url.pathname !== '/api/restore' || url.search) return reject(res, 403, 'RESOURCE_FORBIDDEN');
      if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return reject(res, 405, 'METHOD_NOT_ALLOWED');
      }
      const body = req.body;
      if (!body || typeof body !== 'object' || Array.isArray(body)
          || Object.keys(body).length !== 1 || typeof body.id !== 'string'
          || !UUID_PATTERN.test(body.id)) return reject(res, 400, 'INVALID_RESTORE');
      const { data, error } = await db.rpc('stage10_restore_judge_b_note', {
        p_run_id: identity.runId, p_owner_id: identity.userId, p_note_id: body.id.toLowerCase(),
      });
      if (error) {
        if (error.code === 'P0002') return reject(res, 404, 'BACKUP_NOT_FOUND');
        if (error.code === '23505') return reject(res, 409, 'RESTORE_CONFLICT');
        return reject(res, 503, 'RESTORE_UNAVAILABLE');
      }
      if (!data || data.id !== body.id.toLowerCase() || data.restored !== true) {
        return reject(res, 503, 'RESTORE_UNAVAILABLE');
      }
      return res.status(200).json({ id: data.id, restored: true });
    } catch { return reject(res, 503, 'RESTORE_UNAVAILABLE'); }
  };
}

export const handleRestore = createRestoreHandler();
