// Distinct logical resources; paths remain compatible with the existing notes API.
export const RESOURCE_IDS = Object.freeze({ notes: 'student_notes', announcements: 'instructor_announcements' });
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function resourceRoute(method, path, { fixture = false } = {}) {
  if (typeof path !== 'string' || path.includes('?') || path.includes('#') || path.includes('%')) return null;
  if (path === '/api/notes' && ['GET', 'POST'].includes(method)) {
    return { resourceId: RESOURCE_IDS.notes, route: `${method} /api/notes`, id: null };
  }
  const note = /^\/api\/notes\/([^/]+)$/u.exec(path);
  if (note && UUID_PATTERN.test(note[1]) && ['GET', 'PUT', 'DELETE'].includes(method)) {
    return { resourceId: RESOURCE_IDS.notes, route: `${method} /api/notes/:id`, id: note[1] };
  }
  const announcement = /^\/api\/announcements\/([^/]+)$/u.exec(path);
  if (announcement && UUID_PATTERN.test(announcement[1]) && ['GET', 'PUT'].includes(method)) {
    return { resourceId: RESOURCE_IDS.announcements, route: `${method} /api/announcements/:id`, id: announcement[1] };
  }
  // Existing public local fixture contract uses /notes/demo rather than the deployed UUID URL.
  if (fixture && method === 'GET' && path === '/notes/demo') {
    return { resourceId: RESOURCE_IDS.notes, route: 'GET /notes/:id', id: 'demo' };
  }
  return null;
}
