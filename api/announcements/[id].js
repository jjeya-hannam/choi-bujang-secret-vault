import { handleAnnouncement } from '../../src/notes-api.mjs';

export default async function handler(request, response) {
  return handleAnnouncement(request, response);
}
