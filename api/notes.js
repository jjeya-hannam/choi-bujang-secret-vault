import { handleNotes } from '../src/notes-api.mjs';

export default async function handler(request, response) {
  return handleNotes(request, response);
}
