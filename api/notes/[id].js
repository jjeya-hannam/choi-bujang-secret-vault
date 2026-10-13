import { handleNotes } from '../../src/notes-api.mjs';

export default async function handler(request, response) {
  return handleNotes(request, response, new URL(request.url, 'https://api.invalid').pathname.split('/').at(-1));
}
