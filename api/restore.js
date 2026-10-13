import { handleRestore } from '../src/restore-api.mjs';

export default async function handler(request, response) {
  return handleRestore(request, response);
}
