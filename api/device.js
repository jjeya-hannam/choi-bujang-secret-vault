import { createAuthHandler } from './auth.js';
const auth = createAuthHandler();
export default async function handler(req, res) {
  // Enrollment requests cannot approve devices.
  if (req.method === 'POST') return auth({ ...req, body: { action: 'requestDevice' } }, res);
  return auth(req, res);
}
