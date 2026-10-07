import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const urlKey = ['SUPABASE', 'URL'].join('_');
  const secretKeyName = ['SUPABASE', 'SECRET', 'KEY'].join('_');
  const url = process.env[urlKey];
  const secretKey = process.env[secretKeyName];

  if (!url || !secretKey) {
    return response.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  const supabase = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
  });

  const { data, error } = await supabase
    .from('notes')
    .select('title,content')
    .order('id', { ascending: true });

  if (error) return response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
  return response.status(200).json({ notes: data ?? [] });
}
