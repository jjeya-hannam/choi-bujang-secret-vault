-- Stage 5: the browser may no longer read or write notes through Data API.
-- Server functions retain the separate service_role grant and owner checks.
revoke all on table public.notes from public, anon, authenticated;
revoke all on sequence public.notes_id_seq from public, anon, authenticated;
grant select, insert, update, delete on table public.notes to service_role;
grant usage, select on sequence public.notes_id_seq to service_role;
alter table public.notes enable row level security;
