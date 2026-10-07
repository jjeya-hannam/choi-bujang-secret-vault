-- Applied to the jjeya-hannam learning project on 2026-10-07.
-- Keep existing sample rows and their integer keys; public API uses note_id UUID.
alter table public.notes add column if not exists note_id uuid default gen_random_uuid();
update public.notes set note_id = gen_random_uuid() where note_id is null;
alter table public.notes alter column note_id set not null;
create unique index if not exists notes_note_id_key on public.notes(note_id);
grant select, insert, update, delete on public.notes to service_role;
grant usage, select on sequence public.notes_id_seq to service_role;
