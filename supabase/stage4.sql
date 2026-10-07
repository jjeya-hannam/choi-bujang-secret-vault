-- Stage 4: direct Data API privileges still require row ownership.
-- Applies only to the public.notes learning table.
revoke all on table public.notes from public, anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;
grant usage, select on sequence public.notes_id_seq to authenticated;
alter table public.notes enable row level security;

drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

create policy notes_select_own on public.notes for select to authenticated
using ((select auth.uid()) = owner_id);
create policy notes_insert_own on public.notes for insert to authenticated
with check ((select auth.uid()) = owner_id);
create policy notes_update_own on public.notes for update to authenticated
using ((select auth.uid()) = owner_id)
with check ((select auth.uid()) = owner_id);
create policy notes_delete_own on public.notes for delete to authenticated
using ((select auth.uid()) = owner_id);
