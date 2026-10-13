-- Stage 10: synthetic judge B recovery only. Review and test before applying.
-- No existing note is read, modified, deleted, or backed up by this setup script.
begin;

create schema if not exists aleph_private;
revoke all on schema aleph_private from public, anon, authenticated;
grant usage on schema aleph_private to service_role;

create table if not exists aleph_private.judge_b_note_backups (
  run_id uuid not null,
  note_id uuid not null,
  owner_id uuid not null,
  original_row jsonb not null,
  original_hash bytea not null check (octet_length(original_hash) = 32),
  captured_at timestamptz not null default now(),
  primary key (run_id, note_id, owner_id)
);
alter table aleph_private.judge_b_note_backups enable row level security;
revoke all on table aleph_private.judge_b_note_backups from public, anon, authenticated, service_role;
grant select, insert on table aleph_private.judge_b_note_backups to service_role;

create or replace function aleph_private.reject_backup_mutation()
returns trigger language plpgsql security invoker set search_path = '' as $$
begin
  raise exception 'immutable_backup' using errcode = '42501';
end;
$$;
revoke all on function aleph_private.reject_backup_mutation() from public, anon, authenticated;
drop trigger if exists judge_b_backups_immutable on aleph_private.judge_b_note_backups;
create trigger judge_b_backups_immutable before update or delete
on aleph_private.judge_b_note_backups for each row
execute function aleph_private.reject_backup_mutation();

create or replace function public.stage10_create_judge_b_note(
  p_run_id uuid, p_owner_id uuid, p_note_id uuid, p_title text, p_content text
) returns uuid language plpgsql security invoker set search_path = '' set timezone = 'UTC' as $$
declare
  original public.notes%rowtype;
  snapshot jsonb;
begin
  if p_run_id is null or p_owner_id is null or p_note_id is null
      or p_title is null or length(btrim(p_title)) = 0 or length(p_title) > 160
      or p_content is null or length(p_content) > 10000 then
    raise exception 'invalid_note' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_note_id::text, 0));
  insert into public.notes(note_id, owner_id, title, content)
  values (p_note_id, p_owner_id, btrim(p_title), p_content)
  returning * into original;
  snapshot := to_jsonb(original);
  insert into aleph_private.judge_b_note_backups(run_id, note_id, owner_id, original_row, original_hash)
  values (p_run_id, p_note_id, p_owner_id, snapshot, sha256(convert_to(snapshot::text, 'UTF8')));
  return original.note_id;
end;
$$;
revoke all on function public.stage10_create_judge_b_note(uuid, uuid, uuid, text, text)
from public, anon, authenticated;
grant execute on function public.stage10_create_judge_b_note(uuid, uuid, uuid, text, text) to service_role;

create or replace function public.stage10_restore_judge_b_note(
  p_run_id uuid, p_owner_id uuid, p_note_id uuid
) returns jsonb language plpgsql security invoker set search_path = '' set timezone = 'UTC' as $$
declare
  backup aleph_private.judge_b_note_backups%rowtype;
  original public.notes%rowtype;
  restored public.notes%rowtype;
begin
  if p_run_id is null or p_owner_id is null or p_note_id is null then
    raise exception 'backup_not_found' using errcode = 'P0002';
  end if;
  -- A single-note transaction lock avoids concurrent restores without locking
  -- immutable backups or unrelated notes. No external calls occur under the lock.
  perform pg_advisory_xact_lock(hashtextextended(p_note_id::text, 0));
  select * into backup from aleph_private.judge_b_note_backups
    where run_id = p_run_id and owner_id = p_owner_id and note_id = p_note_id;
  if not found then raise exception 'backup_not_found' using errcode = 'P0002'; end if;
  if sha256(convert_to(backup.original_row::text, 'UTF8')) <> backup.original_hash then
    raise exception 'backup_integrity_failed' using errcode = '22000';
  end if;
  select * into original from jsonb_populate_record(null::public.notes, backup.original_row);
  if original.id is null or original.note_id is distinct from p_note_id
      or original.owner_id is distinct from p_owner_id or original.created_at is null
      or original.title is null or original.content is null then
    raise exception 'backup_identity_failed' using errcode = '22000';
  end if;

  insert into public.notes(id, note_id, owner_id, title, content, created_at)
    values (original.id, original.note_id, original.owner_id, original.title, original.content, original.created_at)
  on conflict (note_id) do update
    set id = excluded.id, owner_id = excluded.owner_id, title = excluded.title,
        content = excluded.content, created_at = excluded.created_at
    where public.notes.owner_id = p_owner_id
  returning * into restored;
  if not found then raise exception 'restore_owner_conflict' using errcode = '23505'; end if;
  if sha256(convert_to(to_jsonb(restored)::text, 'UTF8')) <> backup.original_hash then
    raise exception 'restore_integrity_failed' using errcode = '22000';
  end if;
  return jsonb_build_object('id', restored.note_id, 'restored', true);
end;
$$;
revoke all on function public.stage10_restore_judge_b_note(uuid, uuid, uuid)
from public, anon, authenticated;
grant execute on function public.stage10_restore_judge_b_note(uuid, uuid, uuid) to service_role;

commit;
