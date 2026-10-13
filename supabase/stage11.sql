-- Server-approved browser credentials; no hardware attestation is claimed.
-- Setup only: no existing users, notes, backups, or devices are approved.
begin;
create schema if not exists aleph_private;
revoke all on schema aleph_private from public, anon, authenticated;
grant usage on schema aleph_private to service_role;
create table if not exists aleph_private.browser_devices (
  device_id uuid primary key default gen_random_uuid(), user_id uuid not null,
  credential_hash bytea not null check (octet_length(credential_hash)=32),
  status text not null default 'pending' check(status in ('pending','approved','revoked')),
  requested_at timestamptz not null default now(), approved_at timestamptz,
  unique(user_id,credential_hash), unique(user_id,device_id)
);
create table if not exists aleph_private.browser_sessions (
  session_hash bytea primary key check(octet_length(session_hash)=32),
  user_id uuid not null, device_id uuid not null, expires_at timestamptz not null,
  created_at timestamptz not null default now(), revoked_at timestamptz,
  foreign key(user_id,device_id) references aleph_private.browser_devices(user_id,device_id)
);
alter table aleph_private.browser_devices enable row level security;
alter table aleph_private.browser_sessions enable row level security;
revoke all on table aleph_private.browser_devices,aleph_private.browser_sessions from public,anon,authenticated,service_role;
grant select,insert,update on table aleph_private.browser_devices,aleph_private.browser_sessions to service_role;

create or replace function public.stage11_create_browser_session(p_user_id uuid,p_session_hash bytea,p_device_hash bytea,p_expires_at timestamptz)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare dev aleph_private.browser_devices%rowtype;
begin
  if p_user_id is null or p_session_hash is null or octet_length(p_session_hash)<>32
    or p_device_hash is null or octet_length(p_device_hash)<>32 or p_expires_at is null
    or p_expires_at<=now()+interval '30 seconds' or p_expires_at>now()+interval '1 hour 5 seconds' then
    raise exception 'invalid_session' using errcode='22023';
  end if;
  insert into aleph_private.browser_devices(user_id,credential_hash)
    values(p_user_id,p_device_hash) on conflict(user_id,credential_hash) do nothing;
  select * into dev from aleph_private.browser_devices where user_id=p_user_id and credential_hash=p_device_hash;
  insert into aleph_private.browser_sessions(session_hash,user_id,device_id,expires_at)
    values(p_session_hash,p_user_id,dev.device_id,p_expires_at);
  return jsonb_build_object('deviceStatus',dev.status);
end; $$;

create or replace function public.stage11_lookup_browser_session(p_session_hash bytea,p_device_hash bytea)
returns jsonb language sql stable security invoker set search_path='' as $$
  select coalesce((select jsonb_build_object('signedIn',true,'userId',s.user_id,'deviceStatus',d.status)
    from aleph_private.browser_sessions s join aleph_private.browser_devices d
      on s.user_id=d.user_id and s.device_id=d.device_id
    where s.session_hash=p_session_hash and d.credential_hash=p_device_hash
      and s.expires_at>now() and s.revoked_at is null),jsonb_build_object('signedIn',false));
$$;

create or replace function public.stage11_revoke_browser_session(p_session_hash bytea,p_device_hash bytea)
returns void language sql security invoker set search_path='' as $$
  update aleph_private.browser_sessions s set revoked_at=now()
    where s.session_hash=p_session_hash and exists(select 1 from aleph_private.browser_devices d
      where d.device_id=s.device_id and d.user_id=s.user_id and d.credential_hash=p_device_hash);
$$;

-- Trusted out-of-band operator only. No HTTP approval route exists.
create or replace function public.stage11_approve_browser_device(p_user_id uuid,p_device_id uuid)
returns boolean language plpgsql security invoker set search_path='' as $$
begin
  update aleph_private.browser_devices set status='approved',approved_at=now()
    where user_id=p_user_id and device_id=p_device_id and status='pending';
  return found;
end; $$;

revoke all on function public.stage11_create_browser_session(uuid,bytea,bytea,timestamptz),
  public.stage11_lookup_browser_session(bytea,bytea),public.stage11_revoke_browser_session(bytea,bytea),
  public.stage11_approve_browser_device(uuid,uuid) from public,anon,authenticated;
grant execute on function public.stage11_create_browser_session(uuid,bytea,bytea,timestamptz),
  public.stage11_lookup_browser_session(bytea,bytea),public.stage11_revoke_browser_session(bytea,bytea),
  public.stage11_approve_browser_device(uuid,uuid) to service_role;
commit;
