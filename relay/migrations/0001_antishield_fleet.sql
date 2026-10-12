-- H&H AntiShield – schránka firemní správy (Supabase / PostgreSQL 15+).
--
-- Schránka je jen poštovní přihrádka mezi správcem a firemními Macy. Obsah
-- zpráv je podepsaný a zašifrovaný v aplikacích; tady leží jen jako text
-- v base64, který server neumí přečíst ani podvrhnout. Schránka hlídá jen
-- to, kdo smí zprávu uložit nebo vyzvednout (tokeny, uložené jako SHA-256),
-- limity a úklid starých dat.
--
-- Tabulky jsou ve vlastním schématu bez přístupu z API. Volat jde jen funkce
-- public.antishield_fleet_* (SECURITY DEFINER, prázdná search_path), a to jen
-- rolí anon (veřejný klíč aplikace).

create schema if not exists antishield_fleet;
revoke all on schema antishield_fleet from public, anon, authenticated;

-- Jednorázové aktivační kódy pro založení firmy (vydává provozovatel schránky,
-- ukládá se jen SHA-256 kódu).
create table if not exists antishield_fleet.activations (
  code_hash bytea primary key check (octet_length(code_hash) = 32),
  note text not null default '' check (char_length(note) <= 200),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  uses_left integer not null default 1 check (uses_left >= 0),
  last_used_at timestamptz
);

create table if not exists antishield_fleet.fleets (
  id uuid primary key,
  admin_token_hash bytea not null check (octet_length(admin_token_hash) = 32),
  activation_hash bytea not null,
  created_at timestamptz not null default now(),
  last_admin_at timestamptz
);

create table if not exists antishield_fleet.invites (
  token_id text primary key check (char_length(token_id) between 16 and 64),
  fleet_id uuid not null references antishield_fleet.fleets (id) on delete cascade,
  bundle text not null check (char_length(bundle) <= 8192),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  used_at timestamptz,
  device_id uuid
);
create index if not exists invites_fleet on antishield_fleet.invites (fleet_id);

create table if not exists antishield_fleet.devices (
  id uuid primary key,
  fleet_id uuid not null references antishield_fleet.fleets (id) on delete cascade,
  token_hash bytea not null check (octet_length(token_hash) = 32),
  invite_token_id text not null,
  bundle text not null check (char_length(bundle) <= 8192),
  report text check (char_length(report) <= 65536),
  report_at timestamptz,
  last_seen timestamptz,
  left_notice text check (char_length(left_notice) <= 8192),
  left_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists devices_fleet on antishield_fleet.devices (fleet_id);

create table if not exists antishield_fleet.commands (
  id uuid primary key,
  fleet_id uuid not null references antishield_fleet.fleets (id) on delete cascade,
  device_id uuid not null references antishield_fleet.devices (id) on delete cascade,
  envelope text not null check (char_length(envelope) <= 16384),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  delivered_at timestamptz,
  result text check (char_length(result) <= 16384),
  result_at timestamptz
);
create index if not exists commands_device on antishield_fleet.commands (device_id, created_at);
create index if not exists commands_fleet on antishield_fleet.commands (fleet_id, created_at);

-- Obrana do hloubky: bez politik nemá k řádkům přístup nikdo kromě vlastníka.
alter table antishield_fleet.activations enable row level security;
alter table antishield_fleet.fleets enable row level security;
alter table antishield_fleet.invites enable row level security;
alter table antishield_fleet.devices enable row level security;
alter table antishield_fleet.commands enable row level security;
revoke all on all tables in schema antishield_fleet from public, anon, authenticated;

-- ---------- Pomocné funkce (jen uvnitř schránky) ----------

create or replace function antishield_fleet.hash_token(p_token text)
returns bytea
language sql immutable
set search_path = ''
as $$
  select sha256(convert_to(p_token, 'UTF8'))
$$;

create or replace function antishield_fleet.ms(p_at timestamptz)
returns bigint
language sql immutable
set search_path = ''
as $$
  select (extract(epoch from p_at) * 1000)::bigint
$$;

create or replace function antishield_fleet.at_ms(p_ms bigint)
returns timestamptz
language sql immutable
set search_path = ''
as $$
  select to_timestamp(p_ms / 1000.0)
$$;

create or replace function antishield_fleet.check_admin(p_fleet uuid, p_token text)
returns void
language plpgsql
set search_path = ''
as $$
begin
  if p_fleet is null or p_token is null or char_length(p_token) > 128 then
    raise exception 'fleet_not_authorized';
  end if;
  update antishield_fleet.fleets
     set last_admin_at = now()
   where id = p_fleet and admin_token_hash = antishield_fleet.hash_token(p_token);
  if not found then
    raise exception 'fleet_not_authorized';
  end if;
end
$$;

create or replace function antishield_fleet.check_device(p_device uuid, p_token text)
returns uuid
language plpgsql
set search_path = ''
as $$
declare
  v_fleet uuid;
begin
  if p_device is null or p_token is null or char_length(p_token) > 128 then
    raise exception 'fleet_not_authorized';
  end if;
  update antishield_fleet.devices
     set last_seen = now()
   where id = p_device
     and token_hash = antishield_fleet.hash_token(p_token)
     and left_at is null
  returning fleet_id into v_fleet;
  if v_fleet is null then
    raise exception 'fleet_not_authorized';
  end if;
  return v_fleet;
end
$$;

revoke all on all functions in schema antishield_fleet from public, anon, authenticated;

-- ---------- Správce ----------

create or replace function public.antishield_fleet_create(
  p_activation text, p_fleet uuid, p_admin_token text
)
returns void
language plpgsql security definer
set search_path = ''
as $$
declare
  v_hash bytea;
begin
  if p_activation is null or char_length(p_activation) > 64 or p_fleet is null
     or p_admin_token is null or char_length(p_admin_token) not between 40 and 128 then
    raise exception 'fleet_bad_request';
  end if;
  v_hash := antishield_fleet.hash_token(p_activation);
  update antishield_fleet.activations
     set uses_left = uses_left - 1, last_used_at = now()
   where code_hash = v_hash and uses_left > 0 and expires_at > now();
  if not found then
    raise exception 'fleet_activation_invalid';
  end if;
  if (select count(*) from antishield_fleet.fleets) >= 50 then
    raise exception 'fleet_limit';
  end if;
  insert into antishield_fleet.fleets (id, admin_token_hash, activation_hash)
  values (p_fleet, antishield_fleet.hash_token(p_admin_token), v_hash);
end
$$;

create or replace function public.antishield_fleet_admin_invite(
  p_fleet uuid, p_token text, p_token_id text, p_bundle text, p_expires_at_ms bigint
)
returns void
language plpgsql security definer
set search_path = ''
as $$
declare
  v_expires timestamptz := antishield_fleet.at_ms(p_expires_at_ms);
begin
  perform antishield_fleet.check_admin(p_fleet, p_token);
  if p_token_id is null or char_length(p_token_id) not between 16 and 64
     or p_bundle is null or char_length(p_bundle) > 8192
     or v_expires is null or v_expires <= now() or v_expires > now() + interval '8 days' then
    raise exception 'fleet_bad_request';
  end if;
  if (select count(*) from antishield_fleet.invites i
       where i.fleet_id = p_fleet and i.used_at is null and i.expires_at > now()) >= 50 then
    raise exception 'fleet_limit';
  end if;
  insert into antishield_fleet.invites (token_id, fleet_id, bundle, expires_at)
  values (p_token_id, p_fleet, p_bundle, v_expires);
end
$$;

create or replace function public.antishield_fleet_admin_revoke_invite(
  p_fleet uuid, p_token text, p_token_id text
)
returns void
language plpgsql security definer
set search_path = ''
as $$
begin
  perform antishield_fleet.check_admin(p_fleet, p_token);
  delete from antishield_fleet.invites i
   where i.fleet_id = p_fleet and i.token_id = p_token_id and i.used_at is null;
end
$$;

create or replace function public.antishield_fleet_admin_state(p_fleet uuid, p_token text)
returns jsonb
language plpgsql security definer
set search_path = ''
as $$
begin
  perform antishield_fleet.check_admin(p_fleet, p_token);
  delete from antishield_fleet.commands c
   where c.fleet_id = p_fleet and c.created_at < now() - interval '30 days';
  delete from antishield_fleet.invites i
   where i.fleet_id = p_fleet and i.expires_at < now() - interval '30 days';
  return jsonb_build_object(
    'nowMs', antishield_fleet.ms(now()),
    'devices', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', d.id,
        'bundle', d.bundle,
        'inviteTokenId', d.invite_token_id,
        'report', d.report,
        'reportAtMs', antishield_fleet.ms(d.report_at),
        'lastSeenMs', antishield_fleet.ms(d.last_seen),
        'leftNotice', d.left_notice,
        'createdAtMs', antishield_fleet.ms(d.created_at)
      ) order by d.created_at)
      from antishield_fleet.devices d
      where d.fleet_id = p_fleet), '[]'::jsonb),
    'commands', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', c.id,
        'deviceId', c.device_id,
        'createdAtMs', antishield_fleet.ms(c.created_at),
        'expiresAtMs', antishield_fleet.ms(c.expires_at),
        'deliveredAtMs', antishield_fleet.ms(c.delivered_at),
        'result', c.result,
        'resultAtMs', antishield_fleet.ms(c.result_at)
      ) order by c.created_at desc)
      from (
        select x.*
          from antishield_fleet.commands x
         where x.fleet_id = p_fleet
         order by x.created_at desc
         limit 500
      ) c), '[]'::jsonb),
    'invites', coalesce((
      select jsonb_agg(jsonb_build_object(
        'tokenId', i.token_id,
        'expiresAtMs', antishield_fleet.ms(i.expires_at),
        'usedAtMs', antishield_fleet.ms(i.used_at),
        'deviceId', i.device_id
      ))
      from antishield_fleet.invites i
      where i.fleet_id = p_fleet), '[]'::jsonb)
  );
end
$$;

create or replace function public.antishield_fleet_admin_command(
  p_fleet uuid, p_token text, p_command uuid, p_device uuid, p_envelope text, p_expires_at_ms bigint
)
returns void
language plpgsql security definer
set search_path = ''
as $$
declare
  v_expires timestamptz := antishield_fleet.at_ms(p_expires_at_ms);
begin
  perform antishield_fleet.check_admin(p_fleet, p_token);
  if p_command is null or p_device is null
     or p_envelope is null or char_length(p_envelope) > 16384
     or v_expires is null or v_expires <= now() or v_expires > now() + interval '8 days' then
    raise exception 'fleet_bad_request';
  end if;
  if not exists (
    select 1 from antishield_fleet.devices d
     where d.id = p_device and d.fleet_id = p_fleet and d.left_at is null
  ) then
    raise exception 'fleet_unknown_device';
  end if;
  if (select count(*) from antishield_fleet.commands c
       where c.device_id = p_device and c.result_at is null and c.expires_at > now()) >= 50 then
    raise exception 'fleet_limit';
  end if;
  insert into antishield_fleet.commands (id, fleet_id, device_id, envelope, expires_at)
  values (p_command, p_fleet, p_device, p_envelope, v_expires);
end
$$;

create or replace function public.antishield_fleet_admin_remove_device(
  p_fleet uuid, p_token text, p_device uuid
)
returns void
language plpgsql security definer
set search_path = ''
as $$
begin
  perform antishield_fleet.check_admin(p_fleet, p_token);
  delete from antishield_fleet.devices d where d.id = p_device and d.fleet_id = p_fleet;
end
$$;

create or replace function public.antishield_fleet_admin_delete_fleet(p_fleet uuid, p_token text)
returns void
language plpgsql security definer
set search_path = ''
as $$
begin
  perform antishield_fleet.check_admin(p_fleet, p_token);
  delete from antishield_fleet.fleets f where f.id = p_fleet;
end
$$;

-- ---------- Firemní Mac ----------

create or replace function public.antishield_fleet_invite(p_token_id text)
returns table (bundle text, expires_at_ms bigint)
language sql stable security definer
set search_path = ''
as $$
  select i.bundle, antishield_fleet.ms(i.expires_at)
    from antishield_fleet.invites i
   where i.token_id = p_token_id and i.used_at is null and i.expires_at > now()
$$;

create or replace function public.antishield_fleet_enroll(
  p_token_id text, p_device uuid, p_device_token text, p_bundle text
)
returns void
language plpgsql security definer
set search_path = ''
as $$
declare
  v_fleet uuid;
begin
  if p_token_id is null or p_device is null
     or p_device_token is null or char_length(p_device_token) not between 40 and 128
     or p_bundle is null or char_length(p_bundle) > 8192 then
    raise exception 'fleet_bad_request';
  end if;
  update antishield_fleet.invites i
     set used_at = now(), device_id = p_device
   where i.token_id = p_token_id and i.used_at is null and i.expires_at > now()
  returning i.fleet_id into v_fleet;
  if v_fleet is null then
    raise exception 'fleet_invite_invalid';
  end if;
  if (select count(*) from antishield_fleet.devices d where d.fleet_id = v_fleet) >= 200 then
    raise exception 'fleet_limit';
  end if;
  insert into antishield_fleet.devices (id, fleet_id, token_hash, invite_token_id, bundle, last_seen)
  values (p_device, v_fleet, antishield_fleet.hash_token(p_device_token), p_token_id, p_bundle, now());
end
$$;

create or replace function public.antishield_fleet_poll(p_device uuid, p_token text)
returns table (id uuid, envelope text)
language plpgsql security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  perform antishield_fleet.check_device(p_device, p_token);
  delete from antishield_fleet.commands c
   where c.device_id = p_device and c.created_at < now() - interval '30 days';
  -- Nevyřízený příkaz se doručí znovu po 10 minutách (Mac mohl spadnout);
  -- Mac opakovaný příkaz pozná a jen znovu pošle svůj výsledek.
  return query
    update antishield_fleet.commands c
       set delivered_at = now()
     where c.id in (
       select x.id
         from antishield_fleet.commands x
        where x.device_id = p_device
          and x.result_at is null
          and x.expires_at > now()
          and (x.delivered_at is null or x.delivered_at < now() - interval '10 minutes')
        order by x.created_at
        limit 20)
    returning c.id, c.envelope;
end
$$;

create or replace function public.antishield_fleet_report(p_device uuid, p_token text, p_report text)
returns void
language plpgsql security definer
set search_path = ''
as $$
begin
  perform antishield_fleet.check_device(p_device, p_token);
  if p_report is null or char_length(p_report) > 65536 then
    raise exception 'fleet_bad_request';
  end if;
  update antishield_fleet.devices d
     set report = p_report, report_at = now()
   where d.id = p_device;
end
$$;

create or replace function public.antishield_fleet_result(
  p_device uuid, p_token text, p_command uuid, p_result text
)
returns void
language plpgsql security definer
set search_path = ''
as $$
begin
  perform antishield_fleet.check_device(p_device, p_token);
  if p_command is null or p_result is null or char_length(p_result) > 16384 then
    raise exception 'fleet_bad_request';
  end if;
  update antishield_fleet.commands c
     set result = p_result, result_at = now()
   where c.id = p_command and c.device_id = p_device;
  if not found then
    raise exception 'fleet_unknown_command';
  end if;
end
$$;

create or replace function public.antishield_fleet_leave(p_device uuid, p_token text, p_notice text)
returns void
language plpgsql security definer
set search_path = ''
as $$
begin
  perform antishield_fleet.check_device(p_device, p_token);
  if p_notice is null or char_length(p_notice) > 8192 then
    raise exception 'fleet_bad_request';
  end if;
  update antishield_fleet.devices d
     set left_notice = p_notice, left_at = now()
   where d.id = p_device;
  delete from antishield_fleet.commands c where c.device_id = p_device and c.result_at is null;
end
$$;

-- ---------- Práva: jen anon a jen tyto funkce ----------

do $$
declare
  f record;
begin
  for f in
    select p.oid::regprocedure as signature
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.proname like 'antishield\_fleet\_%'
  loop
    execute format('revoke all on function %s from public, anon, authenticated', f.signature);
    execute format('grant execute on function %s to anon', f.signature);
  end loop;
end
$$;

notify pgrst, 'reload schema';
