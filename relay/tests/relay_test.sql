-- Funkční test schránky jako role anon (jen na zkušební databázi).
\set ON_ERROR_STOP 1
\set fleet '11111111-1111-4111-8111-111111111111'
\set fleet2 '55555555-5555-4555-8555-555555555555'
\set dev '22222222-2222-4222-8222-222222222222'
\set dev2 '44444444-4444-4444-8444-444444444444'
\set cmd '33333333-3333-4333-8333-333333333333'
\set atok 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
\set dtok 'ddddddddddddddddddddddddddddddddddddddddddd'
\set d2tok 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'

create schema test;
grant usage on schema test to anon, authenticated;
create function test.expect(p_sql text, p_error text) returns void language plpgsql as $$
begin
  begin
    execute p_sql;
  exception when others then
    if sqlerrm like p_error then
      raise notice 'ok  % -> %', left(p_sql, 70), sqlerrm;
      return;
    end if;
    raise exception 'WRONG ERROR for %: % (expected %)', p_sql, sqlerrm, p_error;
  end;
  raise exception 'NO ERROR for %, expected %', p_sql, p_error;
end $$;
create function test.check(p_cond boolean, p_what text) returns void language plpgsql as $$
begin
  if p_cond is not true then raise exception 'CHECK FAILED: %', p_what; end if;
  raise notice 'ok  %', p_what;
end $$;
grant execute on all functions in schema test to anon, authenticated;

insert into antishield_fleet.activations (code_hash, note, expires_at, uses_left)
values (sha256(convert_to('HHA1TESTACTIVATION', 'UTF8')), 'test', now() + interval '1 day', 1),
       (sha256(convert_to('HHA1EXPIRED', 'UTF8')), 'test', now() - interval '1 minute', 5);

select (extract(epoch from now() + interval '1 day') * 1000)::bigint as exp_ms \gset
select (extract(epoch from now() + interval '9 days') * 1000)::bigint as far_ms \gset

create table test.vars (k text primary key, v text);
insert into test.vars values ('fleet', :'fleet'), ('fleet2', :'fleet2'), ('dev', :'dev'), ('dev2', :'dev2'),
  ('cmd', :'cmd'), ('atok', :'atok'), ('dtok', :'dtok'), ('d2tok', :'d2tok'), ('exp_ms', :'exp_ms'), ('far_ms', :'far_ms');
create function test.v(p_k text) returns text language sql stable as $$ select v from test.vars where k = p_k $$;
grant select on test.vars to anon, authenticated;
grant execute on function test.v(text) to anon, authenticated;

-- ---------- Přístup ----------
set role authenticated;
select test.expect($$select public.antishield_fleet_create('HHA1TESTACTIVATION', gen_random_uuid(), repeat('a', 43))$$, 'permission denied%');
select test.expect($$select public.antishield_fleet_poll(gen_random_uuid(), 'x')$$, 'permission denied%');

set role anon;
select test.expect('select * from antishield_fleet.devices', 'permission denied%');
select test.expect('select * from antishield_fleet.activations', 'permission denied%');
select test.expect($$insert into antishield_fleet.activations (code_hash, expires_at) values (sha256('x'::bytea), now() + interval '1 day')$$, 'permission denied%');
select test.expect($$select antishield_fleet.hash_token('x')$$, 'permission denied%');

-- ---------- Založení firmy ----------
select test.expect($$select public.antishield_fleet_create('HHA1WRONG', test.v('fleet')::uuid, test.v('atok'))$$, 'fleet_activation_invalid');
select test.expect($$select public.antishield_fleet_create('HHA1EXPIRED', test.v('fleet')::uuid, test.v('atok'))$$, 'fleet_activation_invalid');
select test.expect($$select public.antishield_fleet_create('HHA1TESTACTIVATION', test.v('fleet')::uuid, 'short')$$, 'fleet_bad_request');
select public.antishield_fleet_create('HHA1TESTACTIVATION', :'fleet', :'atok');
select test.expect($$select public.antishield_fleet_create('HHA1TESTACTIVATION', test.v('fleet2')::uuid, test.v('atok'))$$, 'fleet_activation_invalid');

-- ---------- Pozvánka ----------
select test.expect($$select public.antishield_fleet_admin_invite(test.v('fleet')::uuid, 'wrong-token', 'INVITETOKENID0001', 'B1', test.v('exp_ms')::bigint)$$, 'fleet_not_authorized');
select test.expect($$select public.antishield_fleet_admin_invite(test.v('fleet')::uuid, test.v('atok'), 'INVITETOKENID0001', 'B1', test.v('far_ms')::bigint)$$, 'fleet_bad_request');
select test.expect($$select public.antishield_fleet_admin_invite(test.v('fleet')::uuid, test.v('atok'), 'SHORT', 'B1', test.v('exp_ms')::bigint)$$, 'fleet_bad_request');
select public.antishield_fleet_admin_invite(:'fleet', :'atok', 'INVITETOKENID0001', 'B1', :exp_ms);
select public.antishield_fleet_admin_invite(:'fleet', :'atok', 'INVITETOKENID0002', 'B2', :exp_ms);
select public.antishield_fleet_admin_invite(:'fleet', :'atok', 'INVITETOKENID0003', 'B3', :exp_ms);
select test.check((select count(*) = 1 and min(bundle) = 'B1' and abs(min(expires_at_ms) - :exp_ms) < 2
                     from public.antishield_fleet_invite('INVITETOKENID0001')), 'invite returns its bundle and expiry');
select test.check((select count(*) = 0 from public.antishield_fleet_invite('NOSUCHINVITE0000')), 'unknown invite returns nothing');

-- ---------- Připojení Macu ----------
select test.expect($$select public.antishield_fleet_enroll('INVITETOKENID0001', test.v('dev')::uuid, 'short', 'DB1')$$, 'fleet_bad_request');
select public.antishield_fleet_enroll('INVITETOKENID0001', :'dev', :'dtok', 'DB1');
select test.expect($$select public.antishield_fleet_enroll('INVITETOKENID0001', test.v('dev2')::uuid, test.v('d2tok'), 'DB2')$$, 'fleet_invite_invalid');
select test.check((select count(*) = 0 from public.antishield_fleet_invite('INVITETOKENID0001')), 'used invite is gone');
select public.antishield_fleet_enroll('INVITETOKENID0002', :'dev2', :'d2tok', 'DB2');

-- ---------- Příkazy ----------
select test.expect($$select public.antishield_fleet_admin_command(test.v('fleet')::uuid, test.v('atok'), test.v('cmd')::uuid, gen_random_uuid(), 'E1', test.v('exp_ms')::bigint)$$, 'fleet_unknown_device');
select test.expect($$select public.antishield_fleet_admin_command(test.v('fleet')::uuid, test.v('atok'), test.v('cmd')::uuid, test.v('dev')::uuid, 'E1', test.v('far_ms')::bigint)$$, 'fleet_bad_request');
select public.antishield_fleet_admin_command(:'fleet', :'atok', :'cmd', :'dev', 'E1', :exp_ms);
select test.expect($$select * from public.antishield_fleet_poll(test.v('dev')::uuid, test.v('d2tok'))$$, 'fleet_not_authorized');
select test.check((select count(*) = 1 and min(envelope) = 'E1' and min(id::text) = :'cmd'
                     from public.antishield_fleet_poll(:'dev', :'dtok')), 'poll delivers the command');
select test.check((select count(*) = 0 from public.antishield_fleet_poll(:'dev', :'dtok')), 'delivered command is not repeated at once');
select test.check((select count(*) = 0 from public.antishield_fleet_poll(:'dev2', :'d2tok')), 'other Mac gets nothing');
reset role;
update antishield_fleet.commands set delivered_at = now() - interval '11 minutes' where id = :'cmd';
set role anon;
select test.check((select count(*) = 1 from public.antishield_fleet_poll(:'dev', :'dtok')), 'unanswered command is redelivered after 10 minutes');

select public.antishield_fleet_report(:'dev', :'dtok', 'R1');
select test.expect($$select public.antishield_fleet_result(test.v('dev2')::uuid, test.v('d2tok'), test.v('cmd')::uuid, 'X')$$, 'fleet_unknown_command');
select public.antishield_fleet_result(:'dev', :'dtok', :'cmd', 'RES1');
reset role;
update antishield_fleet.commands set delivered_at = now() - interval '11 minutes' where id = :'cmd';
set role anon;
select test.check((select count(*) = 0 from public.antishield_fleet_poll(:'dev', :'dtok')), 'answered command is not redelivered');

-- Limity: 50 nevyřízených příkazů na Mac, poll vrací nejvýš 20.
do $$
begin
  for i in 1..50 loop
    perform public.antishield_fleet_admin_command('11111111-1111-4111-8111-111111111111', repeat('a', 43),
      gen_random_uuid(), '44444444-4444-4444-8444-444444444444', 'L' || i,
      (extract(epoch from now() + interval '1 day') * 1000)::bigint);
  end loop;
end $$;
select test.expect($$select public.antishield_fleet_admin_command(test.v('fleet')::uuid, test.v('atok'), gen_random_uuid(), test.v('dev2')::uuid, 'L51', test.v('exp_ms')::bigint)$$, 'fleet_limit');
select test.check((select count(*) = 20 from public.antishield_fleet_poll(:'dev2', :'d2tok')), 'poll returns at most 20');
select test.check((select count(*) = 20 from public.antishield_fleet_poll(:'dev2', :'d2tok')), 'next poll returns the next 20');
select test.check((select count(*) = 10 from public.antishield_fleet_poll(:'dev2', :'d2tok')), 'then the rest');

-- ---------- Stav pro správce ----------
select public.antishield_fleet_admin_state(:'fleet', :'atok') as st \gset
select test.check((:'st'::jsonb ->> 'nowMs')::bigint > 0, 'state has nowMs');
select test.check(jsonb_array_length(:'st'::jsonb -> 'devices') = 2, 'state lists both Macs');
select test.check((select d ->> 'report' = 'R1' and d ->> 'bundle' = 'DB1' and d ->> 'inviteTokenId' = 'INVITETOKENID0001'
                          and (d ->> 'lastSeenMs')::bigint > 0 and (d ->> 'createdAtMs')::bigint > 0 and d -> 'leftNotice' = 'null'::jsonb
                     from jsonb_array_elements(:'st'::jsonb -> 'devices') d where d ->> 'id' = :'dev'), 'state shows Mac report and bundle');
select test.check((select c ->> 'result' = 'RES1' and (c ->> 'deliveredAtMs')::bigint > 0 and (c ->> 'resultAtMs')::bigint > 0
                     from jsonb_array_elements(:'st'::jsonb -> 'commands') c where c ->> 'id' = :'cmd'), 'state shows command result');
select test.check(jsonb_array_length(:'st'::jsonb -> 'commands') = 51, 'state lists all commands');
select test.check(jsonb_array_length(:'st'::jsonb -> 'invites') = 3, 'state lists invites');
select test.expect($$select public.antishield_fleet_admin_state(test.v('fleet')::uuid, 'wrong-token')$$, 'fleet_not_authorized');

-- ---------- Zrušení pozvánky ----------
select public.antishield_fleet_admin_revoke_invite(:'fleet', :'atok', 'INVITETOKENID0003');
select public.antishield_fleet_admin_revoke_invite(:'fleet', :'atok', 'INVITETOKENID0001');
select test.check((select count(*) = 0 from public.antishield_fleet_invite('INVITETOKENID0003')), 'revoked invite is gone');
select test.check(jsonb_array_length(public.antishield_fleet_admin_state(:'fleet', :'atok') -> 'invites') = 2, 'used invite stays recorded');

-- ---------- Odpojení Macu ----------
select public.antishield_fleet_leave(:'dev2', :'d2tok', 'BYE2');
select test.expect($$select * from public.antishield_fleet_poll(test.v('dev2')::uuid, test.v('d2tok'))$$, 'fleet_not_authorized');
select test.expect($$select public.antishield_fleet_report(test.v('dev2')::uuid, test.v('d2tok'), 'R')$$, 'fleet_not_authorized');
select test.expect($$select public.antishield_fleet_admin_command(test.v('fleet')::uuid, test.v('atok'), gen_random_uuid(), test.v('dev2')::uuid, 'E', test.v('exp_ms')::bigint)$$, 'fleet_unknown_device');
select public.antishield_fleet_admin_state(:'fleet', :'atok') as st \gset
select test.check((select d ->> 'leftNotice' = 'BYE2' from jsonb_array_elements(:'st'::jsonb -> 'devices') d where d ->> 'id' = :'dev2'), 'state shows goodbye');
select test.check(jsonb_array_length(:'st'::jsonb -> 'commands') = 1, 'pending commands of the leaving Mac are dropped');

-- ---------- Odebrání Macu a smazání firmy ----------
select test.expect($$select public.antishield_fleet_admin_remove_device(test.v('fleet')::uuid, 'wrong-token', test.v('dev2')::uuid)$$, 'fleet_not_authorized');
select public.antishield_fleet_admin_remove_device(:'fleet', :'atok', :'dev2');
select test.check(jsonb_array_length(public.antishield_fleet_admin_state(:'fleet', :'atok') -> 'devices') = 1, 'removed Mac is gone');
select test.expect($$select public.antishield_fleet_admin_delete_fleet(test.v('fleet')::uuid, 'wrong-token')$$, 'fleet_not_authorized');
select public.antishield_fleet_admin_delete_fleet(:'fleet', :'atok');
select test.expect($$select public.antishield_fleet_admin_state(test.v('fleet')::uuid, test.v('atok'))$$, 'fleet_not_authorized');
select test.expect($$select * from public.antishield_fleet_poll(test.v('dev')::uuid, test.v('dtok'))$$, 'fleet_not_authorized');

reset role;
select test.check((select count(*) = 0 from antishield_fleet.fleets) and (select count(*) = 0 from antishield_fleet.devices)
                  and (select count(*) = 0 from antishield_fleet.commands) and (select count(*) = 0 from antishield_fleet.invites),
                  'deleting the fleet removes everything');
select test.check((select uses_left = 0 and last_used_at is not null from antishield_fleet.activations
                    where code_hash = sha256(convert_to('HHA1TESTACTIVATION', 'UTF8'))), 'activation code was used up');
\echo ALL RELAY TESTS PASSED
