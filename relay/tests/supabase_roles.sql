-- Role jako v Supabase, pro zkušební PostgreSQL (ne pro Supabase samotné).
create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;
-- Supabase dává novým funkcím v public právo execute pro všechny API role;
-- migrace ho musí sama omezit jen na anon.
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
grant usage on schema public to anon, authenticated, service_role;
