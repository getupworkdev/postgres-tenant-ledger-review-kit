-- Minimal stand-in for the parts of Supabase this kit depends on, so everything
-- runs on plain Postgres in CI. It reproduces Supabase's default grants on
-- purpose: that is where most real exposure comes from.

do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon')          then create role anon nologin noinherit; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin noinherit; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role')  then create role service_role nologin noinherit bypassrls; end if;
end $$;

do $$ begin
  if not pg_has_role(current_user, 'service_role', 'member') then
    execute format('grant anon, authenticated, service_role to %I', current_user);
  end if;
end $$;

create schema if not exists auth;
grant usage on schema auth to anon, authenticated, service_role;

-- Same contract as Supabase: the user id comes from the request JWT claims.
create or replace function auth.uid() returns uuid
language sql stable
as $$
  select nullif(current_setting('request.jwt.claims', true)::json ->> 'sub', '')::uuid
$$;

create table if not exists auth.users (id uuid primary key);

grant usage on schema public to anon, authenticated, service_role;

-- Supabase's defaults: every new table, function and sequence in public is
-- granted to anon and authenticated. RLS, not grants, is then the only wall.
alter default privileges in schema public grant all on tables    to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
