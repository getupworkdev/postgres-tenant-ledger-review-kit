-- Why GRANT SELECT does not narrow an earlier GRANT ALL: privileges are a set,
-- and GRANT only adds to it. Only REVOKE removes.
\set ON_ERROR_STOP on
\set QUIET on

create table public.grant_demo (id int);           -- Supabase default: ALL to anon, authenticated

do $$ begin
  assert has_table_privilege('authenticated', 'public.grant_demo', 'INSERT'), 'default grant gives INSERT';
end $$;

grant select on public.grant_demo to authenticated; -- the "narrowing" that narrows nothing

do $$ begin
  assert has_table_privilege('authenticated', 'public.grant_demo', 'INSERT'), 'INSERT is still there';
  assert has_table_privilege('authenticated', 'public.grant_demo', 'DELETE'), 'DELETE is still there';
  raise notice 'ok  GRANT SELECT after GRANT ALL leaves INSERT/UPDATE/DELETE in place';
end $$;

revoke all on public.grant_demo from authenticated;
grant select on public.grant_demo to authenticated;

do $$ begin
  assert not has_table_privilege('authenticated', 'public.grant_demo', 'INSERT');
  assert has_table_privilege('authenticated', 'public.grant_demo', 'SELECT');
  raise notice 'ok  REVOKE ALL then GRANT SELECT gives exactly SELECT';
end $$;

-- Functions: EXECUTE goes to PUBLIC by default, so revoking from authenticated
-- alone leaves it callable through PUBLIC.
create function public.fn_demo() returns int language sql security definer set search_path = '' as $$ select 1 $$;
revoke all on function public.fn_demo() from anon, authenticated;
do $$ begin
  assert has_function_privilege('authenticated', 'public.fn_demo()', 'EXECUTE'),
    'still executable via PUBLIC';
end $$;
revoke all on function public.fn_demo() from public;
do $$ begin
  assert not has_function_privilege('authenticated', 'public.fn_demo()', 'EXECUTE');
  raise notice 'ok  SECURITY DEFINER functions need REVOKE ... FROM PUBLIC too';
end $$;

drop function public.fn_demo();
drop table public.grant_demo;
