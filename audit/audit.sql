-- Read-only security audit for Postgres / Supabase.
--
-- Run against staging with a read-only role:
--   psql "$STAGING_URL" -v schemas='public' -f audit/audit.sql
--
-- Every row is a finding: severity, check, object, detail. Nothing is changed.
-- `schemas` is the comma-separated list of schemas exposed through the API.

\if :{?schemas}
\else
  \set schemas 'public'
\endif

begin read only;
select set_config('audit.schemas', :'schemas', true) \g /dev/null

select * from (
with
exposed as (
  select n.oid, n.nspname
  from pg_namespace n
  where n.nspname = any (string_to_array(current_setting('audit.schemas'), ','))
),
client_roles as (
  select oid, rolname from pg_roles where rolname in ('anon', 'authenticated')
  union all select 0, 'PUBLIC'
),
tables as (
  select c.oid, n.nspname, c.relname, c.relrowsecurity, c.relacl, c.relowner,
         obj_description(c.oid, 'pg_class') as comment
  from pg_class c join exposed n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p')
),
table_privs as (
  select t.oid, cr.rolname as grantee, a.privilege_type
  from tables t
  cross join lateral aclexplode(coalesce(t.relacl, acldefault('r', t.relowner))) a
  join client_roles cr on cr.oid = a.grantee
)

-- A1: table reachable by client roles with RLS off.
select 'high' as severity, 'rls_disabled' as check_id,
       format('%I.%I', t.nspname, t.relname) as object,
       'RLS is off and ' || string_agg(distinct p.grantee || ':' || p.privilege_type, ', ') || ' is granted' as detail
from tables t join table_privs p on p.oid = t.oid
where not t.relrowsecurity
group by t.nspname, t.relname

union all
-- A2: permissive policy whose condition is literally true, for client roles.
select 'high', 'policy_always_true',
       format('%I.%I policy %I', pol.schemaname, pol.tablename, pol.policyname),
       format('%s for {%s}: using=%s check=%s', pol.cmd, array_to_string(pol.roles, ','),
              coalesce(pol.qual, '-'), coalesce(pol.with_check, '-'))
from pg_policies pol
join exposed n on n.nspname = pol.schemaname
where pol.permissive = 'PERMISSIVE'
  and pol.roles && array['public', 'anon', 'authenticated']::name[]
  and (pol.qual = 'true' or pol.with_check = 'true')
  and pol.cmd <> 'SELECT'

union all
select 'medium', 'select_policy_always_true',
       format('%I.%I policy %I', pol.schemaname, pol.tablename, pol.policyname),
       format('every row readable by {%s}; fine only for genuinely public data', array_to_string(pol.roles, ','))
from pg_policies pol
join exposed n on n.nspname = pol.schemaname
where pol.permissive = 'PERMISSIVE'
  and pol.roles && array['public', 'anon', 'authenticated']::name[]
  and pol.qual = 'true'
  and pol.cmd = 'SELECT'

union all
-- A3: write privileges held by client roles. With RLS on this is not a leak by
-- itself, but it means a single bad policy becomes a write hole.
select 'medium', 'client_write_grant',
       format('%I.%I', t.nspname, t.relname),
       string_agg(distinct p.grantee || ':' || p.privilege_type, ', ')
from tables t join table_privs p on p.oid = t.oid
where t.relrowsecurity
  and p.privilege_type in ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
group by t.nspname, t.relname

union all
-- A4: SECURITY DEFINER without a pinned search_path.
select 'high', 'definer_no_search_path',
       format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
       'SECURITY DEFINER with no SET search_path; callers can shadow unqualified names'
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef
  and n.nspname not in ('pg_catalog', 'information_schema')
  and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%')

union all
-- A5: SECURITY DEFINER callable by client roles from an exposed schema = an RPC
-- that runs with the owner's rights. Each one needs its own authorisation check.
-- Once reviewed, mark it with COMMENT ON FUNCTION ... IS '... audit: reviewed ...' to drop it to info.
select case when obj_description(p.oid, 'pg_proc') ilike '%audit: reviewed%' then 'info' else 'medium' end,
       'definer_exposed_rpc',
       format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
       'executable by ' || string_agg(distinct cr.rolname, ', ') || '; confirm it checks auth.uid() and tenant membership itself'
from pg_proc p
join exposed n on n.oid = p.pronamespace
cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
join client_roles cr on cr.oid = a.grantee
where p.prosecdef and a.privilege_type = 'EXECUTE'
group by n.nspname, p.proname, p.oid

union all
-- A6: views that run with the owner's rights over RLS tables.
select 'high', 'view_bypasses_rls',
       format('%I.%I', n.nspname, v.relname),
       'view without security_invoker reads RLS table(s): ' || string_agg(distinct format('%I.%I', bn.nspname, b.relname), ', ')
from pg_class v
join exposed n on n.oid = v.relnamespace
join pg_rewrite r on r.ev_class = v.oid
join pg_depend d on d.objid = r.oid and d.classid = 'pg_rewrite'::regclass and d.refclassid = 'pg_class'::regclass
join pg_class b on b.oid = d.refobjid and b.oid <> v.oid and b.relrowsecurity
join pg_namespace bn on bn.oid = b.relnamespace
where v.relkind = 'v'
  and not coalesce('security_invoker=true' = any (v.reloptions) or 'security_invoker=on' = any (v.reloptions), false)
  and exists (
    select 1 from aclexplode(coalesce(v.relacl, acldefault('r', v.relowner))) a
    join client_roles cr on cr.oid = a.grantee where a.privilege_type = 'SELECT')
group by n.nspname, v.relname

union all
-- A7: tables tagged append-only that can still be changed.
select 'high', 'ledger_mutable',
       format('%I.%I', t.nspname, t.relname),
       concat_ws('; ',
         nullif(string_agg(distinct p.grantee || ':' || p.privilege_type, ', ')
                filter (where p.privilege_type in ('UPDATE', 'DELETE', 'TRUNCATE')), ''),
         case when not exists (
           select 1 from pg_trigger tg
           where tg.tgrelid = t.oid and not tg.tgisinternal
             and (tg.tgtype & 8) <> 0 and (tg.tgtype & 16) <> 0)   -- fires on DELETE and UPDATE
         then 'no trigger blocking UPDATE/DELETE' end)
from tables t
left join table_privs p on p.oid = t.oid
where t.comment ilike '%append-only%'
group by t.oid, t.nspname, t.relname
having bool_or(p.privilege_type in ('UPDATE', 'DELETE', 'TRUNCATE'))
    or not exists (
      select 1 from pg_trigger tg
      where tg.tgrelid = t.oid and not tg.tgisinternal
        and (tg.tgtype & 8) <> 0 and (tg.tgtype & 16) <> 0)

union all
-- A8: default privileges that will hand future objects to client roles.
select 'info', 'default_privileges',
       coalesce(n.nspname, '(all schemas)') || ' / ' || case d.defaclobjtype
         when 'r' then 'tables' when 'f' then 'functions' when 'S' then 'sequences' else d.defaclobjtype::text end,
       'new objects created by ' || pg_get_userbyid(d.defaclrole) || ' get: ' ||
       string_agg(distinct cr.rolname || ':' || a.privilege_type, ', ')
from pg_default_acl d
left join pg_namespace n on n.oid = d.defaclnamespace
cross join lateral aclexplode(d.defaclacl) a
join client_roles cr on cr.oid = a.grantee
where n.nspname is null or n.nspname = any (string_to_array(current_setting('audit.schemas'), ','))
group by n.nspname, d.defaclobjtype, d.defaclrole
) findings
order by case severity when 'high' then 1 when 'medium' then 2 else 3 end, check_id, object;

rollback;
