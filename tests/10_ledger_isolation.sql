-- Behaviour tests for demo/10_inventory_ledger.sql. Each block raises on failure.
\set ON_ERROR_STOP on
\set QUIET on

insert into auth.users values
  ('00000000-0000-0000-0000-00000000000a'),  -- staff at tenant A
  ('00000000-0000-0000-0000-00000000000b'),  -- staff at tenant B
  ('00000000-0000-0000-0000-00000000000c');  -- viewer at tenant A
insert into public.tenants values
  ('aaaaaaaa-0000-0000-0000-000000000000', 'Tenant A'),
  ('bbbbbbbb-0000-0000-0000-000000000000', 'Tenant B');
insert into public.tenant_members values
  ('aaaaaaaa-0000-0000-0000-000000000000', '00000000-0000-0000-0000-00000000000a', 'staff'),
  ('bbbbbbbb-0000-0000-0000-000000000000', '00000000-0000-0000-0000-00000000000b', 'staff'),
  ('aaaaaaaa-0000-0000-0000-000000000000', '00000000-0000-0000-0000-00000000000c', 'viewer');

create or replace function pg_temp.as_user(p_user text) returns void language sql as $$
  select set_config('request.jwt.claims', json_build_object('sub', p_user, 'role', 'authenticated')::text, false)
$$;

-- Writers record events through the RPC; a replayed provider event is a no-op.
set role authenticated;
select pg_temp.as_user('00000000-0000-0000-0000-00000000000a') \g /dev/null
do $$ begin
  assert public.record_inventory_event('aaaaaaaa-0000-0000-0000-000000000000', 'SKU-1', 'LOC-1', 10, 'receive', 'shopify', 'evt-1', now()) = 'recorded';
  assert public.record_inventory_event('aaaaaaaa-0000-0000-0000-000000000000', 'SKU-1', 'LOC-1', -3, 'sale',    'shopify', 'evt-2', now()) = 'recorded';
  assert public.record_inventory_event('aaaaaaaa-0000-0000-0000-000000000000', 'SKU-1', 'LOC-1', -3, 'sale',    'shopify', 'evt-2', now()) = 'duplicate',
    'webhook retry must not post twice';
  assert (select on_hand from public.inventory_levels where sku = 'SKU-1') = 7, 'cache should be 10 - 3';
  raise notice 'ok  idempotent writes and cache update';
end $$;

select pg_temp.as_user('00000000-0000-0000-0000-00000000000b') \g /dev/null
do $$ begin
  perform public.record_inventory_event('bbbbbbbb-0000-0000-0000-000000000000', 'SKU-9', 'LOC-9', 5, 'receive', 'shopify', 'evt-1', now());
  assert (select count(*) from public.inventory_levels) = 1, 'B must see only its own row';
  assert (select count(*) from public.inventory_events where tenant_id = 'aaaaaaaa-0000-0000-0000-000000000000') = 0,
    'B must not see A''s events';
  raise notice 'ok  tenant B cannot read tenant A';
end $$;

-- Writing into another tenant through the RPC is refused.
do $$ begin
  begin
    perform public.record_inventory_event('aaaaaaaa-0000-0000-0000-000000000000', 'SKU-1', 'LOC-1', 100, 'adjust', 'manual', 'x', now());
    raise exception 'cross-tenant write was allowed';
  exception when insufficient_privilege then
    raise notice 'ok  cross-tenant write refused';
  end;
end $$;

-- Viewers can read but not write.
select pg_temp.as_user('00000000-0000-0000-0000-00000000000c') \g /dev/null
do $$ begin
  assert (select count(*) from public.inventory_events) = 2, 'viewer reads own tenant';
  begin
    perform public.record_inventory_event('aaaaaaaa-0000-0000-0000-000000000000', 'SKU-1', 'LOC-1', 1, 'adjust', 'manual', 'v', now());
    raise exception 'viewer write was allowed';
  exception when insufficient_privilege then
    raise notice 'ok  viewer is read-only';
  end;
end $$;

-- Direct table writes are refused for clients: no privilege, regardless of policy.
do $$ begin
  begin
    insert into public.inventory_levels values ('aaaaaaaa-0000-0000-0000-000000000000', 'SKU-1', 'LOC-1', 9999, 1);
    raise exception 'client could write the cache directly';
  exception when insufficient_privilege then null;
  end;
  begin
    update public.inventory_events set qty_delta = 1000;
    raise exception 'client could rewrite the ledger';
  exception when insufficient_privilege then null;
  end;
  raise notice 'ok  clients cannot write tables directly';
end $$;

-- Anonymous callers get nothing.
reset role;
set role anon;
select set_config('request.jwt.claims', '', false) \g /dev/null
do $$ begin
  begin
    perform count(*) from public.inventory_events;
    raise exception 'anon could read the ledger';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.record_inventory_event('aaaaaaaa-0000-0000-0000-000000000000', 'SKU-1', 'LOC-1', 1, 'adjust', 'manual', 'anon', now());
    raise exception 'anon could call the write RPC';
  exception when insufficient_privilege then null;
  end;
  raise notice 'ok  anon has no access';
end $$;
reset role;

-- Even the owner cannot rewrite history; corrections are new events.
do $$ begin
  begin
    update public.inventory_events set qty_delta = 1 where id = 1;
    raise exception 'owner could update the ledger';
  exception when insufficient_privilege then null;
  end;
  begin
    delete from public.inventory_events;
    raise exception 'owner could delete from the ledger';
  exception when insufficient_privilege then null;
  end;
  begin
    truncate public.inventory_events cascade;
    raise exception 'owner could truncate the ledger';
  exception when insufficient_privilege then null;
  end;
  raise notice 'ok  ledger is append-only, even for the owner';
end $$;

-- A corrupted cache is detected and rebuilt from the log.
set role service_role;
do $$ begin
  assert (select count(*) from private.inventory_drift) = 0, 'no drift expected yet';
end $$;
reset role;
update public.inventory_levels set on_hand = 500 where sku = 'SKU-1';
set role service_role;
do $$ begin
  assert (select count(*) from private.inventory_drift) = 1, 'drift should be detected';
  perform private.rebuild_inventory_levels('aaaaaaaa-0000-0000-0000-000000000000');
  assert (select count(*) from private.inventory_drift) = 0, 'rebuild should clear drift';
  assert (select on_hand from public.inventory_levels where sku = 'SKU-1') = 7;
  raise notice 'ok  drift detected and cache rebuilt from the log';
end $$;
reset role;

-- Rebuild is not callable by clients.
set role authenticated;
do $$ begin
  begin
    perform private.rebuild_inventory_levels('aaaaaaaa-0000-0000-0000-000000000000');
    raise exception 'client could call rebuild';
  exception when insufficient_privilege then
    raise notice 'ok  rebuild is service-role only';
  end;
end $$;
reset role;
